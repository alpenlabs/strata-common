//! Marker classification, reveal-slot derivation, and payload extraction.
//!
//! The enforcement side of the format: what a reader accepts back off chain.

use std::collections::BTreeMap;

use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::Instruction;
use bitcoin::taproot::LeafVersion;
use bitcoin::{Transaction, Txid};
use strata_l1_envelope_fmt::SIGNED_LEAF_PUBKEY_LEN;
use strata_l1_envelope_fmt::parser::parse_exact_signed_envelope_leaf;
use strata_l1_txfmt::MagicBytes;

use crate::MAX_MARKER_PAYLOAD_BYTES;
use crate::errors::CommitRevealParseError;

/// One commit/reveal set, read back off chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommitReveal<'t> {
    commit: &'t Transaction,
    marker_tail: &'t [u8],
    reveal_pubkey: [u8; SIGNED_LEAF_PUBKEY_LEN],
    chunks: Vec<Vec<u8>>,
}

impl<'t> ParsedCommitReveal<'t> {
    /// The commit transaction of the set.
    pub const fn commit(&self) -> &'t Transaction {
        self.commit
    }

    /// Marker bytes after the magic, for the caller to interpret.
    pub const fn marker_tail(&self) -> &'t [u8] {
        self.marker_tail
    }

    /// The x-only pubkey every reveal leaf in the set carries.
    ///
    /// This crate applies no key policy. Comparing these bytes against a
    /// configured key authenticates the set, but only because the leaves parsed
    /// strictly — see
    /// [`parse_exact_signed_envelope_leaf`](strata_l1_envelope_fmt::parser::parse_exact_signed_envelope_leaf).
    pub const fn reveal_pubkey(&self) -> [u8; SIGNED_LEAF_PUBKEY_LEN] {
        self.reveal_pubkey
    }

    /// Payload chunks in commit-output order.
    ///
    /// The payload is their concatenation. Borrowed rather than joined so a
    /// reader can decode across them, which is what the zkVM guest does to
    /// avoid an allocation and copy the size of the whole payload.
    pub fn chunks(&self) -> &[Vec<u8>] {
        &self.chunks
    }

    /// Consumes the set, joining the chunks into the payload.
    ///
    /// Allocates and copies the whole payload; use [`Self::chunks`] where that
    /// matters.
    pub fn into_payload(self) -> Vec<u8> {
        self.chunks.concat()
    }
}

/// The reveal-slot range `[1, last_vout]` of a commit transaction.
///
/// Output 0 is the marker, so slots start at 1. Chunk count is conveyed by the
/// length of this run and never written on chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevealSlotRange {
    last_vout: u32,
}

impl RevealSlotRange {
    /// Constructs a range covering outputs `1..=last_vout`.
    ///
    /// # Errors
    ///
    /// Returns [`CommitRevealParseError::EmptyRevealSlotRange`] when
    /// `last_vout` is 0, since output 0 is the marker and never a slot.
    pub fn try_new(last_vout: u32) -> Result<Self, CommitRevealParseError> {
        if last_vout == 0 {
            return Err(CommitRevealParseError::EmptyRevealSlotRange);
        }
        Ok(Self { last_vout })
    }

    /// The last output index in the range.
    pub const fn last_vout(&self) -> u32 {
        self.last_vout
    }

    /// Whether `vout` is a reveal slot of this commit.
    pub const fn contains(&self, vout: u32) -> bool {
        vout >= 1 && vout <= self.last_vout
    }
}

/// Reads the marker tail from a candidate commit transaction.
///
/// Returns `Some(tail)` when output 0 is an `OP_RETURN` carrying exactly
/// one push that starts with the supplied magic and is no longer than
/// [`MAX_MARKER_PAYLOAD_BYTES`], `None` otherwise.
///
/// Never fails: this runs against every transaction in an L1 range, so "not
/// ours" is an ordinary answer. The tail is not interpreted here; consumers
/// decide whether it is valid for their payload and version.
///
/// Deliberately not built on [`strata_l1_txfmt::ParseConfig`]: SPS-50 tags
/// are a different format with their own minimum length, and SPS-53
/// requires the marker to be exactly one push, which the SPS-50 reader does
/// not check.
pub fn read_commit_marker<'t>(magic: &MagicBytes, tx: &'t Transaction) -> Option<&'t [u8]> {
    let first_output = tx.output.first()?;
    let mut instructions = first_output.script_pubkey.instructions();

    match instructions.next() {
        Some(Ok(Instruction::Op(OP_RETURN))) => {}
        _ => return None,
    }

    let Some(Ok(Instruction::PushBytes(push))) = instructions.next() else {
        return None;
    };

    // Exactly one push: a second instruction means this is some other
    // protocol's OP_RETURN that happens to share our prefix.
    if instructions.next().is_some() {
        return None;
    }

    let payload = push.as_bytes();
    if payload.len() > MAX_MARKER_PAYLOAD_BYTES {
        return None;
    }

    payload.strip_prefix(magic.as_bytes().as_slice())
}

/// Extracts a set for a commit the caller has already identified.
///
/// The range-scanner entry point. Nothing here re-classifies transactions
/// by marker, so a reveal that is itself the next commit is read as a
/// reveal. Every slot must be covered exactly once.
///
/// `reveals` must already be grouped to transactions that may spend this
/// commit. This is not a filter over a whole L1 range: an unrelated
/// transaction yields [`CommitRevealParseError::RevealWrongCommit`] rather
/// than being skipped.
///
/// Whether a reveal *also* serves some other commit is invisible here: a
/// foreign input cannot be told apart from a fee-funding UTXO without the
/// set of commits in the range, which only a scanner holds.
///
/// # Errors
///
/// Returns [`CommitRevealParseError::MissingCommit`] if `commit` carries no
/// marker for `magic`. Otherwise returns [`CommitRevealParseError`] if the
/// commit has no reveal slots, if any slot is missing or claimed twice, if any
/// reveal fails to parse, or if the reveals do not agree on one pubkey.
pub fn extract_payload_for_commit<'t>(
    magic: &MagicBytes,
    commit: &'t Transaction,
    reveals: impl IntoIterator<Item = &'t Transaction>,
) -> Result<ParsedCommitReveal<'t>, CommitRevealParseError> {
    let marker_tail =
        read_commit_marker(magic, commit).ok_or(CommitRevealParseError::MissingCommit)?;

    extract_for_commit(commit, marker_tail, reveals)
}

/// [`extract_payload_for_commit`], rejecting a set whose reveals are
/// not keyed to `expected_reveal_pubkey`.
///
/// Comparing the recovered pubkey is only meaningful because the leaves
/// parsed strictly: the shape is what makes a confirmed spend evidence that
/// the key's holder signed. Callers that compare the key themselves get the
/// same guarantee; this is the same check spelled once.
///
/// # Errors
///
/// As [`extract_payload_for_commit`], plus
/// [`CommitRevealParseError::UnexpectedRevealPubkey`] if the key differs.
pub fn extract_authenticated_payload_for_commit<'t>(
    magic: &MagicBytes,
    commit: &'t Transaction,
    reveals: impl IntoIterator<Item = &'t Transaction>,
    expected_reveal_pubkey: &[u8; SIGNED_LEAF_PUBKEY_LEN],
) -> Result<ParsedCommitReveal<'t>, CommitRevealParseError> {
    let parsed = extract_payload_for_commit(magic, commit, reveals)?;

    if parsed.reveal_pubkey() != *expected_reveal_pubkey {
        return Err(CommitRevealParseError::UnexpectedRevealPubkey);
    }

    Ok(parsed)
}

/// Extracts a set from a closed group holding one commit plus its reveals.
///
/// For callers handed a fixed set that is *supposed* to be one commit plus
/// its reveals, such as a proof witness. There "no commit" and "two
/// commits" are real errors, so the commit is selected by marker here.
///
/// Range scanners must use [`extract_payload_for_commit`] instead:
/// they know their commit already, and re-classifying would misread a
/// reveal that is itself the next commit.
///
/// # Errors
///
/// Returns [`CommitRevealParseError::MissingCommit`] or
/// [`CommitRevealParseError::MultipleCommits`] if the group does not hold
/// exactly one commit, or any extraction error from the reveals.
pub fn extract_payload_from_single_commit_set<'t>(
    magic: &MagicBytes,
    txs: impl IntoIterator<Item = &'t Transaction>,
) -> Result<ParsedCommitReveal<'t>, CommitRevealParseError> {
    let mut commit = None;
    let mut reveals = Vec::new();

    for tx in txs {
        match read_commit_marker(magic, tx) {
            Some(tail) => {
                if commit.replace((tx, tail)).is_some() {
                    return Err(CommitRevealParseError::MultipleCommits);
                }
            }
            None => reveals.push(tx),
        }
    }

    let (commit, marker_tail) = commit.ok_or(CommitRevealParseError::MissingCommit)?;

    extract_for_commit(commit, marker_tail, reveals)
}

/// Derives the reveal-slot range of a commit transaction.
///
/// Returns the last index of the contiguous P2TR run starting at output 1, or
/// `Ok(None)` when there is none.
///
/// Reading chunk count off this run is sound only while change is non-P2TR,
/// which is Layout A's rule. A full SPS-53 transaction writer must enforce it
/// by refusing a P2TR change address; this crate builds scripts, not funded
/// transactions, so it cannot. The parser therefore rejects a P2TR output after
/// the run has closed rather than guessing the boundary.
///
/// # Errors
///
/// Returns [`CommitRevealParseError::AmbiguousTaprootChangeOutput`] when a P2TR
/// output follows a non-P2TR one.
pub fn derive_reveal_slot_range(
    commit: &Transaction,
) -> Result<Option<RevealSlotRange>, CommitRevealParseError> {
    let mut last_reveal_vout = None;
    let mut run_closed = false;

    for (idx, output) in commit.output.iter().enumerate().skip(1) {
        if output.script_pubkey.is_p2tr() {
            if run_closed {
                return Err(CommitRevealParseError::AmbiguousTaprootChangeOutput {
                    vout: idx as u32,
                });
            }
            last_reveal_vout = Some(idx as u32);
        } else {
            run_closed = true;
        }
    }

    last_reveal_vout.map(RevealSlotRange::try_new).transpose()
}

/// Assembles a set once the commit and its marker tail are known.
fn extract_for_commit<'t>(
    commit: &'t Transaction,
    marker_tail: &'t [u8],
    reveals: impl IntoIterator<Item = &'t Transaction>,
) -> Result<ParsedCommitReveal<'t>, CommitRevealParseError> {
    let slots =
        derive_reveal_slot_range(commit)?.ok_or(CommitRevealParseError::MissingRevealSlots)?;
    let commit_txid = commit.compute_txid();

    let mut by_vout = BTreeMap::new();
    for reveal in reveals {
        let (vout, pubkey, bytes) = extract_reveal_chunk_for_commit(reveal, commit_txid, slots)?;
        if by_vout.insert(vout, (pubkey, bytes)).is_some() {
            return Err(CommitRevealParseError::DuplicateReveal { vout });
        }
    }

    for vout in 1..=slots.last_vout() {
        if !by_vout.contains_key(&vout) {
            return Err(CommitRevealParseError::MissingReveal { vout });
        }
    }

    // SPS-53 signs every reveal of an inscription under one producer key, so
    // disagreement means there is no single key to authenticate against.
    let mut reveal_pubkey = None;
    let mut chunks = Vec::with_capacity(by_vout.len());
    for (vout, (pubkey, bytes)) in by_vout {
        match reveal_pubkey {
            None => reveal_pubkey = Some(pubkey),
            Some(first) if first != pubkey => {
                return Err(CommitRevealParseError::InconsistentRevealPubkey { vout });
            }
            Some(_) => {}
        }
        chunks.push(bytes);
    }

    Ok(ParsedCommitReveal {
        commit,
        marker_tail,
        reveal_pubkey: reveal_pubkey.expect("a slot range always covers at least one reveal"),
        chunks,
    })
}

/// Extracts the chunk a single reveal transaction carries for a known commit.
///
/// The reveal must spend exactly one slot of `commit_txid` with a tapscript
/// leaf matching the strict signed envelope shape.
///
/// The commit is named, not discovered, so this is safe against arbitrary L1: a
/// reveal that also carries its own marker at output 0 is still read as a
/// reveal for `commit_txid`.
fn extract_reveal_chunk_for_commit(
    reveal: &Transaction,
    commit_txid: Txid,
    slots: RevealSlotRange,
) -> Result<(u32, [u8; SIGNED_LEAF_PUBKEY_LEN], Vec<u8>), CommitRevealParseError> {
    if reveal.input.is_empty() {
        return Err(CommitRevealParseError::RevealMissingInputs);
    }

    // Non-marker defects are accumulated rather than reported on sight, and the
    // reported vout is the lowest offending one, so a transaction carrying more
    // than one gives the same error whatever order its inputs are in.
    let mut matching_input = None;
    let mut unexpected_vout = None;
    let mut has_multiple_slot_spends = false;

    for input in &reveal.input {
        if input.previous_output.txid != commit_txid {
            continue;
        }

        let vout = input.previous_output.vout;
        if vout == 0 {
            return Err(CommitRevealParseError::RevealSpendsMarker);
        }

        if !slots.contains(vout) {
            unexpected_vout = Some(unexpected_vout.map_or(vout, |seen: u32| seen.min(vout)));
            continue;
        }

        if matching_input.replace(input).is_some() {
            has_multiple_slot_spends = true;
        }
    }

    // Reported even when another input does spend a slot: a reveal that also
    // consumes a non-slot output of its commit is malformed, and ignoring it
    // would let such a set still look complete.
    if let Some(vout) = unexpected_vout {
        return Err(CommitRevealParseError::UnexpectedReveal { vout });
    }

    if has_multiple_slot_spends {
        return Err(CommitRevealParseError::RevealMultipleCommitSpends);
    }

    let input = matching_input.ok_or(CommitRevealParseError::RevealWrongCommit)?;

    let leaf = input
        .witness
        .taproot_leaf_script()
        .ok_or(CommitRevealParseError::RevealMissingLeafScript)?;
    if leaf.version != LeafVersion::TapScript {
        return Err(CommitRevealParseError::RevealUnsupportedLeafVersion {
            version: leaf.version.to_consensus(),
        });
    }

    let parsed = parse_exact_signed_envelope_leaf(&leaf.script.into())?;

    Ok((
        input.previous_output.vout,
        *parsed.pubkey(),
        parsed.into_payload(),
    ))
}
#[cfg(test)]
mod tests {
    use bitcoin::ScriptBuf;
    use bitcoin::blockdata::script::Builder;
    use bitcoin::opcodes::OP_TRUE;
    use bitcoin::script::PushBytesBuf;
    use strata_l1_envelope_fmt::builder::MAX_ENVELOPE_PAYLOAD_SIZE;
    use strata_l1_txfmt::MagicBytes;

    use super::*;
    use crate::builder::build_commit_reveal_scripts;
    use crate::test_utils::{
        DEFAULT_KEY_SEED, TEST_MAGIC, assemble_commit_tx, build_commit_tx,
        build_marker_candidate_tx, build_reveal_input, build_reveal_input_from_leaf,
        build_reveal_tx, build_reveal_tx_with_marker_output, build_unsupported_leaf_reveal_input,
        make_change_script, make_p2tr_script, make_txid, make_xonly_pubkey_bytes,
    };

    const OTHER_MAGIC: MagicBytes = MagicBytes::new(*b"OTHR");

    /// Reads across chunks without joining them, as the guest's decoder does.
    struct ChunkReader<'a> {
        chunks: &'a [Vec<u8>],
        chunk: usize,
        offset: usize,
    }

    impl ChunkReader<'_> {
        /// Fills `buf` across chunk boundaries, returning bytes read.
        fn read(&mut self, buf: &mut [u8]) -> usize {
            let mut filled = 0;
            while filled < buf.len() {
                let Some(chunk) = self.chunks.get(self.chunk) else {
                    break;
                };
                if self.offset == chunk.len() {
                    self.chunk += 1;
                    self.offset = 0;
                    continue;
                }
                let take = (chunk.len() - self.offset).min(buf.len() - filled);
                buf[filled..filled + take].copy_from_slice(&chunk[self.offset..self.offset + take]);
                self.offset += take;
                filled += take;
            }
            filled
        }
    }

    fn build_op_return_script(payload: &[u8]) -> ScriptBuf {
        Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_RETURN)
            .push_slice(PushBytesBuf::try_from(payload.to_vec()).expect("push fits"))
            .into_script()
    }

    /// Builds fixture commit/reveal txs from builder-produced scripts.
    fn build_commit_reveal_txs(payload: &[u8]) -> (Transaction, Vec<Transaction>) {
        let scripts = build_commit_reveal_scripts(
            &TEST_MAGIC,
            [],
            &make_xonly_pubkey_bytes(DEFAULT_KEY_SEED),
            payload,
        )
        .expect("builds");
        let (marker, leaves) = scripts.into_parts();
        let commit = assemble_commit_tx(marker, leaves.len());
        let commit_txid = commit.compute_txid();
        let reveals = leaves
            .into_iter()
            .enumerate()
            .map(|(idx, leaf)| {
                build_reveal_tx(vec![build_reveal_input_from_leaf(
                    commit_txid,
                    idx as u32 + 1,
                    leaf,
                    DEFAULT_KEY_SEED,
                )])
            })
            .collect();

        (commit, reveals)
    }

    // Marker classification.

    #[test]
    fn test_marker_returns_tail_for_matching_magic() {
        let commit = build_commit_tx(&TEST_MAGIC, &[1, 2, 3, 4], 1, &[]);

        assert_eq!(
            read_commit_marker(&TEST_MAGIC, &commit),
            Some([1, 2, 3, 4].as_slice())
        );
    }

    #[test]
    fn test_marker_accepts_empty_tail() {
        let commit = build_commit_tx(&TEST_MAGIC, &[], 1, &[]);

        assert_eq!(
            read_commit_marker(&TEST_MAGIC, &commit),
            Some([].as_slice())
        );
    }

    /// No magic value is baked in: the same transaction is ours or not
    /// depending only on the magic the caller supplies.
    #[test]
    fn test_marker_rejects_different_configured_magic() {
        let commit = build_commit_tx(&TEST_MAGIC, &[1, 2, 3, 4], 1, &[]);

        assert!(read_commit_marker(&OTHER_MAGIC, &commit).is_none());
    }

    #[test]
    fn test_marker_ignores_unrelated_op_return() {
        let tx = build_marker_candidate_tx(build_op_return_script(b"somebody elses protocol"));

        assert!(read_commit_marker(&TEST_MAGIC, &tx).is_none());
    }

    #[test]
    fn test_marker_ignores_push_shorter_than_magic() {
        let tx = build_marker_candidate_tx(build_op_return_script(b"TE"));

        assert!(read_commit_marker(&TEST_MAGIC, &tx).is_none());
    }

    #[test]
    fn test_marker_ignores_extra_opcodes() {
        let script = Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_RETURN)
            .push_slice(*b"TESTtail")
            .push_opcode(OP_TRUE)
            .into_script();
        let tx = build_marker_candidate_tx(script);

        assert!(read_commit_marker(&TEST_MAGIC, &tx).is_none());
    }

    #[test]
    fn test_marker_ignores_non_op_return_first_output() {
        let tx = build_marker_candidate_tx(make_p2tr_script());

        assert!(read_commit_marker(&TEST_MAGIC, &tx).is_none());
    }

    #[test]
    fn test_marker_accepts_push_at_policy_limit() {
        let payload = [b"TEST".as_slice(), &[0u8; MAX_MARKER_PAYLOAD_BYTES - 4]].concat();
        assert_eq!(payload.len(), MAX_MARKER_PAYLOAD_BYTES);
        let tx = build_marker_candidate_tx(build_op_return_script(&payload));

        assert_eq!(
            read_commit_marker(&TEST_MAGIC, &tx).map(<[u8]>::len),
            Some(MAX_MARKER_PAYLOAD_BYTES - 4)
        );
    }

    #[test]
    fn test_marker_ignores_push_over_policy_limit() {
        let payload = [b"TEST".as_slice(), &[0u8; MAX_MARKER_PAYLOAD_BYTES - 3]].concat();
        assert_eq!(payload.len(), MAX_MARKER_PAYLOAD_BYTES + 1);
        let tx = build_marker_candidate_tx(build_op_return_script(&payload));

        assert!(read_commit_marker(&TEST_MAGIC, &tx).is_none());
    }

    // Reveal-slot range.

    #[test]
    fn test_slot_range_covers_contiguous_p2tr_run() {
        let commit = build_commit_tx(&TEST_MAGIC, &[], 3, &[make_change_script()]);

        let range = derive_reveal_slot_range(&commit)
            .expect("valid commit")
            .expect("has slots");

        assert_eq!(range.last_vout(), 3);
        assert!(range.contains(1) && range.contains(3));
        assert!(!range.contains(0) && !range.contains(4));
    }

    #[test]
    fn test_slot_range_rejects_p2tr_after_change() {
        let commit = build_commit_tx(
            &TEST_MAGIC,
            &[],
            2,
            &[make_change_script(), make_p2tr_script()],
        );

        let error =
            derive_reveal_slot_range(&commit).expect_err("ambiguous change must be rejected");

        assert!(matches!(
            error,
            CommitRevealParseError::AmbiguousTaprootChangeOutput { vout: 4 }
        ));
    }

    #[test]
    fn test_slot_range_absent_when_no_p2tr_outputs() {
        let commit = build_commit_tx(&TEST_MAGIC, &[], 0, &[make_change_script()]);

        assert!(
            derive_reveal_slot_range(&commit)
                .expect("valid commit")
                .is_none()
        );
    }

    #[test]
    fn test_slot_range_rejects_zero_last_vout() {
        let error = RevealSlotRange::try_new(0).expect_err("output 0 is the marker");

        assert!(matches!(
            error,
            CommitRevealParseError::EmptyRevealSlotRange
        ));
    }

    // Chunk extraction.

    #[test]
    fn test_chunks_are_ordered_by_commit_output() {
        let commit = build_commit_tx(&TEST_MAGIC, &[], 2, &[]);
        let commit_txid = commit.compute_txid();
        let second = build_reveal_tx(vec![build_reveal_input(
            commit_txid,
            2,
            Some(b"second"),
            DEFAULT_KEY_SEED,
        )]);
        let first = build_reveal_tx(vec![build_reveal_input(
            commit_txid,
            1,
            Some(b"first"),
            DEFAULT_KEY_SEED,
        )]);

        let parsed = extract_payload_for_commit(&TEST_MAGIC, &commit, [&second, &first])
            .expect("valid envelope");

        // Supplied out of order; ordering follows the spent commit vout.
        assert_eq!(parsed.chunks(), [b"first".to_vec(), b"second".to_vec()]);
        assert_eq!(parsed.into_payload(), b"firstsecond");
    }

    #[test]
    fn test_extraction_rejects_missing_reveal() {
        let commit = build_commit_tx(&TEST_MAGIC, &[], 2, &[]);
        let reveal = build_reveal_tx(vec![build_reveal_input(
            commit.compute_txid(),
            1,
            Some(b"one"),
            DEFAULT_KEY_SEED,
        )]);

        let error = extract_payload_for_commit(&TEST_MAGIC, &commit, [&reveal])
            .expect_err("slot 2 is unfilled");

        assert!(matches!(
            error,
            CommitRevealParseError::MissingReveal { vout: 2 }
        ));
    }

    #[test]
    fn test_extraction_rejects_duplicate_reveal() {
        let commit = build_commit_tx(&TEST_MAGIC, &[], 1, &[]);
        let commit_txid = commit.compute_txid();
        let one = build_reveal_tx(vec![build_reveal_input(
            commit_txid,
            1,
            Some(b"a"),
            DEFAULT_KEY_SEED,
        )]);
        let two = build_reveal_tx(vec![build_reveal_input(
            commit_txid,
            1,
            Some(b"b"),
            DEFAULT_KEY_SEED,
        )]);

        let error = extract_payload_for_commit(&TEST_MAGIC, &commit, [&one, &two])
            .expect_err("slot claimed twice");

        assert!(matches!(
            error,
            CommitRevealParseError::DuplicateReveal { vout: 1 }
        ));
    }

    #[test]
    fn test_extraction_rejects_commit_without_slots() {
        let commit = build_commit_tx(&TEST_MAGIC, &[], 0, &[]);

        let error =
            extract_payload_for_commit(&TEST_MAGIC, &commit, []).expect_err("no slots to reveal");

        assert!(matches!(error, CommitRevealParseError::MissingRevealSlots));
    }

    #[test]
    fn test_reveal_rejects_marker_output_spend() {
        let slots = RevealSlotRange::try_new(1).expect("valid range");
        let tx = build_reveal_tx(vec![build_reveal_input(
            make_txid(1),
            0,
            None,
            DEFAULT_KEY_SEED,
        )]);

        let error = extract_reveal_chunk_for_commit(&tx, make_txid(1), slots)
            .expect_err("marker output is not a slot");

        assert!(matches!(error, CommitRevealParseError::RevealSpendsMarker));
    }

    #[test]
    fn test_reveal_rejects_commit_output_outside_slot_range() {
        let slots = RevealSlotRange::try_new(1).expect("valid range");
        let tx = build_reveal_tx(vec![build_reveal_input(
            make_txid(1),
            2,
            None,
            DEFAULT_KEY_SEED,
        )]);

        let error = extract_reveal_chunk_for_commit(&tx, make_txid(1), slots)
            .expect_err("slot 2 is outside");

        assert!(matches!(
            error,
            CommitRevealParseError::UnexpectedReveal { vout: 2 }
        ));
    }

    /// A reveal that spends a valid slot *and* another output of the same
    /// commit is malformed. Accepting it would let the set look complete while
    /// one reveal quietly consumed a non-slot output.
    #[test]
    fn test_reveal_rejects_non_slot_commit_output_alongside_valid_slot() {
        let slots = RevealSlotRange::try_new(1).expect("valid range");
        let tx = build_reveal_tx(vec![
            build_reveal_input(make_txid(1), 1, Some(b"chunk"), DEFAULT_KEY_SEED),
            build_reveal_input(make_txid(1), 2, None, DEFAULT_KEY_SEED),
        ]);

        let error = extract_reveal_chunk_for_commit(&tx, make_txid(1), slots)
            .expect_err("non-slot spend of the same commit");

        assert!(matches!(
            error,
            CommitRevealParseError::UnexpectedReveal { vout: 2 }
        ));
    }

    /// Input order must not decide which defect is reported: the scanner
    /// surfaces these as quarantine reasons, so they have to be stable.
    #[test]
    fn test_reveal_error_does_not_depend_on_input_order() {
        let slots = RevealSlotRange::try_new(2).expect("valid range");
        let duplicate_slot =
            || build_reveal_input(make_txid(1), 1, Some(b"chunk"), DEFAULT_KEY_SEED);
        let out_of_range = || build_reveal_input(make_txid(1), 5, None, DEFAULT_KEY_SEED);

        let forward = build_reveal_tx(vec![duplicate_slot(), duplicate_slot(), out_of_range()]);
        let reversed = build_reveal_tx(vec![out_of_range(), duplicate_slot(), duplicate_slot()]);

        let first = extract_reveal_chunk_for_commit(&forward, make_txid(1), slots)
            .expect_err("malformed reveal");
        let second = extract_reveal_chunk_for_commit(&reversed, make_txid(1), slots)
            .expect_err("malformed reveal");

        assert!(matches!(
            first,
            CommitRevealParseError::UnexpectedReveal { vout: 5 }
        ));
        assert!(matches!(
            second,
            CommitRevealParseError::UnexpectedReveal { vout: 5 }
        ));
    }

    #[test]
    fn test_reveal_rejects_wrong_commit() {
        let slots = RevealSlotRange::try_new(1).expect("valid range");
        let tx = build_reveal_tx(vec![build_reveal_input(
            make_txid(2),
            1,
            Some(b"chunk"),
            DEFAULT_KEY_SEED,
        )]);

        let error = extract_reveal_chunk_for_commit(&tx, make_txid(1), slots)
            .expect_err("spends a different commit");

        assert!(matches!(error, CommitRevealParseError::RevealWrongCommit));
    }

    #[test]
    fn test_reveal_rejects_multiple_slot_spends() {
        let slots = RevealSlotRange::try_new(2).expect("valid range");
        let tx = build_reveal_tx(vec![
            build_reveal_input(make_txid(1), 1, Some(b"a"), DEFAULT_KEY_SEED),
            build_reveal_input(make_txid(1), 2, Some(b"b"), DEFAULT_KEY_SEED),
        ]);

        let error = extract_reveal_chunk_for_commit(&tx, make_txid(1), slots)
            .expect_err("one reveal carries one chunk");

        assert!(matches!(
            error,
            CommitRevealParseError::RevealMultipleCommitSpends
        ));
    }

    #[test]
    fn test_reveal_rejects_no_inputs() {
        let slots = RevealSlotRange::try_new(1).expect("valid range");
        let tx = build_reveal_tx(vec![]);

        let error = extract_reveal_chunk_for_commit(&tx, make_txid(1), slots)
            .expect_err("no inputs to read");

        assert!(matches!(error, CommitRevealParseError::RevealMissingInputs));
    }

    #[test]
    fn test_reveal_rejects_missing_leaf_script() {
        let slots = RevealSlotRange::try_new(1).expect("valid range");
        let tx = build_reveal_tx(vec![build_reveal_input(
            make_txid(1),
            1,
            None,
            DEFAULT_KEY_SEED,
        )]);

        let error = extract_reveal_chunk_for_commit(&tx, make_txid(1), slots)
            .expect_err("witness has no leaf");

        assert!(matches!(
            error,
            CommitRevealParseError::RevealMissingLeafScript
        ));
    }

    #[test]
    fn test_reveal_rejects_non_tapscript_leaf() {
        let slots = RevealSlotRange::try_new(1).expect("valid range");
        let future = LeafVersion::from_consensus(0xc2).expect("future leaf version");
        let tx = build_reveal_tx(vec![build_unsupported_leaf_reveal_input(
            make_txid(1),
            1,
            b"chunk",
            DEFAULT_KEY_SEED,
            future,
        )]);

        let error = extract_reveal_chunk_for_commit(&tx, make_txid(1), slots)
            .expect_err("only tapscript leaves are parsed");

        assert!(matches!(
            error,
            CommitRevealParseError::RevealUnsupportedLeafVersion { version } if version == 0xc2
        ));
    }

    /// The parser applies no key policy: it reports whichever key the leaf
    /// commits to and leaves authentication to the caller.
    #[test]
    fn test_reveal_reports_observed_pubkey_without_policy() {
        let slots = RevealSlotRange::try_new(1).expect("valid range");
        let tx = build_reveal_tx(vec![build_reveal_input(
            make_txid(1),
            1,
            Some(b"chunk"),
            11,
        )]);

        let (_, pubkey, _) =
            extract_reveal_chunk_for_commit(&tx, make_txid(1), slots).expect("parses fine");

        assert_eq!(pubkey, make_xonly_pubkey_bytes(11));
    }

    /// A reveal may itself be the next commit. The range-scanner entry point
    /// takes the commit by reference and must not re-classify by marker.
    #[test]
    fn test_extraction_is_safe_when_reveal_is_also_a_commit() {
        let commit = build_commit_tx(&TEST_MAGIC, &[], 1, &[]);
        let commit_txid = commit.compute_txid();
        let next_commit_marker = build_commit_tx(&TEST_MAGIC, &[9], 1, &[]).output[0].clone();
        let reveal = build_reveal_tx_with_marker_output(
            vec![build_reveal_input(
                commit_txid,
                1,
                Some(b"chunk"),
                DEFAULT_KEY_SEED,
            )],
            next_commit_marker,
        );

        assert!(read_commit_marker(&TEST_MAGIC, &reveal).is_some());

        let parsed = extract_payload_for_commit(&TEST_MAGIC, &commit, [&reveal])
            .expect("reveal still parses");

        assert_eq!(parsed.into_payload(), b"chunk");
    }

    // Single-commit-set entry point.

    #[test]
    fn test_single_commit_set_returns_commit_tail_and_chunks() {
        let commit = build_commit_tx(&TEST_MAGIC, &[7, 7], 2, &[]);
        let commit_txid = commit.compute_txid();
        let one = build_reveal_tx(vec![build_reveal_input(
            commit_txid,
            1,
            Some(b"first"),
            DEFAULT_KEY_SEED,
        )]);
        let two = build_reveal_tx(vec![build_reveal_input(
            commit_txid,
            2,
            Some(b"second"),
            DEFAULT_KEY_SEED,
        )]);

        let set = extract_payload_from_single_commit_set(&TEST_MAGIC, [&commit, &two, &one])
            .expect("well-formed set");

        assert_eq!(set.commit().compute_txid(), commit_txid);
        assert_eq!(set.marker_tail(), &[7, 7]);
        assert_eq!(set.chunks().len(), 2);
        assert_eq!(set.into_payload(), b"firstsecond");
    }

    #[test]
    fn test_single_commit_set_rejects_missing_commit() {
        let reveal = build_reveal_tx(vec![build_reveal_input(
            make_txid(1),
            1,
            Some(b"chunk"),
            DEFAULT_KEY_SEED,
        )]);

        let error = extract_payload_from_single_commit_set(&TEST_MAGIC, [&reveal])
            .expect_err("set has no commit");

        assert!(matches!(error, CommitRevealParseError::MissingCommit));
    }

    #[test]
    fn test_single_commit_set_rejects_multiple_commits() {
        let one = build_commit_tx(&TEST_MAGIC, &[1], 1, &[]);
        let two = build_commit_tx(&TEST_MAGIC, &[2], 1, &[]);

        let error = extract_payload_from_single_commit_set(&TEST_MAGIC, [&one, &two])
            .expect_err("set has two commits");

        assert!(matches!(error, CommitRevealParseError::MultipleCommits));
    }

    // Pubkey agreement and authentication.

    /// SPS-53 signs every reveal of an inscription under one producer key, so a
    /// set whose leaves disagree has no single key to authenticate against.
    #[test]
    fn test_extraction_rejects_reveals_with_different_pubkeys() {
        let commit = build_commit_tx(&TEST_MAGIC, &[], 2, &[]);
        let commit_txid = commit.compute_txid();
        let one = build_reveal_tx(vec![build_reveal_input(
            commit_txid,
            1,
            Some(b"first"),
            DEFAULT_KEY_SEED,
        )]);
        let two = build_reveal_tx(vec![build_reveal_input(
            commit_txid,
            2,
            Some(b"second"),
            DEFAULT_KEY_SEED + 1,
        )]);

        let error = extract_payload_for_commit(&TEST_MAGIC, &commit, [&one, &two])
            .expect_err("reveals must agree on one key");

        assert!(matches!(
            error,
            CommitRevealParseError::InconsistentRevealPubkey { vout: 2 }
        ));
    }

    #[test]
    fn test_authenticated_extraction_accepts_the_expected_key() {
        let commit = build_commit_tx(&TEST_MAGIC, &[], 1, &[]);
        let reveal = build_reveal_tx(vec![build_reveal_input(
            commit.compute_txid(),
            1,
            Some(b"chunk"),
            DEFAULT_KEY_SEED,
        )]);

        let parsed = extract_authenticated_payload_for_commit(
            &TEST_MAGIC,
            &commit,
            [&reveal],
            &make_xonly_pubkey_bytes(DEFAULT_KEY_SEED),
        )
        .expect("key matches");

        assert_eq!(parsed.into_payload(), b"chunk");
    }

    #[test]
    fn test_authenticated_extraction_rejects_another_key() {
        let commit = build_commit_tx(&TEST_MAGIC, &[], 1, &[]);
        let reveal = build_reveal_tx(vec![build_reveal_input(
            commit.compute_txid(),
            1,
            Some(b"chunk"),
            DEFAULT_KEY_SEED,
        )]);

        let error = extract_authenticated_payload_for_commit(
            &TEST_MAGIC,
            &commit,
            [&reveal],
            &make_xonly_pubkey_bytes(DEFAULT_KEY_SEED + 1),
        )
        .expect_err("key differs");

        assert!(matches!(
            error,
            CommitRevealParseError::UnexpectedRevealPubkey
        ));
    }

    /// Chunk count is never written on chain, so what a consumer observes must
    /// follow from the payload size and the per-reveal ceiling alone.
    #[test]
    fn test_chunks_observed_follow_the_envelope_ceiling() {
        for (len, expected) in [
            // One empty chunk, so a set always has a reveal and therefore a
            // pubkey to report.
            (0, vec![0]),
            (
                MAX_ENVELOPE_PAYLOAD_SIZE - 1,
                vec![MAX_ENVELOPE_PAYLOAD_SIZE - 1],
            ),
            (MAX_ENVELOPE_PAYLOAD_SIZE, vec![MAX_ENVELOPE_PAYLOAD_SIZE]),
            (
                MAX_ENVELOPE_PAYLOAD_SIZE + 1,
                vec![MAX_ENVELOPE_PAYLOAD_SIZE, 1],
            ),
        ] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let (commit, reveals) = build_commit_reveal_txs(&payload);

            let parsed = extract_payload_for_commit(&TEST_MAGIC, &commit, reveals.iter())
                .expect("round trips");

            let lens: Vec<usize> = parsed.chunks().iter().map(Vec::len).collect();
            assert_eq!(lens, expected, "payload of {len} bytes");
            assert_eq!(parsed.into_payload(), payload, "payload of {len} bytes");
        }
    }

    /// Two non-slot spends must report the same vout either way round, or the
    /// public error depends on input ordering.
    #[test]
    fn test_non_slot_commit_output_reported_is_the_lowest() {
        let commit = build_commit_tx(&TEST_MAGIC, &[], 1, &[]);
        let commit_txid = commit.compute_txid();
        let low = build_reveal_input(commit_txid, 5, None, DEFAULT_KEY_SEED);
        let high = build_reveal_input(commit_txid, 7, None, DEFAULT_KEY_SEED);

        for inputs in [
            vec![low.clone(), high.clone()],
            vec![high.clone(), low.clone()],
        ] {
            let reveal = build_reveal_tx(inputs);

            let error = extract_payload_for_commit(&TEST_MAGIC, &commit, [&reveal])
                .expect_err("both spends are outside the slot range");

            assert!(matches!(
                error,
                CommitRevealParseError::UnexpectedReveal { vout: 5 }
            ));
        }
    }

    /// `into_payload` consumes the result, so what a host still needs afterwards
    /// has to borrow from the transactions rather than from the result.
    #[test]
    fn test_commit_and_tail_outlive_the_joined_payload() {
        let commit = build_commit_tx(&TEST_MAGIC, &[7, 7], 1, &[]);
        let reveal = build_reveal_tx(vec![build_reveal_input(
            commit.compute_txid(),
            1,
            Some(b"chunk"),
            DEFAULT_KEY_SEED,
        )]);

        let parsed =
            extract_payload_for_commit(&TEST_MAGIC, &commit, [&reveal]).expect("round trips");
        let tail = parsed.marker_tail();
        let parsed_commit = parsed.commit();

        assert_eq!(parsed.into_payload(), b"chunk");
        assert_eq!(tail, &[7, 7]);
        assert_eq!(parsed_commit.compute_txid(), commit.compute_txid());
    }

    /// Reads that straddle a chunk boundary must work off the borrowed view,
    /// since the guest decodes without joining.
    #[test]
    fn test_payload_reads_across_a_chunk_boundary_without_joining() {
        let payload: Vec<u8> = (0..MAX_ENVELOPE_PAYLOAD_SIZE + 64)
            .map(|i| (i % 251) as u8)
            .collect();
        let (commit, reveals) = build_commit_reveal_txs(&payload);

        let parsed =
            extract_payload_for_commit(&TEST_MAGIC, &commit, reveals.iter()).expect("round trips");
        assert_eq!(parsed.chunks().len(), 2, "payload must span two reveals");

        // A step that does not divide the ceiling guarantees a read lands
        // astride the boundary rather than flush against it.
        const STEP: usize = 7;
        assert_ne!(MAX_ENVELOPE_PAYLOAD_SIZE % STEP, 0, "step must straddle");

        let mut reader = ChunkReader {
            chunks: parsed.chunks(),
            chunk: 0,
            offset: 0,
        };
        let mut seen = Vec::new();
        let mut buf = [0u8; STEP];
        loop {
            let read = reader.read(&mut buf);
            if read == 0 {
                break;
            }
            seen.extend_from_slice(&buf[..read]);
        }

        assert_eq!(seen, payload);
    }
}
