use std::num::{NonZeroU32, NonZeroUsize};

use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::Instruction;
use bitcoin::taproot::LeafVersion;
use bitcoin::{Transaction, Txid};
use strata_l1_txfmt::MagicBytes;

use super::envelope::{SignedEnvelopeLeaf, parse_signed_envelope_leaf};
use crate::parser::errors::CommitRevealParseError;

/// Maximum commit-marker push, in bytes.
///
/// The marker MUST fit a single standard OP_RETURN.
const MAX_MARKER_PAYLOAD_BYTES: usize = 80;

/// The reveal-slot range `[1, last_vout]` of a commit transaction.
///
/// Output 0 is the marker, so slots start at 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RevealSlotRange {
    last_vout: NonZeroU32,
}

impl RevealSlotRange {
    /// Constructs a range.
    fn new(last_vout: NonZeroU32) -> Self {
        Self { last_vout }
    }

    /// Whether `vout` is a reveal slot of this commit.
    pub(crate) const fn contains(&self, vout: u32) -> bool {
        vout >= 1 && vout <= self.last_vout.get()
    }

    /// How many reveals a complete set has.
    pub(crate) fn slot_count(&self) -> NonZeroUsize {
        NonZeroUsize::new(self.last_vout.get() as usize).expect("non zero u32 should fit")
    }
}

/// The id and slot of a commit transaction a reveal spends.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RevealSlotSpend {
    pub(crate) commit_txid: Txid,
    pub(crate) vout: u32,
}

/// Owned metadata for a transaction parsed as marker-bearing commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedCommit {
    txid: Txid,
    marker_tail: Vec<u8>,
    reveal_slots: RevealSlotRange,
}

impl ParsedCommit {
    /// The commit transaction id.
    pub(crate) fn txid(&self) -> Txid {
        self.txid
    }

    /// Marker bytes after the magic.
    pub(crate) fn marker_tail(&self) -> &[u8] {
        &self.marker_tail
    }

    /// The commit's reveal-slot range.
    pub(crate) const fn reveal_slots(&self) -> RevealSlotRange {
        self.reveal_slots
    }

    pub(crate) fn reveal_slot_spend(
        &self,
        vout: u32,
    ) -> Result<RevealSlotSpend, CommitRevealParseError> {
        if vout == 0 {
            return Err(CommitRevealParseError::RevealSpendsMarker);
        }
        if !self.reveal_slots.contains(vout) {
            return Err(CommitRevealParseError::UnexpectedReveal { vout });
        }

        Ok(RevealSlotSpend {
            commit_txid: self.txid,
            vout,
        })
    }
}

pub(crate) fn convert_marker_tail_to_array<const N: usize>(
    tail: &[u8],
) -> Result<&[u8; N], CommitRevealParseError> {
    tail.try_into()
        .map_err(|_| CommitRevealParseError::UnexpectedMarkerTailLength {
            expected: N,
            found: tail.len(),
        })
}

/// Reads the opaque marker tail from a transaction.
///
/// Returns `Some(tail)` when output 0 is an `OP_RETURN` carrying exactly one
/// push that starts with `magic` and is no longer than
/// [`MAX_MARKER_PAYLOAD_BYTES`], `None` otherwise. The tail is not interpreted.
pub(crate) fn read_anchor_marker<'t>(magic: &MagicBytes, tx: &'t Transaction) -> Option<&'t [u8]> {
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
    // protocol's OP_RETURN that happens to share the same prefix.
    if instructions.next().is_some() {
        return None;
    }

    let payload = push.as_bytes();
    if payload.len() > MAX_MARKER_PAYLOAD_BYTES {
        return None;
    }

    payload.strip_prefix(magic.as_bytes().as_slice())
}

/// Derives the reveal-slot range of a commit transaction.
///
/// Uses Layout A from SPS-53: marker at vout 0, then P2TR reveal slots,
/// then non-P2TR change.
///
/// # Errors
///
/// Returns [`CommitRevealParseError::AmbiguousTaprootChangeOutput`] when a P2TR
/// output follows a non-P2TR one.
pub(crate) fn derive_reveal_slot_range(
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
            last_reveal_vout = Some(idx);
        } else {
            run_closed = true;
        }
    }

    match last_reveal_vout {
        Some(last) => Ok(Some(RevealSlotRange::new(
            NonZeroU32::new(last as u32).expect("vout must be non-zero"),
        ))),
        None => Ok(None),
    }
}

/// Parses a marker-bearing transaction as a commit candidate.
///
/// Returns `Ok(None)` when the transaction does not carry the expected marker or
/// does not have a valid reveal slot range.
///
/// # Errors
///
/// [`CommitRevealParseError::MissingRevealSlots`] when the matching marker has
/// no reveal slots; [`CommitRevealParseError::AmbiguousTaprootChangeOutput`]
/// when a P2TR output follows a non-P2TR one in the reveal-slot run.
pub(crate) fn parse_commit_candidate(
    magic: &MagicBytes,
    tx: &Transaction,
) -> Result<Option<ParsedCommit>, CommitRevealParseError> {
    // We don't error for transactions missing a marker.
    // They can be valid reveal transactions.
    let Some(marker_tail) = read_anchor_marker(magic, tx) else {
        return Ok(None);
    };

    let reveal_slots =
        derive_reveal_slot_range(tx)?.ok_or(CommitRevealParseError::MissingRevealSlots)?;
    Ok(Some(ParsedCommit {
        txid: tx.compute_txid(),
        marker_tail: marker_tail.to_vec(),
        reveal_slots,
    }))
}

/// Extracts the signed envelope leaf carried by a reveal transaction's first input.
///
/// Checks the reveal witness shape: the input must carry a taproot
/// leaf script, the leaf version must be Tapscript, and the script must be a
/// strict signed envelope leaf.
///
/// # Errors
///
/// Returns [`CommitRevealParseError`] if the transaction has no inputs or multiple inputs,
/// the first input does not carry a taproot leaf script, the leaf version is not
/// Tapscript, or the script is not a strict signed envelope leaf.
pub(crate) fn extract_signed_reveal_envelope(
    tx: &Transaction,
) -> Result<SignedEnvelopeLeaf, CommitRevealParseError> {
    let first_input = tx
        .input
        .first()
        .ok_or(CommitRevealParseError::RevealMissingInputs)?;

    if tx.input.len() > 1 {
        return Err(CommitRevealParseError::RevealHasMultipleInputs);
    }

    let leaf = first_input
        .witness
        .taproot_leaf_script()
        .ok_or(CommitRevealParseError::RevealMissingLeafScript)?;
    if leaf.version != LeafVersion::TapScript {
        return Err(CommitRevealParseError::UnsupportedRevealLeafVersion {
            version: leaf.version.to_consensus(),
        });
    }

    let envelope = parse_signed_envelope_leaf(leaf.script)?;
    if envelope.payload().is_empty() {
        return Err(CommitRevealParseError::EmptyRevealPayload);
    }

    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use bitcoin::ScriptBuf;
    use bitcoin::blockdata::script::Builder;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF};
    use bitcoin::opcodes::{OP_FALSE, OP_TRUE};
    use bitcoin::script::PushBytesBuf;

    use super::*;
    use crate::test_utils::*;
    use crate::{EnvelopeParseError, SIGNED_LEAF_PUBKEY_LEN};

    const OTHER_MAGIC: MagicBytes = MagicBytes::new(*b"OTHR");

    fn build_op_return_script(payload: &[u8]) -> ScriptBuf {
        Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_RETURN)
            .push_slice(PushBytesBuf::try_from(payload.to_vec()).expect("push fits"))
            .into_script()
    }

    fn build_marker_candidate(magic: &MagicBytes, tail: &[u8]) -> Transaction {
        build_marker_candidate_tx(build_marker_script(magic, tail))
    }

    // Marker classification.

    #[test]
    fn test_marker_with_non_op_return_first_output_ignored() {
        let tx = build_marker_candidate_tx(make_p2tr_script());

        assert!(read_anchor_marker(&TEST_MAGIC, &tx).is_none());
    }

    #[test]
    fn test_marker_with_unrelated_op_return_ignored() {
        let tx = build_marker_candidate_tx(build_op_return_script(b"a different protocol"));

        assert!(read_anchor_marker(&TEST_MAGIC, &tx).is_none());
    }

    #[test]
    fn test_marker_with_extra_opcodes_ignored() {
        let mut payload = Vec::from(TEST_MAGIC.as_bytes());
        payload.extend_from_slice(b"tail");
        let script = Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_RETURN)
            .push_slice(PushBytesBuf::try_from(payload).expect("push fits"))
            .push_opcode(OP_TRUE)
            .into_script();
        let tx = build_marker_candidate_tx(script);

        assert!(read_anchor_marker(&TEST_MAGIC, &tx).is_none());
    }

    #[test]
    fn test_valid_marker_with_matching_magic() {
        let tx = build_marker_candidate(&TEST_MAGIC, &[1, 2, 3, 4]);

        assert_eq!(
            read_anchor_marker(&TEST_MAGIC, &tx),
            Some([1, 2, 3, 4].as_slice())
        );
    }

    #[test]
    fn test_marker_with_different_magic_ignored() {
        let tx = build_marker_candidate(&TEST_MAGIC, &[1, 2, 3, 4]);

        assert!(read_anchor_marker(&OTHER_MAGIC, &tx).is_none());
    }

    #[test]
    fn test_marker_with_push_shorter_than_magic_ignored() {
        let tx = build_marker_candidate_tx(build_op_return_script(b"TE"));

        assert!(read_anchor_marker(&TEST_MAGIC, &tx).is_none());
    }

    #[test]
    fn test_marker_with_empty_tail() {
        let tx = build_marker_candidate(&TEST_MAGIC, &[]);

        assert_eq!(read_anchor_marker(&TEST_MAGIC, &tx), Some([].as_slice()));
    }

    #[test]
    fn test_marker_with_push_at_policy_limit() {
        let tail_len = MAX_MARKER_PAYLOAD_BYTES - TEST_MAGIC.as_bytes().len();
        let tail = vec![0u8; tail_len];
        let tx = build_marker_candidate(&TEST_MAGIC, &tail);

        assert_eq!(
            read_anchor_marker(&TEST_MAGIC, &tx).map(<[u8]>::len),
            Some(tail_len)
        );
    }

    #[test]
    fn test_marker_with_push_over_policy_limit_ignored() {
        let tail_len = MAX_MARKER_PAYLOAD_BYTES + 1 - TEST_MAGIC.as_bytes().len();
        let tail = vec![0u8; tail_len];
        let tx = build_marker_candidate(&TEST_MAGIC, &tail);

        assert!(read_anchor_marker(&TEST_MAGIC, &tx).is_none());
    }

    // Commit candidate parsing.

    #[test]
    fn test_valid_commit() {
        let commit = build_commit_tx(&TEST_MAGIC, &[3, 4], 2, &[]);

        let parsed = parse_commit_candidate(&TEST_MAGIC, &commit)
            .expect("valid commit")
            .expect("marker matches");

        assert_eq!(parsed.txid(), commit.compute_txid());
        assert_eq!(parsed.marker_tail(), &[3, 4]);
        assert_eq!(parsed.reveal_slots().slot_count().get(), 2);
    }

    #[test]
    fn test_invalid_commit_is_ignored() {
        let not_a_commit = build_reveal_tx(vec![build_reveal_input(
            make_txid(1),
            1,
            Some(b"chunk"),
            DEFAULT_KEY_SEED,
        )]);

        assert!(
            parse_commit_candidate(&TEST_MAGIC, &not_a_commit)
                .expect("not a malformed commit")
                .is_none()
        );
    }

    #[test]
    fn test_commit_without_slots_rejected() {
        let no_slots = build_commit_tx(&TEST_MAGIC, &[7, 7], 0, &[]);

        let error =
            parse_commit_candidate(&TEST_MAGIC, &no_slots).expect_err("commit has no slots");

        assert!(matches!(error, CommitRevealParseError::MissingRevealSlots));
    }

    #[test]
    fn test_commit_with_ambiguous_change_rejected() {
        let mut tx = build_commit_tx(&TEST_MAGIC, &[7, 7], 1, &[make_change_script()]);
        tx.output.push(bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(1000),
            script_pubkey: make_p2tr_script(),
        });

        let error = parse_commit_candidate(&TEST_MAGIC, &tx).expect_err("ambiguous change");

        assert!(matches!(
            error,
            CommitRevealParseError::AmbiguousTaprootChangeOutput { .. }
        ));
    }

    #[test]
    fn test_reveal_slot_spend_for_valid_commit() {
        let commit = build_commit_tx(&TEST_MAGIC, &[3, 4], 2, &[]);
        let parsed = parse_commit_candidate(&TEST_MAGIC, &commit)
            .expect("valid commit")
            .expect("marker matches");

        let spend = parsed.reveal_slot_spend(2).expect("slot 2 is valid");

        assert_eq!(spend.commit_txid, parsed.txid());
        assert_eq!(spend.vout, 2);
    }

    #[test]
    fn test_reveal_spends_marker_rejected() {
        let commit = build_commit_tx(&TEST_MAGIC, &[3, 4], 2, &[]);
        let parsed = parse_commit_candidate(&TEST_MAGIC, &commit)
            .expect("valid commit")
            .expect("marker matches");

        let error = parsed
            .reveal_slot_spend(0)
            .expect_err("output 0 is the marker");

        assert!(matches!(error, CommitRevealParseError::RevealSpendsMarker));
    }

    #[test]
    fn test_reveal_spend_outside_range_rejected() {
        let commit = build_commit_tx(&TEST_MAGIC, &[3, 4], 2, &[]);
        let parsed = parse_commit_candidate(&TEST_MAGIC, &commit)
            .expect("valid commit")
            .expect("marker matches");

        let error = parsed
            .reveal_slot_spend(3)
            .expect_err("slot range ends at output 2");

        assert!(matches!(
            error,
            CommitRevealParseError::UnexpectedReveal { vout: 3 }
        ));
    }

    // Reveal envelope extraction.

    #[test]
    fn test_valid_reveal_envelope_extraction() {
        let tx = build_reveal_tx(vec![build_reveal_input(
            make_txid(1),
            1,
            Some(b"chunk"),
            11,
        )]);

        let leaf = extract_signed_reveal_envelope(&tx).expect("valid reveal tx");

        assert_eq!(leaf.pubkey(), &make_xonly_pubkey_bytes(11));
        assert_eq!(leaf.payload(), b"chunk");
    }

    #[test]
    fn test_reveal_envelope_without_input_rejected() {
        let tx = build_reveal_tx(vec![]);

        let error = extract_signed_reveal_envelope(&tx).expect_err("input required");

        assert!(matches!(error, CommitRevealParseError::RevealMissingInputs));
    }

    #[test]
    fn test_reveal_envelope_with_multiple_inputs_rejected() {
        let tx = build_reveal_tx(vec![
            build_reveal_input(make_txid(1), 1, Some(b"chunk"), DEFAULT_KEY_SEED),
            build_reveal_input(make_txid(2), 1, Some(b"chunk"), DEFAULT_KEY_SEED),
        ]);

        let error = extract_signed_reveal_envelope(&tx).expect_err("one input is required");

        assert!(matches!(
            error,
            CommitRevealParseError::RevealHasMultipleInputs
        ));
    }

    #[test]
    fn test_reveal_envelope_without_leaf_script_rejected() {
        let tx = build_reveal_tx(vec![build_reveal_input(
            make_txid(1),
            1,
            None,
            DEFAULT_KEY_SEED,
        )]);

        let error = extract_signed_reveal_envelope(&tx).expect_err("leaf script required");

        assert!(matches!(
            error,
            CommitRevealParseError::RevealMissingLeafScript
        ));
    }

    #[test]
    fn test_reveal_envelope_with_unsupported_version_rejected() {
        let future = LeafVersion::from_consensus(0xc2).expect("future leaf version");
        let tx = build_reveal_tx(vec![build_unsupported_leaf_reveal_input(
            make_txid(1),
            1,
            b"chunk",
            DEFAULT_KEY_SEED,
            future,
        )]);

        let error =
            extract_signed_reveal_envelope(&tx).expect_err("only tapscript leaves are parsed");

        assert!(matches!(
            error,
            CommitRevealParseError::UnsupportedRevealLeafVersion { version } if version == 0xc2
        ));
    }

    #[test]
    fn test_invalid_pubkey_rejected() {
        let invalid_leaf = Builder::new()
            .push_slice(
                PushBytesBuf::try_from(vec![2u8; SIGNED_LEAF_PUBKEY_LEN + 1])
                    .expect("pubkey push fits"),
            )
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_opcode(OP_ENDIF)
            .into_script();
        let tx = build_reveal_tx(vec![build_reveal_input_from_leaf(
            make_txid(1),
            1,
            invalid_leaf,
            DEFAULT_KEY_SEED,
        )]);

        let error =
            extract_signed_reveal_envelope(&tx).expect_err("strict leaf parser rejects this");

        assert!(matches!(
            error,
            CommitRevealParseError::InvalidRevealEnvelope {
                source: EnvelopeParseError::InvalidPubkeyLength { found: 33, .. }
            }
        ));
    }

    #[test]
    fn test_reveal_envelope_with_empty_payload_rejected() {
        let tx = build_reveal_tx(vec![build_reveal_input(
            make_txid(1),
            1,
            Some(b""),
            DEFAULT_KEY_SEED,
        )]);

        let error = extract_signed_reveal_envelope(&tx).expect_err("empty payload is invalid");

        assert!(matches!(error, CommitRevealParseError::EmptyRevealPayload));
    }

    // Reveal-slot range.

    #[test]
    fn test_contiguous_p2tr_run() {
        let commit = build_commit_tx(&TEST_MAGIC, &[], 3, &[make_change_script()]);

        let range = derive_reveal_slot_range(&commit)
            .expect("valid commit")
            .expect("has slots");

        assert_eq!(range.slot_count().get(), 3);
        assert!(range.contains(1) && range.contains(3));
        assert!(!range.contains(0) && !range.contains(4));
    }

    #[test]
    fn test_p2tr_after_change_rejected() {
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
    fn test_slot_range_count_matches_last_slot() {
        let range = RevealSlotRange::new(NonZeroU32::new(3).expect("valid slot"));

        assert_eq!(range.slot_count().get(), 3);
        assert!(range.contains(3));
        assert!(!range.contains(4));
    }
}
