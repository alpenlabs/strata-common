use std::collections::{BTreeMap, BTreeSet};

use bitcoin::{Transaction, Txid};
use strata_identifiers::L1Height;
use strata_l1_txfmt::MagicBytes;
use tracing::warn;

use super::commit_reveal::{
    ParsedCommit, RevealSlotSpend, convert_marker_tail_to_array, extract_signed_reveal_envelope,
    parse_commit_candidate, read_anchor_marker,
};
use super::envelope::SignedEnvelopeLeaf;
use crate::SIGNED_LEAF_PUBKEY_LEN;
use crate::parser::errors::CommitRevealParseError;

/// Number of L1 blocks an incomplete payload is retained in
/// [`PayloadParser`] state after the entry is added.
///
/// 1024 blocks is approximately one week.
const PENDING_PAYLOAD_RETENTION_BLOCKS: L1Height = 1024;

/// A recovered marker-anchored payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredPayload {
    anchor_txid: Txid,
    tail: Vec<u8>,
    producer_pubkey: [u8; SIGNED_LEAF_PUBKEY_LEN],
    chunks: Vec<Vec<u8>>,
}

impl RecoveredPayload {
    /// [`Txid`] of the marker-bearing anchor transaction.
    pub const fn anchor_txid(&self) -> Txid {
        self.anchor_txid
    }

    /// Opaque marker bytes after the magic.
    pub fn tail(&self) -> &[u8] {
        &self.tail
    }

    /// Tail as a fixed-width byte array.
    pub fn tail_array<const N: usize>(&self) -> Result<&[u8; N], CommitRevealParseError> {
        convert_marker_tail_to_array(&self.tail)
    }

    /// Producer x-only pubkey observed in the signed payload leaf or leaves.
    pub const fn producer_pubkey(&self) -> [u8; SIGNED_LEAF_PUBKEY_LEN] {
        self.producer_pubkey
    }

    /// Requires the recovered producer key to match `expected`.
    pub fn require_producer(
        self,
        expected: &[u8; SIGNED_LEAF_PUBKEY_LEN],
    ) -> Result<Self, CommitRevealParseError> {
        if self.producer_pubkey != *expected {
            return Err(CommitRevealParseError::UnexpectedRevealPubkey {
                expected: *expected,
                found: self.producer_pubkey,
            });
        }
        Ok(self)
    }

    /// Ordered payload chunks.
    pub fn chunks(&self) -> &[Vec<u8>] {
        &self.chunks
    }

    /// Consumes the payload, returning ordered chunks.
    pub fn into_chunks(self) -> Vec<Vec<u8>> {
        self.chunks
    }

    /// Consumes the payload, returning ordered chunks.
    pub fn into_payload(self) -> Vec<u8> {
        self.chunks.concat()
    }
}

/// Output produced by [`PayloadParser`] after parsing a batch of transactions.
#[derive(Debug)]
pub struct PayloadParserOutput {
    /// Recovered payloads.
    payloads: Vec<RecoveredPayload>,
}

impl PayloadParserOutput {
    /// Recovered payloads.
    pub fn payloads(&self) -> &[RecoveredPayload] {
        &self.payloads
    }

    /// Consumes the output, returning recovered payloads.
    pub fn into_payloads(self) -> Vec<RecoveredPayload> {
        self.payloads
    }
}

/// Payload carrier type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PayloadCarrier {
    /// A single reveal transaction with marker and payload.
    SingleReveal,

    /// A commit transaction with marker and reveal slots,
    /// each of which is spent by a reveal transaction.
    ChunkedReveals,
}

/// Configuration for marker-anchored payload parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadParserConfig {
    magic: MagicBytes,
    carrier: PayloadCarrier,
}

impl PayloadParserConfig {
    /// Configuration to extract payloads carried by a marker-bearing reveal transaction.
    pub const fn single_reveal(magic: MagicBytes) -> Self {
        Self {
            magic,
            carrier: PayloadCarrier::SingleReveal,
        }
    }

    /// Configuration to parse payloads carried by reveal transactions anchored to one commit
    /// transaction.
    pub const fn chunked_reveals(magic: MagicBytes) -> Self {
        Self {
            magic,
            carrier: PayloadCarrier::ChunkedReveals,
        }
    }
}

/// An incomplete chunked payload anchored by a commit transaction.
#[derive(Debug)]
struct IncompletePayloadEntry {
    commit: ParsedCommit,
    commit_block_height: L1Height,
    producer_pubkey: Option<[u8; SIGNED_LEAF_PUBKEY_LEN]>,
    reveals: BTreeMap<u32, SignedEnvelopeLeaf>,
}

impl IncompletePayloadEntry {
    fn insert_reveal(
        &mut self,
        vout: u32,
        envelope: SignedEnvelopeLeaf,
    ) -> Result<(), CommitRevealParseError> {
        if self.reveals.contains_key(&vout) {
            return Err(CommitRevealParseError::DuplicateReveal { vout });
        }

        let found = *envelope.pubkey();
        match self.producer_pubkey {
            None => self.producer_pubkey = Some(found),
            Some(expected) if expected == found => {}
            Some(_) => return Err(CommitRevealParseError::InconsistentRevealPubkey),
        }

        self.reveals.insert(vout, envelope);
        Ok(())
    }
}

/// Payload parser.
///
/// Parses a batch of transactions and recovers payloads.
#[derive(Debug)]
pub struct PayloadParser {
    config: PayloadParserConfig,
    incomplete_payloads: BTreeMap<Txid, IncompletePayloadEntry>,
}

impl PayloadParser {
    /// Creates a parser with passed marker and carrier configuration.
    pub fn new(config: PayloadParserConfig) -> Self {
        Self {
            config,
            incomplete_payloads: BTreeMap::new(),
        }
    }

    /// Parses transactions and returns recovered payloads.
    ///
    /// Transactions that lead to errors are ignored.
    pub fn parse<'a>(
        &mut self,
        txs: impl IntoIterator<Item = &'a Transaction>,
        l1_block_height: L1Height,
    ) -> PayloadParserOutput {
        // Prune stale incomplete entries.
        // We prune before processing because incoming transactions may update stale entries.
        self.prune_stale(l1_block_height);

        match self.config.carrier {
            PayloadCarrier::SingleReveal => self.parse_single_reveals(txs),
            PayloadCarrier::ChunkedReveals => self.parse_chunked_reveals(txs, l1_block_height),
        }
    }

    /// Parses transactions that match [`PayloadCarrier::SingleReveal`].
    ///
    /// Reveal transactions matching the carrier must have protocol marker in output 0
    /// and payload in input 0 witness. Malformed candidates are ignored.
    fn parse_single_reveals<'a>(
        &mut self,
        txs: impl IntoIterator<Item = &'a Transaction>,
    ) -> PayloadParserOutput {
        let mut payloads = Vec::new();

        for tx in txs {
            let txid = tx.compute_txid();
            let tail = match read_anchor_marker(&self.config.magic, tx) {
                Some(tail) => tail,
                None => {
                    continue;
                }
            };

            let envelope = match extract_signed_reveal_envelope(tx) {
                Ok(reveal_envelope) => reveal_envelope,
                Err(e) => {
                    warn!(txid = %txid, error = %e, "failed to parse single reveal");
                    continue;
                }
            };

            let producer_pubkey = *envelope.pubkey();
            payloads.push(RecoveredPayload {
                anchor_txid: txid,
                tail: tail.to_vec(),
                producer_pubkey,
                chunks: vec![envelope.into_payload()],
            });
        }

        PayloadParserOutput { payloads }
    }

    /// Parses a batch of chunked commit-reveals transactions.
    ///
    /// Transactions that do not match the chunked reveal format are ignored.
    /// Reveal transactions arriving in a batch earlier than their anchor are ignored.
    fn parse_chunked_reveals<'a>(
        &mut self,
        txs: impl IntoIterator<Item = &'a Transaction>,
        l1_block_height: L1Height,
    ) -> PayloadParserOutput {
        let txs = txs.into_iter().collect::<Vec<_>>();
        let mut malformed_commits = BTreeSet::new();
        let mut new_commits = BTreeSet::new();
        let mut payloads = Vec::new();

        // First pass to identify commits.
        for tx in &txs {
            let txid = tx.compute_txid();
            match parse_commit_candidate(&self.config.magic, tx) {
                Ok(Some(commit)) => {
                    self.incomplete_payloads.entry(commit.txid()).or_insert(
                        IncompletePayloadEntry {
                            commit,
                            commit_block_height: l1_block_height,
                            producer_pubkey: None,
                            reveals: BTreeMap::new(),
                        },
                    );
                    new_commits.insert(txid);
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(txid = %txid, error=%e, "failed to parse commit candidate");
                    malformed_commits.insert(txid);
                }
            }
        }

        // Second pass to identify and assign reveals to their commits.
        for tx in txs {
            let txid = tx.compute_txid();
            if malformed_commits.contains(&txid) || new_commits.contains(&txid) {
                continue;
            }

            match self.parse_reveal_candidate(tx) {
                Ok(Some(payload)) => {
                    payloads.push(payload);
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(txid = %txid, error=%e, "failed to parse reveal candidate");
                }
            }
        }

        PayloadParserOutput { payloads }
    }

    /// Parses a transaction that may be a reveal spending a commit.
    ///
    /// If it is a valid commit, assigns to matching commit.
    fn parse_reveal_candidate(
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<RecoveredPayload>, CommitRevealParseError> {
        let Some(spend) = self.find_reveal_slot_spend(tx)? else {
            return Ok(None);
        };

        let envelope = extract_signed_reveal_envelope(tx)?;
        let Some(entry) = self.incomplete_payloads.get_mut(&spend.commit_txid) else {
            return Ok(None);
        };
        entry.insert_reveal(spend.vout, envelope)?;

        Ok(self.take_payload_if_complete(spend.commit_txid))
    }

    /// Find the matching commit and slot for a reveal candidate.
    fn find_reveal_slot_spend(
        &self,
        tx: &Transaction,
    ) -> Result<Option<RevealSlotSpend>, CommitRevealParseError> {
        let mut matched: Option<RevealSlotSpend> = None;

        for input in &tx.input {
            let outpoint = input.previous_output;
            let Some(entry) = self.incomplete_payloads.get(&outpoint.txid) else {
                continue;
            };

            let spend = entry.commit.reveal_slot_spend(outpoint.vout)?;

            if let Some(previous) = matched {
                return if previous.commit_txid == spend.commit_txid {
                    Err(CommitRevealParseError::RevealSpendsMultipleSlots)
                } else {
                    Err(CommitRevealParseError::RevealSpansMultipleCommits)
                };
            }
            matched = Some(spend);
        }

        Ok(matched)
    }

    /// Takes an incomplete payload entry if it is now complete.
    ///
    /// If complete, removes the entry from state and returns recovered payload.
    fn take_payload_if_complete(&mut self, commit_txid: Txid) -> Option<RecoveredPayload> {
        let entry = self.incomplete_payloads.get(&commit_txid)?;
        let slot_count = entry.commit.reveal_slots().slot_count().get();
        if entry.reveals.len() != slot_count {
            return None;
        }
        let producer_pubkey = entry.producer_pubkey?;

        let entry = self.incomplete_payloads.remove(&commit_txid)?;
        let chunks = entry
            .reveals
            .into_values()
            .map(SignedEnvelopeLeaf::into_payload)
            .collect();

        Some(RecoveredPayload {
            anchor_txid: entry.commit.txid(),
            tail: entry.commit.marker_tail().to_vec(),
            producer_pubkey,
            chunks,
        })
    }

    /// Drops incomplete payload entries older than [`PENDING_PAYLOAD_RETENTION_BLOCKS`].
    fn prune_stale(&mut self, current_l1_height: L1Height) {
        let cutoff = current_l1_height.saturating_sub(PENDING_PAYLOAD_RETENTION_BLOCKS);
        let stale_txids = self
            .incomplete_payloads
            .iter()
            .filter_map(|(txid, entry)| (entry.commit_block_height <= cutoff).then_some(*txid))
            .collect::<Vec<_>>();

        for txid in stale_txids {
            self.incomplete_payloads.remove(&txid);
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{Amount, Transaction, TxOut};
    use strata_l1_txfmt::MagicBytes;

    use super::*;
    use crate::test_utils::*;

    const TEST_L1_HEIGHT: L1Height = 100;

    fn build_marker_output(magic: &MagicBytes, tail: &[u8]) -> TxOut {
        TxOut {
            value: Amount::ZERO,
            script_pubkey: build_marker_script(magic, tail),
        }
    }

    fn build_single_reveal_tx(
        magic: &MagicBytes,
        tail: &[u8],
        payload: &[u8],
        key_seed: u8,
    ) -> Transaction {
        build_reveal_tx_with_marker_output(
            vec![build_reveal_input(
                make_txid(21),
                1,
                Some(payload),
                key_seed,
            )],
            build_marker_output(magic, tail),
        )
    }

    fn parse_with_config<'a>(
        config: PayloadParserConfig,
        txs: impl IntoIterator<Item = &'a Transaction>,
        l1_block_height: L1Height,
    ) -> PayloadParserOutput {
        let mut parser = PayloadParser::new(config);
        parser.parse(txs, l1_block_height)
    }

    #[test]
    fn test_recovered_payload_requires_expected_producer() {
        let observed_pubkey = [1u8; SIGNED_LEAF_PUBKEY_LEN];
        let expected_pubkey = [2u8; SIGNED_LEAF_PUBKEY_LEN];
        let payload = RecoveredPayload {
            anchor_txid: make_txid(1),
            tail: Vec::new(),
            producer_pubkey: observed_pubkey,
            chunks: vec![b"payload".to_vec()],
        };

        let error = payload
            .require_producer(&expected_pubkey)
            .expect_err("wrong producer");

        assert!(matches!(
            error,
            CommitRevealParseError::UnexpectedRevealPubkey { expected, found }
                if expected == expected_pubkey && found == observed_pubkey
        ));
    }

    #[test]
    fn test_single_reveal_payload() {
        let tx = build_single_reveal_tx(&TEST_MAGIC, &[1, 2, 3, 4], b"payload", 11);
        let txid = tx.compute_txid();
        let output = parse_with_config(
            PayloadParserConfig::single_reveal(TEST_MAGIC),
            [&tx],
            TEST_L1_HEIGHT,
        );

        assert_eq!(output.payloads.len(), 1);
        let payload = &output.payloads[0];
        assert_eq!(payload.anchor_txid(), txid);
        assert_eq!(payload.tail(), &[1, 2, 3, 4]);
        assert_eq!(payload.producer_pubkey(), make_xonly_pubkey_bytes(11));
        assert_eq!(payload.chunks(), &[b"payload".to_vec()]);
    }

    #[test]
    fn test_single_reveal_without_marker_ignored() {
        let tx = build_reveal_tx(vec![build_reveal_input(
            make_txid(21),
            1,
            Some(b"checkpoint"),
            DEFAULT_KEY_SEED,
        )]);
        let output = parse_with_config(
            PayloadParserConfig::single_reveal(TEST_MAGIC),
            [&tx],
            TEST_L1_HEIGHT,
        );

        assert!(output.payloads.is_empty());
    }

    #[test]
    fn test_recovered_payload_tail_requires_requested_width() {
        let tx = build_single_reveal_tx(&TEST_MAGIC, &[1, 2, 3, 4], b"payload", DEFAULT_KEY_SEED);
        let output = parse_with_config(
            PayloadParserConfig::single_reveal(TEST_MAGIC),
            [&tx],
            TEST_L1_HEIGHT,
        );
        let payload = &output.payloads[0];

        assert_eq!(
            payload.tail_array::<4>().expect("four-byte tail"),
            &[1, 2, 3, 4]
        );
        assert!(matches!(
            payload.tail_array::<3>().expect_err("wrong tail width"),
            CommitRevealParseError::UnexpectedMarkerTailLength {
                expected: 3,
                found: 4
            }
        ));
    }

    #[test]
    fn test_chunked_reveals_payload_across_batches() {
        let chunks: [&[u8]; 2] = [b"first", b"second"];
        let txs = build_commit_reveal_set(&TEST_MAGIC, &[7, 8], &chunks, 13);
        let mut parser = PayloadParser::new(PayloadParserConfig::chunked_reveals(TEST_MAGIC));

        let first = parser.parse([&txs.commit], TEST_L1_HEIGHT);
        assert!(first.payloads.is_empty());

        let second = parser.parse(txs.reveals.iter(), TEST_L1_HEIGHT + 1);

        assert_eq!(second.payloads.len(), 1);
        assert_eq!(
            second.payloads[0].chunks(),
            &[b"first".to_vec(), b"second".to_vec()]
        );
    }

    #[test]
    fn test_chunked_reveal_payloads_ordered_by_slot() {
        let chunks: [&[u8]; 2] = [b"first", b"second"];
        let txs = build_commit_reveal_set(&TEST_MAGIC, &[7, 8], &chunks, 13);

        let output = parse_with_config(
            PayloadParserConfig::chunked_reveals(TEST_MAGIC),
            std::iter::once(&txs.commit).chain(txs.reveals.iter()),
            TEST_L1_HEIGHT,
        );

        assert_eq!(output.payloads.len(), 1);
        assert_eq!(
            output.payloads[0].chunks(),
            &[b"first".to_vec(), b"second".to_vec()]
        );
    }

    #[test]
    fn test_reveals_before_commit_ignored() {
        let chunks: [&[u8]; 1] = [b"chunk"];
        let txs = build_commit_reveal_set(&TEST_MAGIC, &[7, 8], &chunks, 13);
        let mut parser = PayloadParser::new(PayloadParserConfig::chunked_reveals(TEST_MAGIC));

        let reveal_first = parser.parse(txs.reveals.iter(), TEST_L1_HEIGHT + 1);
        assert!(reveal_first.payloads.is_empty());

        let commit_second = parser.parse([&txs.commit], TEST_L1_HEIGHT);

        assert!(commit_second.payloads.is_empty());
    }

    #[test]
    fn test_incomplete_payload_pruned() {
        let chunks1: [&[u8]; 2] = [b"chunks1-a", b"chunks1-b"];
        let chunks2: [&[u8]; 3] = [b"chunks2-a", b"chunks2-b", b"chunks2-c"];
        let txs1 = build_commit_reveal_set(&TEST_MAGIC, &[1], &chunks1, 11);
        let txs2 = build_commit_reveal_set(&TEST_MAGIC, &[2], &chunks2, 12);
        let mut parser = PayloadParser::new(PayloadParserConfig::chunked_reveals(TEST_MAGIC));

        let commits = parser.parse([&txs1.commit, &txs2.commit], TEST_L1_HEIGHT);
        assert!(commits.payloads.is_empty());

        let first_reveals = parser.parse([&txs1.reveals[0], &txs2.reveals[0]], TEST_L1_HEIGHT + 1);
        assert!(first_reveals.payloads.is_empty());

        // Parse reveals for `chunks1` before prune height.
        let chunks1_completion_height = TEST_L1_HEIGHT + PENDING_PAYLOAD_RETENTION_BLOCKS - 1;
        let chunks1_output = parser.parse([&txs1.reveals[1]], chunks1_completion_height);
        assert!(chunks1_output.payloads.len() == 1);
        assert_eq!(
            chunks1_output.payloads[0].anchor_txid(),
            txs1.commit.compute_txid()
        );
        assert_eq!(
            chunks1_output.payloads[0].chunks(),
            &[b"chunks1-a".to_vec(), b"chunks1-b".to_vec(),]
        );

        let unrelated_tx = build_reveal_tx(vec![build_reveal_input(
            make_txid(77),
            1,
            Some(b"unrelated"),
            DEFAULT_KEY_SEED,
        )]);
        let prune_height = chunks1_completion_height + 1;
        let unrelated = parser.parse([&unrelated_tx], prune_height);
        assert!(unrelated.payloads.is_empty());

        // Parse reveals for `chunks2` after prune height.
        let pruned = parser.parse(txs2.reveals[1..].iter(), prune_height + 1);
        // Incomplete entry should have been pruned. So no payloads.
        assert_eq!(pruned.payloads.len(), 0);
    }

    #[test]
    fn test_unrelated_transaction_ignored() {
        let unrelated = build_reveal_tx(vec![build_reveal_input(
            make_txid(77),
            1,
            Some(b"unrelated"),
            DEFAULT_KEY_SEED,
        )]);

        let output = parse_with_config(
            PayloadParserConfig::chunked_reveals(TEST_MAGIC),
            [&unrelated],
            TEST_L1_HEIGHT,
        );

        assert!(output.payloads.is_empty());
    }

    #[test]
    fn test_reveal_spending_multiple_slots_ignored() {
        let commit = build_commit_tx(&TEST_MAGIC, &[7, 8], 2, &[]);
        let reveal = build_reveal_tx(vec![
            build_reveal_input(commit.compute_txid(), 1, Some(b"first"), DEFAULT_KEY_SEED),
            build_reveal_input(commit.compute_txid(), 2, Some(b"second"), DEFAULT_KEY_SEED),
        ]);

        let mut parser = PayloadParser::new(PayloadParserConfig::chunked_reveals(TEST_MAGIC));
        parser.parse([&commit], TEST_L1_HEIGHT);
        let output = parser.parse([&reveal], TEST_L1_HEIGHT + 1);

        assert!(output.payloads.is_empty());
    }

    #[test]
    fn test_reveal_spanning_multiple_commits_ignored() {
        let first_commit = build_commit_tx(&TEST_MAGIC, &[1], 1, &[]);
        let second_commit = build_commit_tx(&TEST_MAGIC, &[2], 1, &[]);
        let reveal = build_reveal_tx(vec![
            build_reveal_input(
                first_commit.compute_txid(),
                1,
                Some(b"first"),
                DEFAULT_KEY_SEED,
            ),
            build_reveal_input(
                second_commit.compute_txid(),
                1,
                Some(b"second"),
                DEFAULT_KEY_SEED,
            ),
        ]);

        let mut parser = PayloadParser::new(PayloadParserConfig::chunked_reveals(TEST_MAGIC));
        parser.parse([&first_commit, &second_commit], TEST_L1_HEIGHT);

        let output = parser.parse([&reveal], TEST_L1_HEIGHT);

        assert!(output.payloads.is_empty());
    }

    #[test]
    fn test_reveal_with_duplicate_slot_ignored() {
        let chunks: [&[u8]; 2] = [b"first", b"second"];
        let txs = build_commit_reveal_set(&TEST_MAGIC, &[7, 8], &chunks, DEFAULT_KEY_SEED);
        let mut parser = PayloadParser::new(PayloadParserConfig::chunked_reveals(TEST_MAGIC));

        let commit = parser.parse([&txs.commit], TEST_L1_HEIGHT);
        assert!(commit.payloads.is_empty());

        let first = parser.parse([&txs.reveals[0]], TEST_L1_HEIGHT + 1);
        assert!(first.payloads.is_empty());

        let duplicate = parser.parse([&txs.reveals[0]], TEST_L1_HEIGHT + 2);

        assert!(duplicate.payloads.is_empty());
    }

    #[test]
    fn test_chunked_reveal_inconsistent_pubkey_ignored() {
        let commit = build_commit_tx(&TEST_MAGIC, &[7, 8], 2, &[]);
        let first_reveal = build_reveal_tx(vec![build_reveal_input(
            commit.compute_txid(),
            1,
            Some(b"first"),
            11,
        )]);
        let second_reveal = build_reveal_tx(vec![build_reveal_input(
            commit.compute_txid(),
            2,
            Some(b"second"),
            12,
        )]);
        let mut parser = PayloadParser::new(PayloadParserConfig::chunked_reveals(TEST_MAGIC));

        let commit_output = parser.parse([&commit], TEST_L1_HEIGHT);
        assert!(commit_output.payloads.is_empty());

        let first = parser.parse([&first_reveal], TEST_L1_HEIGHT + 1);
        assert!(first.payloads.is_empty());

        let inconsistent = parser.parse([&second_reveal], TEST_L1_HEIGHT + 2);

        assert!(inconsistent.payloads.is_empty());
    }
}
