//! Commit discovery and reveal grouping helpers.
//!
//! These functions are stateless. The caller owns block iteration,
//! confirmation policy, reorg handling, persistence, and telemetry.

use bitcoin::{Transaction, Txid};
use strata_l1_txfmt::MagicBytes;

use crate::errors::{CommitRevealParseError, MarkerTailArrayLengthError};
use crate::parser::{
    ParsedCommitReveal, RevealSlotRange, assemble_from_slots, classify_reveal_inputs_for_commit,
    convert_marker_tail_to_array_ref, derive_reveal_slot_range, read_commit_marker,
};

/// Owned metadata for a transaction parsed as an SPS-53 commit.
///
/// The marker matches the supplied magic, the reveal-slot run is present and
/// unambiguous, and the marker tail is available for caller-specific
/// interpretation. It says nothing about confirmation, auth, payload type, or
/// reveal completeness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommit {
    txid: Txid,
    marker_tail: Vec<u8>,
    reveal_slots: RevealSlotRange,
}

impl ParsedCommit {
    /// The commit transaction's id.
    pub fn txid(&self) -> Txid {
        self.txid
    }

    /// Marker bytes after the magic.
    pub fn marker_tail(&self) -> &[u8] {
        &self.marker_tail
    }

    /// Marker tail as a fixed-width byte array.
    ///
    /// This only checks length. The caller still owns any meaning assigned to
    /// the tail bytes.
    pub fn marker_tail_array<const N: usize>(
        &self,
    ) -> Result<&[u8; N], MarkerTailArrayLengthError> {
        convert_marker_tail_to_array_ref(&self.marker_tail)
    }

    /// The commit's reveal-slot range.
    pub const fn reveal_slots(&self) -> RevealSlotRange {
        self.reveal_slots
    }
}

/// Classifies one transaction as a commit candidate.
///
/// `Ok(Some)` means the marker matches `magic` and the reveal-slot run is
/// unambiguous. `Ok(None)` means no marker matches. A matching marker with a
/// malformed commit layout is an error.
///
/// # Errors
///
/// [`CommitRevealParseError::MissingRevealSlots`] for a matching marker with no
/// reveal slots; [`CommitRevealParseError::AmbiguousTaprootChangeOutput`] when a
/// P2TR output follows a non-P2TR one in the reveal-slot run.
pub fn parse_commit_candidate(
    magic: &MagicBytes,
    tx: &Transaction,
) -> Result<Option<ParsedCommit>, CommitRevealParseError> {
    let Some(marker_tail) = read_commit_marker(magic, tx) else {
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

/// Assigns one transaction to the commit whose reveal slot it spends.
///
/// Returns `Ok(None)` when `tx` spends no reveal slot from `commits`. Returns
/// [`CommitRevealParseError::RevealSpansMultipleCommits`] when it spends reveal
/// slots from more than one commit.
///
/// # Errors
///
/// Also returns [`CommitRevealParseError::RevealSpendsMarker`],
/// [`CommitRevealParseError::UnexpectedReveal`], or
/// [`CommitRevealParseError::RevealMultipleCommitSpends`] when the transaction
/// spends a malformed set of outputs from its assigned commit.
pub fn assign_reveal_to_commit<'c>(
    commits: impl IntoIterator<Item = &'c ParsedCommit>,
    tx: &Transaction,
) -> Result<Option<Txid>, CommitRevealParseError> {
    let mut assigned: Option<&ParsedCommit> = None;
    for commit in commits {
        let spends_commit_slot = tx.input.iter().any(|input| {
            let prev = input.previous_output;
            prev.txid == commit.txid && commit.reveal_slots.contains(prev.vout)
        });
        if !spends_commit_slot {
            continue;
        }

        match assigned {
            Some(existing) if existing.txid != commit.txid => {
                return Err(CommitRevealParseError::RevealSpansMultipleCommits);
            }
            Some(_) => {}
            None => assigned = Some(commit),
        }
    }

    let Some(commit) = assigned else {
        return Ok(None);
    };

    let slot_spend = classify_reveal_inputs_for_commit(tx, commit.txid, commit.reveal_slots)?;
    debug_assert!(
        slot_spend.is_some(),
        "assigned commit has a reveal-slot spend"
    );

    Ok(Some(commit.txid))
}

/// Extracts the payload for a parsed commit from its reveal transactions.
///
/// # Errors
///
/// Returns a [`CommitRevealParseError`] if a slot is missing or claimed twice, a
/// reveal fails to parse, or the reveals disagree on one pubkey.
pub fn extract_payload_for_parsed_commit<'c, 't>(
    commit: &'c ParsedCommit,
    reveals: impl IntoIterator<Item = &'t Transaction>,
) -> Result<ParsedCommitReveal<'c>, CommitRevealParseError> {
    assemble_from_slots(
        commit.txid,
        &commit.marker_tail,
        commit.reveal_slots,
        reveals,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract_payload_from_single_commit_set;
    use crate::test_utils::{
        DEFAULT_KEY_SEED, TEST_MAGIC, build_commit_reveal_set, build_commit_tx, build_reveal_input,
        build_reveal_tx, build_reveal_tx_with_marker_output, make_change_script, make_p2tr_script,
        make_txid,
    };

    fn parsed_commit(commit: &Transaction) -> ParsedCommit {
        parse_commit_candidate(&TEST_MAGIC, commit)
            .expect("valid commit")
            .expect("marker matches")
    }

    #[test]
    fn test_parse_commit_candidate_returns_parsed_commit() {
        let commit = build_commit_tx(&TEST_MAGIC, &[3, 4], 2, &[]);

        let parsed = parse_commit_candidate(&TEST_MAGIC, &commit)
            .expect("valid commit")
            .expect("marker matches");

        assert_eq!(parsed.txid(), commit.compute_txid());
        assert_eq!(parsed.marker_tail(), &[3, 4]);
        assert_eq!(parsed.reveal_slots().last_vout(), 2);
        assert_eq!(parsed.reveal_slots().slot_count().get(), 2);
    }

    #[test]
    fn test_parse_commit_candidate_fixed_width_tail_succeeds() {
        let commit = build_commit_tx(&TEST_MAGIC, &[0, 0, 0, 7], 2, &[]);

        let parsed = parsed_commit(&commit);

        assert_eq!(
            parsed.marker_tail_array::<4>().expect("width matches"),
            &[0, 0, 0, 7]
        );
    }

    #[test]
    fn test_parse_commit_candidate_wrong_width_tail_fails() {
        let commit = build_commit_tx(&TEST_MAGIC, &[7, 7], 2, &[]);
        let parsed = parsed_commit(&commit);

        let error = parsed
            .marker_tail_array::<4>()
            .expect_err("tail is not four bytes");

        assert_eq!(
            error,
            MarkerTailArrayLengthError {
                expected: 4,
                found: 2,
            }
        );
    }

    #[test]
    fn test_parse_commit_candidate_ignores_non_commit() {
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
    fn test_parse_commit_candidate_rejects_marker_without_slots() {
        let no_slots = build_commit_tx(&TEST_MAGIC, &[7, 7], 0, &[]);

        let error =
            parse_commit_candidate(&TEST_MAGIC, &no_slots).expect_err("commit has no slots");

        assert!(matches!(error, CommitRevealParseError::MissingRevealSlots));
    }

    #[test]
    fn test_parse_commit_candidate_rejects_ambiguous_change() {
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
    fn test_assign_reveal_to_commit_returns_owner() {
        let set_a = build_commit_reveal_set(
            &TEST_MAGIC,
            &[1],
            &[b"a1".as_slice(), b"a2".as_slice()],
            DEFAULT_KEY_SEED,
        );
        let set_b =
            build_commit_reveal_set(&TEST_MAGIC, &[2], &[b"b1".as_slice()], DEFAULT_KEY_SEED);
        let (parsed_a, parsed_b) = (parsed_commit(&set_a.commit), parsed_commit(&set_b.commit));

        let owner = assign_reveal_to_commit([&parsed_a, &parsed_b], &set_a.reveals[0])
            .expect("valid reveal")
            .expect("assigned");

        assert_eq!(owner, parsed_a.txid());
    }

    #[test]
    fn test_assign_reveal_to_commit_ignores_unrelated_tx() {
        let commit = build_commit_tx(&TEST_MAGIC, &[1], 1, &[]);
        let parsed = parsed_commit(&commit);
        let unrelated = build_reveal_tx(vec![build_reveal_input(
            make_txid(99),
            1,
            Some(b"x"),
            DEFAULT_KEY_SEED,
        )]);

        assert_eq!(
            assign_reveal_to_commit([&parsed], &unrelated).expect("not malformed"),
            None
        );
    }

    #[test]
    fn test_assign_reveal_to_commit_rejects_same_commit_outpoint_defects() {
        let commit = build_commit_tx(&TEST_MAGIC, &[1], 2, &[]);
        let parsed = parsed_commit(&commit);

        let spends_marker = build_reveal_tx(vec![
            build_reveal_input(parsed.txid(), 1, Some(b"a"), DEFAULT_KEY_SEED),
            build_reveal_input(parsed.txid(), 0, Some(b"m"), DEFAULT_KEY_SEED),
        ]);
        let spends_non_slot = build_reveal_tx(vec![
            build_reveal_input(parsed.txid(), 1, Some(b"a"), DEFAULT_KEY_SEED),
            build_reveal_input(parsed.txid(), 3, Some(b"n"), DEFAULT_KEY_SEED),
        ]);
        let spends_two_slots = build_reveal_tx(vec![
            build_reveal_input(parsed.txid(), 1, Some(b"a"), DEFAULT_KEY_SEED),
            build_reveal_input(parsed.txid(), 2, Some(b"b"), DEFAULT_KEY_SEED),
        ]);

        let marker_error = assign_reveal_to_commit([&parsed], &spends_marker)
            .expect_err("marker output is not a slot");
        let non_slot_error = assign_reveal_to_commit([&parsed], &spends_non_slot)
            .expect_err("non-slot output is not a reveal");
        let multi_slot_error = assign_reveal_to_commit([&parsed], &spends_two_slots)
            .expect_err("one reveal carries one chunk");

        assert!(matches!(
            marker_error,
            CommitRevealParseError::RevealSpendsMarker
        ));
        assert!(matches!(
            non_slot_error,
            CommitRevealParseError::UnexpectedReveal { vout: 3 }
        ));
        assert!(matches!(
            multi_slot_error,
            CommitRevealParseError::RevealMultipleCommitSpends
        ));
    }

    #[test]
    fn test_assign_reveal_to_commit_ignores_other_commit_non_slot_spend() {
        let commit_a = build_commit_tx(&TEST_MAGIC, &[1], 1, &[make_change_script()]);
        let commit_b = build_commit_tx(&TEST_MAGIC, &[2], 1, &[]);
        let (parsed_a, parsed_b) = (parsed_commit(&commit_a), parsed_commit(&commit_b));
        let reveal = build_reveal_tx(vec![
            build_reveal_input(parsed_b.txid(), 1, Some(b"b"), DEFAULT_KEY_SEED),
            build_reveal_input(parsed_a.txid(), 2, None, DEFAULT_KEY_SEED),
        ]);

        let owner = assign_reveal_to_commit([&parsed_a, &parsed_b], &reveal)
            .expect("other commit's non-slot spend is unrelated")
            .expect("assigned");

        assert_eq!(owner, parsed_b.txid());
    }

    #[test]
    fn test_assign_reveal_to_commit_rejects_cross_commit_reveal() {
        let commit_a = build_commit_tx(&TEST_MAGIC, &[1], 1, &[]);
        let commit_b = build_commit_tx(&TEST_MAGIC, &[2], 1, &[]);
        let (parsed_a, parsed_b) = (parsed_commit(&commit_a), parsed_commit(&commit_b));
        let reveal = build_reveal_tx(vec![
            build_reveal_input(parsed_a.txid(), 1, Some(b"a"), DEFAULT_KEY_SEED),
            build_reveal_input(parsed_b.txid(), 1, Some(b"b"), DEFAULT_KEY_SEED),
        ]);

        let error =
            assign_reveal_to_commit([&parsed_a, &parsed_b], &reveal).expect_err("spans commits");

        assert!(matches!(
            error,
            CommitRevealParseError::RevealSpansMultipleCommits
        ));
    }

    #[test]
    fn test_assign_reveal_to_commit_ignores_marker_output_on_reveal() {
        let commit = build_commit_tx(&TEST_MAGIC, &[], 1, &[]);
        let parsed = parsed_commit(&commit);
        let marker = build_commit_tx(&TEST_MAGIC, &[9], 1, &[]).output[0].clone();
        let reveal = build_reveal_tx_with_marker_output(
            vec![build_reveal_input(
                parsed.txid(),
                1,
                Some(b"chunk"),
                DEFAULT_KEY_SEED,
            )],
            marker,
        );

        let owner = assign_reveal_to_commit([&parsed], &reveal)
            .expect("reveal output marker is unrelated")
            .expect("assigned");

        assert_eq!(owner, parsed.txid());
    }

    #[test]
    fn test_extract_payload_for_parsed_commit_matches_closed_set() {
        let set = build_commit_reveal_set(
            &TEST_MAGIC,
            &[7, 7],
            &[b"first".as_slice(), b"second".as_slice()],
            DEFAULT_KEY_SEED,
        );
        let parsed = parsed_commit(&set.commit);

        let via_set = extract_payload_from_single_commit_set(
            &TEST_MAGIC,
            [&set.commit].into_iter().chain(set.reveals.iter()),
        )
        .expect("closed set parses");
        let via_parsed =
            extract_payload_for_parsed_commit(&parsed, set.reveals.iter()).expect("parsed");

        assert_eq!(via_set, via_parsed);
    }
}
