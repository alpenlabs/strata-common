//! Reveal grouping helpers.
//!
//! These functions are stateless. The caller owns block iteration,
//! confirmation policy, reorg handling, persistence, and telemetry.

use bitcoin::{Transaction, Txid};

use crate::errors::CommitRevealGroupingError;
use crate::parser::{ParsedCommit, classify_reveal_inputs_for_commit};

/// Assigns one transaction to the commit whose reveal slot it spends.
///
/// Returns `Ok(None)` when `tx` spends no reveal slot from `commits`. Returns
/// [`CommitRevealGroupingError::RevealSpansMultipleCommits`] when it spends reveal
/// slots from more than one commit.
///
/// # Errors
///
/// Also returns [`CommitRevealGroupingError::Parse`] when parser checks fail
/// for the assigned commit.
pub fn assign_reveal_to_commit<'c>(
    commits: impl IntoIterator<Item = &'c ParsedCommit>,
    tx: &Transaction,
) -> Result<Option<Txid>, CommitRevealGroupingError> {
    let mut assigned: Option<&ParsedCommit> = None;
    for commit in commits {
        let commit_txid = commit.txid();
        let reveal_slots = commit.reveal_slots();
        let spends_commit_slot = tx.input.iter().any(|input| {
            let prev = input.previous_output;
            prev.txid == commit_txid && reveal_slots.contains(prev.vout)
        });
        if !spends_commit_slot {
            continue;
        }

        match assigned {
            Some(existing) if existing.txid() != commit_txid => {
                return Err(CommitRevealGroupingError::RevealSpansMultipleCommits);
            }
            Some(_) => {}
            None => assigned = Some(commit),
        }
    }

    let Some(commit) = assigned else {
        return Ok(None);
    };

    let slot_spend = classify_reveal_inputs_for_commit(tx, commit.txid(), commit.reveal_slots())?;
    debug_assert!(
        slot_spend.is_some(),
        "assigned commit has a reveal-slot spend"
    );

    Ok(Some(commit.txid()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        DEFAULT_KEY_SEED, TEST_MAGIC, build_commit_reveal_set, build_commit_tx, build_reveal_input,
        build_reveal_tx, build_reveal_tx_with_marker_output, make_change_script, make_txid,
        parse_commit,
    };
    use crate::{CommitRevealParseError, extract_payload_for_commit};

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
        let (parsed_a, parsed_b) = (parse_commit(&set_a.commit), parse_commit(&set_b.commit));

        let owner = assign_reveal_to_commit([&parsed_a, &parsed_b], &set_a.reveals[0])
            .expect("valid reveal")
            .expect("assigned");

        assert_eq!(owner, parsed_a.txid());
    }

    #[test]
    fn test_assign_reveal_to_commit_ignores_unrelated_tx() {
        let commit = build_commit_tx(&TEST_MAGIC, &[1], 1, &[]);
        let parsed = parse_commit(&commit);
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
        let parsed = parse_commit(&commit);

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
            CommitRevealGroupingError::Parse {
                source: CommitRevealParseError::RevealSpendsMarker
            }
        ));
        assert!(matches!(
            non_slot_error,
            CommitRevealGroupingError::Parse {
                source: CommitRevealParseError::UnexpectedReveal { vout: 3 }
            }
        ));
        assert!(matches!(
            multi_slot_error,
            CommitRevealGroupingError::Parse {
                source: CommitRevealParseError::RevealSpendsMultipleSlots
            }
        ));
    }

    #[test]
    fn test_assign_reveal_to_commit_ignores_other_commit_non_slot_spend() {
        let commit_a = build_commit_tx(&TEST_MAGIC, &[1], 1, &[make_change_script()]);
        let commit_b = build_commit_tx(&TEST_MAGIC, &[2], 1, &[]);
        let (parsed_a, parsed_b) = (parse_commit(&commit_a), parse_commit(&commit_b));
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
        let (parsed_a, parsed_b) = (parse_commit(&commit_a), parse_commit(&commit_b));
        let reveal = build_reveal_tx(vec![
            build_reveal_input(parsed_a.txid(), 1, Some(b"a"), DEFAULT_KEY_SEED),
            build_reveal_input(parsed_b.txid(), 1, Some(b"b"), DEFAULT_KEY_SEED),
        ]);

        let error =
            assign_reveal_to_commit([&parsed_a, &parsed_b], &reveal).expect_err("spans commits");

        assert!(matches!(
            error,
            CommitRevealGroupingError::RevealSpansMultipleCommits
        ));
    }

    #[test]
    fn test_assign_reveal_to_commit_ignores_marker_output_on_reveal() {
        let commit = build_commit_tx(&TEST_MAGIC, &[], 1, &[]);
        let parsed = parse_commit(&commit);
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
    fn test_scanner_flow_handles_marker_bearing_reveal() {
        let commit = build_commit_tx(&TEST_MAGIC, &[7, 7], 1, &[]);
        let parsed = parse_commit(&commit);
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
            .expect("reveal is valid for commit")
            .expect("assigned");
        assert_eq!(owner, parsed.txid());

        let payload = extract_payload_for_commit(&TEST_MAGIC, &commit, [&reveal])
            .expect("assigned reveal extracts");

        assert_eq!(payload.marker_tail(), &[7, 7]);
        assert_eq!(payload.into_payload(), b"chunk");
    }
}
