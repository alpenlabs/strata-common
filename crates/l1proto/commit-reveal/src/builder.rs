//! Script construction for one commit/reveal set.

use std::num::NonZeroUsize;

use bitcoin::blockdata::script::Builder;
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::PushBytesBuf;
use bitcoin::{Script, ScriptBuf};
use strata_l1_envelope_fmt::SIGNED_LEAF_PUBKEY_LEN;
use strata_l1_envelope_fmt::builder::{EnvelopeScriptBuilder, MAX_ENVELOPE_PAYLOAD_SIZE};
use strata_l1_txfmt::MagicBytes;

use crate::MAX_MARKER_TAIL_BYTES;
use crate::errors::CommitRevealBuildError;

/// The scripts for one commit/reveal set.
///
/// Holding this is the writer-side contract: if it carries N reveal leaves, the
/// commit transaction must fund exactly N reveal-slot outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitRevealScripts {
    marker_script: ScriptBuf,
    reveal_leaf_scripts: Vec<ScriptBuf>,
}

impl CommitRevealScripts {
    /// The commit transaction's output-0 marker script.
    pub fn marker_script(&self) -> &Script {
        &self.marker_script
    }

    /// The reveal leaf scripts, in commit-output order.
    pub fn reveal_leaf_scripts(&self) -> &[ScriptBuf] {
        &self.reveal_leaf_scripts
    }

    /// How many P2TR reveal slots the commit transaction must fund.
    ///
    /// Never zero: an empty payload still yields one chunk, so a set always has
    /// at least one reveal.
    pub fn reveal_slot_count(&self) -> NonZeroUsize {
        NonZeroUsize::new(self.reveal_leaf_scripts.len())
            .expect("payload splitting always yields at least one chunk")
    }

    /// Consumes the set, returning the marker script and the leaf scripts.
    pub fn into_parts(self) -> (ScriptBuf, Vec<ScriptBuf>) {
        (self.marker_script, self.reveal_leaf_scripts)
    }
}

/// Builds the marker and reveal-leaf scripts for one payload.
///
/// The payload is split into one chunk per reveal, each within
/// [`MAX_ENVELOPE_PAYLOAD_SIZE`]. Split points are builder output, not caller
/// data: the parser returns chunks in commit-vout order and the payload is
/// their concatenation, so boundaries carry no meaning. Whether a reader joins
/// them is its own choice — a guest decoding across the chunks avoids the
/// copy.
///
/// `marker_tail` is copied into the marker after the magic and is never
/// interpreted here. `reveal_pubkey` is fixed at
/// [`SIGNED_LEAF_PUBKEY_LEN`] bytes because a tapscript pubkey of any other
/// length makes `OP_CHECKSIG` succeed without verifying a signature.
///
/// # Errors
///
/// Returns [`CommitRevealBuildError::MarkerTailTooLarge`] if `marker_tail`
/// exceeds [`MAX_MARKER_TAIL_BYTES`], or
/// [`CommitRevealBuildError::RevealLeaf`] if a leaf script cannot be built.
pub fn build_commit_reveal_scripts(
    magic: &MagicBytes,
    marker_tail: impl AsRef<[u8]>,
    reveal_pubkey: &[u8; SIGNED_LEAF_PUBKEY_LEN],
    payload: impl AsRef<[u8]>,
) -> Result<CommitRevealScripts, CommitRevealBuildError> {
    let marker_script = build_commit_marker_script(magic, marker_tail.as_ref())?;
    let reveal_leaf_scripts = split_payload(payload.as_ref())
        .into_iter()
        .map(|chunk| build_reveal_leaf_script(reveal_pubkey, chunk))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CommitRevealScripts {
        marker_script,
        reveal_leaf_scripts,
    })
}

/// Builds the commit transaction's output-0 marker script.
///
/// Produces `OP_RETURN <magic || tail>` as a single push. `tail` is copied
/// verbatim; this crate does not interpret it.
///
/// # Errors
///
/// Returns [`CommitRevealBuildError::MarkerTailTooLarge`] if `tail` exceeds
/// [`MAX_MARKER_TAIL_BYTES`].
pub(crate) fn build_commit_marker_script(
    magic: &MagicBytes,
    tail: &[u8],
) -> Result<ScriptBuf, CommitRevealBuildError> {
    if tail.len() > MAX_MARKER_TAIL_BYTES {
        return Err(CommitRevealBuildError::MarkerTailTooLarge {
            tail_len: tail.len(),
            max: MAX_MARKER_TAIL_BYTES,
        });
    }

    let mut payload = Vec::with_capacity(magic.as_bytes().len() + tail.len());
    payload.extend_from_slice(magic.as_bytes());
    payload.extend_from_slice(tail);

    let push = PushBytesBuf::try_from(payload)
        .expect("marker within the OP_RETURN push limit is a valid push");

    Ok(Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(push)
        .into_script())
}

/// Builds the tapscript leaf for one reveal.
///
/// Produces `<pubkey> OP_CHECKSIG OP_FALSE OP_IF <chunk pushes> OP_ENDIF`. The
/// envelope builder's recommended minimum payload size is not applied: chunk
/// sizes follow from payload splitting, not from a caller's choice.
///
/// # Errors
///
/// Returns [`CommitRevealBuildError::RevealLeaf`] if the script cannot be
/// built.
pub(crate) fn build_reveal_leaf_script(
    pubkey: &[u8; SIGNED_LEAF_PUBKEY_LEN],
    chunk: &[u8],
) -> Result<ScriptBuf, CommitRevealBuildError> {
    let script = EnvelopeScriptBuilder::with_pubkey(pubkey)?
        .add_envelope(chunk)?
        .build_without_min_check()?;

    Ok(script)
}

/// Splits a payload into chunks, one per reveal.
///
/// Chunks are [`MAX_ENVELOPE_PAYLOAD_SIZE`] bytes except the last, and
/// concatenating them in order recovers the payload. An empty payload gives one
/// empty chunk, so a set is still buildable; a writer publishing nothing should
/// not build a set at all.
pub(crate) fn split_payload(payload: &[u8]) -> Vec<&[u8]> {
    if payload.is_empty() {
        return vec![&[]];
    }
    payload.chunks(MAX_ENVELOPE_PAYLOAD_SIZE).collect()
}

#[cfg(test)]
mod tests {
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF};
    use bitcoin::opcodes::{OP_0, OP_FALSE};
    use bitcoin::script::Instruction;

    use super::*;
    use crate::test_utils::{DEFAULT_KEY_SEED, TEST_MAGIC, make_xonly_pubkey_bytes};

    fn build(tail: &[u8], payload: &[u8]) -> CommitRevealScripts {
        build_commit_reveal_scripts(
            &TEST_MAGIC,
            tail,
            &make_xonly_pubkey_bytes(DEFAULT_KEY_SEED),
            payload,
        )
        .expect("builds")
    }

    /// The marker must be a single push so a reader can tell it from another
    /// protocol's OP_RETURN that happens to share the magic prefix.
    #[test]
    fn test_marker_is_op_return_with_one_push_of_magic_and_tail() {
        let scripts = build(&[1, 2, 3, 4], b"payload");

        let mut instructions = scripts.marker_script().instructions();
        assert!(matches!(
            instructions.next(),
            Some(Ok(Instruction::Op(op))) if op == OP_RETURN
        ));
        let Some(Ok(Instruction::PushBytes(push))) = instructions.next() else {
            panic!("marker must carry a push");
        };
        assert_eq!(push.as_bytes(), b"TEST\x01\x02\x03\x04");
        assert!(instructions.next().is_none(), "marker must be one push");
    }

    #[test]
    fn test_marker_accepts_tail_up_to_limit() {
        let tail = vec![0u8; MAX_MARKER_TAIL_BYTES];

        assert!(build_commit_marker_script(&TEST_MAGIC, &tail).is_ok());
    }

    #[test]
    fn test_marker_rejects_tail_over_limit() {
        let tail = vec![0u8; MAX_MARKER_TAIL_BYTES + 1];

        let error = build_commit_marker_script(&TEST_MAGIC, &tail).expect_err("over limit");

        assert!(matches!(
            error,
            CommitRevealBuildError::MarkerTailTooLarge { max, .. }
                if max == MAX_MARKER_TAIL_BYTES
        ));
    }

    /// The leaf shape is what makes a confirmed spend evidence that the pubkey
    /// holder signed, so the pubkey must sit first, guarded by OP_CHECKSIG.
    #[test]
    fn test_reveal_leaf_opens_with_pubkey_and_checksig() {
        let pubkey = make_xonly_pubkey_bytes(DEFAULT_KEY_SEED);
        let scripts = build(&[], b"chunk");

        let mut instructions = scripts.reveal_leaf_scripts()[0].instructions();
        let Some(Ok(Instruction::PushBytes(push))) = instructions.next() else {
            panic!("leaf must open with a pubkey push");
        };
        assert_eq!(push.as_bytes(), pubkey.as_slice());
        assert!(matches!(
            instructions.next(),
            Some(Ok(Instruction::Op(op))) if op == OP_CHECKSIG
        ));
        // OP_FALSE pushes an empty byte array, so a decoded script presents it
        // as an empty push rather than as the opcode.
        let opener = instructions.next();
        assert!(
            matches!(opener, Some(Ok(Instruction::Op(op))) if op == OP_FALSE || op == OP_0)
                || matches!(opener, Some(Ok(Instruction::PushBytes(b))) if b.as_bytes().is_empty()),
            "envelope must open with OP_FALSE in one of its equivalent forms"
        );
        assert!(matches!(
            instructions.next(),
            Some(Ok(Instruction::Op(op))) if op == OP_IF
        ));
    }

    #[test]
    fn test_reveal_leaf_ends_with_endif() {
        let scripts = build(&[], b"chunk");

        let last = scripts.reveal_leaf_scripts()[0].instructions().last();

        assert!(matches!(last, Some(Ok(Instruction::Op(op))) if op == OP_ENDIF));
    }

    #[test]
    fn test_payload_below_one_chunk_yields_one_leaf() {
        let scripts = build(&[], b"short");

        assert_eq!(scripts.reveal_leaf_scripts().len(), 1);
        assert_eq!(scripts.reveal_slot_count().get(), 1);
    }

    /// Reveal count is not written on chain, so it has to follow from the
    /// payload size and the per-reveal ceiling alone.
    #[test]
    fn test_payload_over_one_chunk_yields_one_leaf_per_chunk() {
        let payload = vec![7u8; MAX_ENVELOPE_PAYLOAD_SIZE + 1];

        let scripts = build(&[], &payload);

        assert_eq!(scripts.reveal_slot_count().get(), 2);
    }

    /// An empty payload still funds one slot: a commit with no reveal slots
    /// cannot be read back as a set.
    #[test]
    fn test_empty_payload_yields_one_leaf() {
        let scripts = build(&[], b"");

        assert_eq!(scripts.reveal_slot_count().get(), 1);
    }

    #[test]
    fn test_build_rejects_oversized_marker() {
        let tail = vec![0u8; MAX_MARKER_TAIL_BYTES + 1];

        let error = build_commit_reveal_scripts(
            &TEST_MAGIC,
            tail,
            &make_xonly_pubkey_bytes(DEFAULT_KEY_SEED),
            b"payload",
        )
        .expect_err("marker over limit");

        assert!(matches!(
            error,
            CommitRevealBuildError::MarkerTailTooLarge { .. }
        ));
    }

    /// `concat(chunks) == payload` must hold: nothing records the split points,
    /// so the chunks the parser returns are only meaningful in order.
    #[test]
    fn test_split_payload_round_trips_through_concatenation() {
        let large: Vec<u8> = (0..MAX_ENVELOPE_PAYLOAD_SIZE + 1234)
            .map(|i| (i % 251) as u8)
            .collect();

        for payload in [vec![], vec![1u8], large] {
            assert_eq!(split_payload(&payload).concat(), payload);
        }
    }

    /// The off-by-one that would break concat-and-re-split identity: a payload
    /// of exactly the ceiling must stay one chunk, not spill into an empty
    /// second one.
    #[test]
    fn test_split_payload_at_exactly_envelope_maximum_yields_one_chunk() {
        let payload = vec![0u8; MAX_ENVELOPE_PAYLOAD_SIZE];

        let chunks = split_payload(&payload);

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), MAX_ENVELOPE_PAYLOAD_SIZE);
    }

    #[test]
    fn test_split_payload_chunks_at_envelope_maximum() {
        let payload = vec![0u8; MAX_ENVELOPE_PAYLOAD_SIZE + 1];

        let chunks = split_payload(&payload);

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), MAX_ENVELOPE_PAYLOAD_SIZE);
        assert_eq!(chunks[1].len(), 1);
    }

    /// Re-splitting a concatenated payload must reproduce the same boundaries,
    /// or reveal leaves stop matching an already-signed commit. Alpen's schema
    /// migration relies on this.
    #[test]
    fn test_split_payload_is_stable_across_concat_and_resplit() {
        for len in [
            0,
            1,
            MAX_ENVELOPE_PAYLOAD_SIZE - 1,
            MAX_ENVELOPE_PAYLOAD_SIZE,
            MAX_ENVELOPE_PAYLOAD_SIZE + 1,
            MAX_ENVELOPE_PAYLOAD_SIZE * 2,
        ] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let chunks = split_payload(&payload);

            assert_eq!(split_payload(&chunks.concat()), chunks, "len {len}");
        }
    }
}
