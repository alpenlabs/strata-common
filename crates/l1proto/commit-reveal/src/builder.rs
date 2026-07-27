//! Script construction for one commit-reveal set.

use std::num::NonZeroUsize;

use bitcoin::blockdata::script::Builder;
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::PushBytesBuf;
use bitcoin::{Script, ScriptBuf};
use strata_l1_envelope_fmt::SIGNED_LEAF_PUBKEY_LEN;
use strata_l1_envelope_fmt::builder::{
    build_signed_envelope_leaf, split_payload_into_envelope_chunks,
};
use strata_l1_txfmt::MagicBytes;

use crate::MAX_MARKER_TAIL_BYTES;
use crate::errors::CommitRevealBuildError;

/// The scripts for one commit-reveal set.
///
/// Holding this is the writer-side contract: if it carries N reveal leaves, the
/// commit transaction must fund exactly N reveal-slot outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitRevealScripts {
    marker_script: ScriptBuf,
    reveal_leaf_scripts: Vec<ScriptBuf>,
}

impl CommitRevealScripts {
    /// The commit marker script.
    pub fn marker_script(&self) -> &Script {
        &self.marker_script
    }

    /// The reveal leaf scripts, in commit-output order.
    pub fn reveal_leaf_scripts(&self) -> &[ScriptBuf] {
        &self.reveal_leaf_scripts
    }

    /// How many P2TR reveal slots the commit transaction must fund.
    ///
    /// Never zero: an empty chunk list is rejected with
    /// [`CommitRevealBuildError::NoChunks`].
    pub fn reveal_slot_count(&self) -> NonZeroUsize {
        NonZeroUsize::new(self.reveal_leaf_scripts.len())
            .expect("builder rejects an empty chunk list, so there is at least one leaf")
    }

    /// Consumes the set, returning the marker script and the leaf scripts.
    pub fn into_parts(self) -> (ScriptBuf, Vec<ScriptBuf>) {
        (self.marker_script, self.reveal_leaf_scripts)
    }
}

/// Builds the marker and one reveal leaf per supplied chunk.
///
/// `marker_tail` follows the magic in the marker and is not interpreted here.
/// Chunk boundaries are preserved: each supplied chunk becomes exactly one
/// reveal leaf.
///
/// # Errors
///
/// [`CommitRevealBuildError::NoChunks`] if `chunks` is empty,
/// [`CommitRevealBuildError::EmptyChunk`] if any chunk is empty,
/// [`CommitRevealBuildError::MarkerTailTooLarge`] if `marker_tail` exceeds
/// [`MAX_MARKER_TAIL_BYTES`], or [`CommitRevealBuildError::RevealLeaf`] if a leaf
/// cannot be built.
pub fn build_commit_reveal_scripts_from_chunks(
    magic: &MagicBytes,
    marker_tail: impl AsRef<[u8]>,
    reveal_pubkey: &[u8; SIGNED_LEAF_PUBKEY_LEN],
    chunks: &[impl AsRef<[u8]>],
) -> Result<CommitRevealScripts, CommitRevealBuildError> {
    if chunks.is_empty() {
        return Err(CommitRevealBuildError::NoChunks);
    }

    if let Some(index) = chunks.iter().position(|chunk| chunk.as_ref().is_empty()) {
        return Err(CommitRevealBuildError::EmptyChunk { index });
    }

    let marker_script = build_commit_marker_script(magic, marker_tail.as_ref())?;
    let reveal_leaf_scripts = chunks
        .iter()
        .map(|chunk| build_signed_envelope_leaf(reveal_pubkey, chunk.as_ref()))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CommitRevealScripts {
        marker_script,
        reveal_leaf_scripts,
    })
}

/// Builds the marker and reveal leaves for one payload.
///
/// Convenience over [`build_commit_reveal_scripts_from_chunks`] that splits
/// `payload` into envelope-sized chunks first. An empty payload yields no chunks
/// and returns [`CommitRevealBuildError::NoChunks`].
///
/// # Errors
///
/// As [`build_commit_reveal_scripts_from_chunks`].
pub fn build_commit_reveal_scripts(
    magic: &MagicBytes,
    marker_tail: impl AsRef<[u8]>,
    reveal_pubkey: &[u8; SIGNED_LEAF_PUBKEY_LEN],
    payload: impl AsRef<[u8]>,
) -> Result<CommitRevealScripts, CommitRevealBuildError> {
    let chunks = split_payload_into_envelope_chunks(payload.as_ref());
    build_commit_reveal_scripts_from_chunks(magic, marker_tail, reveal_pubkey, &chunks)
}

/// Builds the commit marker script.
///
/// Produces `OP_RETURN <magic || tail>` as a single push; `tail` is opaque.
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

#[cfg(test)]
mod tests {
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF};
    use bitcoin::opcodes::{OP_0, OP_FALSE};
    use bitcoin::script::Instruction;
    use strata_l1_envelope_fmt::builder::MAX_ENVELOPE_PAYLOAD_SIZE;

    use super::*;
    use crate::test_utils::{DEFAULT_KEY_SEED, TEST_MAGIC, make_xonly_pubkey_bytes};

    /// The marker must be a single push so a reader can tell it from another
    /// protocol's OP_RETURN that happens to share the magic prefix.
    #[test]
    fn test_marker_is_op_return_with_one_push_of_magic_and_tail() {
        let scripts = build_commit_reveal_scripts(
            &TEST_MAGIC,
            [1, 2, 3, 4],
            &make_xonly_pubkey_bytes(DEFAULT_KEY_SEED),
            b"payload",
        )
        .expect("builds");

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
        let scripts = build_commit_reveal_scripts(
            &TEST_MAGIC,
            [],
            &make_xonly_pubkey_bytes(DEFAULT_KEY_SEED),
            b"chunk",
        )
        .expect("builds");

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
        let scripts = build_commit_reveal_scripts(
            &TEST_MAGIC,
            [],
            &make_xonly_pubkey_bytes(DEFAULT_KEY_SEED),
            b"chunk",
        )
        .expect("builds");

        let last = scripts.reveal_leaf_scripts()[0].instructions().last();

        assert!(matches!(last, Some(Ok(Instruction::Op(op))) if op == OP_ENDIF));
    }

    #[test]
    fn test_payload_below_one_chunk_yields_one_leaf() {
        let scripts = build_commit_reveal_scripts(
            &TEST_MAGIC,
            [],
            &make_xonly_pubkey_bytes(DEFAULT_KEY_SEED),
            b"short",
        )
        .expect("builds");

        assert_eq!(scripts.reveal_leaf_scripts().len(), 1);
        assert_eq!(scripts.reveal_slot_count().get(), 1);
    }

    /// Reveal count is not written on chain, so it has to follow from the
    /// payload size and the per-reveal ceiling alone.
    #[test]
    fn test_payload_over_one_chunk_yields_one_leaf_per_chunk() {
        let payload = vec![7u8; MAX_ENVELOPE_PAYLOAD_SIZE + 1];

        let scripts = build_commit_reveal_scripts(
            &TEST_MAGIC,
            [],
            &make_xonly_pubkey_bytes(DEFAULT_KEY_SEED),
            &payload,
        )
        .expect("builds");

        assert_eq!(scripts.reveal_slot_count().get(), 2);
    }

    /// The primitive builds one leaf per supplied chunk, without re-splitting.
    #[test]
    fn test_each_chunk_becomes_one_reveal_leaf() {
        let chunks: [&[u8]; 3] = [b"a", b"bb", b"ccc"];

        let scripts = build_commit_reveal_scripts_from_chunks(
            &TEST_MAGIC,
            b"",
            &make_xonly_pubkey_bytes(DEFAULT_KEY_SEED),
            &chunks,
        )
        .expect("builds");

        assert_eq!(scripts.reveal_slot_count().get(), 3);
    }

    /// A writer publishing nothing must not build a set: both entry points
    /// reject an empty input with `NoChunks`.
    #[test]
    fn test_empty_chunk_list_is_rejected() {
        let empty: [&[u8]; 0] = [];

        let error = build_commit_reveal_scripts_from_chunks(
            &TEST_MAGIC,
            b"",
            &make_xonly_pubkey_bytes(DEFAULT_KEY_SEED),
            &empty,
        )
        .expect_err("no chunks");

        assert!(matches!(error, CommitRevealBuildError::NoChunks));
    }

    /// An empty chunk would build a reveal carrying nothing, so it is rejected —
    /// on its own and when mixed with non-empty chunks — and the reported index
    /// points at the offending chunk.
    #[test]
    fn test_empty_chunk_is_rejected() {
        let key = make_xonly_pubkey_bytes(DEFAULT_KEY_SEED);
        let lone: &[&[u8]] = &[b"" as &[u8]];
        let mixed: &[&[u8]] = &[b"payload" as &[u8], b""];

        for (chunks, expected_index) in [(lone, 0usize), (mixed, 1)] {
            let error = build_commit_reveal_scripts_from_chunks(&TEST_MAGIC, b"", &key, chunks)
                .expect_err("empty chunk");

            assert!(
                matches!(error, CommitRevealBuildError::EmptyChunk { index } if index == expected_index),
                "expected EmptyChunk {{ index: {expected_index} }}, got {error:?}"
            );
        }
    }

    #[test]
    fn test_empty_payload_is_rejected() {
        let error = build_commit_reveal_scripts(
            &TEST_MAGIC,
            b"",
            &make_xonly_pubkey_bytes(DEFAULT_KEY_SEED),
            b"",
        )
        .expect_err("empty payload");

        assert!(matches!(error, CommitRevealBuildError::NoChunks));
    }

    #[test]
    fn test_oversized_marker_tail_is_rejected() {
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
}
