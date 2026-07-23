//! Fixtures for commit/reveal tests.
//!
//! These reproduce transaction *shape*, which is all the parser reads. Witness
//! signatures are placeholders and the P2TR slots do not commit to the leaves
//! revealed against them, so nothing built here is spend-valid.

use std::sync::OnceLock;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Keypair, Parity, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapNodeHash, TaprootMerkleBranch};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use strata_l1_envelope_fmt::SIGNED_LEAF_PUBKEY_LEN;
use strata_l1_txfmt::MagicBytes;

use crate::builder::{build_commit_marker_script, build_reveal_leaf_script};

/// Magic used by fixtures unless a test needs a different one.
pub const TEST_MAGIC: MagicBytes = MagicBytes::new(*b"TEST");

/// Key seed used by fixtures unless a test needs a different one.
pub const DEFAULT_KEY_SEED: u8 = 7;

/// Verification context for fixture key derivation.
fn secp() -> &'static Secp256k1<All> {
    static SECP: OnceLock<Secp256k1<All>> = OnceLock::new();
    SECP.get_or_init(Secp256k1::new)
}

/// A deterministic txid, distinct per `seed`.
pub fn make_txid(seed: u8) -> Txid {
    Txid::from_byte_array([seed; 32])
}

/// A deterministic x-only key, distinct per `seed`.
///
/// Every `u8` seed is valid. The scalar keeps a fixed non-zero prefix and
/// varies only its last byte, since a repeated seed would give an all-zero
/// scalar at `seed == 0`, which secp256k1 rejects.
pub fn make_xonly_pubkey(seed: u8) -> XOnlyPublicKey {
    let mut secret = [1u8; 32];
    secret[31] = seed;
    let secret_key = SecretKey::from_slice(&secret).expect("non-zero scalar below curve order");
    let keypair = Keypair::from_secret_key(secp(), &secret_key);
    XOnlyPublicKey::from_keypair(&keypair).0
}

/// The 32-byte serialization of [`make_xonly_pubkey`].
pub fn make_xonly_pubkey_bytes(seed: u8) -> [u8; SIGNED_LEAF_PUBKEY_LEN] {
    make_xonly_pubkey(seed).serialize()
}

fn build_control_block(internal_key: XOnlyPublicKey, leaf_version: LeafVersion) -> ControlBlock {
    let branch: [TapNodeHash; 0] = [];
    ControlBlock {
        leaf_version,
        output_key_parity: Parity::Even,
        internal_key,
        merkle_branch: TaprootMerkleBranch::from(branch),
    }
}

/// A P2TR script, for extending or breaking a reveal-slot run.
pub fn make_p2tr_script() -> ScriptBuf {
    ScriptBuf::new_p2tr(secp(), make_xonly_pubkey(9), None)
}

/// A non-P2TR script, standing in for wallet change.
pub fn make_change_script() -> ScriptBuf {
    ScriptBuf::new_op_return([0u8; 4])
}

/// Builds a commit tx: marker at output 0, `reveal_slots` P2TR outputs, then
/// `trailing_outputs` standing in for change.
///
/// # Panics
///
/// If `tail` exceeds [`MAX_MARKER_TAIL_BYTES`](crate::MAX_MARKER_TAIL_BYTES).
pub fn build_commit_tx(
    magic: &MagicBytes,
    tail: &[u8],
    reveal_slots: usize,
    trailing_outputs: &[ScriptBuf],
) -> Transaction {
    let marker = build_commit_marker_script(magic, tail).expect("marker within limit");
    let mut tx = assemble_commit_tx(marker, reveal_slots);
    for script in trailing_outputs {
        tx.output.push(TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: script.clone(),
        });
    }
    tx
}

/// Assembles a commit tx from a prebuilt marker script and a slot count.
///
/// The counterpart to [`CommitRevealScripts`](crate::builder::CommitRevealScripts):
/// a writer funds exactly `reveal_slots` P2TR outputs after the marker.
pub fn assemble_commit_tx(marker: ScriptBuf, reveal_slots: usize) -> Transaction {
    let reveal_key = make_xonly_pubkey(3);
    let mut output = vec![TxOut {
        value: Amount::ZERO,
        script_pubkey: marker,
    }];
    for _ in 0..reveal_slots {
        output.push(TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new_p2tr(secp(), reveal_key, None),
        });
    }

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output,
    }
}

/// Builds a transaction carrying `script` at output 0.
///
/// For exercising marker classification against output-0 scripts the commit
/// builder would never produce.
pub fn build_marker_candidate_tx(script: ScriptBuf) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: script,
        }],
    }
}

/// Builds a reveal input spending `commit_txid:vout`, whose leaf carries
/// `key_seed`'s pubkey.
///
/// With `chunk`, the witness carries a well-formed signed envelope leaf and a
/// placeholder signature; with `None` the witness is empty.
///
/// One seed keys both the leaf and the control block, since SPS-53 uses the
/// producer key as the taproot internal key as well.
///
/// The witness signature is a placeholder, not a real signature over the
/// spend. These fixtures exercise leaf *shape*, which is what the parser
/// checks; they prove nothing about signature validity.
///
/// # Panics
///
/// If `chunk` exceeds the per-reveal envelope maximum.
pub fn build_reveal_input(
    commit_txid: Txid,
    vout: u32,
    chunk: Option<&[u8]>,
    key_seed: u8,
) -> TxIn {
    match chunk {
        Some(chunk) => {
            let leaf = build_reveal_leaf_script(&make_xonly_pubkey_bytes(key_seed), chunk)
                .expect("leaf builds");
            build_reveal_input_from_leaf(commit_txid, vout, leaf, key_seed)
        }
        None => build_input(commit_txid, vout, Witness::new()),
    }
}

/// Builds a reveal input whose witness carries `leaf`, for driving the parser
/// with scripts a builder produced.
///
/// `internal_key_seed` keys the control block only. The leaf's pubkey is
/// whatever `leaf` already carries, unlike [`build_reveal_input`] where the
/// seed chooses it.
pub fn build_reveal_input_from_leaf(
    commit_txid: Txid,
    vout: u32,
    leaf: ScriptBuf,
    internal_key_seed: u8,
) -> TxIn {
    let mut witness = Witness::new();
    witness.push([1u8; 64]);
    witness.push(leaf);
    witness.push(
        build_control_block(make_xonly_pubkey(internal_key_seed), LeafVersion::TapScript)
            .serialize(),
    );

    build_input(commit_txid, vout, witness)
}

/// Builds a reveal input whose leaf carries an unsupported leaf version.
///
/// # Panics
///
/// If `chunk` exceeds the per-reveal envelope maximum.
pub fn build_unsupported_leaf_reveal_input(
    commit_txid: Txid,
    vout: u32,
    chunk: &[u8],
    key_seed: u8,
    leaf_version: LeafVersion,
) -> TxIn {
    let mut witness = Witness::new();
    witness.push([1u8; 64]);
    witness.push(
        build_reveal_leaf_script(&make_xonly_pubkey_bytes(key_seed), chunk).expect("leaf builds"),
    );
    witness.push(build_control_block(make_xonly_pubkey(key_seed), leaf_version).serialize());

    build_input(commit_txid, vout, witness)
}

fn build_input(commit_txid: Txid, vout: u32, witness: Witness) -> TxIn {
    TxIn {
        previous_output: OutPoint {
            txid: commit_txid,
            vout,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness,
    }
}

/// Builds a reveal tx that carries no marker of its own.
pub fn build_reveal_tx(inputs: Vec<TxIn>) -> Transaction {
    build_tx(
        inputs,
        vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new(),
        }],
    )
}

/// Builds a reveal tx carrying a marker output at vout 0.
///
/// Production writers chain envelopes this way, and the range-scanner entry
/// point must not misread such a transaction as a second commit.
pub fn build_reveal_tx_with_marker_output(inputs: Vec<TxIn>, marker: TxOut) -> Transaction {
    build_tx(inputs, vec![marker])
}

fn build_tx(input: Vec<TxIn>, output: Vec<TxOut>) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input,
        output,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// Seed 0 would panic on a repeated-byte scalar: all zeros is not a valid
    /// secp256k1 secret key.
    #[test]
    fn test_make_xonly_pubkey_accepts_every_seed() {
        let keys: BTreeSet<_> = (u8::MIN..=u8::MAX).map(make_xonly_pubkey_bytes).collect();

        assert_eq!(keys.len(), 256, "each seed must give a distinct key");
    }
}
