//! Fixtures for commit/reveal tests.

use std::sync::OnceLock;

use bitcoin::secp256k1::{All, Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use strata_l1_envelope_fmt::SIGNED_LEAF_PUBKEY_LEN;
use strata_l1_txfmt::MagicBytes;

/// Magic used by fixtures unless a test needs a different one.
pub(crate) const TEST_MAGIC: MagicBytes = MagicBytes::new(*b"TEST");

/// Key seed used by fixtures unless a test needs a different one.
pub(crate) const DEFAULT_KEY_SEED: u8 = 7;

/// Verification context for fixture key derivation.
fn secp() -> &'static Secp256k1<All> {
    static SECP: OnceLock<Secp256k1<All>> = OnceLock::new();
    SECP.get_or_init(Secp256k1::new)
}

/// A deterministic x-only key, distinct per `seed`.
///
/// Every `u8` seed is valid. The scalar keeps a fixed non-zero prefix and
/// varies only its last byte, since a repeated seed would give an all-zero
/// scalar at `seed == 0`, which secp256k1 rejects.
pub(crate) fn make_xonly_pubkey(seed: u8) -> XOnlyPublicKey {
    let mut secret = [1u8; 32];
    secret[31] = seed;
    let secret_key = SecretKey::from_slice(&secret).expect("non-zero scalar below curve order");
    let keypair = Keypair::from_secret_key(secp(), &secret_key);
    XOnlyPublicKey::from_keypair(&keypair).0
}

/// The 32-byte serialization of [`make_xonly_pubkey`].
pub(crate) fn make_xonly_pubkey_bytes(seed: u8) -> [u8; SIGNED_LEAF_PUBKEY_LEN] {
    make_xonly_pubkey(seed).serialize()
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
