//! Hashing primitives for MMR: hash types and hashing strategies.
use std::cell::LazyCell;

use digest::Digest;
use sha2::Sha256;

type Tag = [u8; 64];

const NODE_TAG_PREFIX: LazyCell<Tag> = LazyCell::new(|| make_tag(b"node"));
const LEAF_TAG_PREFIX: LazyCell<Tag> = LazyCell::new(|| make_tag(b"leaf"));

/// Makes a 64 byte tag from a slice, which ideally contains a ASCII string.
fn make_tag(s: &[u8]) -> Tag {
    let raw = Sha256::digest(s);
    let mut buf = [0; 64];
    buf[..32].copy_from_slice(&raw);
    buf[32..].copy_from_slice(&raw);
    buf
}

/// Hash wrapper trait used by the MMR.
pub trait MerkleHash: Copy + Clone + 'static {
    /// Length of the hash in bytes.
    const HASH_LEN: usize;

    /// Returns a zero hash.
    fn zero() -> Self;

    /// Checks if two hashes are equal, attempting to do it in constant time.
    fn eq_ct(a: &Self, b: &Self) -> bool;

    /// Returns if a hash is the zero hash.
    fn is_zero(h: &Self) -> bool;
}

impl<const LEN: usize> MerkleHash for [u8; LEN] {
    const HASH_LEN: usize = LEN;

    fn zero() -> Self {
        [0; LEN]
    }

    fn eq_ct(a: &Self, b: &Self) -> bool {
        // Attempt to constant-time comparison.  This is *really hard* to do in
        // Rust, because LLVM likes to obliterate unnecessary instructions.
        //
        // I could use some of the more advanced libraries for this, but this
        // isn't actually relevant for security at all, it's just good practice,
        // so we can avoid pulling in additional dependencies.  This is
        // primarily used when verifying a root computed from a proof against a
        // trusted one, and presumably the party that might be probing us
        // already knows what the known-good root is if they're giving us a
        // proof against it.
        let mut acc: u32 = 0;
        for i in 0..LEN {
            acc += (a[i] ^ b[i]) as u32;
        }

        acc == 0
    }

    fn is_zero(h: &Self) -> bool {
        Self::eq_ct(h, &Self::zero())
    }
}

/// Generic merkle hashing trait.
pub trait MerkleHasher {
    /// Hash value.
    type Hash: MerkleHash;

    /// Hashes an arbitrary message as leaf data to compute a leaf hash.
    fn hash_leaf(buf: &[u8]) -> Self::Hash;

    /// Hashes a node's left and right children to compute the node's hash.
    fn hash_node(left: Self::Hash, right: Self::Hash) -> Self::Hash;

    /// Convenience function that returns a zero hash from the associated hash
    /// type.
    fn zero_hash() -> Self::Hash {
        <Self::Hash as MerkleHash>::zero()
    }
}

/// Merkle hash for arbitrary digest impl.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DigestMerkleHasher<D: Digest, const N: usize>(std::marker::PhantomData<D>);

/// Generic impl over [`Digest`] impls, where hash is `[u8; 32]`.
impl<D: Digest, const N: usize> MerkleHasher for DigestMerkleHasher<D, N> {
    type Hash = [u8; N];

    fn hash_leaf(buf: &[u8]) -> Self::Hash {
        // This is technically vulnerable to length-extension, but in MMRs that
        // should not matter, and we use the prefix to prevent type confusion.
        let mut context = D::new();
        context.update(*LEAF_TAG_PREFIX);
        context.update(buf);

        let result = context.finalize();
        result
            .as_ref()
            .try_into()
            .expect("digest output length mismatch")
    }

    fn hash_node(left: Self::Hash, right: Self::Hash) -> Self::Hash {
        let mut context = D::new();
        context.update(*NODE_TAG_PREFIX);
        context.update(left);
        context.update(right);

        let result = context.finalize();
        result
            .as_ref()
            .try_into()
            .expect("digest output length mismatch")
    }
}

/// Merkle hasher for arbitrary digest impl that does not prefix
/// node/leaf inputs. Useful for interoperating with trees that
/// define their hash as `H(leaf)` and `H(left || right)` directly.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DigestMerkleHasherNoPrefix<D: Digest, const N: usize>(std::marker::PhantomData<D>);

impl<D: Digest, const N: usize> MerkleHasher for DigestMerkleHasherNoPrefix<D, N> {
    type Hash = [u8; N];

    fn hash_leaf(buf: &[u8]) -> Self::Hash {
        let mut context = D::new();
        context.update(buf);

        let result = context.finalize();
        result
            .as_ref()
            .try_into()
            .expect("digest output length mismatch")
    }

    fn hash_node(left: Self::Hash, right: Self::Hash) -> Self::Hash {
        let mut context = D::new();
        context.update(left);
        context.update(right);

        let result = context.finalize();
        result
            .as_ref()
            .try_into()
            .expect("digest output length mismatch")
    }
}
