//! Generic binary Merkle tree implementation built on `MerkleHasher`.
//!
//! This complements the MMR by providing standard “binary Merkle tree”
//! functionality: construct from leaves, generate inclusion proofs, and verify
//! those proofs.

use crate::hasher::MerkleHasher;
use crate::proof::MerkleProof;

/// Simple binary Merkle tree backed by in-memory levels.
///
/// Construction duplicates the last node when a level has odd length.
#[derive(Clone, Debug)]
pub struct BinaryMerkleTree<MH: MerkleHasher> {
    /// Level 0 is leaves; last level has a single root.
    levels: Vec<Vec<MH::Hash>>,
}

impl<MH: MerkleHasher> BinaryMerkleTree<MH> {
    /// Builds a tree from leaf hashes. Returns an empty tree if `leaves` is empty.
    pub fn from_leaves(leaves: &[MH::Hash]) -> Self {
        let mut levels = Vec::new();
        if leaves.is_empty() {
            return Self { levels };
        }

        levels.push(leaves.to_vec());
        while levels.last().map_or(0, |l| l.len()) > 1 {
            let prev = levels.last().unwrap();
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            let mut i = 0;
            while i < prev.len() {
                let left = prev[i];
                let right = if i + 1 < prev.len() { prev[i + 1] } else { prev[i] };
                next.push(MH::hash_node(left, right));
                i += 2;
            }
            levels.push(next);
        }

        Self { levels }
    }

    /// Returns the tree root if present.
    pub fn root(&self) -> Option<MH::Hash> {
        if self.levels.is_empty() {
            None
        } else {
            self.levels.last().and_then(|lvl| lvl.first().copied())
        }
    }

    /// Generates an inclusion proof for `index` if it exists.
    pub fn gen_proof(&self, index: usize) -> Option<MerkleProof<MH::Hash>> {
        if self.levels.is_empty() || index >= self.levels[0].len() {
            return None;
        }

        let mut idx = index;
        let mut path = Vec::new();
        for lvl in &self.levels[..self.levels.len().saturating_sub(1)] {
            let is_right = idx % 2 == 1;
            let sib_idx = if is_right { idx - 1 } else { idx + 1 };
            let sibling = if sib_idx < lvl.len() { lvl[sib_idx] } else { lvl[idx] };
            path.push(sibling);
            idx /= 2;
        }

        Some(MerkleProof::from_cohashes(path, index as u64))
    }

    /// Verifies a `proof` for `leaf` against the provided `root`.
    pub fn verify_proof(root: &MH::Hash, proof: &MerkleProof<MH::Hash>, leaf: &MH::Hash) -> bool {
        proof.verify_with_root::<MH>(root, leaf)
    }
}

#[cfg(test)]
mod tests {
    use super::BinaryMerkleTree;
    use crate::hasher::DigestMerkleHasher;
    use crate::proof::MerkleProof;
    use sha2::Sha256;

    type H = [u8; 32];
    type Sha256Hasher = DigestMerkleHasher<Sha256, 32>;

    fn make_leaves(n: usize) -> Vec<H> {
        use sha2::Digest;
        (0..n).map(|i| Sha256::digest(i.to_be_bytes()).into()).collect()
    }

    #[test]
    fn empty_tree() {
        let tree: BinaryMerkleTree<Sha256Hasher> = BinaryMerkleTree::from_leaves(&[]);
        assert!(tree.root().is_none());
        assert!(tree.gen_proof(0).is_none());
    }

    #[test]
    fn build_and_verify() {
        let leaves = make_leaves(5);
        let tree: BinaryMerkleTree<Sha256Hasher> = BinaryMerkleTree::from_leaves(&leaves);
        let root = tree.root().unwrap();

        for (i, leaf) in leaves.iter().enumerate() {
            let proof: MerkleProof<H> = tree.gen_proof(i).unwrap();
            assert!(BinaryMerkleTree::<Sha256Hasher>::verify_proof(&root, &proof, leaf));
        }
    }
}
