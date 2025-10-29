//! Generic binary Merkle tree implementation.
//!
//! This complements the MMR by providing standard “binary Merkle tree”
//! functionality: construct from leaves, generate inclusion proofs, and verify
//! those proofs.
use crate::error::MerkleError;
use crate::hasher::{MerkleHash, MerkleHasher};
use crate::proof::MerkleProof;

/// Simple binary Merkle tree backed by in-memory levels.
#[derive(Clone, Debug)]
pub struct BinaryMerkleTree<H: MerkleHash> {
    /// Level 0 is leaves; last level has a single root.
    levels: Vec<Vec<H>>,
}

impl<H: MerkleHash> BinaryMerkleTree<H> {
    /// Builds a tree from leaf hashes.
    ///
    /// `leaves.len()` must be a power of two (including 1). Any other length,
    /// including zero, returns `Err(MerkleError::NotPowerOfTwo)`.
    pub fn from_leaves<MH>(leaves: &[H]) -> Result<Self, MerkleError>
    where
        MH: MerkleHasher<Hash = H>,
    {
        let mut levels = Vec::new();
        if !leaves.len().is_power_of_two() {
            return Err(MerkleError::NotPowerOfTwo);
        }

        levels.push(leaves.to_vec());
        while levels.last().map_or(0, |l| l.len()) > 1 {
            let prev = levels.last().unwrap();
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            let mut i = 0;
            while i < prev.len() {
                let left = prev[i];
                let right = prev[i + 1];
                next.push(MH::hash_node(left, right));
                i += 2;
            }
            levels.push(next);
        }

        Ok(Self { levels })
    }

    /// Returns the tree root.
    ///
    /// In this construction, tree creation rejects non-power-of-two sizes,
    /// including zero, so a root is always present.
    pub fn root(&self) -> H {
        // SAFETY: constructor guarantees at least one level with at least one node.
        self.levels
            .last()
            .and_then(|lvl| lvl.first().copied())
            .expect("BinaryMerkleTree: root must exist")
    }

    /// Generates an inclusion proof for `index` if it exists.
    pub fn gen_proof(&self, index: usize) -> Option<MerkleProof<H>> {
        if self.levels.is_empty() || index >= self.levels[0].len() {
            return None;
        }

        let mut idx = index;
        let mut path = Vec::new();
        for lvl in &self.levels[..self.levels.len().saturating_sub(1)] {
            let is_right = idx % 2 == 1;
            let sib_idx = if is_right { idx - 1 } else { idx + 1 };
            let sibling = lvl[sib_idx];
            path.push(sibling);
            idx /= 2;
        }

        Some(MerkleProof::from_cohashes(path, index as u64))
    }

    /// Verifies a `proof` for `leaf` against the provided `root`.
    pub fn verify_proof<MH>(&self, proof: &MerkleProof<H>, leaf: &H) -> bool
    where
        MH: MerkleHasher<Hash = H>,
    {
        proof.verify_with_root::<MH>(&self.root(), leaf)
    }
}

#[cfg(test)]
mod tests {
    use super::BinaryMerkleTree;
    use crate::error::MerkleError;
    use crate::hasher::DigestMerkleHasher;
    use crate::proof::MerkleProof;
    use sha2::Sha256;

    type H = [u8; 32];
    type Sha256Hasher = DigestMerkleHasher<Sha256, 32>;

    fn make_leaves(n: usize) -> Vec<H> {
        use sha2::Digest;
        (0..n)
            .map(|i| Sha256::digest(i.to_be_bytes()).into())
            .collect()
    }

    #[test]
    fn empty_tree_rejected() {
        let err = BinaryMerkleTree::from_leaves::<Sha256Hasher>(&[]).unwrap_err();
        assert_eq!(err, MerkleError::NotPowerOfTwo);
    }

    #[test]
    fn single_leaf_tree() {
        let leaf = [1u8; 32];
        let tree: BinaryMerkleTree<H> =
            BinaryMerkleTree::from_leaves::<Sha256Hasher>(&[leaf]).unwrap();
        assert_eq!(tree.root(), leaf);
        let proof: MerkleProof<H> = tree.gen_proof(0).expect("proof exists");
        assert!(tree.verify_proof::<Sha256Hasher>(&proof, &leaf));
    }

    #[test]
    fn build_and_verify() {
        let leaves = make_leaves(4);
        let tree: BinaryMerkleTree<H> =
            BinaryMerkleTree::from_leaves::<Sha256Hasher>(&leaves).unwrap();

        for (i, leaf) in leaves.iter().enumerate() {
            let proof: MerkleProof<H> = tree.gen_proof(i).unwrap();
            assert!(tree.verify_proof::<Sha256Hasher>(&proof, &leaf));
        }
    }

    #[test]
    fn not_power_of_two_rejected() {
        let leaves = make_leaves(5);
        let err = BinaryMerkleTree::from_leaves::<Sha256Hasher>(&leaves).unwrap_err();
        assert_eq!(err, MerkleError::NotPowerOfTwo);
    }
}
