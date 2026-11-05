//! Generic binary Merkle tree implementation.
//!
//! This complements the MMR by providing standard “binary Merkle tree”
//! functionality: construct from leaves, generate inclusion proofs, and verify
//! those proofs.
use crate::error::MerkleError;
use crate::hasher::*;
use crate::proof::MerkleProof;

/// Simple binary Merkle tree backed by a flattened node array.
#[derive(Clone, Debug)]
pub struct BinaryMerkleTree<H: MerkleHash> {
    /// All nodes flattened into a single vector of length `2*n - 1`.
    /// Layout: leaves first (`n` items), then each upper level in order,
    /// finishing with the root at the last position.
    nodes: Vec<H>,
}

impl<H: MerkleHash> BinaryMerkleTree<H> {
    /// Builds a tree from leaf hashes.
    ///
    /// `leaves.len()` must be a power of two (including 1). Any other length,
    /// including zero, returns `Err(MerkleError::NotPowerOfTwo)`.
    pub fn from_leaves<MH>(leaves: impl Into<Vec<H>>) -> Result<Self, MerkleError>
    where
        MH: MerkleHasher<Hash = H>,
    {
        let mut nodes = leaves.into();
        if !nodes.len().is_power_of_two() || nodes.is_empty() {
            return Err(MerkleError::NotPowerOfTwo);
        }
        let n = nodes.len();
        let total = 2 * n - 1;
        nodes.resize(total, H::zero());

        // Build upper levels, writing parents to absolute indices.
        let mut level_start = 0; // start index of current level
        let mut level_size = n; // size of current level
        let mut write_pos = n; // absolute index to write next parent

        // Stop when level_size == 1, as that single node is the root
        while level_size > 1 {
            for i in (0..level_size).step_by(2) {
                let left = nodes[level_start + i];
                let right = nodes[level_start + i + 1];
                nodes[write_pos] = MH::hash_node(left, right);
                write_pos += 1;
            }
            // next level starts where we just appended
            level_start += level_size;
            level_size >>= 1;
        }

        Ok(Self { nodes })
    }

    /// Returns the number of leaves in the tree.
    pub fn num_leafs(&self) -> usize {
        self.nodes.len().div_ceil(2)
    }

    /// Returns a slice of the leaf nodes.
    pub fn leafs(&self) -> &[H] {
        let n = self.num_leafs();
        &self.nodes[..n]
    }

    /// Returns the height of the tree (number of levels from leaves to root).
    pub fn height(&self) -> usize {
        self.num_leafs().ilog2() as usize + 1
    }

    /// Returns the tree root.
    ///
    /// In this construction, tree creation rejects non-power-of-two sizes,
    /// including zero, so a root is always present.
    pub fn root(&self) -> &H {
        self.nodes
            .last()
            .expect("BinaryMerkleTree: root must exist")
    }

    /// Generates an inclusion proof for `index` if it exists.
    pub fn gen_proof(&self, index: usize) -> Option<MerkleProof<H>> {
        // Derive leaf count from flattened length: len = 2*n - 1
        let leaves = self.nodes.len().div_ceil(2);
        if index >= leaves {
            return None;
        }

        let mut level_start = 0usize;
        let mut level_size = leaves;
        let mut local_idx = index;
        let mut path = Vec::with_capacity(leaves.ilog2() as usize);

        while level_size > 1 {
            // sibling local index: flip lowest bit
            let sib_local = local_idx ^ 1;
            let sibling = self.nodes[level_start + sib_local];
            path.push(sibling);

            // move up one level
            local_idx >>= 1;
            level_start += level_size;
            level_size >>= 1;
        }

        Some(MerkleProof::from_cohashes(path, index as u64))
    }

    /// Verifies that `proof` proves `leaf` at `proof.index()` in this tree.
    ///
    /// Rejects a proof whose cohash path is not exactly as long as the tree is
    /// deep, since a path of any other length would let a node that isn't a
    /// leaf pass as one. With the path length fixed, the index check in
    /// [`verify_with_root`](crate::verify_with_root) limits the index to this
    /// tree's leaves.
    pub fn verify_proof<MH>(&self, proof: &MerkleProof<H>, leaf: &H) -> bool
    where
        MH: MerkleHasher<Hash = H>,
    {
        proof.verify_with_root_at_depth::<MH>(self.root(), self.depth(), leaf)
    }

    /// Returns the number of edges from a leaf to the root, which is the
    /// cohash count of every proof in this tree.
    fn depth(&self) -> usize {
        self.num_leafs().ilog2() as usize
    }
}

#[cfg(test)]
mod tests {
    use sha2::Sha256;

    use super::BinaryMerkleTree;
    use crate::error::MerkleError;
    use crate::proof::MerkleProof;
    use crate::{Sha256Hasher, StrataMerkle};

    type H = [u8; 32];

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
    fn test_nodes() {
        type H = Sha256Hasher;
        let a = H::hash_leaf(&[1]);
        let b = H::hash_leaf(&[2]);
        let c = H::hash_leaf(&[3]);
        let d = H::hash_leaf(&[4]);
        let ab = H::hash_node(a, b);
        let cd = H::hash_node(c, d);
        let abcd = H::hash_node(ab, cd);

        let tree = BinaryMerkleTree::from_leaves::<H>(vec![a, b, c, d]).unwrap();
        assert_eq!(tree.nodes, vec![a, b, c, d, ab, cd, abcd]);
    }

    #[test]
    fn single_leaf_tree() {
        let leaf = [1u8; 32];
        let tree: BinaryMerkleTree<H> =
            BinaryMerkleTree::from_leaves::<Sha256Hasher>(vec![leaf]).unwrap();
        assert_eq!(tree.root(), &leaf);
        assert_eq!(tree.num_leafs(), 1);
        assert_eq!(tree.leafs(), &[leaf]);
        let proof: MerkleProof<H> = tree.gen_proof(0).expect("proof exists");
        assert!(tree.verify_proof::<Sha256Hasher>(&proof, &leaf));
    }

    #[test]
    fn build_and_verify() {
        let num_leafs = 4;
        let leaves = make_leaves(num_leafs);
        let tree: BinaryMerkleTree<H> =
            BinaryMerkleTree::from_leaves::<Sha256Hasher>(leaves.clone()).unwrap();
        assert_eq!(tree.leafs().to_vec(), leaves.clone());
        assert_eq!(tree.num_leafs(), num_leafs);

        for (i, leaf) in leaves.iter().enumerate() {
            let proof: MerkleProof<H> = tree.gen_proof(i).unwrap();
            assert!(tree.verify_proof::<Sha256Hasher>(&proof, leaf));
        }
    }

    #[test]
    fn verify_proof_rejects_other_indices() {
        for num_leafs in [1, 2, 4, 8] {
            let leaves = make_leaves(num_leafs);
            let tree = BinaryMerkleTree::from_leaves::<Sha256Hasher>(leaves.clone()).unwrap();
            for (leaf_index, leaf) in leaves.iter().enumerate() {
                let cohashes = tree.gen_proof(leaf_index).unwrap().cohashes().to_vec();
                // Hashing reads only the low `depth` bits of the index, so an
                // index past the last leaf whose low bits equal `leaf_index`
                // would pass on hashing alone.
                let claimed_indices = (0..num_leafs as u64 * 4)
                    .chain([512, u64::MAX - 1, u64::MAX])
                    .collect::<Vec<_>>();
                for claimed in claimed_indices {
                    let proof = MerkleProof::from_cohashes(cohashes.clone(), claimed);
                    assert_eq!(
                        tree.verify_proof::<Sha256Hasher>(&proof, leaf),
                        claimed == leaf_index as u64,
                        "num_leafs={num_leafs} leaf_index={leaf_index} claimed={claimed}"
                    );
                }
            }
        }
    }

    #[test]
    fn verify_proof_rejects_wrong_path_length() {
        let leaves = make_leaves(4);
        let tree = BinaryMerkleTree::from_leaves::<Sha256Hasher>(leaves.clone()).unwrap();
        let ab = Sha256Hasher::hash_node(leaves[0], leaves[1]);
        let cd = Sha256Hasher::hash_node(leaves[2], leaves[3]);

        // The root itself with an empty path.
        let empty = MerkleProof::from_cohashes(Vec::new(), 0);
        assert!(!tree.verify_proof::<Sha256Hasher>(&empty, tree.root()));

        // An inner node with a one-step path.
        let short = MerkleProof::from_cohashes(vec![cd], 0);
        assert_eq!(short.compute_root::<Sha256Hasher>(&ab), *tree.root());
        assert!(!tree.verify_proof::<Sha256Hasher>(&short, &ab));

        // A valid path with an extra cohash.
        let mut cohashes = tree.gen_proof(0).unwrap().cohashes().to_vec();
        cohashes.push(leaves[0]);
        let long = MerkleProof::from_cohashes(cohashes, 0);
        assert!(!tree.verify_proof::<Sha256Hasher>(&long, &leaves[0]));
    }

    #[test]
    fn not_power_of_two_rejected() {
        let leaves = make_leaves(5);
        let err = BinaryMerkleTree::from_leaves::<Sha256Hasher>(leaves).unwrap_err();
        assert_eq!(err, MerkleError::NotPowerOfTwo);
    }
}
