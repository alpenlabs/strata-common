//! MMR (Merkle Mountain Range) algorithms implemented as an extension trait over
//! [`MmrState`].

use crate::error::MerkleError;
use crate::hasher::MerkleHasher;
use crate::proof::{MerkleProof, ProofData, RawMerkleProof};
use crate::traits::MmrState;

/// Extension trait that provides MMR algorithms over any [`MmrState`] implementation.
///
/// This trait is generic over a [`MerkleHasher`] which defines how leaves and nodes
/// are hashed. The blanket implementation provides the actual MMR algorithms that
/// work with any state backend implementing [`MmrState`].
pub trait Mmr<MH: MerkleHasher>: MmrState<MH::Hash> {
    /// Returns if the MMR is empty.
    fn is_empty(&self) -> bool {
        self.num_entries() == 0
    }

    /// Returns the maximum capacity of the MMR based on `max_num_peaks`.
    fn max_capacity(&self) -> u64 {
        let peaks = self.max_num_peaks();
        if peaks == 0 {
            0
        } else if peaks >= 64 {
            u64::MAX
        } else {
            (1u64 << peaks) - 1
        }
    }

    /// Checks if we can insert a new element. Returns error if at capacity.
    fn check_capacity(&self) -> Result<(), MerkleError> {
        if self.num_entries() == self.max_capacity() {
            return Err(MerkleError::MaxCapacity);
        }
        Ok(())
    }

    /// Adds a new leaf to the MMR.
    fn add_leaf(&mut self, leaf: MH::Hash) -> Result<(), MerkleError> {
        self.check_capacity()?;

        let num = self.num_entries();

        if num == 0 {
            self.set_peak(0, leaf);
            return Ok(());
        }

        // The number of elements in MMR is also the mask of peaks.
        let peak_mask = num;

        // Iterate through the heights, merging peaks as needed.
        let mut current_node = leaf;
        let mut current_height = 0u8;

        while (peak_mask >> current_height) & 1 == 1 {
            let prev_peak = self
                .get_peak(current_height)
                .copied()
                .expect("mmr: peak should exist based on peak_mask");

            let next_node = MH::hash_node(prev_peak, current_node);

            // Clear the peak at current height.
            self.set_peak(current_height, MH::zero_hash());

            current_node = next_node;
            current_height += 1;
        }

        self.set_peak(current_height, current_node);

        Ok(())
    }

    /// If the MMR has a power-of-2 number of elements, extracts the single
    /// populated root that commits to all of them.
    fn get_single_root(&self) -> Result<MH::Hash, MerkleError> {
        let num = self.num_entries();

        if num == 0 {
            return Err(MerkleError::NoElements);
        }

        if !num.is_power_of_two() {
            return Err(MerkleError::NotPowerOfTwo);
        }

        let height = num.trailing_zeros() as u8;
        self.get_peak(height)
            .copied()
            .ok_or(MerkleError::NoElements)
    }

    /// Verifies a proof for a leaf against the current MMR state.
    ///
    /// This method accepts any proof type implementing [`ProofData`], including
    /// both `MerkleProof<H>` and SSZ-specific types like `MerkleProofB32`.
    fn verify<P: ProofData<Hash = MH::Hash>>(&self, proof: &P, leaf: &MH::Hash) -> bool {
        let height = proof.cohashes_len();
        let root = match self.get_peak(height as u8) {
            Some(r) => r,
            None => return false,
        };
        crate::proof::verify_with_root::<P, MH>(proof, root, leaf)
    }

    /// Adds a new leaf, returning an updated version of the proof passed.
    ///
    /// If the proof passed does not match the accumulator, then the returned
    /// proof will be nonsensical.
    fn add_leaf_updating_proof(
        &mut self,
        next: MH::Hash,
        proof: &MerkleProof<MH::Hash>,
    ) -> Result<MerkleProof<MH::Hash>, MerkleError> {
        self.check_capacity()?;

        let num = self.num_entries();

        if num == 0 {
            self.add_leaf(next)?;
            return Ok(MerkleProof::new_zero());
        }

        let mut updated_proof = proof.clone();
        let new_leaf_index = num;
        let peak_mask = num;

        let mut current_node = next;
        let mut current_height = 0usize;

        while (peak_mask >> current_height) & 1 == 1 {
            let prev_node = self
                .get_peak(current_height as u8)
                .copied()
                .expect("mmr: peak should exist based on peak_mask");

            let next_node = MH::hash_node(prev_node, current_node);
            let leaf_parent_tree = new_leaf_index >> (current_height + 1);

            let proof_index = updated_proof.index();
            Self::update_single_proof::<MH>(
                updated_proof.inner_mut(),
                proof_index,
                leaf_parent_tree,
                current_height,
                prev_node,
                current_node,
            );

            // Clear the peak at current height.
            self.set_peak(current_height as u8, MH::zero_hash());

            current_node = next_node;
            current_height += 1;
        }

        self.set_peak(current_height as u8, current_node);

        Ok(updated_proof)
    }

    /// Adds a leaf to the accumulator, updating the proofs in a provided list
    /// of proofs in-place, and returning a proof to the new leaf.
    fn add_leaf_updating_proof_list(
        &mut self,
        next: MH::Hash,
        proof_list: &mut [MerkleProof<MH::Hash>],
    ) -> Result<MerkleProof<MH::Hash>, MerkleError> {
        self.check_capacity()?;

        let num = self.num_entries();

        if num == 0 {
            self.add_leaf(next)?;
            return Ok(MerkleProof::new_zero());
        }

        let mut new_proof = MerkleProof::<MH::Hash>::new_empty(num);
        let new_proof_index = new_proof.index();
        debug_assert_eq!(new_proof_index, num);

        let new_leaf_index = num;
        let peak_mask = num;

        let mut current_node = next;
        let mut current_height = 0usize;

        while (peak_mask >> current_height) & 1 == 1 {
            let prev_node = self
                .get_peak(current_height as u8)
                .copied()
                .expect("mmr: peak should exist based on peak_mask");

            let next_node = MH::hash_node(prev_node, current_node);
            let leaf_parent_tree = new_leaf_index >> (current_height + 1);

            // Update all existing proofs.
            for proof in proof_list.iter_mut() {
                let index = proof.index();
                Self::update_single_proof::<MH>(
                    proof.inner_mut(),
                    index,
                    leaf_parent_tree,
                    current_height,
                    prev_node,
                    current_node,
                );
            }

            // Update the new proof.
            Self::update_single_proof::<MH>(
                new_proof.inner_mut(),
                new_proof_index,
                leaf_parent_tree,
                current_height,
                prev_node,
                current_node,
            );

            // Clear the peak at current height.
            self.set_peak(current_height as u8, MH::zero_hash());

            current_node = next_node;
            current_height += 1;
        }

        self.set_peak(current_height as u8, current_node);

        Ok(new_proof)
    }

    /// Helper to update a single proof during leaf insertion.
    fn update_single_proof<MH2: MerkleHasher<Hash = MH::Hash>>(
        proof: &mut RawMerkleProof<MH::Hash>,
        proof_index: u64,
        leaf_parent_tree: u64,
        current_height: usize,
        prev_node: MH::Hash,
        current_node: MH::Hash,
    ) {
        let proof_parent_tree = proof_index >> (current_height + 1);

        if leaf_parent_tree == proof_parent_tree {
            let cohashes = proof.cohashes_vec_mut();

            if current_height >= cohashes.len() {
                cohashes.resize(current_height + 1, MH2::zero_hash());
            }

            if (proof_index >> current_height) & 1 == 1 {
                cohashes[current_height] = prev_node;
            } else {
                cohashes[current_height] = current_node;
            }
        }
    }
}

/// Blanket implementation of [`Mmr`] for any type implementing [`MmrState`].
impl<MH, S> Mmr<MH> for S
where
    MH: MerkleHasher,
    S: MmrState<MH::Hash>,
{
}

#[cfg(test)]
#[allow(deprecated)] // Tests use MerkleMr64 for differential testing
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::mmr::{CompactMmr64, MerkleMr64};
    use crate::proof::MerkleProof;
    use crate::traits::MmrState;
    use crate::{NewMmrState, Sha256Hasher};

    #[cfg(feature = "ssz")]
    use {
        crate::{CompactMmr64B32, MerkleMr64B32, MerkleProofB32},
        ssz::{Decode, Encode},
    };

    type Hash32 = [u8; 32];

    fn make_hash(data: &[u8]) -> Hash32 {
        Sha256::digest(data).into()
    }

    #[test]
    fn test_empty_mmr() {
        let state = NewMmrState::<Hash32>::new_empty();
        assert!(Mmr::<Sha256Hasher>::is_empty(&state));
        assert_eq!(state.num_entries(), 0);
    }

    #[test]
    fn test_add_single_leaf() {
        let mut state = NewMmrState::<Hash32>::new_empty();
        let hash = make_hash(b"leaf1");

        Mmr::<Sha256Hasher>::add_leaf(&mut state, hash).unwrap();

        assert!(!Mmr::<Sha256Hasher>::is_empty(&state));
        assert_eq!(state.num_entries(), 1);
        assert_eq!(state.get_peak(0), Some(&hash));
    }

    #[test]
    fn test_add_two_leaves_merge() {
        let mut state = NewMmrState::<Hash32>::new_empty();
        let hash1 = make_hash(b"leaf1");
        let hash2 = make_hash(b"leaf2");

        Mmr::<Sha256Hasher>::add_leaf(&mut state, hash1).unwrap();
        Mmr::<Sha256Hasher>::add_leaf(&mut state, hash2).unwrap();

        assert_eq!(state.num_entries(), 2);
        // After 2 leaves, we should have one peak at height 1
        assert!(state.get_peak(0).is_none());
        assert!(state.get_peak(1).is_some());
    }

    #[test]
    fn test_add_three_leaves() {
        let mut state = NewMmrState::<Hash32>::new_empty();
        let hash1 = make_hash(b"leaf1");
        let hash2 = make_hash(b"leaf2");
        let hash3 = make_hash(b"leaf3");

        Mmr::<Sha256Hasher>::add_leaf(&mut state, hash1).unwrap();
        Mmr::<Sha256Hasher>::add_leaf(&mut state, hash2).unwrap();
        Mmr::<Sha256Hasher>::add_leaf(&mut state, hash3).unwrap();

        assert_eq!(state.num_entries(), 3);
        // After 3 leaves (binary 11), peaks at height 0 and 1
        assert!(state.get_peak(0).is_some());
        assert!(state.get_peak(1).is_some());
    }

    #[test]
    fn test_get_single_root_power_of_two() {
        let mut state = NewMmrState::<Hash32>::new_empty();
        let hash = make_hash(b"leaf1");

        Mmr::<Sha256Hasher>::add_leaf(&mut state, hash).unwrap();

        let root = Mmr::<Sha256Hasher>::get_single_root(&state).unwrap();
        assert_eq!(root, hash);
    }

    #[test]
    fn test_get_single_root_not_power_of_two() {
        let mut state = NewMmrState::<Hash32>::new_empty();

        Mmr::<Sha256Hasher>::add_leaf(&mut state, make_hash(b"leaf1")).unwrap();
        Mmr::<Sha256Hasher>::add_leaf(&mut state, make_hash(b"leaf2")).unwrap();
        Mmr::<Sha256Hasher>::add_leaf(&mut state, make_hash(b"leaf3")).unwrap();

        let result = Mmr::<Sha256Hasher>::get_single_root(&state);
        assert_eq!(result, Err(MerkleError::NotPowerOfTwo));
    }

    #[test]
    fn test_verify_proof() {
        let mut state = NewMmrState::<Hash32>::new_empty();
        let mut proof_list: Vec<MerkleProof<Hash32>> = Vec::new();

        let hash1 = make_hash(b"leaf1");
        let hash2 = make_hash(b"leaf2");

        let proof1 =
            Mmr::<Sha256Hasher>::add_leaf_updating_proof_list(&mut state, hash1, &mut proof_list)
                .unwrap();
        proof_list.push(proof1);

        let proof2 =
            Mmr::<Sha256Hasher>::add_leaf_updating_proof_list(&mut state, hash2, &mut proof_list)
                .unwrap();
        proof_list.push(proof2);

        // Verify both proofs.
        assert!(Mmr::<Sha256Hasher>::verify(&state, &proof_list[0], &hash1));
        assert!(Mmr::<Sha256Hasher>::verify(&state, &proof_list[1], &hash2));

        // Verify wrong leaf fails.
        let wrong_hash = make_hash(b"wrong");
        assert!(!Mmr::<Sha256Hasher>::verify(
            &state,
            &proof_list[0],
            &wrong_hash
        ));
    }

    #[test]
    fn test_add_leaf_updating_single_proof() {
        let mut state = NewMmrState::<Hash32>::new_empty();

        let hash1 = make_hash(b"leaf1");
        let hash2 = make_hash(b"leaf2");
        let hash3 = make_hash(b"leaf3");

        // Add first leaf.
        Mmr::<Sha256Hasher>::add_leaf(&mut state, hash1).unwrap();
        let mut proof1 = MerkleProof::<Hash32>::new_empty(0);

        // Add second leaf, updating proof1.
        proof1 = Mmr::<Sha256Hasher>::add_leaf_updating_proof(&mut state, hash2, &proof1).unwrap();

        // Add third leaf, updating proof1.
        proof1 = Mmr::<Sha256Hasher>::add_leaf_updating_proof(&mut state, hash3, &proof1).unwrap();

        // Verify proof1 still works.
        assert!(Mmr::<Sha256Hasher>::verify(&state, &proof1, &hash1));
    }

    #[test]
    fn test_add_many_leaves_with_proofs() {
        let mut state = NewMmrState::<Hash32>::new_empty();
        let mut proof_list: Vec<MerkleProof<Hash32>> = Vec::new();

        let hashes: Vec<Hash32> = (0..10).map(|i| make_hash(&[i])).collect();

        for hash in &hashes {
            let proof = Mmr::<Sha256Hasher>::add_leaf_updating_proof_list(
                &mut state,
                *hash,
                &mut proof_list,
            )
            .unwrap();
            proof_list.push(proof);
        }

        assert_eq!(state.num_entries(), 10);

        // Verify all proofs.
        for (i, hash) in hashes.iter().enumerate() {
            assert!(
                Mmr::<Sha256Hasher>::verify(&state, &proof_list[i], hash),
                "proof {} failed",
                i
            );
        }
    }

    #[test]
    fn test_compare_with_old_mmr() {
        use crate::mmr::MerkleMr64;

        // Test that new implementation produces same results as old one.
        let mut old_mmr = MerkleMr64::<Sha256Hasher>::new(64);
        let mut new_state = NewMmrState::<Hash32>::new_empty();

        let hashes: Vec<Hash32> = (0..20).map(|i| make_hash(&[i])).collect();

        for hash in &hashes {
            old_mmr.add_leaf(*hash).unwrap();
            Mmr::<Sha256Hasher>::add_leaf(&mut new_state, *hash).unwrap();
        }

        // Compare num_entries.
        assert_eq!(old_mmr.num_entries(), new_state.num_entries());

        // Compare peaks.
        for (height, old_peak) in old_mmr.peaks_iter() {
            let new_peak = new_state.get_peak(height);
            assert_eq!(
                Some(old_peak),
                new_peak,
                "peak mismatch at height {}",
                height
            );
        }
    }

    #[test]
    fn test_compare_proofs_with_old_mmr() {
        use crate::mmr::MerkleMr64;

        let mut old_mmr = MerkleMr64::<Sha256Hasher>::new(64);
        let mut new_state = NewMmrState::<Hash32>::new_empty();

        let mut old_proof_list: Vec<MerkleProof<Hash32>> = Vec::new();
        let mut new_proof_list: Vec<MerkleProof<Hash32>> = Vec::new();

        let hashes: Vec<Hash32> = (0..10).map(|i| make_hash(&[i])).collect();

        for hash in &hashes {
            let old_proof = old_mmr
                .add_leaf_updating_proof_list(*hash, &mut old_proof_list)
                .unwrap();
            old_proof_list.push(old_proof);

            let new_proof = Mmr::<Sha256Hasher>::add_leaf_updating_proof_list(
                &mut new_state,
                *hash,
                &mut new_proof_list,
            )
            .unwrap();
            new_proof_list.push(new_proof);
        }

        // Compare proofs.
        for i in 0..hashes.len() {
            assert_eq!(
                old_proof_list[i].index(),
                new_proof_list[i].index(),
                "proof index mismatch at {}",
                i
            );
            assert_eq!(
                old_proof_list[i].cohashes(),
                new_proof_list[i].cohashes(),
                "proof cohashes mismatch at {}",
                i
            );
        }

        // Verify new proofs work with old MMR and vice versa.
        for (i, hash) in hashes.iter().enumerate() {
            assert!(old_mmr.verify(&new_proof_list[i], hash));
            assert!(Mmr::<Sha256Hasher>::verify(
                &new_state,
                &old_proof_list[i],
                hash
            ));
        }
    }

    // ==========================================================================
    // Cross-implementation compatibility tests
    // ==========================================================================

    /// Helper function to insert leaves into any MmrState and return proofs.
    fn insert_leaves_with_proofs<S: MmrState<Hash32>>(
        state: &mut S,
        hashes: &[Hash32],
    ) -> Vec<MerkleProof<Hash32>> {
        let mut proof_list: Vec<MerkleProof<Hash32>> = Vec::new();
        for hash in hashes {
            let proof =
                Mmr::<Sha256Hasher>::add_leaf_updating_proof_list(state, *hash, &mut proof_list)
                    .expect("add leaf should succeed");
            proof_list.push(proof);
        }
        proof_list
    }

    /// Helper function to collect peaks from any MmrState.
    fn collect_peaks<S: MmrState<Hash32>>(state: &S) -> Vec<(u8, Hash32)> {
        state.iter_peaks().map(|(h, hash)| (h, *hash)).collect()
    }

    #[test]
    fn test_cross_impl_same_peaks() {
        // Test that inserting the same sequence into all MmrState implementations
        // produces the same peaks.
        let hashes: Vec<Hash32> = (0u8..20).map(|i| make_hash(&[i])).collect();

        // NewMmrState
        let mut new_state = NewMmrState::<Hash32>::new_empty();
        for hash in &hashes {
            Mmr::<Sha256Hasher>::add_leaf(&mut new_state, *hash).unwrap();
        }
        let new_peaks = collect_peaks(&new_state);

        // MerkleMr64 (legacy)
        let mut legacy_mmr = MerkleMr64::<Sha256Hasher>::new(64);
        for hash in &hashes {
            legacy_mmr.add_leaf(*hash).unwrap();
        }
        let legacy_peaks = collect_peaks(&legacy_mmr);

        // CompactMmr64 (via conversion from MerkleMr64)
        let compact_mmr: CompactMmr64<Hash32> = legacy_mmr.clone().into();
        let compact_peaks = collect_peaks(&compact_mmr);

        // Compare all peaks match
        assert_eq!(
            new_peaks, legacy_peaks,
            "NewMmrState and MerkleMr64 peaks should match"
        );
        assert_eq!(
            new_peaks, compact_peaks,
            "NewMmrState and CompactMmr64 peaks should match"
        );

        // Verify num_entries matches across all implementations
        assert_eq!(new_state.num_entries(), legacy_mmr.num_entries());
        assert_eq!(new_state.num_entries(), compact_mmr.num_entries());
    }

    #[test]
    #[cfg(feature = "ssz")]
    fn test_cross_impl_same_peaks_with_ssz() {
        // Extended test including SSZ types
        let hashes: Vec<Hash32> = (0u8..20).map(|i| make_hash(&[i])).collect();

        // NewMmrState
        let mut new_state = NewMmrState::<Hash32>::new_empty();
        for hash in &hashes {
            Mmr::<Sha256Hasher>::add_leaf(&mut new_state, *hash).unwrap();
        }
        let new_peaks = collect_peaks(&new_state);

        // MerkleMr64 (legacy)
        let mut legacy_mmr = MerkleMr64::<Sha256Hasher>::new(64);
        for hash in &hashes {
            legacy_mmr.add_leaf(*hash).unwrap();
        }

        // MerkleMr64B32 (SSZ flat)
        let ssz_flat_mmr = MerkleMr64B32::from_generic(&legacy_mmr);
        let ssz_flat_peaks = collect_peaks(&ssz_flat_mmr);

        // CompactMmr64B32 (SSZ compact)
        let compact_mmr: CompactMmr64<Hash32> = legacy_mmr.clone().into();
        let ssz_compact_mmr = CompactMmr64B32::from_generic(&compact_mmr);
        let ssz_compact_peaks = collect_peaks(&ssz_compact_mmr);

        // Compare all peaks match
        assert_eq!(
            new_peaks, ssz_flat_peaks,
            "NewMmrState and MerkleMr64B32 peaks should match"
        );
        assert_eq!(
            new_peaks, ssz_compact_peaks,
            "NewMmrState and CompactMmr64B32 peaks should match"
        );

        // Verify num_entries matches
        assert_eq!(new_state.num_entries(), ssz_flat_mmr.num_entries());
        assert_eq!(new_state.num_entries(), ssz_compact_mmr.num_entries());
    }

    #[test]
    fn test_cross_impl_proof_verification() {
        // Generate proof with one impl, verify with another
        let hashes: Vec<Hash32> = (0u8..15).map(|i| make_hash(&[i])).collect();

        // Generate proofs using NewMmrState
        let mut new_state = NewMmrState::<Hash32>::new_empty();
        let new_proofs = insert_leaves_with_proofs(&mut new_state, &hashes);

        // Generate proofs using MerkleMr64
        let mut legacy_mmr = MerkleMr64::<Sha256Hasher>::new(64);
        let legacy_proofs = insert_leaves_with_proofs(&mut legacy_mmr, &hashes);

        // Create CompactMmr64 from legacy
        let compact_mmr: CompactMmr64<Hash32> = legacy_mmr.clone().into();

        // Cross-verify: NewMmrState proofs against all implementations
        for (i, hash) in hashes.iter().enumerate() {
            assert!(
                Mmr::<Sha256Hasher>::verify(&new_state, &new_proofs[i], hash),
                "NewMmrState proof {} should verify against NewMmrState",
                i
            );
            assert!(
                Mmr::<Sha256Hasher>::verify(&legacy_mmr, &new_proofs[i], hash),
                "NewMmrState proof {} should verify against MerkleMr64",
                i
            );
            assert!(
                Mmr::<Sha256Hasher>::verify(&compact_mmr, &new_proofs[i], hash),
                "NewMmrState proof {} should verify against CompactMmr64",
                i
            );
        }

        // Cross-verify: Legacy proofs against all implementations
        for (i, hash) in hashes.iter().enumerate() {
            assert!(
                Mmr::<Sha256Hasher>::verify(&new_state, &legacy_proofs[i], hash),
                "MerkleMr64 proof {} should verify against NewMmrState",
                i
            );
            assert!(
                Mmr::<Sha256Hasher>::verify(&legacy_mmr, &legacy_proofs[i], hash),
                "MerkleMr64 proof {} should verify against MerkleMr64",
                i
            );
            assert!(
                Mmr::<Sha256Hasher>::verify(&compact_mmr, &legacy_proofs[i], hash),
                "MerkleMr64 proof {} should verify against CompactMmr64",
                i
            );
        }
    }

    #[test]
    #[cfg(feature = "ssz")]
    fn test_cross_impl_proof_verification_with_ssz() {
        // Generate proof with generic impl, verify with SSZ impls
        let hashes: Vec<Hash32> = (0u8..15).map(|i| make_hash(&[i])).collect();

        // Generate proofs using NewMmrState
        let mut new_state = NewMmrState::<Hash32>::new_empty();
        let proofs = insert_leaves_with_proofs(&mut new_state, &hashes);

        // Create SSZ types
        let mut legacy_mmr = MerkleMr64::<Sha256Hasher>::new(64);
        for hash in &hashes {
            legacy_mmr.add_leaf(*hash).unwrap();
        }
        let ssz_flat_mmr = MerkleMr64B32::from_generic(&legacy_mmr);
        let compact_mmr: CompactMmr64<Hash32> = legacy_mmr.into();
        let ssz_compact_mmr = CompactMmr64B32::from_generic(&compact_mmr);

        // Convert proofs to SSZ format
        let ssz_proofs: Vec<MerkleProofB32> =
            proofs.iter().map(MerkleProofB32::from_generic).collect();

        // Verify generic proofs against SSZ types
        for (i, hash) in hashes.iter().enumerate() {
            assert!(
                Mmr::<Sha256Hasher>::verify(&ssz_flat_mmr, &proofs[i], hash),
                "Generic proof {} should verify against MerkleMr64B32",
                i
            );
            assert!(
                Mmr::<Sha256Hasher>::verify(&ssz_compact_mmr, &proofs[i], hash),
                "Generic proof {} should verify against CompactMmr64B32",
                i
            );
        }

        // Verify SSZ proofs against all types
        for (i, hash) in hashes.iter().enumerate() {
            assert!(
                Mmr::<Sha256Hasher>::verify(&new_state, &ssz_proofs[i], hash),
                "SSZ proof {} should verify against NewMmrState",
                i
            );
            assert!(
                Mmr::<Sha256Hasher>::verify(&ssz_flat_mmr, &ssz_proofs[i], hash),
                "SSZ proof {} should verify against MerkleMr64B32",
                i
            );
            assert!(
                Mmr::<Sha256Hasher>::verify(&ssz_compact_mmr, &ssz_proofs[i], hash),
                "SSZ proof {} should verify against CompactMmr64B32",
                i
            );
        }
    }

    #[test]
    fn test_conversion_between_representations() {
        // Test conversion between MerkleMr64 and CompactMmr64 preserves invariants
        let hashes: Vec<Hash32> = (0u8..17).map(|i| make_hash(&[i])).collect();

        // Build MMR
        let mut legacy_mmr = MerkleMr64::<Sha256Hasher>::new(64);
        for hash in &hashes {
            legacy_mmr.add_leaf(*hash).unwrap();
        }

        // Convert to compact
        let compact_mmr: CompactMmr64<Hash32> = legacy_mmr.clone().into();

        // Convert back to full
        let restored_mmr: MerkleMr64<Sha256Hasher> = compact_mmr.clone().into();

        // Verify invariants are preserved
        assert_eq!(
            legacy_mmr.num_entries(),
            compact_mmr.num_entries(),
            "num_entries should match after conversion to compact"
        );
        assert_eq!(
            legacy_mmr.num_entries(),
            restored_mmr.num_entries(),
            "num_entries should match after roundtrip"
        );

        // Verify peaks match
        let original_peaks = collect_peaks(&legacy_mmr);
        let compact_peaks = collect_peaks(&compact_mmr);
        let restored_peaks = collect_peaks(&restored_mmr);

        assert_eq!(
            original_peaks, compact_peaks,
            "peaks should match after conversion to compact"
        );
        assert_eq!(
            original_peaks, restored_peaks,
            "peaks should match after roundtrip"
        );

        // Verify proofs still work after conversion
        let mut proof_list: Vec<MerkleProof<Hash32>> = Vec::new();
        let mut mmr_for_proofs = MerkleMr64::<Sha256Hasher>::new(64);
        for hash in &hashes {
            let proof = mmr_for_proofs
                .add_leaf_updating_proof_list(*hash, &mut proof_list)
                .unwrap();
            proof_list.push(proof);
        }

        for (i, hash) in hashes.iter().enumerate() {
            assert!(
                Mmr::<Sha256Hasher>::verify(&compact_mmr, &proof_list[i], hash),
                "proof {} should verify against converted compact MMR",
                i
            );
            assert!(
                Mmr::<Sha256Hasher>::verify(&restored_mmr, &proof_list[i], hash),
                "proof {} should verify against roundtrip-restored MMR",
                i
            );
        }
    }

    #[test]
    #[cfg(feature = "ssz")]
    fn test_ssz_roundtrip_preserves_mmrstate() {
        // Test that SSZ encode/decode preserves MmrState functionality
        let hashes: Vec<Hash32> = (0u8..13).map(|i| make_hash(&[i])).collect();

        // Build and generate proofs
        let mut legacy_mmr = MerkleMr64::<Sha256Hasher>::new(64);
        let mut proof_list: Vec<MerkleProof<Hash32>> = Vec::new();
        for hash in &hashes {
            let proof = legacy_mmr
                .add_leaf_updating_proof_list(*hash, &mut proof_list)
                .unwrap();
            proof_list.push(proof);
        }

        // Test MerkleMr64B32 SSZ roundtrip
        let ssz_flat = MerkleMr64B32::from_generic(&legacy_mmr);
        let encoded_flat = ssz_flat.as_ssz_bytes();
        let decoded_flat =
            MerkleMr64B32::from_ssz_bytes(&encoded_flat).expect("SSZ decode should succeed");

        // Verify MmrState methods work correctly after roundtrip
        assert_eq!(ssz_flat.num_entries(), decoded_flat.num_entries());
        assert_eq!(
            collect_peaks(&ssz_flat),
            collect_peaks(&decoded_flat),
            "peaks should match after SSZ roundtrip for MerkleMr64B32"
        );

        // Verify proofs against decoded SSZ type
        for (i, hash) in hashes.iter().enumerate() {
            assert!(
                Mmr::<Sha256Hasher>::verify(&decoded_flat, &proof_list[i], hash),
                "proof {} should verify against SSZ-roundtripped MerkleMr64B32",
                i
            );
        }

        // Test CompactMmr64B32 SSZ roundtrip
        let compact_mmr: CompactMmr64<Hash32> = legacy_mmr.into();
        let ssz_compact = CompactMmr64B32::from_generic(&compact_mmr);
        let encoded_compact = ssz_compact.as_ssz_bytes();
        let decoded_compact =
            CompactMmr64B32::from_ssz_bytes(&encoded_compact).expect("SSZ decode should succeed");

        // Verify MmrState methods work correctly after roundtrip
        assert_eq!(ssz_compact.num_entries(), decoded_compact.num_entries());
        assert_eq!(
            collect_peaks(&ssz_compact),
            collect_peaks(&decoded_compact),
            "peaks should match after SSZ roundtrip for CompactMmr64B32"
        );

        // Verify proofs against decoded SSZ type
        for (i, hash) in hashes.iter().enumerate() {
            assert!(
                Mmr::<Sha256Hasher>::verify(&decoded_compact, &proof_list[i], hash),
                "proof {} should verify against SSZ-roundtripped CompactMmr64B32",
                i
            );
        }
    }

    #[test]
    #[cfg(feature = "ssz")]
    fn test_ssz_proof_roundtrip() {
        // Test that proofs survive SSZ roundtrip
        let hashes: Vec<Hash32> = (0u8..10).map(|i| make_hash(&[i])).collect();

        let mut new_state = NewMmrState::<Hash32>::new_empty();
        let proofs = insert_leaves_with_proofs(&mut new_state, &hashes);

        // Roundtrip each proof through SSZ and verify
        for (i, hash) in hashes.iter().enumerate() {
            let ssz_proof = MerkleProofB32::from_generic(&proofs[i]);
            let encoded = ssz_proof.as_ssz_bytes();
            let decoded =
                MerkleProofB32::from_ssz_bytes(&encoded).expect("SSZ decode should succeed");

            // Verify decoded proof works
            assert!(
                Mmr::<Sha256Hasher>::verify(&new_state, &decoded, hash),
                "SSZ-roundtripped proof {} should verify",
                i
            );

            // Verify proof fields match
            assert_eq!(
                ssz_proof.index(),
                decoded.index(),
                "proof {} index should match after roundtrip",
                i
            );
            assert_eq!(
                ssz_proof.cohashes().len(),
                decoded.cohashes().len(),
                "proof {} cohashes length should match after roundtrip",
                i
            );
        }
    }

    #[test]
    #[cfg(feature = "ssz")]
    fn test_compact_to_flat_conversion_ssz() {
        // Test conversion between CompactMmr64B32 and MerkleMr64B32
        let hashes: Vec<Hash32> = (0u8..11).map(|i| make_hash(&[i])).collect();

        // Build via MerkleMr64B32
        let mut ssz_flat = MerkleMr64B32::new(64);
        for hash in &hashes {
            ssz_flat.add_leaf(*hash).unwrap();
        }

        // Convert to compact and back
        let ssz_compact = ssz_flat.to_compact();
        let restored_flat = MerkleMr64B32::from_compact(&ssz_compact);

        // Verify num_entries and peaks match
        assert_eq!(ssz_flat.num_entries(), ssz_compact.num_entries());
        assert_eq!(ssz_flat.num_entries(), restored_flat.num_entries());
        assert_eq!(
            collect_peaks(&ssz_flat),
            collect_peaks(&ssz_compact),
            "peaks should match after compact conversion"
        );
        assert_eq!(
            collect_peaks(&ssz_flat),
            collect_peaks(&restored_flat),
            "peaks should match after roundtrip through compact"
        );
    }

    #[test]
    fn test_all_impls_iter_peaks_order() {
        // Verify that iter_peaks returns peaks in consistent order across impls
        let hashes: Vec<Hash32> = (0u8..7).map(|i| make_hash(&[i])).collect();

        let mut new_state = NewMmrState::<Hash32>::new_empty();
        let mut legacy_mmr = MerkleMr64::<Sha256Hasher>::new(64);

        for hash in &hashes {
            Mmr::<Sha256Hasher>::add_leaf(&mut new_state, *hash).unwrap();
            legacy_mmr.add_leaf(*hash).unwrap();
        }

        let compact_mmr: CompactMmr64<Hash32> = legacy_mmr.clone().into();

        // 7 elements = binary 111, so peaks at heights 0, 1, 2
        let new_iter: Vec<_> = new_state.iter_peaks().collect();
        let legacy_iter: Vec<_> = legacy_mmr.iter_peaks().collect();
        let compact_iter: Vec<_> = compact_mmr.iter_peaks().collect();

        assert_eq!(
            new_iter.len(),
            legacy_iter.len(),
            "iterator lengths should match"
        );
        assert_eq!(
            new_iter.len(),
            compact_iter.len(),
            "iterator lengths should match"
        );

        // Check that heights are in ascending order and values match
        for i in 0..new_iter.len() {
            assert_eq!(
                new_iter[i].0, legacy_iter[i].0,
                "peak heights should match at position {}",
                i
            );
            assert_eq!(
                new_iter[i].0, compact_iter[i].0,
                "peak heights should match at position {}",
                i
            );
            assert_eq!(
                new_iter[i].1, legacy_iter[i].1,
                "peak values should match at position {}",
                i
            );
            assert_eq!(
                new_iter[i].1, compact_iter[i].1,
                "peak values should match at position {}",
                i
            );
        }

        // Verify ascending order
        for i in 1..new_iter.len() {
            assert!(
                new_iter[i].0 > new_iter[i - 1].0,
                "peak heights should be in ascending order"
            );
        }
    }

    #[test]
    fn test_empty_mmr_cross_impl() {
        // Verify all implementations handle empty state correctly
        let new_state = NewMmrState::<Hash32>::new_empty();
        let legacy_mmr = MerkleMr64::<Sha256Hasher>::new(64);
        let compact_mmr = CompactMmr64::<Hash32> {
            entries: 0,
            cap_log2: 64,
            roots: Vec::new(),
        };

        assert_eq!(new_state.num_entries(), 0);
        assert_eq!(legacy_mmr.num_entries(), 0);
        assert_eq!(compact_mmr.num_entries(), 0);

        assert_eq!(new_state.iter_peaks().count(), 0);
        assert_eq!(legacy_mmr.iter_peaks().count(), 0);
        assert_eq!(compact_mmr.iter_peaks().count(), 0);

        // All should return None for any peak
        assert!(new_state.get_peak(0).is_none());
        assert!(legacy_mmr.get_peak(0).is_none());
        assert!(compact_mmr.get_peak(0).is_none());
    }
}
