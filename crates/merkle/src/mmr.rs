//! Merkle Mountain Range (MMR) accumulator and related types.

use crate::hasher::MerkleHash;
use crate::hasher::MerkleHasher;
use crate::proof::MerkleProof;
use crate::traits::MmrState;

/// Compact representation of the MMR that can hold upto 2**64 elements.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
pub struct CompactMmr64<H: MerkleHash> {
    pub(crate) entries: u64,
    pub(crate) cap_log2: u8,
    pub(crate) roots: Vec<H>,
}

impl<H: MerkleHash> CompactMmr64<H> {
    /// Creates a new empty CompactMmr64 with the specified capacity.
    ///
    /// # Arguments
    /// * `cap_log2` - The log2 of the maximum capacity (max 64).
    pub fn new(cap_log2: u8) -> Self {
        Self {
            entries: 0,
            cap_log2,
            roots: Vec::new(),
        }
    }

    /// Gets the number of entries inserted into the MMR.
    pub fn num_entries(&self) -> u64 {
        self.entries
    }

    /// Verifies a single proof for a leaf.
    ///
    /// This method delegates to the unified [`Mmr::verify`](crate::Mmr::verify)
    /// trait method.
    pub fn verify<MH>(&self, proof: &MerkleProof<H>, leaf: &H) -> bool
    where
        MH: MerkleHasher<Hash = H>,
    {
        crate::Mmr::<MH>::verify(self, proof, leaf)
    }

    /// Given a peak index, gets the index in the `roots` field
    /// corresponding to it.
    #[inline(always)]
    fn get_packed_index(&self, peak_idx: u8) -> Option<usize> {
        let bit_mask = 1u64 << peak_idx;

        // Check if this peak is set.
        if (self.entries & bit_mask) == 0 {
            return None;
        }

        // Count how many set bits are BELOW peak_idx.
        // Roots are stored in forward order (lowest height first), so the
        // index equals the number of peaks below this one.
        let bits_below = (self.entries & (bit_mask - 1)).count_ones() as usize;
        Some(bits_below)
    }
}

impl<H: MerkleHash> MmrState<H> for CompactMmr64<H> {
    fn max_num_peaks(&self) -> u8 {
        self.cap_log2
    }

    fn num_entries(&self) -> u64 {
        self.entries
    }

    fn num_present_peaks(&self) -> u8 {
        self.entries.count_ones() as u8
    }

    fn get_peak(&self, i: u8) -> Option<&H> {
        let packed_idx = self.get_packed_index(i)?;
        self.roots.get(packed_idx)
    }

    fn set_peak(&mut self, i: u8, val: H) -> bool {
        // Check if index is within bounds.
        if i >= self.cap_log2 {
            return false;
        }

        let bit_mask = 1u64 << i;
        let is_currently_set = (self.entries & bit_mask) != 0;

        if H::is_zero(&val) {
            // Unsetting the peak.
            if !is_currently_set {
                return false; // Already unset.
            }

            // Find and remove from roots.
            if let Some(packed_idx) = self.get_packed_index(i)
                && packed_idx < self.roots.len()
            {
                self.roots.remove(packed_idx);
                self.entries &= !bit_mask; // Clear the bit.
                return true;
            }

            false
        } else {
            // Setting the peak.
            if is_currently_set {
                // Update existing peak in place.
                if let Some(packed_idx) = self.get_packed_index(i)
                    && let Some(root) = self.roots.get_mut(packed_idx)
                {
                    *root = val;
                    return true;
                }

                false
            } else {
                // Insert new peak at correct position (maintaining forward order).
                // Count how many set bits are *below* index i to find insertion point.
                let bits_below = (self.entries & ((1u64 << i) - 1)).count_ones() as usize;

                if bits_below <= self.roots.len() {
                    self.roots.insert(bits_below, val);
                    self.entries |= bit_mask; // Set the bit
                    return true;
                }

                false
            }
        }
    }

    fn iter_peaks<'a>(&'a self) -> impl Iterator<Item = (u8, &'a H)> + 'a {
        CompactMmr64PeaksIter {
            remaining: self.entries,
            original: self.entries,
            roots: &self.roots,
        }
    }
}

/// Iterator that yields (peak_index, &hash) pairs from lowest to highest peak index for CompactMmr64.
struct CompactMmr64PeaksIter<'a, H> {
    /// Remaining bits to process (gets bits cleared as we iterate).
    remaining: u64,

    /// Original entries value (needed to compute packed index).
    original: u64,

    /// Reference to the roots array.
    roots: &'a Vec<H>,
}

impl<'a, H> Iterator for CompactMmr64PeaksIter<'a, H> {
    type Item = (u8, &'a H);

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        // Find the index of the lowest set bit.
        let peak_idx = self.remaining.trailing_zeros() as u8;

        // Clear the lowest set bit.
        self.remaining &= self.remaining - 1;

        // Compute the packed index using bit manipulation.
        // Roots are stored in forward order (lowest height first), so the
        // index equals the number of peaks below this one.
        let bit_mask = 1u64 << peak_idx;
        let bits_below = (self.original & (bit_mask - 1)).count_ones() as usize;

        self.roots.get(bits_below).map(|root| (peak_idx, root))
    }
}

#[cfg(feature = "ssz")]
mod mmr64b32 {
    use super::*;
    use crate::{Mmr, Sha256Hasher};
    use ssz_types::{FixedBytes, VariableList};

    type Hash32 = <Sha256Hasher as MerkleHasher>::Hash;

    impl crate::Mmr64B32 {
        /// Creates a concrete MMR from a generic CompactMmr64
        pub fn from_generic(mmr: &CompactMmr64<Hash32>) -> Self {
            let roots: Vec<_> = mmr
                .roots
                .iter()
                .map(|r| FixedBytes::<32>::from(*r))
                .collect();
            Self {
                entries: mmr.entries,
                roots: roots.into(),
            }
        }

        /// Converts to a generic CompactMmr64
        pub fn to_generic(&self) -> CompactMmr64<Hash32> {
            CompactMmr64 {
                entries: self.entries,
                cap_log2: 64,
                roots: self.roots.iter().map(|fb| fb.0).collect(),
            }
        }

        /// Gets the number of entries inserted into the MMR.
        pub fn num_entries(&self) -> u64 {
            self.entries
        }

        /// Verifies a single proof for a leaf.
        ///
        /// This method delegates to the unified [`Mmr::verify`](crate::Mmr::verify)
        /// trait method using Sha256Hasher as the merkle hasher implementation.
        pub fn verify(&self, proof: &crate::MerkleProofB32, leaf: &[u8; 32]) -> bool {
            Mmr::<Sha256Hasher>::verify(self, proof, leaf)
        }
    }

    impl MmrState<Hash32> for crate::Mmr64B32 {
        fn max_num_peaks(&self) -> u8 {
            64
        }

        fn num_entries(&self) -> u64 {
            self.entries
        }

        fn num_present_peaks(&self) -> u8 {
            self.entries.count_ones() as u8
        }

        fn get_peak(&self, i: u8) -> Option<&Hash32> {
            let bit_mask = 1u64 << i;

            // Check if this peak is set.
            if (self.entries & bit_mask) == 0 {
                return None;
            }

            // Count how many set bits are BELOW peak_idx.
            // Roots are stored in forward order (lowest height first), so the
            // index equals the number of peaks below this one.
            let bits_below = (self.entries & (bit_mask - 1)).count_ones() as usize;
            self.roots.get(bits_below).map(|fb| &fb.0)
        }

        fn set_peak(&mut self, i: u8, val: Hash32) -> bool {
            // Check if index is within bounds.
            if i >= 64 {
                return false;
            }

            let bit_mask = 1u64 << i;
            let is_currently_set = (self.entries & bit_mask) != 0;

            // Convert VariableList to Vec for manipulation
            let mut roots_vec: Vec<FixedBytes<32>> = self.roots.iter().cloned().collect();

            if Hash32::is_zero(&val) {
                // Unsetting the peak.
                if !is_currently_set {
                    return false; // Already unset.
                }

                // Find and remove from roots.
                // Roots are stored in forward order (lowest height first).
                let bits_below = (self.entries & (bit_mask - 1)).count_ones() as usize;
                if bits_below < roots_vec.len() {
                    roots_vec.remove(bits_below);
                    self.entries &= !bit_mask; // Clear the bit.
                    self.roots = roots_vec.into();
                    return true;
                }

                false
            } else {
                // Setting the peak.
                let val_fb = FixedBytes::<32>::from(val);
                if is_currently_set {
                    // Update existing peak in place.
                    // Roots are stored in forward order (lowest height first).
                    let bits_below = (self.entries & (bit_mask - 1)).count_ones() as usize;
                    if let Some(fb) = roots_vec.get_mut(bits_below) {
                        *fb = val_fb;
                        self.roots = roots_vec.into();
                        return true;
                    }

                    false
                } else {
                    // Insert new peak at correct position (maintaining forward order).
                    // Count how many set bits are *below* index i to find insertion point.
                    let bits_below = (self.entries & ((1u64 << i) - 1)).count_ones() as usize;

                    if bits_below <= roots_vec.len() {
                        roots_vec.insert(bits_below, val_fb);
                        self.entries |= bit_mask; // Set the bit
                        self.roots = roots_vec.into();
                        return true;
                    }

                    false
                }
            }
        }

        fn iter_peaks<'a>(&'a self) -> impl Iterator<Item = (u8, &'a Hash32)> + 'a {
            CompactPeaksIter {
                remaining: self.entries,
                original: self.entries,
                roots: &self.roots,
            }
        }
    }

    /// Iterator that yields (peak_index, &hash) pairs from lowest to highest peak index for Mmr64B32.
    struct CompactPeaksIter<'a> {
        /// Remaining bits to process (gets bits cleared as we iterate).
        remaining: u64,

        /// Original entries value (needed to compute packed index).
        original: u64,

        /// Reference to the roots array.
        roots: &'a VariableList<FixedBytes<32>, 64>,
    }

    impl<'a> Iterator for CompactPeaksIter<'a> {
        type Item = (u8, &'a Hash32);

        fn next(&mut self) -> Option<Self::Item> {
            if self.remaining == 0 {
                return None;
            }

            // Find the index of the lowest set bit.
            let peak_idx = self.remaining.trailing_zeros() as u8;

            // Clear the lowest set bit.
            self.remaining &= self.remaining - 1;

            // Compute the packed index using bit manipulation.
            // Roots are stored in forward order (lowest height first), so the
            // index equals the number of peaks below this one.
            let bit_mask = 1u64 << peak_idx;
            let bits_below = (self.original & (bit_mask - 1)).count_ones() as usize;

            self.roots.get(bits_below).map(|fb| (peak_idx, &fb.0))
        }
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::CompactMmr64;
    use crate::Mmr;
    use crate::Sha256Hasher;
    use crate::proof::MerkleProof;
    use crate::traits::MmrState;

    #[cfg(feature = "ssz")]
    use {
        crate::{MerkleProofB32, Mmr64B32},
        ssz::{Decode, Encode},
        ssz_types::FixedBytes,
    };

    type Hash32 = [u8; 32];

    // Helper functions
    fn make_hash(data: &[u8]) -> Hash32 {
        Sha256::digest(data).into()
    }

    fn generate_hashes_for_n_integers(n: usize) -> Vec<Hash32> {
        (0..n)
            .map(|i| Sha256::digest(i.to_be_bytes()).into())
            .collect::<Vec<Hash32>>()
    }

    fn generate_mmr_with_proofs(n: usize) -> (CompactMmr64<Hash32>, Vec<MerkleProof<Hash32>>) {
        let mut mmr = CompactMmr64::new(64);
        let mut proof_list = Vec::new();
        let hashes = generate_hashes_for_n_integers(n);

        for hash in hashes.iter() {
            let new_proof =
                Mmr::<Sha256Hasher>::add_leaf_updating_proof_list(&mut mmr, *hash, &mut proof_list)
                    .expect("add leaf");
            proof_list.push(new_proof);
        }
        (mmr, proof_list)
    }

    fn mmr_proof_for_specific_nodes(n: usize, specific_nodes: Vec<u64>) {
        let (mmr, proof_list) = generate_mmr_with_proofs(n);

        let hashes = generate_hashes_for_n_integers(n);

        for &idx in &specific_nodes {
            if (idx as usize) < hashes.len() {
                assert!(
                    mmr.verify::<Sha256Hasher>(&proof_list[idx as usize], &hashes[idx as usize]),
                    "proof verification failed for index {}",
                    idx
                );
            }
        }
    }

    #[test]
    fn check_zero_elements() {
        mmr_proof_for_specific_nodes(0, vec![]);
    }

    #[test]
    fn check_two_sibling_leaves() {
        mmr_proof_for_specific_nodes(11, vec![4, 5]);
        mmr_proof_for_specific_nodes(11, vec![5, 6]);
    }

    #[test]
    fn check_single_element() {
        let (mmr, proof_list) = generate_mmr_with_proofs(1);
        let hash = Sha256::digest(0_usize.to_be_bytes()).into();
        assert!(mmr.verify::<Sha256Hasher>(&proof_list[0], &hash));
    }

    #[test]
    fn check_two_peaks() {
        mmr_proof_for_specific_nodes(3, vec![0, 2]);
    }

    #[test]
    fn check_500_elements() {
        mmr_proof_for_specific_nodes(500, vec![0, 456]);
    }

    #[test]
    fn check_peak_for_mmr_single_leaf() {
        let mut mmr = CompactMmr64::<Hash32>::new(64);
        let hashed1: Hash32 = Sha256::digest(b"first").into();

        Mmr::<Sha256Hasher>::add_leaf(&mut mmr, hashed1).expect("add leaf");

        assert_eq!(
            Mmr::<Sha256Hasher>::get_single_root(&mmr),
            Ok([
                167, 147, 123, 100, 184, 202, 165, 143, 3, 114, 27, 182, 186, 207, 92, 120, 203,
                35, 95, 235, 224, 231, 11, 27, 132, 205, 153, 84, 20, 97, 160, 142
            ])
        );
    }

    #[test]
    fn check_peak_for_mmr_three_leaves() {
        let mut mmr = CompactMmr64::<Hash32>::new(64);
        let hashed1: Hash32 = Sha256::digest(b"first").into();

        Mmr::<Sha256Hasher>::add_leaf(&mut mmr, hashed1).expect("add leaf");
        Mmr::<Sha256Hasher>::add_leaf(&mut mmr, hashed1).expect("add leaf");
        Mmr::<Sha256Hasher>::add_leaf(&mut mmr, hashed1).expect("add leaf");

        assert_eq!(
            Mmr::<Sha256Hasher>::get_single_root(&mmr),
            Err(crate::error::MerkleError::NotPowerOfTwo)
        );
    }

    #[test]
    fn check_peak_for_mmr_four_leaves() {
        let mut mmr = CompactMmr64::<Hash32>::new(64);
        let hashed1: Hash32 = Sha256::digest(b"first").into();

        Mmr::<Sha256Hasher>::add_leaf(&mut mmr, hashed1).expect("add leaf");
        Mmr::<Sha256Hasher>::add_leaf(&mut mmr, hashed1).expect("add leaf");
        Mmr::<Sha256Hasher>::add_leaf(&mut mmr, hashed1).expect("add leaf");
        Mmr::<Sha256Hasher>::add_leaf(&mut mmr, hashed1).expect("add leaf");

        assert_eq!(
            Mmr::<Sha256Hasher>::get_single_root(&mmr),
            Ok([
                219, 107, 224, 125, 80, 152, 167, 72, 126, 25, 33, 96, 163, 0, 115, 13, 185, 247,
                54, 143, 195, 73, 7, 39, 95, 68, 14, 90, 198, 145, 216, 71
            ])
        );
    }

    #[test]
    fn check_invalid_proof() {
        let (mmr, _) = generate_mmr_with_proofs(5);
        let invalid_proof = MerkleProof::<Hash32>::new_empty(6);
        let hash = Sha256::digest(42usize.to_be_bytes()).into();
        assert!(!mmr.verify::<Sha256Hasher>(&invalid_proof, &hash));
    }

    #[test]
    fn check_add_node_and_update() {
        let mut mmr = CompactMmr64::<Hash32>::new(64);
        let mut proof_list = Vec::new();

        let hashed0: Hash32 = Sha256::digest(b"first").into();
        let hashed1: Hash32 = Sha256::digest(b"second").into();
        let hashed2: Hash32 = Sha256::digest(b"third").into();
        let hashed3: Hash32 = Sha256::digest(b"fourth").into();
        let hashed4: Hash32 = Sha256::digest(b"fifth").into();

        let new_proof =
            Mmr::<Sha256Hasher>::add_leaf_updating_proof_list(&mut mmr, hashed0, &mut proof_list)
                .expect("add leaf");
        proof_list.push(new_proof);

        let new_proof =
            Mmr::<Sha256Hasher>::add_leaf_updating_proof_list(&mut mmr, hashed1, &mut proof_list)
                .expect("add leaf");
        proof_list.push(new_proof);

        let new_proof =
            Mmr::<Sha256Hasher>::add_leaf_updating_proof_list(&mut mmr, hashed2, &mut proof_list)
                .expect("add leaf");
        proof_list.push(new_proof);

        let new_proof =
            Mmr::<Sha256Hasher>::add_leaf_updating_proof_list(&mut mmr, hashed3, &mut proof_list)
                .expect("add leaf");
        proof_list.push(new_proof);

        let new_proof =
            Mmr::<Sha256Hasher>::add_leaf_updating_proof_list(&mut mmr, hashed4, &mut proof_list)
                .expect("add leaf");
        proof_list.push(new_proof);

        assert!(mmr.verify::<Sha256Hasher>(&proof_list[0], &hashed0));
        assert!(mmr.verify::<Sha256Hasher>(&proof_list[1], &hashed1));
        assert!(mmr.verify::<Sha256Hasher>(&proof_list[2], &hashed2));
        assert!(mmr.verify::<Sha256Hasher>(&proof_list[3], &hashed3));
        assert!(mmr.verify::<Sha256Hasher>(&proof_list[4], &hashed4));
    }

    #[test]
    fn arbitrary_index_proof() {
        let (mut mmr, _) = generate_mmr_with_proofs(20);
        // update proof for 21st element
        let mut proof: MerkleProof<Hash32> = MerkleProof::new_empty(20);

        // add 4 elements into mmr, so 20 + 4 elements
        let num_elems = 4;
        let num_hash = generate_hashes_for_n_integers(num_elems);

        for elem in num_hash.iter().take(num_elems) {
            let new_proof = Mmr::<Sha256Hasher>::add_leaf_updating_proof(&mut mmr, *elem, &proof)
                .expect("add leaf");
            proof = new_proof;
        }

        assert!(mmr.verify::<Sha256Hasher>(&proof, &num_hash[0]));
    }

    #[test]
    fn update_proof_list_from_arbitrary_index() {
        let (mut mmr, _) = generate_mmr_with_proofs(20);
        // update proof for 21st element
        let mut proof_list = Vec::new();

        // add 4 elements into mmr, so 20 + 4 elements
        let num_elems = 4;
        let num_hash = generate_hashes_for_n_integers(num_elems);

        for elem in num_hash.iter().take(num_elems) {
            let new_proof =
                Mmr::<Sha256Hasher>::add_leaf_updating_proof_list(&mut mmr, *elem, &mut proof_list)
                    .expect("add leaf");
            proof_list.push(new_proof);
        }

        for i in 0..num_elems {
            assert!(mmr.verify::<Sha256Hasher>(&proof_list[i], &num_hash[i]));
        }
    }

    #[test]
    fn test_compact_mmr_iter_peaks() {
        let mut mmr = CompactMmr64::<Hash32>::new(64);
        let hashes: Vec<Hash32> = (0u8..7).map(|i| make_hash(&[i])).collect();

        for hash in &hashes {
            Mmr::<Sha256Hasher>::add_leaf(&mut mmr, *hash).unwrap();
        }

        // 7 elements = binary 111, so peaks at heights 0, 1, 2
        let peaks: Vec<_> = mmr.iter_peaks().collect();
        assert_eq!(peaks.len(), 3);

        // Verify ascending order
        for i in 1..peaks.len() {
            assert!(peaks[i].0 > peaks[i - 1].0);
        }
    }

    // SSZ serialization tests
    #[test]
    #[cfg(feature = "ssz")]
    fn test_compact_mmr_ssz_encode_decode() {
        let mut mmr = CompactMmr64::<Hash32>::new(64);

        let hashed0: Hash32 = Sha256::digest(b"first").into();
        let hashed1: Hash32 = Sha256::digest(b"second").into();
        let hashed2: Hash32 = Sha256::digest(b"third").into();

        Mmr::<Sha256Hasher>::add_leaf(&mut mmr, hashed0).expect("add leaf");
        Mmr::<Sha256Hasher>::add_leaf(&mut mmr, hashed1).expect("add leaf");
        Mmr::<Sha256Hasher>::add_leaf(&mut mmr, hashed2).expect("add leaf");

        // Create SSZ type from generic type
        let roots_vec: Vec<_> = mmr
            .roots
            .iter()
            .map(|r| FixedBytes::<32>::from(*r))
            .collect();
        let ssz_mmr = Mmr64B32 {
            entries: mmr.entries,
            roots: roots_vec.into(),
        };

        // Encode to SSZ
        let encoded = ssz_mmr.as_ssz_bytes();

        // Decode from SSZ
        let decoded = Mmr64B32::from_ssz_bytes(&encoded).expect("Failed to decode");

        // Verify fields match
        assert_eq!(ssz_mmr.entries, decoded.entries);
        assert_eq!(ssz_mmr.roots, decoded.roots);
    }

    #[test]
    #[cfg(feature = "ssz")]
    fn test_empty_compact_mmr_ssz() {
        let ssz_mmr = Mmr64B32 {
            entries: 0,
            roots: vec![].try_into().expect("empty vec should work"),
        };

        let encoded = ssz_mmr.as_ssz_bytes();
        let decoded = Mmr64B32::from_ssz_bytes(&encoded).expect("Failed to decode");

        assert_eq!(ssz_mmr.entries, decoded.entries);
        assert_eq!(ssz_mmr.roots, decoded.roots);
    }

    #[test]
    #[cfg(feature = "ssz")]
    fn test_compact_mmr_ssz_roundtrip() {
        // Test with various sizes
        for n in [1, 5, 10, 20, 50] {
            let (mmr, _) = generate_mmr_with_proofs(n);

            let roots_vec: Vec<_> = mmr
                .roots
                .iter()
                .map(|r| FixedBytes::<32>::from(*r))
                .collect();
            let ssz_mmr = Mmr64B32 {
                entries: mmr.entries,
                roots: roots_vec.into(),
            };

            let encoded = ssz_mmr.as_ssz_bytes();
            let decoded = Mmr64B32::from_ssz_bytes(&encoded).expect("Failed to decode");

            assert_eq!(ssz_mmr.entries, decoded.entries);
            assert_eq!(ssz_mmr.roots.len(), decoded.roots.len());
            for (orig, dec) in ssz_mmr.roots.iter().zip(decoded.roots.iter()) {
                assert_eq!(orig, dec);
            }
        }
    }

    #[test]
    #[cfg(feature = "ssz")]
    fn test_compact_mmr_b32_from_generic() {
        let mut mmr = CompactMmr64::<Hash32>::new(64);

        let hash1: Hash32 = Sha256::digest(b"leaf1").into();
        let hash2: Hash32 = Sha256::digest(b"leaf2").into();
        let hash3: Hash32 = Sha256::digest(b"leaf3").into();

        Mmr::<Sha256Hasher>::add_leaf(&mut mmr, hash1).expect("add leaf");
        Mmr::<Sha256Hasher>::add_leaf(&mut mmr, hash2).expect("add leaf");
        Mmr::<Sha256Hasher>::add_leaf(&mut mmr, hash3).expect("add leaf");

        // Convert to concrete
        let concrete_mmr = Mmr64B32::from_generic(&mmr);

        // Verify fields match
        assert_eq!(concrete_mmr.entries, mmr.entries);
        assert_eq!(concrete_mmr.roots.len(), mmr.roots.len());
        for (concrete_root, generic_root) in concrete_mmr.roots.iter().zip(mmr.roots.iter()) {
            assert_eq!(concrete_root.0, *generic_root);
        }
    }

    #[test]
    #[cfg(feature = "ssz")]
    fn test_compact_mmr_b32_proof_verification() {
        let mut mmr = CompactMmr64::<Hash32>::new(64);
        let mut proof_list = Vec::new();

        let hash1: Hash32 = Sha256::digest(b"leaf1").into();
        let hash2: Hash32 = Sha256::digest(b"leaf2").into();

        Mmr::<Sha256Hasher>::add_leaf_updating_proof_list(&mut mmr, hash1, &mut proof_list)
            .unwrap();
        let proof =
            Mmr::<Sha256Hasher>::add_leaf_updating_proof_list(&mut mmr, hash2, &mut proof_list)
                .unwrap();

        // Convert to concrete types
        let concrete_mmr = Mmr64B32::from_generic(&mmr);
        let concrete_proof = MerkleProofB32::from_generic(&proof);

        // Verify the proof using concrete types
        assert!(concrete_mmr.verify(&concrete_proof, &hash2));

        // Verify proof verification fails for wrong leaf
        let wrong_hash: Hash32 = Sha256::digest(b"wrong").into();
        assert!(!concrete_mmr.verify(&concrete_proof, &wrong_hash));
    }
}
