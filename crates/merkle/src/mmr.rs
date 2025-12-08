//! Merkle Mountain Range (MMR) accumulator and related types.

use std::marker::PhantomData;

use crate::error::MerkleError;
use crate::hasher::{MerkleHash, MerkleHasher};
use crate::proof::{MerkleProof, RawMerkleProof};
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
    /// Verifies a single proof for a leaf.
    pub fn verify<MH>(&self, proof: &MerkleProof<H>, leaf: &H) -> bool
    where
        MH: MerkleHasher<Hash = H>,
    {
        let height = proof.cohashes().len();
        let root_index = (self.entries & ((1 << height) - 1)).count_ones() as usize;
        let root = match self.roots.get(root_index) {
            Some(r) => r,
            None => return false,
        };
        proof.verify_with_root::<MH>(root, leaf)
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
        // Mask off bits at and above peak_idx, then count remaining set bits.
        let bits_below = (self.entries & (bit_mask - 1)).count_ones() as usize;

        // Since roots is in reverse order (highest first, lowest last),
        // the index is: len - 1 - bits_below
        self.roots.len().checked_sub(1)?.checked_sub(bits_below)
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
                && packed_idx < self.roots.len() {
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
                    && let Some(root) = self.roots.get_mut(packed_idx) {
                        *root = val;
                        return true;
                    }

                false
            } else {
                // Insert new peak at correct position (maintaining reverse order).
                // Count how many set bits are *above* index i to find insertion point.
                let bits_above = if i >= 63 {
                    0 // No bits above index 63
                } else {
                    (self.entries >> (i + 1)).count_ones() as usize
                };

                if bits_above <= self.roots.len() {
                    self.roots.insert(bits_above, val);
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
        // Count how many set bits are below peak_idx in the original value.
        let bit_mask = 1u64 << peak_idx;
        let bits_below = (self.original & (bit_mask - 1)).count_ones() as usize;
        let packed_idx = self.roots.len().checked_sub(1)?.checked_sub(bits_below)?;

        self.roots.get(packed_idx).map(|root| (peak_idx, root))
    }
}

/// Merkle mountain range that can hold up to 2**64 elements.
#[derive(Clone, Debug)]
pub struct MerkleMr64<MH: MerkleHasher + Clone> {
    /// Total number of elements inserted into MMR.
    pub(crate) num: u64,

    /// Buffer of all possible peaks in MMR.  Only some of these will be valid
    /// at a time.
    pub(crate) peaks: Vec<MH::Hash>,

    /// phantom data for hasher
    _pd: PhantomData<MH>,
}

impl<MH> MerkleMr64<MH>
where
    MH: MerkleHasher + Clone,
{
    /// Constructs a new MMR with some scale.  This is the number of peaks we
    /// will keep in the MMR.  The real capacity is 2**n of this value
    /// specified.
    ///
    /// # Panics
    ///
    /// If the `cap_log2` parameter is larger than 64.
    pub fn new(cap_log2: usize) -> Self {
        if cap_log2 > 64 {
            panic!("mmr: tried to create MMR of size {cap_log2} (max is 64)");
        }

        Self {
            num: 0,
            peaks: vec![MH::zero_hash(); cap_log2],
            _pd: PhantomData,
        }
    }

    /// Constructs an MMR from raw parts.
    ///
    /// This is primarily used by serialization code paths to rebuild an MMR
    /// from a stored `num` and the vector of `peaks`.
    pub fn from_parts(num: u64, peaks: Vec<MH::Hash>) -> Self {
        Self {
            num,
            peaks,
            _pd: PhantomData,
        }
    }

    /// Gets the number of entries inserted into the MMR.
    pub fn num_entries(&self) -> u64 {
        self.num
    }

    /// Gets if there have been no entries inserted into the MMR.
    pub fn is_empty(&self) -> bool {
        self.num_entries() == 0
    }

    /// Returns the internal peaks as a slice.
    ///
    /// Useful for testing and (de)serialization helpers to compare state
    /// without exposing mutation.
    pub fn peaks_slice(&self) -> &[MH::Hash] {
        &self.peaks
    }

    /// Returns an iterator over the set merkle peaks, exposing their height.
    ///
    /// This is mainly useful for testing/troubleshooting.
    pub fn peaks_iter(&self) -> impl Iterator<Item = (u8, &MH::Hash)> {
        self.peaks
            .iter()
            .enumerate()
            .filter(|(_, h)| !<MH::Hash as MerkleHash>::is_zero(h))
            .map(|(i, h)| (i as u8, h))
    }

    /// Returns the total number of elements we're allowed to insert into the
    /// MMR, based on the roots size.
    pub fn max_capacity(&self) -> u64 {
        // Very clean bit manipulation.
        match self.peaks.len() as u64 {
            0 => 0,
            peaks => u64::MAX >> (64 - peaks),
        }
    }

    /// Checks if we can insert a new element.  Returns error if not.
    fn check_capacity(&self) -> Result<(), MerkleError> {
        if self.num == self.max_capacity() {
            return Err(MerkleError::MaxCapacity);
        }
        Ok(())
    }

    /// Adds a new leaf to the MMR.
    pub fn add_leaf(&mut self, leaf: MH::Hash) -> Result<(), MerkleError> {
        self.check_capacity()?;

        if self.num == 0 {
            self.peaks[0] = leaf;
            self.num += 1;
            return Ok(());
        }

        // the number of elements in MMR is also the mask of peaks
        let peak_mask = self.num;

        // Iterate through the height.
        let mut current_node = leaf;
        let mut current_height = 0;
        while (peak_mask >> current_height) & 1 == 1 {
            let next_node = MH::hash_node(self.peaks[current_height], current_node);

            // setting this for debugging purpose
            self.peaks[current_height] = MH::zero_hash();

            current_node = next_node;
            current_height += 1;
        }

        self.peaks[current_height] = current_node;
        self.num += 1;

        Ok(())
    }

    /// If the MMR has a power-of-2 number of elements, then this extracts the
    /// single populated root that commits to all of them.
    pub fn get_single_root(&self) -> Result<MH::Hash, MerkleError> {
        if self.num == 0 {
            return Err(MerkleError::NoElements);
        }

        if !self.num.is_power_of_two() && self.num != 1 {
            return Err(MerkleError::NotPowerOfTwo);
        }

        Ok(self.peaks[(self.num.ilog2()) as usize])
    }

    /// Adds a new leaf, returning an updated version of the proof passed.  If
    /// the proof passed does not match the accumulator, then the returned proof
    /// will be nonsensical.
    // TODO make a version of this that doesn't alloc?
    pub fn add_leaf_updating_proof(
        &mut self,
        next: MH::Hash,
        proof: &MerkleProof<MH::Hash>,
    ) -> Result<MerkleProof<MH::Hash>, MerkleError> {
        self.check_capacity()?;

        // FIXME this is a weird function to call if this is true, since how
        // could a valid proof have been passed?
        if self.num == 0 {
            self.add_leaf(next)?;
            return Ok(MerkleProof::new_zero());
        }

        let mut updated_proof = proof.clone();

        let new_leaf_index = self.num;
        let peak_mask = self.num;
        let mut current_node = next;
        let mut current_height = 0;
        while (peak_mask >> current_height) & 1 == 1 {
            let prev_node = self.peaks[current_height];
            let next_node = MH::hash_node(prev_node, current_node);
            let leaf_parent_tree = new_leaf_index >> (current_height + 1);

            let proof_index = updated_proof.index();
            self.update_single_proof(
                updated_proof.inner_mut(),
                proof_index,
                leaf_parent_tree,
                current_height,
                prev_node,
                current_node,
            );

            self.peaks[current_height] = MH::zero_hash();
            current_node = next_node;
            current_height += 1;
        }

        self.peaks[current_height] = current_node;
        self.num += 1;

        Ok(updated_proof)
    }

    fn update_single_proof(
        &mut self,
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
                cohashes.resize(current_height + 1, MH::zero_hash());
            }

            if (proof_index >> current_height) & 1 == 1 {
                cohashes[current_height] = prev_node;
            } else {
                cohashes[current_height] = current_node;
            }
        }
    }

    /// Adds a leaf to the accumulator, updating the proofs in a provided list
    /// of proofs in-place, and returning a proof to the new leaf.
    pub fn add_leaf_updating_proof_list(
        &mut self,
        next: MH::Hash,
        proof_list: &mut [MerkleProof<MH::Hash>],
    ) -> Result<MerkleProof<MH::Hash>, MerkleError> {
        self.check_capacity()?;

        if self.num == 0 {
            self.add_leaf(next)?;
            return Ok(MerkleProof::new_zero());
        }

        let mut new_proof = MerkleProof::<MH::Hash>::new_empty(self.num);
        let new_proof_index = new_proof.index();
        assert_eq!(new_proof_index, self.num);

        let new_leaf_index = self.num;
        let peak_mask = self.num;
        let mut current_node = next;
        let mut current_height = 0;
        while (peak_mask >> current_height) & 1 == 1 {
            let prev_node = self.peaks[current_height];
            let next_node = MH::hash_node(prev_node, current_node);
            let leaf_parent_tree = new_leaf_index >> (current_height + 1);

            for proof in proof_list.iter_mut() {
                let index = proof.index();
                self.update_single_proof(
                    proof.inner_mut(),
                    index,
                    leaf_parent_tree,
                    current_height,
                    prev_node,
                    current_node,
                );
            }

            self.update_single_proof(
                new_proof.inner_mut(),
                new_proof_index,
                leaf_parent_tree,
                current_height,
                prev_node,
                current_node,
            );

            // the peaks value is no longer needed
            self.peaks[current_height] = MH::zero_hash();
            current_node = next_node;
            current_height += 1;
        }

        self.peaks[current_height] = current_node;
        self.num += 1;

        Ok(new_proof)
    }

    /// Verifies a single proof for a leaf against the current MMR state.
    pub fn verify(&self, proof: &MerkleProof<MH::Hash>, leaf: &MH::Hash) -> bool {
        let root = &self.peaks[proof.cohashes().len()];
        proof.verify_with_root::<MH>(root, leaf)
    }

    #[allow(dead_code, clippy::allow_attributes, reason = "used for testing")]
    pub(crate) fn gen_proof(
        &self,
        proof_list: &[MerkleProof<MH::Hash>],
        index: u64,
    ) -> Result<Option<MerkleProof<MH::Hash>>, MerkleError> {
        if index > self.num {
            return Err(MerkleError::IndexOutOfBounds);
        }

        match proof_list.iter().find(|proof| proof.index == index) {
            Some(proof) => Ok(Some(proof.clone())),
            None => Ok(None),
        }
    }
}

impl<MH> MmrState<MH::Hash> for MerkleMr64<MH>
where
    MH: MerkleHasher + Clone,
{
    fn max_num_peaks(&self) -> u8 {
        self.peaks.len() as u8
    }

    fn num_entries(&self) -> u64 {
        self.num
    }

    fn num_present_peaks(&self) -> u8 {
        self.num.count_ones() as u8
    }

    fn get_peak(&self, i: u8) -> Option<&MH::Hash> {
        let i_usize = i as usize;
        if i_usize >= self.peaks.len() {
            return None;
        }

        // Check if this peak is set (bit is set in num and hash is not zero)
        if (self.num >> i) & 1 == 1 && !MH::Hash::is_zero(&self.peaks[i_usize]) {
            Some(&self.peaks[i_usize])
        } else {
            None
        }
    }

    fn set_peak(&mut self, i: u8, val: MH::Hash) -> bool {
        let i_usize = i as usize;
        if i_usize >= self.peaks.len() {
            return false;
        }

        let bit_mask = 1u64 << i;
        let was_set = (self.num & bit_mask) != 0;

        if MH::Hash::is_zero(&val) {
            // Unsetting the peak.
            if was_set {
                self.peaks[i_usize] = val; // Set to zero hash
                self.num &= !bit_mask; // Clear the bit
                true
            } else {
                false // Already unset
            }
        } else {
            // Setting the peak.
            self.peaks[i_usize] = val;
            if !was_set {
                self.num |= bit_mask; // Set the bit
            }
            true
        }
    }

    fn iter_peaks<'a>(&'a self) -> impl Iterator<Item = (u8, &'a MH::Hash)> + 'a {
        self.peaks.iter().enumerate().filter_map(|(i, hash)| {
            let i_u8 = i as u8;
            // Only include peaks that are set (bit is set in num and hash is not zero)
            if (self.num >> i_u8) & 1 == 1 && !MH::Hash::is_zero(hash) {
                Some((i_u8, hash))
            } else {
                None
            }
        })
    }
}

impl<MH> From<CompactMmr64<MH::Hash>> for MerkleMr64<MH>
where
    MH: MerkleHasher + Clone,
{
    fn from(compact: CompactMmr64<MH::Hash>) -> Self {
        let mut roots = vec![MH::zero_hash(); compact.cap_log2 as usize];
        let mut roots_iter = compact.roots.into_iter();

        for i in 0..compact.cap_log2 {
            if (compact.entries >> i) & 1 != 0 {
                roots[i as usize] = roots_iter.next().expect("compact roots exhausted early");
            }
        }

        Self {
            num: compact.entries,
            peaks: roots,
            _pd: PhantomData,
        }
    }
}

impl<MH> From<MerkleMr64<MH>> for CompactMmr64<MH::Hash>
where
    MH: MerkleHasher + Clone,
{
    fn from(mmr: MerkleMr64<MH>) -> Self {
        Self {
            entries: mmr.num,
            cap_log2: mmr.peaks.len() as u8,
            roots: mmr
                .peaks
                .into_iter()
                .filter(|h| !<MH::Hash as MerkleHash>::is_zero(h))
                .collect(),
        }
    }
}

#[cfg(feature = "ssz")]
mod mmr64b32 {
    use super::*;
    use crate::{new_mmr::Mmr, *};
    use ssz_types::{FixedBytes, VariableList};

    type Hash32 = <Sha256Hasher as MerkleHasher>::Hash;

    impl CompactMmr64B32 {
        /// Creates a concrete MMR from a generic CompactMmr64
        pub fn from_generic(mmr: &CompactMmr64<Hash32>) -> Self {
            let roots: Vec<_> = mmr
                .roots
                .iter()
                .map(|r| FixedBytes::<32>::from(*r))
                .collect();
            Self {
                entries: mmr.entries,
                cap_log2: mmr.cap_log2,
                roots: roots.into(),
            }
        }

        /// Verifies a single proof for a leaf.
        ///
        /// This method uses Sha256Hasher as the merkle hasher implementation.
        pub fn verify(&self, proof: &MerkleProofB32, leaf: &[u8; 32]) -> bool {
            Mmr::<Sha256Hasher>::verify(self, proof, leaf)
        }
    }

    impl MmrState<Hash32> for CompactMmr64B32 {
        fn max_num_peaks(&self) -> u8 {
            self.cap_log2
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
            let bits_below = (self.entries & (bit_mask - 1)).count_ones() as usize;

            // Since roots is in reverse order (highest first, lowest last),
            // the index is: len - 1 - bits_below
            let packed_idx = self.roots.len().checked_sub(1)?.checked_sub(bits_below)?;
            self.roots.get(packed_idx).map(|fb| &fb.0)
        }

        fn set_peak(&mut self, i: u8, val: Hash32) -> bool {
            // Check if index is within bounds.
            if i >= self.cap_log2 {
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
                let bits_below = (self.entries & (bit_mask - 1)).count_ones() as usize;
                let packed_idx = roots_vec.len() - 1 - bits_below;
                if packed_idx < roots_vec.len() {
                    roots_vec.remove(packed_idx);
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
                    let bits_below = (self.entries & (bit_mask - 1)).count_ones() as usize;
                    let packed_idx = roots_vec.len() - 1 - bits_below;
                    if let Some(fb) = roots_vec.get_mut(packed_idx) {
                        *fb = val_fb;
                        self.roots = roots_vec.into();
                        return true;
                    }

                    false
                } else {
                    // Insert new peak at correct position (maintaining reverse order).
                    // Count how many set bits are *above* index i to find insertion point.
                    let bits_above = if i >= 63 {
                        0 // No bits above index 63
                    } else {
                        (self.entries >> (i + 1)).count_ones() as usize
                    };

                    if bits_above <= roots_vec.len() {
                        roots_vec.insert(bits_above, val_fb);
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

    /// Iterator that yields (peak_index, &hash) pairs from lowest to highest peak index for CompactMmr64B32.
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
            // Count how many set bits are below peak_idx in the original value.
            let bit_mask = 1u64 << peak_idx;
            let bits_below = (self.original & (bit_mask - 1)).count_ones() as usize;
            let packed_idx = self.roots.len() - 1 - bits_below;

            self.roots.get(packed_idx).map(|fb| (peak_idx, &fb.0))
        }
    }

    impl MerkleMr64B32 {
        /// Creates a new instance with some specified maximum capacity.
        pub fn new(cap_log2: usize) -> Self {
            let mut peaks = ssz_types::VariableList::empty();
            for _ in 0..cap_log2 {
                peaks
                    .push(ssz_types::FixedBytes::zero())
                    .expect("mmr: too large capacity");
            }
            Self { num: 0, peaks }
        }

        /// Creates a concrete MMR from a generic MerkleMr64
        pub fn from_generic(mmr: &MerkleMr64<Sha256Hasher>) -> Self {
            // TODO make this avoid a bunch of copies
            let peaks: Vec<_> = mmr
                .peaks_slice()
                .iter()
                .map(|p| FixedBytes::<32>::from(*p))
                .collect();
            Self {
                num: mmr.num_entries(),
                peaks: peaks.into(),
            }
        }

        /// Converts to a generic MerkleMr64
        pub fn to_generic(&self) -> MerkleMr64<Sha256Hasher> {
            let peaks: Vec<Hash32> = self.peaks.iter().map(|fb| fb.0).collect();
            MerkleMr64::from_parts(self.num, peaks)
        }

        /// Gets the number of entries inserted into the MMR.
        pub fn num_entries(&self) -> u64 {
            self.num
        }

        /// Gets if there have been no entries inserted into the MMR.
        pub fn is_empty(&self) -> bool {
            self.num == 0
        }

        /// Returns the internal peaks as a slice of FixedBytes.
        pub fn peaks_slice(&self) -> &[FixedBytes<32>] {
            &self.peaks
        }

        /// Adds a new leaf to the MMR.
        ///
        /// This method uses Sha256Hasher as the merkle hasher implementation.
        pub fn add_leaf(&mut self, leaf: [u8; 32]) -> Result<(), MerkleError> {
            let mut generic_mmr = self.to_generic();
            generic_mmr.add_leaf(leaf)?;
            *self = Self::from_generic(&generic_mmr);
            Ok(())
        }

        /// Returns the total number of elements we're allowed to insert into the MMR.
        pub fn max_capacity(&self) -> u64 {
            match self.peaks.len() as u64 {
                0 => 0,
                peaks => u64::MAX >> (64 - peaks),
            }
        }

        /// Converts to CompactMmr64B32 (filters out zero peaks)
        pub fn to_compact(&self) -> CompactMmr64B32 {
            let compact: CompactMmr64<Hash32> = self.to_generic().into();
            CompactMmr64B32::from_generic(&compact)
        }

        /// Creates from CompactMmr64B32 (restores zero peaks)
        pub fn from_compact(compact: &CompactMmr64B32) -> Self {
            // First convert to generic CompactMmr64
            let generic_compact = CompactMmr64 {
                entries: compact.entries,
                cap_log2: compact.cap_log2,
                roots: compact.roots.iter().map(|fb| fb.0).collect(),
            };
            // Then convert to generic MerkleMr64
            let generic_mmr: MerkleMr64<Sha256Hasher> = generic_compact.into();
            // Finally convert to concrete
            Self::from_generic(&generic_mmr)
        }
    }

    impl MmrState<Hash32> for MerkleMr64B32 {
        fn max_num_peaks(&self) -> u8 {
            self.peaks.len() as u8
        }

        fn num_entries(&self) -> u64 {
            self.num
        }

        fn num_present_peaks(&self) -> u8 {
            self.num.count_ones() as u8
        }

        fn get_peak(&self, i: u8) -> Option<&Hash32> {
            let i_usize = i as usize;
            if i_usize >= self.peaks.len() {
                return None;
            }

            let peak = &self.peaks[i_usize];
            let hash = &peak.0;

            // Check if this peak is set (bit is set in num and hash is not zero)
            if (self.num >> i) & 1 == 1 && !Hash32::is_zero(hash) {
                Some(hash)
            } else {
                None
            }
        }

        fn set_peak(&mut self, i: u8, val: Hash32) -> bool {
            let i_usize = i as usize;
            if i_usize >= self.peaks.len() {
                return false;
            }

            let bit_mask = 1u64 << i;
            let was_set = (self.num & bit_mask) != 0;

            if Hash32::is_zero(&val) {
                // Unsetting the peak.
                if was_set {
                    self.peaks[i_usize] = FixedBytes::<32>::zero();
                    self.num &= !bit_mask; // Clear the bit
                    true
                } else {
                    false // Already unset
                }
            } else {
                // Setting the peak.
                let val_fb = FixedBytes::<32>::from(val);
                self.peaks[i_usize] = val_fb;
                if !was_set {
                    self.num |= bit_mask; // Set the bit
                }
                true
            }
        }

        fn iter_peaks<'a>(&'a self) -> impl Iterator<Item = (u8, &'a Hash32)> + 'a {
            self.peaks.iter().enumerate().filter_map(|(i, fb)| {
                let hash = &fb.0;
                let i_u8 = i as u8;
                // Only include peaks that are set (bit is set in num and hash is not zero)
                if (self.num >> i_u8) & 1 == 1 && !Hash32::is_zero(hash) {
                    Some((i_u8, hash))
                } else {
                    None
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::MerkleMr64;
    use crate::error::MerkleError;
    use crate::proof::MerkleProof;
    use crate::{CompactMmr64, Sha256Hasher};

    #[cfg(feature = "ssz")]
    use {
        crate::{CompactMmr64B32, MerkleMr64B32, MerkleProofB32},
        ssz::{Decode, Encode},
        ssz_types::FixedBytes,
    };

    type Hash32 = [u8; 32];

    // B32 type tests
    #[test]
    #[cfg(feature = "ssz")]
    fn test_mmr_conversion_from_generic() {
        // Create a generic MMR
        let mut mmr = MerkleMr64::<Sha256Hasher>::new(10);

        let hash1: Hash32 = Sha256::digest(b"leaf1").into();
        let hash2: Hash32 = Sha256::digest(b"leaf2").into();
        let hash3: Hash32 = Sha256::digest(b"leaf3").into();

        mmr.add_leaf(hash1).expect("add leaf");
        mmr.add_leaf(hash2).expect("add leaf");
        mmr.add_leaf(hash3).expect("add leaf");

        let compact_mmr: CompactMmr64<Hash32> = mmr.into();

        // Convert to concrete
        let concrete_mmr = CompactMmr64B32::from_generic(&compact_mmr);

        // Verify fields match
        assert_eq!(concrete_mmr.entries, compact_mmr.entries);
        assert_eq!(concrete_mmr.cap_log2, compact_mmr.cap_log2);
        assert_eq!(concrete_mmr.roots.len(), compact_mmr.roots.len());
        for (concrete_root, generic_root) in concrete_mmr.roots.iter().zip(compact_mmr.roots.iter())
        {
            assert_eq!(concrete_root.0, *generic_root);
        }
    }

    #[test]
    #[cfg(feature = "ssz")]
    fn test_proof_verification() {
        // Create an MMR and generate a proof
        let mut mmr = MerkleMr64::<Sha256Hasher>::new(10);

        let hash1: Hash32 = Sha256::digest(b"leaf1").into();
        let hash2: Hash32 = Sha256::digest(b"leaf2").into();

        let mut proof_list = Vec::new();
        mmr.add_leaf_updating_proof_list(hash1, &mut proof_list)
            .unwrap();
        let proof = mmr
            .add_leaf_updating_proof_list(hash2, &mut proof_list)
            .unwrap();

        let compact_mmr: CompactMmr64<Hash32> = mmr.into();

        // Convert to concrete types
        let concrete_mmr = CompactMmr64B32::from_generic(&compact_mmr);
        let concrete_proof = MerkleProofB32::from_generic(&proof);

        // Verify the proof using concrete types
        assert!(concrete_mmr.verify(&concrete_proof, &hash2));

        // Verify proof verification fails for wrong leaf
        let wrong_hash: Hash32 = Sha256::digest(b"wrong").into();
        assert!(!concrete_mmr.verify(&concrete_proof, &wrong_hash));
    }

    #[cfg(feature = "ssz")]
    #[test]
    fn test_merklemr64_conversion_from_generic() {
        // Create a generic MMR
        let mut mmr = MerkleMr64::<Sha256Hasher>::new(10);

        let hash1: Hash32 = Sha256::digest(b"leaf1").into();
        let hash2: Hash32 = Sha256::digest(b"leaf2").into();
        let hash3: Hash32 = Sha256::digest(b"leaf3").into();

        mmr.add_leaf(hash1).expect("add leaf");
        mmr.add_leaf(hash2).expect("add leaf");
        mmr.add_leaf(hash3).expect("add leaf");

        // Convert to concrete
        let concrete_mmr = MerkleMr64B32::from_generic(&mmr);

        // Verify fields match
        assert_eq!(concrete_mmr.num_entries(), mmr.num_entries());
        assert_eq!(concrete_mmr.peaks.len(), mmr.peaks_slice().len());
        for (concrete_peak, generic_peak) in concrete_mmr.peaks.iter().zip(mmr.peaks_slice().iter())
        {
            assert_eq!(concrete_peak.0, *generic_peak);
        }
    }

    #[cfg(feature = "ssz")]
    #[test]
    fn test_merklemr64_to_generic() {
        // Create a concrete MMR
        let mut concrete_mmr = MerkleMr64B32 {
            num: 0,
            peaks: vec![FixedBytes([0u8; 32]); 10].into(),
        };

        let hash1: [u8; 32] = Sha256::digest(b"leaf1").into();
        let hash2: [u8; 32] = Sha256::digest(b"leaf2").into();

        concrete_mmr.add_leaf(hash1).expect("add leaf");
        concrete_mmr.add_leaf(hash2).expect("add leaf");

        // Convert to generic
        let generic_mmr = concrete_mmr.to_generic();

        // Verify fields match
        assert_eq!(generic_mmr.num_entries(), concrete_mmr.num_entries());
        assert_eq!(generic_mmr.peaks_slice().len(), concrete_mmr.peaks.len());
    }

    #[cfg(feature = "ssz")]
    #[test]
    fn test_merklemr64_add_leaf() {
        // Create a concrete MMR
        let mut mmr = MerkleMr64B32 {
            num: 0,
            peaks: vec![FixedBytes([0u8; 32]); 10].into(),
        };

        let hash1: [u8; 32] = Sha256::digest(b"leaf1").into();
        let hash2: [u8; 32] = Sha256::digest(b"leaf2").into();
        let hash3: [u8; 32] = Sha256::digest(b"leaf3").into();

        // Add leaves
        mmr.add_leaf(hash1).expect("add leaf");
        assert_eq!(mmr.num_entries(), 1);

        mmr.add_leaf(hash2).expect("add leaf");
        assert_eq!(mmr.num_entries(), 2);

        mmr.add_leaf(hash3).expect("add leaf");
        assert_eq!(mmr.num_entries(), 3);

        // Verify not empty
        assert!(!mmr.is_empty());
    }

    #[cfg(feature = "ssz")]
    #[test]
    fn test_merklemr64_compact_conversion() {
        // Create a concrete MMR with some leaves
        let mut mmr = MerkleMr64B32 {
            num: 0,
            peaks: vec![FixedBytes([0u8; 32]); 10].into(),
        };

        let hash1: [u8; 32] = Sha256::digest(b"leaf1").into();
        let hash2: [u8; 32] = Sha256::digest(b"leaf2").into();
        let hash3: [u8; 32] = Sha256::digest(b"leaf3").into();

        mmr.add_leaf(hash1).expect("add leaf");
        mmr.add_leaf(hash2).expect("add leaf");
        mmr.add_leaf(hash3).expect("add leaf");

        // Convert to compact (should filter zeros)
        let compact = mmr.to_compact();
        assert_eq!(compact.entries, mmr.num_entries());

        // Convert back from compact (should restore zeros)
        let restored = MerkleMr64B32::from_compact(&compact);
        assert_eq!(restored.num_entries(), mmr.num_entries());
        assert_eq!(restored.peaks.len(), mmr.peaks.len());
    }

    #[cfg(feature = "ssz")]
    #[test]
    fn test_merklemr64_ssz_roundtrip() {
        // Create a concrete MMR with some leaves
        let mut mmr = MerkleMr64B32 {
            num: 0,
            peaks: vec![FixedBytes([0u8; 32]); 10].into(),
        };

        let hash1: [u8; 32] = Sha256::digest(b"leaf1").into();
        let hash2: [u8; 32] = Sha256::digest(b"leaf2").into();

        mmr.add_leaf(hash1).expect("add leaf");
        mmr.add_leaf(hash2).expect("add leaf");

        // Serialize
        let encoded = mmr.as_ssz_bytes();

        // Deserialize
        let decoded = MerkleMr64B32::from_ssz_bytes(&encoded).expect("Failed to decode");

        // Verify fields match
        assert_eq!(decoded.num, mmr.num);
        assert_eq!(decoded.peaks.len(), mmr.peaks.len());
        for (orig, dec) in mmr.peaks.iter().zip(decoded.peaks.iter()) {
            assert_eq!(orig.0, dec.0);
        }
    }

    // Generic MMR tests - helper functions
    fn generate_for_n_integers(n: usize) -> (MerkleMr64<Sha256Hasher>, Vec<MerkleProof<Hash32>>) {
        let mut mmr: MerkleMr64<Sha256Hasher> = MerkleMr64::new(14);

        let mut proof = Vec::new();
        let list_of_hashes = generate_hashes_for_n_integers(n);

        (0..n).for_each(|i| {
            let new_proof = mmr
                .add_leaf_updating_proof_list(list_of_hashes[i], &mut proof)
                .expect("test: add leaf");
            proof.push(new_proof);
        });
        (mmr, proof)
    }

    fn generate_hashes_for_n_integers(n: usize) -> Vec<Hash32> {
        (0..n)
            .map(|i| Sha256::digest(i.to_be_bytes()).into())
            .collect::<Vec<Hash32>>()
    }

    fn mmr_proof_for_specific_nodes(n: usize, specific_nodes: Vec<u64>) {
        let (mmr, proof_list) = generate_for_n_integers(n);
        let proof: Vec<MerkleProof<Hash32>> = specific_nodes
            .iter()
            .map(|i| {
                mmr.gen_proof(&proof_list, *i)
                    .unwrap()
                    .expect("cannot find proof for the given index")
            })
            .collect();

        let hash: Vec<Hash32> = specific_nodes
            .iter()
            .map(|i| Sha256::digest(i.to_be_bytes()).into())
            .collect();

        (0..specific_nodes.len()).for_each(|i| {
            assert!(mmr.verify(&proof[i], &hash[i]));
        });

        let compact_mmr: CompactMmr64<Hash32> = mmr.into();
        (0..specific_nodes.len()).for_each(|i| {
            assert!(compact_mmr.verify::<Sha256Hasher>(&proof[i], &hash[i]));
        });
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
        let (mmr, proof_list) = generate_for_n_integers(1);

        let proof = mmr
            .gen_proof(&proof_list, 0)
            .unwrap()
            .expect("Didn't find proof for given index");

        let hash = Sha256::digest(0_usize.to_be_bytes()).into();
        assert!(mmr.verify(&proof, &hash));
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
        let hashed1: Hash32 = Sha256::digest(b"first").into();

        let mut mmr: MerkleMr64<Sha256Hasher> = MerkleMr64::new(14);
        mmr.add_leaf(hashed1).expect("test: add leaf");

        assert_eq!(
            mmr.get_single_root(),
            Ok([
                167, 147, 123, 100, 184, 202, 165, 143, 3, 114, 27, 182, 186, 207, 92, 120, 203,
                35, 95, 235, 224, 231, 11, 27, 132, 205, 153, 84, 20, 97, 160, 142
            ])
        );
    }

    #[test]
    fn check_peak_for_mmr_three_leaves() {
        let hashed1: Hash32 = Sha256::digest(b"first").into();

        let mut mmr: MerkleMr64<Sha256Hasher> = MerkleMr64::new(14);
        mmr.add_leaf(hashed1).expect("test: add leaf");
        mmr.add_leaf(hashed1).expect("test: add leaf");
        mmr.add_leaf(hashed1).expect("test: add leaf");

        assert_eq!(mmr.get_single_root(), Err(MerkleError::NotPowerOfTwo));
    }

    #[test]
    fn check_peak_for_mmr_four_leaves() {
        let hashed1: Hash32 = Sha256::digest(b"first").into();

        let mut mmr: MerkleMr64<Sha256Hasher> = MerkleMr64::new(14);
        mmr.add_leaf(hashed1).expect("test: add leaf");
        mmr.add_leaf(hashed1).expect("test: add leaf");
        mmr.add_leaf(hashed1).expect("test: add leaf");
        mmr.add_leaf(hashed1).expect("test: add leaf");

        assert_eq!(
            mmr.get_single_root(),
            Ok([
                219, 107, 224, 125, 80, 152, 167, 72, 126, 25, 33, 96, 163, 0, 115, 13, 185, 247,
                54, 143, 195, 73, 7, 39, 95, 68, 14, 90, 198, 145, 216, 71
            ])
        );
    }

    #[test]
    fn check_invalid_proof() {
        let (mmr, _) = generate_for_n_integers(5);
        let invalid_proof = MerkleProof::<Hash32>::new_empty(6);
        let hash = Sha256::digest(42usize.to_be_bytes()).into();
        assert!(!mmr.verify(&invalid_proof, &hash));

        let compact_mmr: CompactMmr64<Hash32> = mmr.into();
        assert!(!compact_mmr.verify::<Sha256Hasher>(&invalid_proof, &hash));
    }

    #[test]
    fn check_add_node_and_update() {
        let mut mmr: MerkleMr64<Sha256Hasher> = MerkleMr64::new(14);
        let mut proof_list = Vec::new();

        let hashed0: Hash32 = Sha256::digest(b"first").into();
        let hashed1: Hash32 = Sha256::digest(b"second").into();
        let hashed2: Hash32 = Sha256::digest(b"third").into();
        let hashed3: Hash32 = Sha256::digest(b"fourth").into();
        let hashed4: Hash32 = Sha256::digest(b"fifth").into();

        let new_proof = mmr
            .add_leaf_updating_proof_list(hashed0, &mut proof_list)
            .expect("test: add leaf");
        proof_list.push(new_proof);

        let new_proof = mmr
            .add_leaf_updating_proof_list(hashed1, &mut proof_list)
            .expect("test: add leaf");
        proof_list.push(new_proof);

        let new_proof = mmr
            .add_leaf_updating_proof_list(hashed2, &mut proof_list)
            .expect("test: add leaf");
        proof_list.push(new_proof);

        let new_proof = mmr
            .add_leaf_updating_proof_list(hashed3, &mut proof_list)
            .expect("test: add leaf");
        proof_list.push(new_proof);

        let new_proof = mmr
            .add_leaf_updating_proof_list(hashed4, &mut proof_list)
            .expect("test: add leaf");
        proof_list.push(new_proof);

        assert!(mmr.verify(&proof_list[0], &hashed0));
        assert!(mmr.verify(&proof_list[1], &hashed1));
        assert!(mmr.verify(&proof_list[2], &hashed2));
        assert!(mmr.verify(&proof_list[3], &hashed3));
        assert!(mmr.verify(&proof_list[4], &hashed4));

        let compact_mmr: CompactMmr64<Hash32> = mmr.into();
        assert!(compact_mmr.verify::<Sha256Hasher>(&proof_list[0], &hashed0));
        assert!(compact_mmr.verify::<Sha256Hasher>(&proof_list[1], &hashed1));
        assert!(compact_mmr.verify::<Sha256Hasher>(&proof_list[2], &hashed2));
        assert!(compact_mmr.verify::<Sha256Hasher>(&proof_list[3], &hashed3));
        assert!(compact_mmr.verify::<Sha256Hasher>(&proof_list[4], &hashed4));
    }

    #[test]
    fn check_compact_and_non_compact() {
        let (mmr, _) = generate_for_n_integers(5);

        let compact_mmr: CompactMmr64<_> = mmr.clone().into();
        let deserialized_mmr = MerkleMr64::<Sha256Hasher>::from(compact_mmr);

        assert_eq!(mmr.peaks, deserialized_mmr.peaks);
        assert_eq!(mmr.num, deserialized_mmr.num);
    }

    #[test]
    fn arbitrary_index_proof() {
        let (mut mmr, _) = generate_for_n_integers(20);
        // update proof for 21st element
        let mut proof: MerkleProof<Hash32> = MerkleProof::new_empty(20);

        // add 4 elements into mmr, so 20 + 4 elements
        let num_elems = 4;
        let num_hash = generate_hashes_for_n_integers(num_elems);

        for elem in num_hash.iter().take(num_elems) {
            let new_proof = mmr
                .add_leaf_updating_proof(*elem, &proof)
                .expect("test: add leaf");
            proof = new_proof;
        }

        assert!(mmr.verify(&proof, &num_hash[0]));

        let compact_mmr: CompactMmr64<Hash32> = mmr.into();
        assert!(compact_mmr.verify::<Sha256Hasher>(&proof, &num_hash[0]));
    }

    #[test]
    fn update_proof_list_from_arbitrary_index() {
        let (mut mmr, _) = generate_for_n_integers(20);
        // update proof for 21st element
        let mut proof_list = Vec::new();

        // add 4 elements into mmr, so 20 + 4 elements
        let num_elems = 4;
        let num_hash = generate_hashes_for_n_integers(num_elems);

        for elem in num_hash.iter().take(num_elems) {
            let new_proof = mmr
                .add_leaf_updating_proof_list(*elem, &mut proof_list)
                .expect("test: add leaf");
            proof_list.push(new_proof);
        }

        let compact_mmr: CompactMmr64<Hash32> = mmr.clone().into();
        for i in 0..num_elems {
            assert!(mmr.verify(&proof_list[i], &num_hash[i]));
            assert!(compact_mmr.verify::<Sha256Hasher>(&proof_list[i], &num_hash[i]));
        }
    }

    // SSZ serialization test
    #[test]
    #[cfg(feature = "ssz")]
    fn test_compact_mmr_ssz_encode_decode() {
        // Create a generic CompactMmr64
        let mut mmr = MerkleMr64::<Sha256Hasher>::new(10);

        let hashed0: Hash32 = Sha256::digest(b"first").into();
        let hashed1: Hash32 = Sha256::digest(b"second").into();
        let hashed2: Hash32 = Sha256::digest(b"third").into();

        mmr.add_leaf(hashed0).expect("test: add leaf");
        mmr.add_leaf(hashed1).expect("test: add leaf");
        mmr.add_leaf(hashed2).expect("test: add leaf");

        let compact_mmr: CompactMmr64<Hash32> = mmr.into();

        // Create SSZ type from generic type
        let roots_vec: Vec<_> = compact_mmr
            .roots
            .iter()
            .map(|r| FixedBytes::<32>::from(*r))
            .collect();
        let ssz_mmr = CompactMmr64B32 {
            entries: compact_mmr.entries,
            cap_log2: compact_mmr.cap_log2,
            roots: roots_vec.into(),
        };

        // Encode to SSZ
        let encoded = ssz_mmr.as_ssz_bytes();

        // Decode from SSZ
        let decoded = CompactMmr64B32::from_ssz_bytes(&encoded).expect("Failed to decode");

        // Verify fields match
        assert_eq!(ssz_mmr.entries, decoded.entries);
        assert_eq!(ssz_mmr.cap_log2, decoded.cap_log2);
        assert_eq!(ssz_mmr.roots, decoded.roots);
    }

    #[test]
    #[cfg(feature = "ssz")]
    fn test_empty_compact_mmr_ssz() {
        let ssz_mmr = CompactMmr64B32 {
            entries: 0,
            cap_log2: 0,
            roots: vec![].try_into().expect("empty vec should work"),
        };

        let encoded = ssz_mmr.as_ssz_bytes();
        let decoded = CompactMmr64B32::from_ssz_bytes(&encoded).expect("Failed to decode");

        assert_eq!(ssz_mmr.entries, decoded.entries);
        assert_eq!(ssz_mmr.cap_log2, decoded.cap_log2);
        assert_eq!(ssz_mmr.roots, decoded.roots);
    }

    #[test]
    #[cfg(feature = "ssz")]
    fn test_compact_mmr_ssz_roundtrip() {
        // Test with various sizes
        for n in [1, 5, 10, 20, 50] {
            let (mmr, _) = generate_for_n_integers(n);
            let compact_mmr: CompactMmr64<Hash32> = mmr.into();

            let roots_vec: Vec<_> = compact_mmr
                .roots
                .iter()
                .map(|r| FixedBytes::<32>::from(*r))
                .collect();
            let ssz_mmr = CompactMmr64B32 {
                entries: compact_mmr.entries,
                cap_log2: compact_mmr.cap_log2,
                roots: roots_vec.into(),
            };

            let encoded = ssz_mmr.as_ssz_bytes();
            let decoded = CompactMmr64B32::from_ssz_bytes(&encoded).expect("Failed to decode");

            assert_eq!(ssz_mmr.entries, decoded.entries);
            assert_eq!(ssz_mmr.cap_log2, decoded.cap_log2);
            assert_eq!(ssz_mmr.roots.len(), decoded.roots.len());
            for (orig, dec) in ssz_mmr.roots.iter().zip(decoded.roots.iter()) {
                assert_eq!(orig, dec);
            }
        }
    }
}
