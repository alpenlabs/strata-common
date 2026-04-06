use crate::hasher::*;
use crate::proof::*;
use crate::traits::*;

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
    fn new_empty() -> Self {
        Self {
            // This interface doesn't define a capacity since generally we
            // actually just want to resize as needed.
            cap_log2: 64,
            entries: 0,
            roots: Vec::new(),
        }
    }

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

/// Iterator that yields (peak_index, &hash) pairs from lowest to highest peak index for
/// CompactMmr64.
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
