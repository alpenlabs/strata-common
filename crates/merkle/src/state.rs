//! A compact container for an MMR (Merkle mountain range) state.

use crate::hasher::MerkleHash;
use crate::traits::MmrState;

/// A compact container for an MMR (Merkle mountain range) state.
///
/// This is "compact" because instead of storing all of the peaks in a flat
/// array according to the height they represent, including "zero" peaks that
/// are absent, we only store the peaks that are set.  We pack them together and
/// just store the total number of entries in the MMR.  This is safe, because we
/// the bit pattern in the number of entries happens to also describe which
/// peaks that are present in the accumulator.  Then we can work backwards with
/// that to determine which entry in the list of peaks corresponds to the peak
/// height we're looking for.  Another minor optimization here is that we store
/// them in reverse order, with the entries representing the smallest peaks at
/// the end of the list, since these are the ones we add/remove the most often.
// replace this with one defined in SSZ
#[derive(Clone, Debug)]
pub struct MmrStateVec<H> {
    /// The total number of entries.
    ///
    /// The set bits in this number describe the "real" tiers of the entries in
    /// `packed_peaks`.
    num_entries: u64,

    /// The packed hashes.  This actually stores them in reverse order, so that
    /// the leaf for tree of height 0 will be the last index, because we
    /// manipulate these the most and that reduces the amount of bit manipulation.
    packed_peaks: Vec<H>,
}

impl<H: MerkleHash> MmrStateVec<H> {
    /// Creates a new empty MMR state with no entries and no peaks.
    pub fn new_empty() -> Self {
        Self {
            num_entries: 0,
            packed_peaks: Vec::new(),
        }
    }

    /// Sanity checks, ensuring that the length of `packed_peaks` matches the
    /// number of entries.
    ///
    /// This should be called after making any manipulation to the container.
    #[cfg(test)]
    fn sanity_check(&self) {
        assert_eq!(
            self.packed_peaks.len() as u64,
            self.num_entries.count_ones() as u64,
            "mmr: invariant violated"
        );
    }

    /// Given a peak index, gets the index in the `packed_peaks` field
    /// corresponding to it.
    #[inline(always)]
    fn get_packed_index(&self, peak_idx: u8) -> Option<usize> {
        let bit_mask = 1u64 << peak_idx;

        // Check if this peak is set.
        if (self.num_entries & bit_mask) == 0 {
            return None;
        }

        // Count how many set bits are BELOW peak_idx.
        // Mask off bits at and above peak_idx, then count remaining set bits.
        let bits_below = (self.num_entries & (bit_mask - 1)).count_ones() as usize;

        // Since packed_peaks is in reverse order (highest first, lowest last),
        // the index is: len - 1 - bits_below
        Some(self.packed_peaks.len() - 1 - bits_below)
    }

    #[inline(always)]
    fn set_peak_inner(&mut self, i: u8, val: H) -> bool {
        // Check if index is within bounds.
        if i >= self.max_num_peaks() {
            return false;
        }

        let bit_mask = 1u64 << i;
        let is_currently_set = (self.num_entries & bit_mask) != 0;

        if H::is_zero(&val) {
            // Unsetting the peak.
            if !is_currently_set {
                return false; // Already unset.
            }

            // Find and remove from packed_peaks.
            if let Some(packed_idx) = self.get_packed_index(i) {
                self.packed_peaks.remove(packed_idx);
                self.num_entries &= !bit_mask; // Clear the bit.
                return true;
            }

            false
        } else {
            // Setting the peak.
            if is_currently_set {
                // Update existing peak in place.
                if let Some(packed_idx) = self.get_packed_index(i) {
                    self.packed_peaks[packed_idx] = val;
                    return true;
                }

                false
            } else {
                // Insert new peak at correct position (maintaining reverse
                // order).
                //
                // Count how many set bits are *above* index i to find insertion
                // point.
                let bits_above = if i >= 63 {
                    0 // No bits above index 63
                } else {
                    (self.num_entries >> (i + 1)).count_ones() as usize
                };

                // Sanity check.
                #[cfg(test)]
                if bits_above > self.packed_peaks.len() {
                    panic!("mmr: inserting to nonsensical oob index");
                }

                self.packed_peaks.insert(bits_above, val);
                self.num_entries |= bit_mask; // Set the bit

                true
            }
        }
    }
}

impl<H: MerkleHash> MmrState<H> for MmrStateVec<H> {
    fn max_num_peaks(&self) -> u8 {
        u64::BITS as u8
    }

    fn num_entries(&self) -> u64 {
        self.num_entries
    }

    fn num_present_peaks(&self) -> u8 {
        self.packed_peaks.len() as u8
    }

    fn get_peak(&self, i: u8) -> Option<&H> {
        let peak_idx = self.get_packed_index(i)?;
        Some(&self.packed_peaks[peak_idx])
    }

    fn set_peak(&mut self, i: u8, val: H) -> bool {
        let v = self.set_peak_inner(i, val);

        #[cfg(test)]
        self.sanity_check();

        v
    }

    fn iter_peaks<'a>(&'a self) -> impl Iterator<Item = (u8, &'a H)> + 'a {
        PeaksIter {
            remaining: self.num_entries,
            original: self.num_entries,
            peaks: &self.packed_peaks,
        }
    }
}

/// Iterator that yields (peak_index, &hash) pairs from lowest to highest peak index.
struct PeaksIter<'a, H> {
    /// Remaining bits to process (gets bits cleared as we iterate).
    remaining: u64,

    /// Original num_entries value (needed to compute packed index).
    original: u64,

    /// Reference to the packed peaks array.
    peaks: &'a [H],
}

impl<'a, H> Iterator for PeaksIter<'a, H> {
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
        let packed_idx = self.peaks.len() - 1 - bits_below;

        Some((peak_idx, &self.peaks[packed_idx]))
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    type Hash32 = [u8; 32];

    fn make_hash(data: &[u8]) -> Hash32 {
        Sha256::digest(data).into()
    }

    #[test]
    fn test_new_empty() {
        let state = MmrStateVec::<Hash32>::new_empty();
        assert_eq!(state.num_entries(), 0);
        assert_eq!(state.num_present_peaks(), 0);
        state.sanity_check();
    }

    #[test]
    fn test_set_single_peak() {
        let mut state = MmrStateVec::<Hash32>::new_empty();
        let hash = make_hash(b"peak0");

        // Set peak at height 0
        assert!(state.set_peak(0, hash));
        assert_eq!(state.num_entries(), 1); // binary: 1
        assert_eq!(state.num_present_peaks(), 1);
        assert_eq!(state.get_peak(0), Some(&hash));
        state.sanity_check();
    }

    #[test]
    fn test_set_multiple_peaks() {
        let mut state = MmrStateVec::<Hash32>::new_empty();
        let hash0 = make_hash(b"peak0");
        let hash2 = make_hash(b"peak2");

        // Set peak at height 0, then height 2 (simulating num_entries = 5, binary: 101)
        assert!(state.set_peak(0, hash0));
        assert!(state.set_peak(2, hash2));

        assert_eq!(state.num_entries(), 5); // 1 + 4 = 5
        assert_eq!(state.num_present_peaks(), 2);
        assert_eq!(state.get_peak(0), Some(&hash0));
        assert_eq!(state.get_peak(1), None); // Not set
        assert_eq!(state.get_peak(2), Some(&hash2));
        state.sanity_check();
    }

    #[test]
    fn test_set_peaks_reverse_order() {
        // Test that setting peaks in reverse order also works
        let mut state = MmrStateVec::<Hash32>::new_empty();
        let hash0 = make_hash(b"peak0");
        let hash2 = make_hash(b"peak2");

        // Set peak at height 2 first, then height 0
        assert!(state.set_peak(2, hash2));
        assert!(state.set_peak(0, hash0));

        assert_eq!(state.num_entries(), 5); // 1 + 4 = 5
        assert_eq!(state.num_present_peaks(), 2);
        assert_eq!(state.get_peak(0), Some(&hash0));
        assert_eq!(state.get_peak(2), Some(&hash2));
        state.sanity_check();
    }

    #[test]
    fn test_unset_peak() {
        let mut state = MmrStateVec::<Hash32>::new_empty();
        let hash0 = make_hash(b"peak0");
        let hash2 = make_hash(b"peak2");

        // Set two peaks
        state.set_peak(0, hash0);
        state.set_peak(2, hash2);
        assert_eq!(state.num_entries(), 5);

        // Unset peak at height 0
        let zero_hash = Hash32::zero();
        assert!(state.set_peak(0, zero_hash));
        assert_eq!(state.num_entries(), 4); // Only bit 2 set now
        assert_eq!(state.num_present_peaks(), 1);
        assert_eq!(state.get_peak(0), None);
        assert_eq!(state.get_peak(2), Some(&hash2));
        state.sanity_check();
    }

    #[test]
    fn test_update_existing_peak() {
        let mut state = MmrStateVec::<Hash32>::new_empty();
        let hash_old = make_hash(b"old");
        let hash_new = make_hash(b"new");

        // Set initial peak
        state.set_peak(0, hash_old);
        assert_eq!(state.get_peak(0), Some(&hash_old));

        // Update with new value
        assert!(state.set_peak(0, hash_new));
        assert_eq!(state.get_peak(0), Some(&hash_new));
        assert_eq!(state.num_entries(), 1); // Should remain 1
        state.sanity_check();
    }

    #[test]
    fn test_iter_peaks_empty() {
        let state = MmrStateVec::<Hash32>::new_empty();
        let peaks: Vec<_> = state.iter_peaks().collect();
        assert!(peaks.is_empty());
    }

    #[test]
    fn test_iter_peaks_single() {
        let mut state = MmrStateVec::<Hash32>::new_empty();
        let hash = make_hash(b"peak");
        state.set_peak(3, hash);

        let peaks: Vec<_> = state.iter_peaks().collect();
        assert_eq!(peaks.len(), 1);
        assert_eq!(peaks[0], (3, &hash));
    }

    #[test]
    fn test_iter_peaks_multiple() {
        let mut state = MmrStateVec::<Hash32>::new_empty();
        let hash0 = make_hash(b"peak0");
        let hash1 = make_hash(b"peak1");
        let hash2 = make_hash(b"peak2");

        // Set peaks to simulate num_entries = 7 (binary: 111)
        state.set_peak(0, hash0);
        state.set_peak(1, hash1);
        state.set_peak(2, hash2);

        let peaks: Vec<_> = state.iter_peaks().collect();
        assert_eq!(peaks.len(), 3);

        // Should be in order from lowest to highest
        assert_eq!(peaks[0], (0, &hash0));
        assert_eq!(peaks[1], (1, &hash1));
        assert_eq!(peaks[2], (2, &hash2));
    }

    #[test]
    fn test_iter_peaks_non_contiguous() {
        let mut state = MmrStateVec::<Hash32>::new_empty();
        let hash0 = make_hash(b"peak0");
        let hash3 = make_hash(b"peak3");

        // Set peaks at 0 and 3 (num_entries = 9, binary: 1001)
        state.set_peak(0, hash0);
        state.set_peak(3, hash3);

        let peaks: Vec<_> = state.iter_peaks().collect();
        assert_eq!(peaks.len(), 2);
        assert_eq!(peaks[0], (0, &hash0));
        assert_eq!(peaks[1], (3, &hash3));
    }

    #[test]
    fn test_set_peak_out_of_bounds() {
        let mut state = MmrStateVec::<Hash32>::new_empty();
        let hash = make_hash(b"peak");

        // Peak index 64 is out of bounds (max is 63 for u64)
        assert!(!state.set_peak(64, hash));
        assert_eq!(state.num_entries(), 0);
    }

    #[test]
    fn test_unset_already_unset() {
        let mut state = MmrStateVec::<Hash32>::new_empty();
        let zero_hash = Hash32::zero();

        // Trying to unset a peak that was never set should return false
        assert!(!state.set_peak(0, zero_hash));
        assert_eq!(state.num_entries(), 0);
    }

    #[test]
    fn test_set_then_get_all_heights() {
        let mut state = MmrStateVec::<Hash32>::new_empty();

        // Test a few different heights
        for i in [0u8, 5, 10, 20, 63] {
            let hash = make_hash(&[i]);
            assert!(state.set_peak(i, hash));
            assert_eq!(state.get_peak(i), Some(&hash));
            state.sanity_check();
        }
    }

    #[test]
    fn test_unset_then_get() {
        let mut state = MmrStateVec::<Hash32>::new_empty();
        let hash = make_hash(b"peak");
        let zero_hash = Hash32::zero();

        // Set then unset
        state.set_peak(5, hash);
        assert_eq!(state.get_peak(5), Some(&hash));

        state.set_peak(5, zero_hash);
        assert_eq!(state.get_peak(5), None);
        state.sanity_check();
    }

    #[test]
    fn test_complex_sequence() {
        let mut state = MmrStateVec::<Hash32>::new_empty();
        let zero_hash = Hash32::zero();

        // Simulate a realistic sequence of operations
        // Add entries: 1, 2, 3, 4, 5

        // Entry 1: peak at h=0
        state.set_peak(0, make_hash(b"leaf1"));
        assert_eq!(state.num_entries(), 1);

        // Entry 2: merge h=0, create h=1
        state.set_peak(0, zero_hash);
        state.set_peak(1, make_hash(b"merged_1_2"));
        assert_eq!(state.num_entries(), 2);

        // Entry 3: add h=0
        state.set_peak(0, make_hash(b"leaf3"));
        assert_eq!(state.num_entries(), 3);

        // Entry 4: merge h=0 into h=1, merge h=1 into h=2
        state.set_peak(0, zero_hash);
        state.set_peak(1, zero_hash);
        state.set_peak(2, make_hash(b"merged_all_4"));
        assert_eq!(state.num_entries(), 4);

        // Entry 5: add h=0
        state.set_peak(0, make_hash(b"leaf5"));
        assert_eq!(state.num_entries(), 5);

        // Final state should have peaks at h=0 and h=2
        assert!(state.get_peak(0).is_some());
        assert!(state.get_peak(1).is_none());
        assert!(state.get_peak(2).is_some());
        state.sanity_check();
    }
}
