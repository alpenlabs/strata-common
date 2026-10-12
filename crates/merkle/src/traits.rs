//! Traits for MMR state.

use crate::error::MerkleError;
use crate::hasher::MerkleHash;

/// Abstracts over an MMR accumulator's state.
pub trait MmrState<H: MerkleHash> {
    /// Creates a new empty MMR state instance.
    fn new_empty() -> Self;

    /// Gets the maximum number of peaks we can store.
    fn max_num_peaks(&self) -> u8;

    /// Gets the current number of entries inserted into the MMR.
    fn num_entries(&self) -> u64;

    /// Gets the number of peaks actually stored, saturating at `u8::MAX`.
    ///
    /// For a valid state this is the popcnt of `num_entries`. Count what is
    /// stored rather than deriving it from `num_entries`, so
    /// [`validate`](Self::validate) can catch stored peaks that `get_peak`
    /// never reaches.
    fn num_present_peaks(&self) -> u8;

    /// Gets a peak by its power-of-2 index, or `None` if unset/non-present.
    fn get_peak(&self, i: u8) -> Option<&H>;

    /// Assigns the value of a peak by its power-of-2 index.
    ///
    /// If `MerkleHash::is_zero` returns true, then this indicates that we're
    /// actually "unsetting" the peak.  This means that `get_peak` should return
    /// `None` and it shouldn't be returned by `iter_peaks`.
    ///
    /// Returns if we overwrote a value at that peak index.
    fn set_peak(&mut self, i: u8, val: H) -> bool;

    /// Iterates over the set peaks, from lowest (h=0) to highest.
    fn iter_peaks<'a>(&'a self) -> impl Iterator<Item = (u8, &'a H)> + 'a;

    /// Checks that the peaks match the entry count: one non-zero peak for each
    /// set bit of [`num_entries`](Self::num_entries), and no others, all below
    /// [`max_num_peaks`](Self::max_num_peaks).
    ///
    /// Decoding does not check this, so call it on any accumulator built from
    /// untrusted bytes.
    ///
    /// Errors with [`MerkleError::EntriesExceedCapacity`] when the entry count
    /// has a bit at or above `max_num_peaks`, since `set_peak` cannot store
    /// that peak. Errors with [`MerkleError::PeakCountMismatch`] when
    /// [`num_present_peaks`](Self::num_present_peaks) is wrong, and with
    /// [`MerkleError::MissingPeak`] for a set bit with no peak or a zero-hash
    /// peak, which `set_peak` treats as unset.
    fn validate(&self) -> Result<(), MerkleError> {
        let entries = self.num_entries();
        let max_num_peaks = self.max_num_peaks();
        if u32::from(max_num_peaks) < u64::BITS && entries >> max_num_peaks != 0 {
            return Err(MerkleError::EntriesExceedCapacity {
                entries,
                max_num_peaks,
            });
        }
        let expected = entries.count_ones() as usize;
        let actual = self.num_present_peaks() as usize;
        if actual != expected {
            return Err(MerkleError::PeakCountMismatch { expected, actual });
        }
        for height in 0..u64::BITS as u8 {
            let set = (entries >> height) & 1 == 1;
            if set && !self.get_peak(height).is_some_and(|peak| !H::is_zero(peak)) {
                return Err(MerkleError::MissingPeak { height });
            }
        }
        Ok(())
    }
}
