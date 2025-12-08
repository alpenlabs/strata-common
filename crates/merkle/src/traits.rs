//! Traits for MMR state.

use crate::hasher::MerkleHash;

/// Abstracts over an MMR accumulator's state.
pub trait MmrState<H: MerkleHash> {
    /// Gets the maximum number of peaks we can store.
    fn max_num_peaks(&self) -> u8;

    /// Gets the current number of entries inserted into the MMR.
    fn num_entries(&self) -> u64;

    /// Gets the number of set peaks.
    ///
    /// This should be the popcnt of `num_entries`.
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
}
