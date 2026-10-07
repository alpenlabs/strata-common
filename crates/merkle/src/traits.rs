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

    /// Checks that the peaks match the entry count: one non-zero peak for each
    /// set bit of [`num_entries`](Self::num_entries).
    ///
    /// Decoding does not check this, so call it on any accumulator built from
    /// untrusted bytes. The default only sees peaks through
    /// [`get_peak`](Self::get_peak), so it cannot see extra stored peaks. A type
    /// that stores its peaks in a list should override it to check the list
    /// length too.
    ///
    /// Errors with [`MerkleError::MissingPeak`] for a set bit with no peak or a
    /// zero-hash peak, which `set_peak` treats as unset, and with
    /// [`MerkleError::PeakCountMismatch`] from overrides that check the length.
    fn validate(&self) -> Result<(), MerkleError> {
        check_peaks(self)
    }
}

/// The default [`MmrState::validate`] check, shared with the overrides.
pub(crate) fn check_peaks<H: MerkleHash, S: MmrState<H> + ?Sized>(
    state: &S,
) -> Result<(), MerkleError> {
    let entries = state.num_entries();
    for height in 0..u64::BITS as u8 {
        let set = (entries >> height) & 1 == 1;
        if set && !state.get_peak(height).is_some_and(|peak| !H::is_zero(peak)) {
            return Err(MerkleError::MissingPeak { height });
        }
    }
    Ok(())
}

/// Checks that a list of `stored` peaks has one peak per set bit of `entries`.
#[cfg(any(feature = "ssz", feature = "legacy_compact", test))]
pub(crate) fn check_peak_count(entries: u64, stored: usize) -> Result<(), MerkleError> {
    let expected = entries.count_ones() as usize;
    if stored != expected {
        return Err(MerkleError::PeakCountMismatch {
            expected,
            actual: stored,
        });
    }
    Ok(())
}
