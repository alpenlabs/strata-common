//! Common utilities.

use std::mem;

/// Maximum decoding size hint that we'll respect.
const MAX_RESPECTED_HINT_BYTES: usize = 1 << 20; // 1 MiB

/// Accepts a size hint and returns an new empty [`Vec`], potentially with a
/// preallocated backing buffer.
///
/// If the total bytes that would be allocated based on the hint are below a
/// resaonable size limit, the vec has the length hint number of bytes
/// preallocated.  If it's over the limit, then we prealloc the most that would
/// fit within the capacity limit.
pub(crate) fn prealloc_hinted_vec<T>(hint: Option<usize>) -> Vec<T> {
    let max_safe_len: usize = MAX_RESPECTED_HINT_BYTES / mem::size_of::<T>();
    let len = hint.map(|len| len.min(max_safe_len)).unwrap_or_default();
    Vec::with_capacity(len)
}
