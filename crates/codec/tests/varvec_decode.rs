//! Regression tests for premature allocation during `VarVec` decoding (SECFND-102).
//!
//! Allocations are tracked per thread, so tests running in parallel do not see each
//! other's allocations.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::TryReserveError;
use std::error::Error;
use std::mem::size_of;
use std::ptr::null_mut;

use strata_codec::{
    Codec, CodecError, Decoder, Encoder, VarVec, Varint, decode_buf_exact, encode_to_vec,
};
#[cfg(feature = "derive")]
use strata_codec_derive as _;
use thiserror as _;

#[derive(Clone, Copy, Debug, Default)]
struct AllocationState {
    /// Counts allocation and reallocation requests.
    attempts: usize,

    /// Records the largest requested size in bytes.
    largest_request: usize,

    /// Rejects the next allocation request only, then resets.
    fail_next: bool,

    /// Records whether a request was rejected by failure injection.
    injected_failure: bool,
}

thread_local! {
    static ALLOCATION_STATE: Cell<Option<AllocationState>> = const { Cell::new(None) };
}

/// Records an allocation request and returns whether to reject it.
fn record_allocation(size: usize) -> bool {
    ALLOCATION_STATE
        .try_with(|tracker| {
            let Some(mut allocations) = tracker.get() else {
                return false;
            };
            allocations.attempts += 1;
            allocations.largest_request = allocations.largest_request.max(size);
            let reject = allocations.fail_next;
            allocations.fail_next = false;
            allocations.injected_failure |= reject;
            tracker.set(Some(allocations));
            reject
        })
        .unwrap_or(false)
}

struct TrackingAllocator;

// SAFETY: Successful requests and all deallocations use System with unchanged arguments.
// Rejected requests return null, as permitted by GlobalAlloc.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if record_allocation(layout.size()) {
            return null_mut();
        }
        // SAFETY: The caller supplies a valid allocation layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if record_allocation(layout.size()) {
            return null_mut();
        }
        // SAFETY: The caller supplies a valid allocation layout.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if record_allocation(new_size) {
            return null_mut();
        }
        // SAFETY: Allocations originate from System, and the caller supplies valid arguments.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: Allocations originate from System with the supplied layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

fn track_allocations<T>(action: impl FnOnce() -> T) -> (T, AllocationState) {
    track_allocations_with_state(AllocationState::default(), action)
}

fn track_allocations_failing_first<T>(action: impl FnOnce() -> T) -> (T, AllocationState) {
    track_allocations_with_state(
        AllocationState {
            fail_next: true,
            ..AllocationState::default()
        },
        action,
    )
}

fn track_allocations_with_state<T>(
    state: AllocationState,
    action: impl FnOnce() -> T,
) -> (T, AllocationState) {
    struct ResetTracker;
    impl Drop for ResetTracker {
        fn drop(&mut self) {
            ALLOCATION_STATE.with(|tracker| tracker.set(None));
        }
    }

    ALLOCATION_STATE.with(|tracker| {
        assert!(
            tracker.get().is_none(),
            "allocation tracking must not be nested"
        );
        tracker.set(Some(state));
    });
    let _reset = ResetTracker;
    let result = action();
    let allocations = ALLOCATION_STATE.with(|tracker| tracker.take().unwrap());
    (result, allocations)
}

/// Declared element count with no matching body (1 MiB of `[u8; 32]` if reserved up front).
const DECLARED_LEN: u32 = 32_768;

#[test]
fn length_prefix_without_elements_does_not_allocate() {
    let bytes = encode_to_vec(&Varint::new(DECLARED_LEN).unwrap()).unwrap();
    let (result, allocations) = track_allocations(|| decode_buf_exact::<VarVec<[u8; 32]>>(&bytes));
    assert!(
        matches!(result, Err(CodecError::OverrunInput)),
        "{result:?}"
    );
    assert_eq!(allocations.attempts, 0);
}

#[test]
fn truncated_body_allocates_only_for_decoded_elements() {
    // Establish the one-element growth size outside the tracked decode.
    let mut single_element_vec = Vec::<[u8; 32]>::new();
    single_element_vec.try_reserve(1).unwrap();
    let single_element_bytes = single_element_vec.capacity() * size_of::<[u8; 32]>();

    // Declares DECLARED_LEN elements but supplies only one.
    let mut bytes = encode_to_vec(&Varint::new(DECLARED_LEN).unwrap()).unwrap();
    bytes.extend_from_slice(&[0x11; 32]);
    let (result, allocations) = track_allocations(|| decode_buf_exact::<VarVec<[u8; 32]>>(&bytes));
    assert!(
        matches!(result, Err(CodecError::OverrunInput)),
        "{result:?}"
    );
    assert_eq!(allocations.attempts, 1);
    assert!(
        allocations.largest_request <= single_element_bytes,
        "largest request = {}, one-element growth = {single_element_bytes}",
        allocations.largest_request
    );
}

#[test]
fn length_above_bound_is_rejected_without_allocation() {
    const BOUND: u32 = 8;
    let bytes = encode_to_vec(&Varint::new(BOUND + 1).unwrap()).unwrap();
    let (result, allocations) =
        track_allocations(|| decode_buf_exact::<VarVec<[u8; 32], BOUND>>(&bytes));
    assert!(
        matches!(result, Err(CodecError::OverflowContainer)),
        "{result:?}"
    );
    assert_eq!(allocations.attempts, 0);
}

#[test]
fn nested_length_prefixes_without_elements_do_not_allocate() {
    // Outer count 1, inner count DECLARED_LEN, no inner elements.
    let mut bytes = vec![1];
    bytes.extend_from_slice(&encode_to_vec(&Varint::new(DECLARED_LEN).unwrap()).unwrap());
    let (result, allocations) =
        track_allocations(|| decode_buf_exact::<VarVec<VarVec<[u8; 32]>, 1>>(&bytes));
    assert!(
        matches!(result, Err(CodecError::OverrunInput)),
        "{result:?}"
    );
    assert_eq!(allocations.attempts, 0);
}

#[test]
fn invalid_first_element_returns_its_error_without_allocation() {
    // Count 1, then byte 2, which is not a valid bool.
    let (result, allocations) = track_allocations(|| decode_buf_exact::<VarVec<bool, 1>>(&[1, 2]));
    assert!(
        matches!(result, Err(CodecError::InvalidVariant("bool"))),
        "{result:?}"
    );
    assert_eq!(allocations.attempts, 0);
}

#[test]
fn known_encodings_round_trip_unchanged() {
    // u16 values use big-endian bytes; the final case reaches the bound of four.
    for (bytes, expected) in [
        (&[0][..], &[][..]),
        (&[2, 0x11, 0x22, 0x33, 0x44][..], &[0x1122, 0x3344][..]),
        (
            &[4, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88][..],
            &[0x1122, 0x3344, 0x5566, 0x7788][..],
        ),
    ] {
        let decoded = decode_buf_exact::<VarVec<u16, 4>>(bytes).unwrap();
        assert_eq!(decoded.as_slice(), expected);
        assert_eq!(encode_to_vec(&decoded).unwrap(), bytes);
    }
}

/// Encodes to zero bytes, so a count alone decodes into elements.
#[derive(Debug)]
struct ZeroByteElement;

impl Codec for ZeroByteElement {
    fn decode(_dec: &mut impl Decoder) -> Result<Self, CodecError> {
        Ok(Self)
    }

    fn encode(&self, _enc: &mut impl Encoder) -> Result<(), CodecError> {
        Ok(())
    }
}

#[test]
fn zero_byte_elements_decode_at_bound_without_allocation() {
    const BOUND: u32 = 4;
    let bytes = encode_to_vec(&Varint::new(BOUND).unwrap()).unwrap();
    let (result, allocations) =
        track_allocations(|| decode_buf_exact::<VarVec<ZeroByteElement, BOUND>>(&bytes));
    let decoded = result.unwrap();
    assert_eq!(decoded.len(), BOUND as usize);
    assert_eq!(allocations.attempts, 0);
    assert_eq!(encode_to_vec(&decoded).unwrap(), bytes);
}

#[test]
fn zero_byte_elements_above_bound_are_rejected() {
    const BOUND: u32 = 4;
    let bytes = encode_to_vec(&Varint::new(BOUND + 1).unwrap()).unwrap();
    let (result, allocations) =
        track_allocations(|| decode_buf_exact::<VarVec<ZeroByteElement, BOUND>>(&bytes));
    assert!(
        matches!(result, Err(CodecError::OverflowContainer)),
        "{result:?}"
    );
    assert_eq!(allocations.attempts, 0);
}

#[test]
fn allocation_failure_returns_allocation_failed_with_source() {
    // One u8, so the decoder's first try_reserve hits the injected failure.
    let bytes = [1, 0x11];
    let (result, allocations) =
        track_allocations_failing_first(|| decode_buf_exact::<VarVec<u8, 1>>(&bytes));
    let error = result.unwrap_err();
    assert!(
        matches!(error, CodecError::AllocationFailed(_)),
        "{error:?}"
    );
    assert_eq!(error.to_string(), "allocation failed");
    let source = error
        .source()
        .expect("allocation failure preserves its source");
    assert!(
        source.downcast_ref::<TryReserveError>().is_some(),
        "{source:?}"
    );
    assert!(allocations.injected_failure, "{allocations:?}");
    assert_eq!(allocations.attempts, 1);
}
