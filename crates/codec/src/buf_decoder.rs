//! Simple decoder for a flat buffer.

use crate::errors::CodecError;
use crate::types::Decoder;

/// Decoder for an arbitrary [`AsRef`] on a byte slice.
///
/// You probably don't need to use this directly as a consumer of this library,
/// you can directly call [`crate::decode_buf_exact`] and
/// [`crate::encode_to_vec`].
#[derive(Debug)]
pub struct BufDecoder<B> {
    buf: B,
    at: usize,
}

impl<B: AsRef<[u8]>> BufDecoder<B> {
    /// Constructs a new instance by wrapping a buffer and starting at the
    /// beginning.
    pub fn new(buf: B) -> Self {
        Self { buf, at: 0 }
    }

    /// Returns the length of the underlying buffer.
    pub fn len(&self) -> usize {
        self.buf.as_ref().len()
    }

    /// Returns if the underlying buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.as_ref().is_empty()
    }

    /// Returns the total number of remaining bytes that can be read.
    pub fn remaining(&self) -> usize {
        self.rest().len()
    }

    /// Returns the slice of the remaining unread bytes, which might be empty.
    ///
    /// [`AsRef::as_ref`] is not required to return the same slice on every
    /// call, so this borrows it exactly once and treats a buffer that has
    /// shrunk below the cursor as exhausted instead of panicking. Callers must
    /// bounds-check against the returned slice rather than a separately
    /// computed length.
    fn rest(&self) -> &[u8] {
        self.buf.as_ref().get(self.at..).unwrap_or_default()
    }
}

impl<B: AsRef<[u8]>> Decoder for BufDecoder<B> {
    fn read_buf(&mut self, into: &mut [u8]) -> Result<(), CodecError> {
        let src = self
            .rest()
            .get(..into.len())
            .ok_or(CodecError::OverrunInput)?;
        into.copy_from_slice(src);
        self.at += into.len();
        Ok(())
    }

    fn read_arr<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let src = self.rest().get(..N).ok_or(CodecError::OverrunInput)?;
        let mut buf = [0; N];
        buf.copy_from_slice(src);
        self.at += N;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    /// Buffer whose [`AsRef`] alternates between a long and a short slice,
    /// mimicking a nonidempotent implementation.
    struct RotatingBuf {
        long: [u8; 8],
        short: [u8; 1],
        flip: Cell<bool>,
    }

    impl RotatingBuf {
        fn new() -> Self {
            Self {
                long: [1, 2, 3, 4, 5, 6, 7, 8],
                short: [9],
                flip: Cell::new(false),
            }
        }
    }

    impl AsRef<[u8]> for RotatingBuf {
        fn as_ref(&self) -> &[u8] {
            let flip = self.flip.get();
            self.flip.set(!flip);
            if flip { &self.short } else { &self.long }
        }
    }

    #[test]
    fn read_buf_with_nonidempotent_as_ref_does_not_panic() {
        // Previously `remaining()` saw the long slice and `rest()` indexed the
        // short one, panicking on the first read.
        let mut dec = BufDecoder::new(RotatingBuf::new());
        let mut into = [0u8; 4];

        dec.read_buf(&mut into).unwrap();
        assert_eq!(into, [1, 2, 3, 4]);

        // Short slice is now behind the cursor: report an overrun, not panic.
        assert!(matches!(
            dec.read_buf(&mut into),
            Err(CodecError::OverrunInput)
        ));

        dec.read_buf(&mut into).unwrap();
        assert_eq!(into, [5, 6, 7, 8]);
    }

    #[test]
    fn read_arr_with_nonidempotent_as_ref_does_not_panic() {
        let mut dec = BufDecoder::new(RotatingBuf::new());

        assert_eq!(dec.read_arr::<4>().unwrap(), [1, 2, 3, 4]);
        assert!(matches!(dec.read_arr::<4>(), Err(CodecError::OverrunInput)));
        assert_eq!(dec.read_arr::<4>().unwrap(), [5, 6, 7, 8]);
    }

    #[test]
    fn remaining_with_cursor_past_shrunk_buffer_is_zero() {
        let mut dec = BufDecoder::new(RotatingBuf::new());
        assert_eq!(dec.read_arr::<4>().unwrap(), [1, 2, 3, 4]);

        // Cursor (4) is past the short slice (len 1); this used to underflow.
        assert_eq!(dec.remaining(), 0);
        assert_eq!(dec.remaining(), 4);
    }

    #[test]
    fn read_buf_overrun_on_stable_buffer_errors() {
        let mut dec = BufDecoder::new([1u8, 2, 3]);
        let mut into = [0u8; 4];
        assert!(matches!(
            dec.read_buf(&mut into),
            Err(CodecError::OverrunInput)
        ));
        assert_eq!(dec.remaining(), 3);

        assert_eq!(dec.read_arr::<3>().unwrap(), [1, 2, 3]);
        assert_eq!(dec.remaining(), 0);
        assert!(matches!(dec.read_arr::<1>(), Err(CodecError::OverrunInput)));
    }
}
