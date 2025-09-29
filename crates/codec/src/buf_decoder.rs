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
        self.len() - self.at
    }

    /// Returns the slice of the remaining unread bytes, which might be empty.
    fn rest(&self) -> &[u8] {
        &self.buf.as_ref()[self.at..]
    }
}

impl<B: AsRef<[u8]>> Decoder for BufDecoder<B> {
    fn read_buf(&mut self, into: &mut [u8]) -> Result<(), CodecError> {
        if into.len() > self.remaining() {
            return Err(CodecError::OverrunInput);
        }

        into.copy_from_slice(&self.rest()[..into.len()]);
        Ok(())
    }

    fn read_arr<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        if N > self.remaining() {
            return Err(CodecError::OverrunInput);
        }

        let mut buf = [0; N];
        buf.copy_from_slice(&self.rest()[..N]);
        Ok(buf)
    }
}
