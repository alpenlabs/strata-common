use crate::CodecError;

/// Generic codec trait for "plain old data" types that compactly go between bytes.
pub trait Codec: Sized {
    /// Decodes self from a decoder.
    fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError>;

    /// Encodes self into an encoder.
    fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError>;
}

/// Generic decoder trait that reads inputs.
pub trait Decoder {
    /// Reads a variable-size buf.  This does NOT include length tagging.
    fn read_buf(&mut self, into: &mut [u8]) -> Result<(), CodecError>;

    /// Reads a fixed size buf.  This does NOT include length tagging.
    fn read_arr<const N: usize>(&mut self) -> Result<[u8; N], CodecError>;
}

/// Generic encoder trait that writes outputs.
pub trait Encoder {
    /// Writes a buf.  This does NOT include length tagging.
    fn write_buf(&mut self, buf: &[u8]) -> Result<(), CodecError>;
}

/// Impl for byte arrays.
impl<const N: usize> Codec for [u8; N] {
    fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError> {
        let mut buf = [0; N];
        dec.read_buf(&mut buf)?;
        Ok(buf)
    }

    fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError> {
        enc.write_buf(self)
    }
}

/// Decoder for an arbitrary [`AsRef`] on a byte slice.
#[derive(Debug)]
pub struct BufDecoder<B> {
    buf: B,
    at: usize,
}

impl<B: AsRef<[u8]>> BufDecoder<B> {
    /// Constructs a new instance.
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

impl Encoder for Vec<u8> {
    fn write_buf(&mut self, buf: &[u8]) -> Result<(), CodecError> {
        self.extend_from_slice(buf);
        Ok(())
    }
}

macro_rules! impl_int_codec {
    ( $ity:ident $bytes:literal ) => {
        impl Codec for $ity {
            fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError> {
                let arr: [u8; $bytes] = dec.read_arr()?;
                Ok(<$ity>::from_be_bytes(arr))
            }

            fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError> {
                Ok(enc.write_buf(&self.to_be_bytes())?)
            }
        }
    };
}

impl_int_codec!(u8 1);
impl_int_codec!(i8 1);
impl_int_codec!(u16 2);
impl_int_codec!(i16 2);
impl_int_codec!(u32 4);
impl_int_codec!(i32 4);
impl_int_codec!(u64 8);
impl_int_codec!(i64 8);
