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

/// Encoding to a vec buffer.
impl Encoder for Vec<u8> {
    fn write_buf(&mut self, buf: &[u8]) -> Result<(), CodecError> {
        self.extend_from_slice(buf);
        Ok(())
    }
}

/// Impl for byte arrays.
impl<const N: usize> Codec for [u8; N] {
    fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError> {
        dec.read_arr::<N>()
    }

    fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError> {
        enc.write_buf(self)
    }
}

impl Codec for bool {
    fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError> {
        let b = dec.read_arr::<1>()?;
        match b[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CodecError::InvalidVariant("bool")),
        }
    }

    fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError> {
        enc.write_buf(&[if *self { 1 } else { 0 }])
    }
}

/// Simple macro to wrap the fixed size int types, not much to see.
macro_rules! impl_int_codec {
    ( $ity:ident $bytes:literal ) => {
        impl Codec for $ity {
            fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError> {
                let arr: [u8; $bytes] = dec.read_arr()?;
                Ok(<$ity>::from_be_bytes(arr))
            }

            fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError> {
                enc.write_buf(&self.to_be_bytes())
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
