use crate::CodecError;

/// Generic codec trait for "plain old data" types that compactly go between bytes.
pub trait Codec: Sized {
    /// Decodes self from a decoder.
    fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError>;

    /// Encodes self into an encoder.
    fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError>;
}

/// Which byte spellings of a value a decoder accepts.
///
/// Canonical decoding is the rule: every value has the one encoding `encode`
/// writes, so bytes under a hash or a signature cannot be rewritten without
/// changing what they decode to. Data that was proven or signed before the
/// decoders enforced that rule must still decode as it did then, so a decoder
/// can be told to take the spellings they accepted at the time. Which rules an
/// input decodes under is the caller's decision, made where the input's
/// provenance is known.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum DecodeRules {
    /// Only the bytes `encode` writes.
    #[default]
    Canonical,

    /// Also the longer or padded spellings the decoders accepted before
    /// canonical decoding was enforced. The value decodes the same; only the
    /// one-encoding guarantee is given up.
    Lenient,
}

impl DecodeRules {
    /// Returns whether only canonical encodings are accepted.
    pub const fn is_canonical(self) -> bool {
        matches!(self, Self::Canonical)
    }
}

/// Generic decoder trait that reads inputs.
pub trait Decoder {
    /// Reads a variable-size buf.  This does NOT include length tagging.
    fn read_buf(&mut self, into: &mut [u8]) -> Result<(), CodecError>;

    /// Reads a fixed size buf.  This does NOT include length tagging.
    fn read_arr<const N: usize>(&mut self) -> Result<[u8; N], CodecError>;

    /// Returns the rules this decoder reads under.
    ///
    /// Codecs with more than one possible spelling per value consult this and
    /// reject the noncanonical ones unless the rules are
    /// [`DecodeRules::Lenient`]. A decoder that does not choose reads
    /// canonically.
    fn rules(&self) -> DecodeRules {
        DecodeRules::Canonical
    }
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
