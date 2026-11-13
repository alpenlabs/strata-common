//! High-level util functions.

use crate::{BufDecoder, Codec, CodecError, DecodeRules};

/// Decodes a value from a buffer under [`DecodeRules::Canonical`], throwing an
/// error if there's leftover bytes.
pub fn decode_buf_exact<T: Codec>(buf: &[u8]) -> Result<T, CodecError> {
    decode_buf_exact_with_rules(buf, DecodeRules::Canonical)
}

/// Decodes a value from a buffer under the given rules, throwing an error if
/// there's leftover bytes.
///
/// [`DecodeRules::Lenient`] is for input whose bytes were fixed under the
/// older decoders, such as data a proof already covers; new input should go
/// through [`decode_buf_exact`].
pub fn decode_buf_exact_with_rules<T: Codec>(
    buf: &[u8],
    rules: DecodeRules,
) -> Result<T, CodecError> {
    let mut dec = BufDecoder::with_rules(buf, rules);
    let v = T::decode(&mut dec)?;
    if dec.remaining() > 0 {
        return Err(CodecError::ExtraInput);
    }
    Ok(v)
}

/// Encodes the value into a newly allocated vec.
pub fn encode_to_vec<T: Codec>(v: &T) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::new();
    v.encode(&mut buf)?;
    Ok(buf)
}
