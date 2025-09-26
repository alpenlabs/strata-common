//! High-level util functions.

use crate::{BufDecoder, Codec, CodecError};

/// Decodes a buffer from a buffer, throwing an error if there's leftover bytes.
pub fn decode_buf_exact<T: Codec>(buf: &[u8]) -> Result<T, CodecError> {
    let mut dec = BufDecoder::new(buf);
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
