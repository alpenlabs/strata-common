//! Shims for [`strata-codec`](strata_codec) decodeable types.

use std::marker::PhantomData;

use rkyv::{Archive, Deserialize, Serialize};
use rkyv_impl::archive_impl;
use strata_codec::{Codec, CodecError, decode_buf_exact, encode_to_vec};

/// Wrapper around [`Vec<u8>`] which is presumed to contain a valid
/// [`Codec`]-encoded instance of a `T`.  Exposes helpers for decoding.
#[derive(Clone, Debug, Archive, Deserialize, Serialize)]
pub struct RkCodec<T: Codec>(Vec<u8>, PhantomData<T>);

impl<T: Codec> RkCodec<T> {
    /// Constructs a new instance from an arbitrary buffer without checking its
    /// validity.
    pub fn new_unchecked(buf: Vec<u8>) -> Self {
        Self(buf, PhantomData)
    }

    /// Encodes a [`Codec`] value to bytes and returns the [`RkCodec`] of it.
    pub fn encode(val: &T) -> Result<Self, CodecError> {
        Ok(Self::new_unchecked(encode_to_vec(val)?))
    }

    /// Unwraps the container and returns the underlying buffer.
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

/// A buffer presumed to contain a valid [`Codec`]-encoded instance of
/// [`CodecBuf::Target`].
///
/// Implemented by both [`RkCodec`] and its archived form, so consumers can be
/// generic over which representation they accept.  The raw bytes are accessed
/// via the [`AsRef<[u8]>`] supertrait; [`try_decode`](CodecBuf::try_decode) is
/// provided.
pub trait CodecBuf: AsRef<[u8]> {
    /// The type the buffer is expected to decode to.
    type Target: Codec;

    /// Attempts to decode the contained value, propagating any error.
    fn try_decode(&self) -> Result<Self::Target, CodecError> {
        decode_buf_exact(self.as_ref())
    }
}

/// Generates `AsRef<[u8]>` for both [`RkCodec`] and `ArchivedRkCodec`; both
/// store the bytes in field `0` (a `Vec<u8>`/`ArchivedVec<u8>`) which exposes
/// `as_slice`.
#[archive_impl]
impl<T: Codec> AsRef<[u8]> for RkCodec<T> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<T: Codec> CodecBuf for RkCodec<T> {
    type Target = T;
}

impl<T: Codec> CodecBuf for ArchivedRkCodec<T> {
    type Target = T;
}

#[cfg(test)]
mod tests {
    use rkyv::rancor::Error as RkyvError;
    use rkyv::{Archive, Deserialize, Serialize};
    use strata_codec::{Codec, VarVec};

    use super::*;

    /// A nontrivial [`Codec`] container mixing fixed-size fields (`u64`, `bool`,
    /// a byte array) with variable-length fields (the two [`VarVec`]s), so the
    /// encoding has to deal with length prefixes rather than a flat fixed
    /// layout.
    #[derive(Debug, Clone, PartialEq, Eq, Codec)]
    struct ExampleMsg {
        id: u64,
        flag: bool,
        salt: [u8; 4],
        payload: VarVec<u8>,
        tags: VarVec<u32>,
    }

    /// An outer rkyv type that carries a [`Codec`] payload via [`RkCodec`].
    /// This is the real intended use: a [`Codec`]-encoded value living inside an
    /// rkyv structure.
    #[derive(Archive, Serialize, Deserialize, Debug)]
    struct Envelope {
        seq: u32,
        body: RkCodec<ExampleMsg>,
    }

    fn sample_msg() -> ExampleMsg {
        ExampleMsg {
            id: 0xdead_beef_0000_1234,
            flag: true,
            salt: [0xde, 0xad, 0xbe, 0xef],
            payload: VarVec::from_vec(vec![1, 2, 3, 4, 5]).expect("payload"),
            tags: VarVec::from_vec(vec![0xaabb_ccdd, 0x1122_3344, 7]).expect("tags"),
        }
    }

    #[test]
    fn encode_matches_direct_codec_and_decodes() {
        let msg = sample_msg();
        let wrapped = RkCodec::encode(&msg).expect("codec encode");

        // The wrapped buffer is exactly what a direct codec encode produces.
        assert_eq!(
            wrapped.as_ref(),
            encode_to_vec(&msg).expect("encode").as_slice()
        );

        // ...and it decodes back to the original value.
        assert_eq!(wrapped.try_decode().expect("codec decode"), msg);
    }

    #[test]
    fn try_decode_rejects_truncated_buffer() {
        // The `id` field alone needs 8 bytes, so this can't decode.
        let bad = RkCodec::<ExampleMsg>::new_unchecked(vec![0x00, 0x01]);
        assert!(bad.try_decode().is_err());
    }

    /// The full intended path: codec-encode a value, wrap it in an rkyv type,
    /// serialize the whole thing through rkyv, read it back, and recover the
    /// original codec value -- both zero-copy from the archived form and via a
    /// full deserialize.
    #[test]
    fn full_codec_then_rkyv_roundtrip() {
        let msg = sample_msg();
        let envelope = Envelope {
            seq: 42,
            body: RkCodec::encode(&msg).expect("codec encode"),
        };

        // rkyv serialize the whole envelope.
        let bytes = rkyv::to_bytes::<RkyvError>(&envelope).expect("rkyv serialize");

        // Zero-copy access to the archived form; the codec bytes survive intact
        // and decode straight out of the archived buffer.
        let archived = rkyv::access::<ArchivedEnvelope, RkyvError>(&bytes).expect("rkyv access");
        assert_eq!(archived.seq.to_native(), 42);
        assert_eq!(
            archived.body.as_ref(),
            encode_to_vec(&msg).expect("encode").as_slice()
        );
        assert_eq!(
            archived.body.try_decode().expect("codec decode archived"),
            msg
        );

        // Full rkyv deserialize back to an owned `Envelope`, then codec-decode.
        let owned: Envelope = rkyv::from_bytes::<_, RkyvError>(&bytes).expect("rkyv deserialize");
        assert_eq!(owned.seq, 42);
        assert_eq!(
            owned.body.as_ref(),
            encode_to_vec(&msg).expect("encode").as_slice()
        );
        assert_eq!(owned.body.try_decode().expect("codec decode owned"), msg);
    }
}
