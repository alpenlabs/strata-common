//! Shims for SSZ decodeable types.

use std::marker::PhantomData;

use rkyv::{Archive, Deserialize, Serialize};
use rkyv_impl::archive_impl;
use ssz::{Decode, DecodeError, Encode};

/// Wrapper around [`Vec<u8>`] which is presumed to contain a valid SSZ-encoded
/// instance of a `T`.  Exposes helpers for decoding.
#[derive(Clone, Debug, Archive, Deserialize, Serialize)]
pub struct RkSsz<T: Decode>(Vec<u8>, PhantomData<T>);

impl<T: Decode> RkSsz<T> {
    /// Constructs a new instance from an arbitrary buffer without checking its
    /// validity.
    pub fn new_unchecked(buf: Vec<u8>) -> Self {
        Self(buf, PhantomData)
    }

    /// Encodes a SSZ value to bytes and returns the [`RkSsz`] of it.
    pub fn encode(val: &T) -> Self
    where
        T: Encode,
    {
        Self::new_unchecked(val.as_ssz_bytes())
    }

    /// Unwraps the container and returns the underlying buffer.
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

/// A buffer presumed to contain a valid SSZ-encoded instance of [`SszBuf::Target`].
///
/// Implemented by both [`RkSsz`] and its archived form, so consumers can be
/// generic over which representation they accept.  The raw bytes are accessed
/// via the [`AsRef<[u8]>`] supertrait; [`try_decode`](SszBuf::try_decode) is
/// provided.
pub trait SszBuf: AsRef<[u8]> {
    /// The type the buffer is expected to decode to.
    type Target: Decode;

    /// Attempts to decode the contained value, propagating any error.
    fn try_decode(&self) -> Result<Self::Target, DecodeError> {
        Self::Target::from_ssz_bytes(self.as_ref())
    }
}

/// Generates `AsRef<[u8]>` for both [`RkSsz`] and `ArchivedRkSsz`; both store
/// the bytes in field `0` (a `Vec<u8>`/`ArchivedVec<u8>`) which exposes
/// `as_slice`.
#[archive_impl]
impl<T: Decode> AsRef<[u8]> for RkSsz<T> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<T: Decode> SszBuf for RkSsz<T> {
    type Target = T;
}

impl<T: Decode> SszBuf for ArchivedRkSsz<T> {
    type Target = T;
}

#[cfg(test)]
mod tests {
    use rkyv::rancor::Error as RkyvError;
    use rkyv::{Archive, Deserialize, Serialize};
    use ssz_derive::{Decode, Encode};

    use super::*;

    /// A nontrivial SSZ container mixing fixed-size fields (`u64`, `bool`) with
    /// variable-length fields (the two `Vec`s), so SSZ encoding has to deal with
    /// offsets rather than a flat fixed layout.
    #[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
    #[ssz(struct_behaviour = "container")]
    struct ExampleMsg {
        id: u64,
        flag: bool,
        payload: Vec<u8>,
        tags: Vec<u32>,
    }

    /// An outer rkyv type that carries an SSZ payload via [`RkSsz`].  This is the
    /// real intended use: an SSZ-encoded value living inside an rkyv structure.
    #[derive(Archive, Serialize, Deserialize, Debug)]
    struct Envelope {
        seq: u32,
        body: RkSsz<ExampleMsg>,
    }

    fn sample_msg() -> ExampleMsg {
        ExampleMsg {
            id: 0xdead_beef_0000_1234,
            flag: true,
            payload: vec![1, 2, 3, 4, 5],
            tags: vec![0xaabb_ccdd, 0x1122_3344, 7],
        }
    }

    #[test]
    fn encode_matches_direct_ssz_and_decodes() {
        let msg = sample_msg();
        let wrapped = RkSsz::encode(&msg);

        // The wrapped buffer is exactly what a direct SSZ encode produces.
        assert_eq!(wrapped.as_ref(), msg.as_ssz_bytes().as_slice());

        // ...and it decodes back to the original value.
        assert_eq!(wrapped.try_decode().expect("ssz decode"), msg);
    }

    #[test]
    fn try_decode_rejects_truncated_buffer() {
        // The `id` field alone needs 8 bytes, so this can't decode.
        let bad = RkSsz::<ExampleMsg>::new_unchecked(vec![0x00, 0x01]);
        assert!(bad.try_decode().is_err());
    }

    /// The full intended path: SSZ-encode a value, wrap it in an rkyv type,
    /// serialize the whole thing through rkyv, read it back, and recover the
    /// original SSZ value -- both zero-copy from the archived form and via a
    /// full deserialize.
    #[test]
    fn full_ssz_then_rkyv_roundtrip() {
        let msg = sample_msg();
        let envelope = Envelope {
            seq: 42,
            body: RkSsz::encode(&msg),
        };

        // rkyv serialize the whole envelope.
        let bytes = rkyv::to_bytes::<RkyvError>(&envelope).expect("rkyv serialize");

        // Zero-copy access to the archived form; the SSZ bytes survive intact
        // and decode straight out of the archived buffer.
        let archived = rkyv::access::<ArchivedEnvelope, RkyvError>(&bytes).expect("rkyv access");
        assert_eq!(archived.seq.to_native(), 42);
        assert_eq!(archived.body.as_ref(), msg.as_ssz_bytes().as_slice());
        assert_eq!(
            archived.body.try_decode().expect("ssz decode archived"),
            msg
        );

        // Full rkyv deserialize back to an owned `Envelope`, then SSZ-decode.
        let owned: Envelope = rkyv::from_bytes::<_, RkyvError>(&bytes).expect("rkyv deserialize");
        assert_eq!(owned.seq, 42);
        assert_eq!(owned.body.as_ref(), msg.as_ssz_bytes().as_slice());
        assert_eq!(owned.body.try_decode().expect("ssz decode owned"), msg);
    }
}
