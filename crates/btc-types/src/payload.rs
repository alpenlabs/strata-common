//! Types relating to payloads.
//!
//! These types don't care about the *purpose* of the payloads, we only care about what's in them.

use arbitrary::Arbitrary;
use borsh::{BorshDeserialize, BorshSerialize};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use ssz::DecodeError;
use ssz_derive::{Decode, Encode};
use ssz_primitives::FixedBytes;
use strata_identifiers::{Buf32, SszDelegate, impl_borsh_via_ssz, impl_ssz_via_delegate};
use strata_l1_txfmt::TagData;

use crate::ssz_generated::ssz::btc::{
    BlobSpecSsz, L1PayloadSsz, MAX_PAYLOAD_CHUNK_LEN, MAX_PAYLOAD_CHUNKS, PayloadIntentSsz,
    PayloadSpecSsz,
};

/// DA destination identifier. This will eventually be used to enable
/// storing payloads on alternative availability schemes.
#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    BorshDeserialize,
    BorshSerialize,
    IntoPrimitive,
    TryFromPrimitive,
    Serialize,
    Deserialize,
    Encode,
    Decode,
)]
#[borsh(use_discriminant = true)]
#[ssz(enum_behaviour = "tag")]
#[repr(u8)]
pub enum PayloadDest {
    /// If we expect the DA to be on the L1 chain that we settle to. This is
    /// always the strongest DA layer we have access to.
    L1 = 0,
}

/// Manual `Arbitrary` impl so that we always generate L1 DA if we add future
/// ones that would work in totally different ways.
impl<'a> Arbitrary<'a> for PayloadDest {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::L1)
    }
}

/// Summary of a DA payload to be included on a DA layer. Specifies the target and
/// a commitment to the payload.
#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Hash,
    Arbitrary,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
)]
pub struct BlobSpec {
    /// Target settlement layer we're expecting the DA on.
    dest: PayloadDest,

    /// Commitment to the payload (probably just a hash or a
    /// merkle root) that we expect to see committed to DA.
    commitment: Buf32,
}

// SSZ encoding delegates to the generated [`BlobSpecSsz`] container — correct by
// construction rather than hand-rolled.
impl SszDelegate for BlobSpec {
    type Delegate = BlobSpecSsz;

    fn into_delegate(self) -> Self::Delegate {
        BlobSpecSsz {
            dest: self.dest.into(),
            commitment: FixedBytes(self.commitment.0),
        }
    }

    fn from_delegate(delegate: Self::Delegate) -> Result<Self, DecodeError> {
        Ok(Self {
            dest: PayloadDest::try_from(delegate.dest)
                .map_err(|err| DecodeError::BytesInvalid(err.to_string()))?,
            commitment: Buf32::from(delegate.commitment),
        })
    }
}

impl_ssz_via_delegate!(BlobSpec);

impl BlobSpec {
    /// The target we expect the DA payload to be stored on.
    pub fn dest(&self) -> PayloadDest {
        self.dest
    }

    /// Commitment to the payload.
    pub fn commitment(&self) -> &Buf32 {
        &self.commitment
    }

    #[expect(dead_code, reason = "Constructor for testing purposes")]
    fn new(dest: PayloadDest, commitment: Buf32) -> Self {
        Self { dest, commitment }
    }
}

/// Summary of a DA payload to be included on a DA layer. Specifies the target and
/// a commitment to the payload.
#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Hash,
    Arbitrary,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
)]
pub struct PayloadSpec {
    /// Target settlement layer we're expecting the DA on.
    dest: PayloadDest,

    /// Commitment to the payload (probably just a hash or a
    /// merkle root) that we expect to see committed to DA.
    commitment: Buf32,
}

// SSZ encoding delegates to the generated [`PayloadSpecSsz`] container — correct
// by construction rather than hand-rolled.
impl SszDelegate for PayloadSpec {
    type Delegate = PayloadSpecSsz;

    fn into_delegate(self) -> Self::Delegate {
        PayloadSpecSsz {
            dest: self.dest.into(),
            commitment: FixedBytes(self.commitment.0),
        }
    }

    fn from_delegate(delegate: Self::Delegate) -> Result<Self, DecodeError> {
        Ok(Self {
            dest: PayloadDest::try_from(delegate.dest)
                .map_err(|err| DecodeError::BytesInvalid(err.to_string()))?,
            commitment: Buf32::from(delegate.commitment),
        })
    }
}

impl_ssz_via_delegate!(PayloadSpec);

impl PayloadSpec {
    /// The target we expect the DA payload to be stored on.
    pub fn dest(&self) -> PayloadDest {
        self.dest
    }

    /// Commitment to the payload.
    pub fn commitment(&self) -> &Buf32 {
        &self.commitment
    }

    fn new(dest: PayloadDest, commitment: Buf32) -> Self {
        Self { dest, commitment }
    }
}

/// Error returned when constructing an [`L1Payload`] with data that exceeds the
/// SSZ encoding bounds.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum L1PayloadError {
    /// A single payload chunk is longer than `MAX_PAYLOAD_CHUNK_LEN`.
    #[error("payload chunk of {len} bytes exceeds maximum of {MAX_PAYLOAD_CHUNK_LEN}")]
    ChunkTooLong {
        /// Length of the offending chunk.
        len: usize,
    },

    /// The payload has more than `MAX_PAYLOAD_CHUNKS` chunks.
    #[error("payload has {count} chunks, exceeding maximum of {MAX_PAYLOAD_CHUNKS}")]
    TooManyChunks {
        /// Number of chunks supplied.
        count: usize,
    },
}

/// Data that is submitted to L1. This can be DA, Checkpoint, etc.
///
/// The chunk bounds enforced by [`L1Payload::new`] mirror the SSZ container's
/// length-bounded lists, so a constructed (or deserialized) `L1Payload` is
/// always SSZ-encodable.
///
/// The serde representation flattens the [`TagData`] fields alongside the
/// payload (`{payload, subproto_id, tx_type, aux_data}`); deserialization
/// routes through [`L1Payload::new`] (and `TagData`'s own validating
/// `Deserialize`) so the same invariants hold.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct L1Payload {
    /// Data payload.
    #[serde(rename = "payload")]
    data: Vec<Vec<u8>>,

    /// Transaction type.
    #[serde(flatten)]
    tag: TagData,
}

impl L1Payload {
    /// Creates a new L1 payload from data chunks and tag metadata.
    ///
    /// # Errors
    ///
    /// Returns [`L1PayloadError`] if the data exceeds the SSZ encoding bounds:
    /// any chunk longer than `MAX_PAYLOAD_CHUNK_LEN`, or more than
    /// `MAX_PAYLOAD_CHUNKS` chunks.
    pub fn new(payload: Vec<Vec<u8>>, tag: TagData) -> Result<Self, L1PayloadError> {
        if payload.len() > MAX_PAYLOAD_CHUNKS as usize {
            return Err(L1PayloadError::TooManyChunks {
                count: payload.len(),
            });
        }
        if let Some(chunk) = payload
            .iter()
            .find(|chunk| chunk.len() > MAX_PAYLOAD_CHUNK_LEN as usize)
        {
            return Err(L1PayloadError::ChunkTooLong { len: chunk.len() });
        }
        Ok(Self { data: payload, tag })
    }

    /// Returns the data payload chunks.
    pub fn data(&self) -> &[Vec<u8>] {
        &self.data
    }

    /// Returns a reference to the tag metadata.
    pub fn tag(&self) -> &TagData {
        &self.tag
    }
}

/// [`Deserialize`] is implemented manually to route through [`L1Payload::new`],
/// enforcing the same chunk bounds that direct construction does.
impl<'de> Deserialize<'de> for L1Payload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(rename = "payload")]
            data: Vec<Vec<u8>>,
            #[serde(flatten)]
            tag: TagData,
        }

        let raw = Raw::deserialize(deserializer)?;
        Self::new(raw.data, raw.tag).map_err(serde::de::Error::custom)
    }
}

// Borsh is implemented as a length-prefixed shim over the SSZ encoding, so it
// inherits the same validation (bounded lists and `TagData::new`) on decode
// rather than re-implementing it by hand.
impl_borsh_via_ssz!(L1Payload);

// SSZ encoding delegates to the generated [`L1PayloadSsz`] container, whose
// length-bounded lists (`data`, `aux_data`) lay out the fixed/variable parts per
// the SSZ spec — correct by construction rather than hand-rolled.
impl SszDelegate for L1Payload {
    type Delegate = L1PayloadSsz;

    fn into_delegate(self) -> Self::Delegate {
        // These conversions cannot fail: `L1Payload::new` (and all decode paths)
        // enforce the same bounds, so the type can never hold out-of-range data.
        let data = self
            .data
            .into_iter()
            .map(|chunk| {
                chunk
                    .try_into()
                    .expect("payload chunk exceeds MAX_PAYLOAD_CHUNK_LEN")
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("payload has more than MAX_PAYLOAD_CHUNKS chunks");
        L1PayloadSsz {
            data,
            subproto_id: self.tag.subproto_id(),
            tx_type: self.tag.tx_type(),
            aux_data: self
                .tag
                .aux_data()
                .to_vec()
                .try_into()
                .expect("aux data exceeds MAX_AUX_DATA_LEN"),
        }
    }

    fn from_delegate(delegate: Self::Delegate) -> Result<Self, DecodeError> {
        let tag = TagData::new(
            delegate.subproto_id,
            delegate.tx_type,
            delegate.aux_data.to_vec(),
        )
        .map_err(|err| DecodeError::BytesInvalid(err.to_string()))?;
        let data = delegate
            .data
            .iter()
            .map(|chunk| chunk.to_vec())
            .collect::<Vec<Vec<u8>>>();
        Ok(Self { data, tag })
    }
}

impl_ssz_via_delegate!(L1Payload);

impl<'a> arbitrary::Arbitrary<'a> for L1Payload {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate a bounded number of bounded chunks so the result is always a
        // valid (SSZ-encodable) payload.
        let num_chunks = u.int_in_range(0..=8)?;
        let mut data = Vec::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            let chunk_len = u.int_in_range(0..=64)?;
            let mut chunk = Vec::with_capacity(chunk_len);
            for _ in 0..chunk_len {
                chunk.push(u8::arbitrary(u)?);
            }
            data.push(chunk);
        }

        let subproto_id = u8::arbitrary(u)?;
        let tx_type = u8::arbitrary(u)?;
        // Limit aux_data to a reasonable size (max 74 bytes as per TagData)
        let aux_data_len = u.int_in_range(0..=74)?;
        let mut aux_data = Vec::with_capacity(aux_data_len);
        for _ in 0..aux_data_len {
            aux_data.push(u8::arbitrary(u)?);
        }

        let tag = TagData::new(subproto_id, tx_type, aux_data)
            .map_err(|_| arbitrary::Error::IncorrectFormat)?;

        Ok(Self { data, tag })
    }
}

/// Intent produced by the EE on a "full" verification, but if we're just
/// verifying a proof we may not have access to this but still want to reason
/// about it.
///
/// These are never stored on-chain.
#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, BorshSerialize, BorshDeserialize)]
// TODO: rename this to L1PayloadIntent and remove the dest field
pub struct PayloadIntent {
    /// The destination for this payload.
    dest: PayloadDest,

    /// Commitment to the payload.
    commitment: Buf32,

    /// Blob payload.
    payload: L1Payload,
}

// SSZ encoding delegates to the generated [`PayloadIntentSsz`] container, whose
// `payload` field reuses the [`L1PayloadSsz`] delegate — correct by construction
// rather than hand-rolled.
impl SszDelegate for PayloadIntent {
    type Delegate = PayloadIntentSsz;

    fn into_delegate(self) -> Self::Delegate {
        PayloadIntentSsz {
            dest: self.dest.into(),
            commitment: FixedBytes(self.commitment.0),
            payload: self.payload.into_delegate(),
        }
    }

    fn from_delegate(delegate: Self::Delegate) -> Result<Self, DecodeError> {
        Ok(Self {
            dest: PayloadDest::try_from(delegate.dest)
                .map_err(|err| DecodeError::BytesInvalid(err.to_string()))?,
            commitment: Buf32::from(delegate.commitment),
            payload: L1Payload::from_delegate(delegate.payload)?,
        })
    }
}

impl_ssz_via_delegate!(PayloadIntent);

impl PayloadIntent {
    /// Creates a new payload intent with a destination, commitment, and payload.
    pub fn new(dest: PayloadDest, commitment: Buf32, payload: L1Payload) -> Self {
        Self {
            dest,
            commitment,
            payload,
        }
    }

    /// The target we expect the DA payload to be stored on.
    pub fn dest(&self) -> PayloadDest {
        self.dest
    }

    /// Commitment to the payload, which might be context-specific. This
    /// is conceptually unrelated to the payload ID that we use for tracking which
    /// payloads we've written in the L1 writer bookkeeping.
    pub fn commitment(&self) -> &Buf32 {
        &self.commitment
    }

    /// The payload that matches the commitment.
    pub fn payload(&self) -> &L1Payload {
        &self.payload
    }

    /// Generates the spec from the relevant parts of the payload intent that
    /// uniquely refers to the payload data.
    pub fn to_spec(&self) -> PayloadSpec {
        PayloadSpec::new(self.dest, self.commitment)
    }
}

#[cfg(test)]
mod tests {
    use strata_l1_txfmt::TagData;

    use crate::payload::{L1Payload, L1PayloadError};
    use crate::ssz_generated::ssz::btc::{MAX_PAYLOAD_CHUNK_LEN, MAX_PAYLOAD_CHUNKS};
    use crate::test_helpers::ArbitraryGenerator;

    #[test]
    fn test_l1_payload_borsh_roundtrip() {
        let l1_payload: L1Payload = ArbitraryGenerator::new().generate();
        let buf = borsh::to_vec(&l1_payload).unwrap();
        let res: L1Payload = borsh::from_slice(&buf).unwrap();
        assert_eq!(res, l1_payload);
    }

    #[test]
    fn test_l1_payload_serde_roundtrip() {
        let l1_payload: L1Payload = ArbitraryGenerator::new().generate();
        let json = serde_json::to_string(&l1_payload).unwrap();
        let res: L1Payload = serde_json::from_str(&json).unwrap();
        assert_eq!(res, l1_payload);
    }

    #[test]
    fn test_l1_payload_serde_flat_shape() {
        // Guards the JSON layout: the tag fields are flattened alongside
        // `payload` rather than nested, preserving the historical shape.
        let payload = L1Payload::new(
            vec![vec![1, 2, 3]],
            TagData::new(5, 9, vec![0xAA, 0xBB]).unwrap(),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::to_value(&payload).unwrap();
        let obj = value.as_object().unwrap();

        assert_eq!(obj["payload"], serde_json::json!([[1, 2, 3]]));
        assert_eq!(obj["subproto_id"], 5);
        assert_eq!(obj["tx_type"], 9);
        assert_eq!(obj["aux_data"], serde_json::json!([0xAA, 0xBB]));
        assert!(
            !obj.contains_key("tag"),
            "tag must be flattened, not nested"
        );
    }

    #[test]
    fn test_l1_payload_new_rejects_long_chunk() {
        let tag = TagData::new(1, 1, vec![]).unwrap();
        let chunk = vec![0u8; MAX_PAYLOAD_CHUNK_LEN as usize + 1];
        assert!(matches!(
            L1Payload::new(vec![chunk], tag),
            Err(L1PayloadError::ChunkTooLong { .. })
        ));
    }

    #[test]
    fn test_l1_payload_new_rejects_too_many_chunks() {
        let tag = TagData::new(1, 1, vec![]).unwrap();
        let chunks = vec![vec![]; MAX_PAYLOAD_CHUNKS as usize + 1];
        assert!(matches!(
            L1Payload::new(chunks, tag),
            Err(L1PayloadError::TooManyChunks { .. })
        ));
    }

    #[test]
    fn test_l1_payload_deserialize_rejects_long_chunk() {
        // A JSON payload with an over-long chunk must be rejected by the
        // validating `Deserialize` rather than producing a panicking value.
        let long = MAX_PAYLOAD_CHUNK_LEN as usize + 1;
        let json = serde_json::json!({
            "payload": [vec![0u8; long]],
            "subproto_id": 1,
            "tx_type": 1,
            "aux_data": [],
        });
        assert!(serde_json::from_value::<L1Payload>(json).is_err());
    }
}
