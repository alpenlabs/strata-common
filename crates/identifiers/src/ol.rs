use std::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "ssz")]
use ssz_derive::{Decode, Encode};
#[cfg(feature = "codec")]
use strata_codec::Codec;

use crate::buf::Buf32;

/// Sequential slot number within the OL chain.
pub type Slot = u64;
/// Epoch index within the OL chain.
pub type Epoch = u32;

/// ID of an OL (Orchestration Layer) block, usually the hash of its root header.
#[derive(Copy, Clone, Eq, Default, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "ssz", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "codec", derive(Codec))]
pub struct OLBlockId(Buf32);

impl_buf_wrapper!(OLBlockId, Buf32, 32);

#[cfg(feature = "ssz")]
crate::impl_ssz_transparent_wrapper!(OLBlockId, Buf32);

impl OLBlockId {
    /// Returns a dummy blkid that is all zeroes.
    pub fn null() -> Self {
        Self::from(Buf32::zero())
    }

    /// Checks to see if this is the dummy "zero" blkid.
    pub fn is_null(&self) -> bool {
        self.0.is_zero()
    }
}

/// Alias for backward compatibility
pub type L2BlockId = OLBlockId;

/// Commitment to an OL block by ID at a particular slot.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Default, PartialOrd, Ord)]
#[cfg_attr(feature = "ssz", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "codec", derive(Codec))]
#[cfg_attr(feature = "ssz", ssz(struct_behaviour = "container"))]
pub struct OLBlockCommitment {
    /// The slot number of this block.
    pub slot: Slot,
    /// The block ID (hash).
    pub blkid: OLBlockId,
}

#[cfg(feature = "ssz")]
crate::impl_ssz_fixed_container!(OLBlockCommitment, [slot: Slot, blkid: OLBlockId]);

impl OLBlockCommitment {
    /// Creates a new block commitment from a slot and block ID.
    pub fn new(slot: Slot, blkid: OLBlockId) -> Self {
        Self { slot, blkid }
    }

    /// Creates a "null" commitment with slot 0 and a zeroed block ID.
    pub fn null() -> Self {
        Self::new(0, OLBlockId::from(Buf32::zero()))
    }

    /// Returns the slot number.
    pub fn slot(&self) -> Slot {
        self.slot
    }

    /// Returns a reference to the block ID.
    pub fn blkid(&self) -> &OLBlockId {
        &self.blkid
    }

    /// Returns `true` if this is the null commitment.
    pub fn is_null(&self) -> bool {
        self.slot == 0 && self.blkid.0.is_zero()
    }
}

impl fmt::Display for OLBlockCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.slot, self.blkid)
    }
}

// Use macro to generate Borsh implementations via SSZ (fixed-size, no length prefix)
#[cfg(all(feature = "borsh", feature = "ssz"))]
crate::impl_borsh_via_ssz_fixed!(OLBlockCommitment);

/// Alias for backward compatibility
pub type L2BlockCommitment = OLBlockCommitment;

/// ID of an OL (Orchestration Layer) transaction.
#[derive(Copy, Clone, Eq, Default, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "ssz", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "codec", derive(Codec))]
pub struct OLTxId(Buf32);

impl_buf_wrapper!(OLTxId, Buf32, 32);

#[cfg(feature = "ssz")]
crate::impl_ssz_transparent_wrapper!(OLTxId, Buf32);

#[cfg(all(test, feature = "ssz"))]
mod tests {
    use strata_ssz_tests::ssz_proptest;

    use super::*;
    use crate::test_utils::{buf32_strategy, ol_block_commitment_strategy};

    mod ol_block_id {
        use super::*;

        ssz_proptest!(
            OLBlockId,
            buf32_strategy(),
            transparent_wrapper_of(Buf32, from)
        );
    }

    mod ol_block_commitment {
        use super::*;

        ssz_proptest!(OLBlockCommitment, ol_block_commitment_strategy());
    }

    mod ol_tx_id {
        use super::*;

        ssz_proptest!(
            OLTxId,
            buf32_strategy(),
            transparent_wrapper_of(Buf32, from)
        );
    }
}
