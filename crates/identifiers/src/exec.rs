#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::buf::Buf32;

/// Alias to [`Buf32`] used as a universal hash type in EE.
pub type Hash = Buf32;

/// Structure for `ExecUpdate.input.extra_payload` for EVM EL
#[derive(Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct EVMExtraPayload {
    block_hash: [u8; 32],
}

impl EVMExtraPayload {
    /// Creates a new payload from a raw block hash.
    pub fn new(block_hash: [u8; 32]) -> Self {
        Self { block_hash }
    }

    /// Returns the block hash as a [`Buf32`].
    pub fn block_hash(&self) -> Buf32 {
        self.block_hash.into()
    }
}

/// Serializes a block hash into a byte vector for use as an EVM extra payload.
pub fn create_evm_extra_payload(block_hash: Buf32) -> Vec<u8> {
    block_hash.0.to_vec()
}

/// Commitment to an execution block, containing slot and block ID.
///
/// This type was previously named `EvmEeBlockCommitment` but has been renamed
/// to `ExecBlockCommitment` to be more generic and not tied to EVM.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshDeserialize, BorshSerialize))]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub struct ExecBlockCommitment {
    slot: u64,
    blkid: Buf32,
}

impl ExecBlockCommitment {
    /// Creates a new execution block commitment.
    pub fn new(slot: u64, blkid: Buf32) -> Self {
        Self { slot, blkid }
    }

    /// Creates a null commitment with slot 0 and zeroed block ID.
    pub fn null() -> Self {
        Self::new(0, Buf32::zero())
    }

    /// Returns the slot number.
    pub fn slot(&self) -> u64 {
        self.slot
    }

    /// Returns the block ID.
    pub fn blkid(&self) -> &Buf32 {
        &self.blkid
    }

    /// Returns `true` if this is a null commitment.
    pub fn is_null(&self) -> bool {
        self.slot == 0 && self.blkid().is_zero()
    }
}

/// Alias for backward compatibility
pub type EvmEeBlockCommitment = ExecBlockCommitment;
