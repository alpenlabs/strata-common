use serde::{Deserialize, Serialize};
use strata_identifiers::{L1BlockCommitment, L1BlockId};

/// Number of timestamps used for the median time past calculation.
pub const TIMESTAMPS_FOR_MEDIAN: usize = 11;

/// Snapshot of L1 state at genesis, used to bootstrap header verification.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct GenesisL1View {
    /// L1 block commitment at genesis.
    pub blk: L1BlockCommitment,
    /// Next difficulty target as a compact `nBits` value.
    pub next_target: u32,
    /// Timestamp of the current difficulty epoch start.
    pub epoch_start_timestamp: u32,
    /// Last 11 block timestamps for median time past calculation.
    pub last_11_timestamps: [u32; TIMESTAMPS_FOR_MEDIAN],
}

impl GenesisL1View {
    /// Returns the L1 block height at genesis.
    pub fn height(&self) -> u32 {
        self.blk.height()
    }

    /// Returns the L1 block ID at genesis.
    pub fn blkid(&self) -> L1BlockId {
        *self.blk.blkid()
    }
}
