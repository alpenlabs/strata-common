/// Prefill leaf used for L1-height-indexed MMRs before genesis.
///
/// For L1-height-indexed MMRs, positions for blocks at heights
/// `0..=genesis_l1_height` are filled with this constant so that the entry
/// for height `h` lands at MMR index `h`. The value is non-zero because the
/// MMR encoding treats `[0; 32]` as "no peak present"; the specific bytes do
/// not affect protocol semantics, since no real proof references an L1 block
/// at or before genesis.
pub const L1_HEIGHT_MMR_PREFILL_LEAF: [u8; 32] = [0xffu8; 32];
