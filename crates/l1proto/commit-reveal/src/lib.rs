//! SPS-53 chunked envelope format for Bitcoin L1.
//!
//! Where [`strata_l1_envelope_fmt`] handles one script envelope, this crate
//! covers the multi-transaction carrier on top of it: a commit transaction's
//! OP_RETURN marker plus one signed reveal leaf per payload chunk.
//!
//! The builder is layout-neutral — it returns the marker and leaf scripts
//! without fixing where those outputs sit, since output ordering is transaction
//! assembly, which is out of scope along with funding, fees, change, and
//! signing.
//!
//! The crate is consumer-neutral: no magic value, no interpretation of the
//! marker tail, no key policy. Callers supply all of that.

use strata_l1_txfmt::MAGIC_BYTES_LEN;

mod builder;
mod errors;

#[cfg(test)]
mod test_utils;

/// Maximum commit-marker push, in bytes, as specified by SPS-53.
///
/// The cap follows OP_RETURN relay policy rather than consensus, so a confirmed
/// transaction can carry a larger push. Such a transaction is not a valid
/// commit under this format.
pub const MAX_MARKER_PAYLOAD_BYTES: usize = 80;

/// Maximum consumer-defined marker tail, in bytes.
///
/// The marker is `magic || tail` in a single push, so the tail a caller may
/// supply is [`MAX_MARKER_PAYLOAD_BYTES`] less the fixed magic length. Derived
/// rather than written out, so the two cannot drift.
pub const MAX_MARKER_TAIL_BYTES: usize = MAX_MARKER_PAYLOAD_BYTES - MAGIC_BYTES_LEN;

pub use builder::{
    CommitRevealScripts, build_commit_reveal_scripts, build_commit_reveal_scripts_from_chunks,
};
pub use errors::CommitRevealBuildError;
