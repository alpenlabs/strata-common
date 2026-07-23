//! SPS-53 chunked envelope format for Bitcoin L1.
//!
//! Where [`strata_l1_envelope_fmt`] handles one script envelope, this crate
//! covers the multi-transaction carrier on top of it: a commit transaction's
//! OP_RETURN marker plus one signed reveal leaf per payload chunk.
//!
//! ```text
//! commit tx:
//!   vout 0    = OP_RETURN <single push: magic || consumer-defined tail>
//!   vout 1..N = P2TR reveal slots (contiguous run)
//!   change afterwards, which MUST NOT be P2TR
//!
//! reveal tx i:
//!   spends commit vout i
//!   witness tapscript leaf carries exactly one envelope chunk
//! ```
//!
//! The chunk count is not on chain; it is the length of the contiguous P2TR run
//! after marker output 0. The builder is layout-neutral — it emits the marker
//! and leaf scripts without fixing where outputs sit — but the parser reads
//! Layout A: marker at vout 0, then that run. The run's change MUST NOT be P2TR,
//! or it would be indistinguishable from a slot.
//!
//! The crate is consumer-neutral: no magic value, no interpretation of the
//! marker tail, no key policy. Callers supply all of that. Transaction assembly
//! — funding, fees, change, signing — is out of scope.

use strata_l1_txfmt::MAGIC_BYTES_LEN;

mod builder;
mod errors;
mod grouping;
mod parser;

/// Transaction fixtures, behind the `test-utils` feature.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

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
pub use errors::{CommitRevealBuildError, CommitRevealParseError, MarkerTailArrayLengthError};
pub use grouping::{
    ParsedCommit, assign_reveal_to_commit, extract_payload_for_parsed_commit,
    parse_commit_candidate,
};
pub use parser::{
    ParsedCommitReveal, RevealSlotRange, extract_payload_from_single_commit_set, read_commit_marker,
};
