//! SPS-53 chunked envelope building and parsing for Bitcoin L1.
//!
//! Where [`strata_l1_envelope_fmt`] handles one script envelope, this crate
//! handles the multi-transaction carrier built on top of it: a commit
//! transaction whose outputs fund N reveal transactions, each carrying one
//! chunk of a larger payload.
//!
//! SPS-53 leaves the arrangement of those outputs to the consuming protocol.
//! Under Layout A, the one Alpen uses:
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
//! The chunk count is not written on chain: it follows from where the marker
//! sits. That is why Layout A's change MUST NOT be P2TR — it would be
//! indistinguishable from a reveal slot. Layout B instead places the marker
//! after the chunk outputs, so its change may be any type, and the spec says
//! the two are not exhaustive.
//!
//! The two directions differ on this. The builder returns a marker script and
//! one leaf script per chunk without fixing where those outputs sit, since
//! output ordering is transaction assembly, so a writer using another layout
//! can use it unchanged. The parser reads Layout A: it expects the marker at
//! vout 0 and derives the slot run from there. Supporting another layout is
//! therefore a parser-side change.
//!
//! The crate is consumer-neutral. It carries no consumer or deployment values:
//! it defines no magic, encodes and decodes nothing after the magic, and
//! applies no key policy. Callers supply their magic and put whatever they like
//! in the marker tail.
//!
//! Transaction assembly — funding, fees, change, signing — is out of scope. The
//! builder produces scripts; a wallet turns them into transactions.

use strata_l1_txfmt::MAGIC_BYTES_LEN;

mod builder;
mod errors;
mod parser;

/// Transaction fixtures, behind the `test-utils` feature.
///
/// A separate namespace from the format surface above, which is why this is the
/// one public module: fixtures should not sit beside the protocol contract.
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

pub use builder::{CommitRevealScripts, build_commit_reveal_scripts};
pub use errors::{CommitRevealBuildError, CommitRevealParseError};
pub use parser::{
    ParsedCommitReveal, RevealSlotRange, derive_reveal_slot_range,
    extract_authenticated_payload_for_commit, extract_payload_for_commit,
    extract_payload_from_single_commit_set, read_commit_marker,
};
