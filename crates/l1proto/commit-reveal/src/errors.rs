//! Error types for commit-reveal parsing and grouping.

use strata_l1_envelope_fmt::errors::EnvelopeParseError;
use thiserror::Error;

/// Error returned when the marker tail has an unexpected length.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("expected marker tail to be {expected} bytes, found {found}")]
pub struct MarkerTailArrayLengthError {
    /// Expected marker-tail length.
    pub expected: usize,

    /// Actual marker-tail length.
    pub found: usize,
}

/// Errors that can occur while parsing a commit-reveal set.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CommitRevealParseError {
    /// No commit marker was found for the supplied magic.
    ///
    /// No transaction in the supplied set carries one.
    #[error("no commit marker for the supplied magic")]
    MissingCommit,

    /// The transaction set contains more than one commit-marked transaction.
    #[error("multiple commit txs in set")]
    MultipleCommits,

    /// A commit output run has no reveal slots at all.
    #[error("commit has no reveal slots")]
    MissingRevealSlots,

    /// A P2TR output follows a non-P2TR one, so the reveal-slot run is
    /// ambiguous.
    ///
    /// Chunk count is derived from the contiguous run of P2TR outputs after the
    /// marker, which is only sound while change is non-P2TR. A P2TR output
    /// appearing after the run has closed makes the boundary unknowable, so the
    /// commit is rejected rather than guessed at.
    #[error("ambiguous P2TR change output at commit output {vout}")]
    AmbiguousTaprootChangeOutput {
        /// Output index of the offending P2TR output.
        vout: u32,
    },

    /// A reveal-slot range was built with no slots in it.
    ///
    /// Output 0 carries the marker and is never a reveal slot, so a range
    /// ending at 0 is empty.
    #[error("reveal slot range must end after output 0")]
    EmptyRevealSlotRange,

    /// A reveal transaction has no inputs.
    #[error("reveal tx has no inputs")]
    RevealMissingInputs,

    /// A reveal transaction does not spend the expected commit transaction.
    #[error("reveal tx does not spend the commit tx")]
    RevealWrongCommit,

    /// A reveal transaction spends the commit's marker output.
    #[error("reveal spends commit output 0 (marker)")]
    RevealSpendsMarker,

    /// A reveal transaction spends a commit output outside the reveal-slot run.
    #[error("unexpected reveal for commit output {vout}")]
    UnexpectedReveal {
        /// Output index spent outside the reveal-slot run.
        vout: u32,
    },

    /// A single reveal transaction spends more than one reveal slot.
    #[error("reveal spends multiple reveal slots of the commit tx")]
    RevealSpendsMultipleSlots,

    /// Two reveal transactions claim the same commit output.
    #[error("duplicate reveal for commit output {vout}")]
    DuplicateReveal {
        /// Output index claimed twice.
        vout: u32,
    },

    /// No reveal transaction was supplied for a commit output in the run.
    #[error("missing reveal for commit output {vout}")]
    MissingReveal {
        /// Output index with no reveal.
        vout: u32,
    },

    /// A reveal input carries no taproot leaf script in its witness.
    #[error("reveal tx witness has no taproot leaf script")]
    RevealMissingLeafScript,

    /// A reveal leaf uses a leaf version other than tapscript.
    #[error("reveal leaf uses unsupported leaf version {version:#04x}")]
    UnsupportedRevealLeafVersion {
        /// Consensus encoding of the offending leaf version.
        version: u8,
    },

    /// A reveal leaf carries an empty payload; every reveal must carry data.
    #[error("reveal for commit output {vout} carries an empty payload")]
    EmptyReveal {
        /// Output index whose reveal payload is empty.
        vout: u32,
    },

    /// Reveal leaves in one set carry different pubkeys.
    ///
    /// SPS-53 signs every reveal of an inscription under one producer key, so a
    /// set whose leaves disagree has no single key to authenticate against.
    #[error("reveal for commit output {vout} carries a different pubkey than earlier reveals")]
    InconsistentRevealPubkey {
        /// Output index whose reveal pubkey differs.
        vout: u32,
    },

    /// The reveal pubkey does not match the key the caller expected.
    #[error("reveal pubkey does not match the expected key")]
    UnexpectedRevealPubkey,

    /// A reveal leaf did not match the strict signed envelope shape.
    #[error("failed to parse reveal envelope: {source}")]
    InvalidRevealEnvelope {
        /// The underlying envelope parse failure.
        #[from]
        source: EnvelopeParseError,
    },
}

/// Errors that can occur while assigning reveals to parsed commits.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CommitRevealGroupingError {
    /// A reveal transaction spends reveal slots of more than one parsed commit.
    #[error("reveal tx spends reveal slots of multiple commits")]
    RevealSpansMultipleCommits,

    /// A parser error found while checking the assigned commit.
    #[error("malformed reveal for assigned commit: {source}")]
    Parse {
        /// The underlying commit-reveal parse failure.
        #[from]
        source: CommitRevealParseError,
    },
}
