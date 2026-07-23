//! Errors raised when building a commit/reveal set.

use strata_l1_envelope_fmt::errors::EnvelopeBuildError;
use thiserror::Error;

/// Errors that can occur while building commit/reveal scripts.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CommitRevealBuildError {
    /// The marker tail exceeds the room left after the magic.
    #[error("commit marker tail ({tail_len} bytes) exceeds maximum ({max} bytes)")]
    MarkerTailTooLarge {
        /// Length of the supplied tail.
        tail_len: usize,

        /// The maximum allowed tail length.
        max: usize,
    },

    /// A reveal leaf script could not be built.
    #[error("failed to build reveal leaf script: {source}")]
    RevealLeaf {
        /// The underlying envelope builder error.
        #[from]
        source: EnvelopeBuildError,
    },
}
