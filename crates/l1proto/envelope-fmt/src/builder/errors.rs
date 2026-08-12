use thiserror::Error;

/// Errors that can occur while building Bitcoin script envelopes.
#[derive(Debug, Error)]
pub enum EnvelopeBuildError {
    /// Failed to convert a payload chunk into `PushBytesBuf`.
    #[error("failed to convert {chunk_size} byte payload chunk to push bytes buffer")]
    PayloadChunkConversion {
        /// Size of the chunk that failed to convert.
        chunk_size: usize,
    },

    /// Failed to convert a pubkey into `PushBytesBuf`.
    #[error("failed to convert pubkey to push bytes buffer")]
    PubkeyConversion,

    /// Total envelope payload size is below the recommended minimum.
    /// It would be more efficient to pass small data in the SPS-50 aux field.
    #[error(
        "total envelope payload size ({total_size} bytes) is below recommended minimum ({min} bytes); consider using SPS-50 aux field instead"
    )]
    PayloadTooSmall {
        /// The actual total size of all payloads.
        total_size: usize,

        /// The minimum recommended size.
        min: usize,
    },

    /// Total envelope payload size exceeds the maximum allowed.
    /// Must be under 395 KB to stay below Bitcoin's 400 KB transaction standardness limit.
    #[error("total envelope payload size ({total_size} bytes) exceeds maximum ({max} bytes)")]
    PayloadTooLarge {
        /// The actual total size of all payloads.
        total_size: usize,

        /// The maximum allowed size.
        max: usize,
    },
}
