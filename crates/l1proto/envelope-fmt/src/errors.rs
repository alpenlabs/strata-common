use thiserror::Error;

/// Errors that can occur while parsing Bitcoin script envelopes.
#[derive(Debug, Error)]
pub enum EnvelopeParseError {
    /// No envelopes found in the script.
    #[error("no envelopes found in script")]
    NoEnvelopesFound,

    /// Missing or invalid pubkey in envelope container.
    #[error("missing or invalid pubkey in container")]
    MissingPubkey,

    /// Missing CHECKSIGVERIFY opcode after pubkey in container.
    #[error("missing CHECKSIGVERIFY after pubkey")]
    MissingChecksigverify,

    /// Missing OP_FALSE at the start of an envelope.
    #[error("missing OP_FALSE at envelope start")]
    MissingOpFalse,

    /// OP_FALSE not followed by OP_IF in envelope structure.
    #[error("OP_FALSE must be followed by OP_IF")]
    MissingOpIf,

    /// The payload data is malformed or contains invalid instructions.
    #[error("invalid payload data")]
    InvalidPayload,
}

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
}
