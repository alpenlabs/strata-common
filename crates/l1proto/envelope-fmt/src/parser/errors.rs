use thiserror::Error;

use crate::SIGNED_LEAF_PUBKEY_LEN;

/// Errors that can occur while parsing Bitcoin script envelopes.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EnvelopeParseError {
    /// No envelopes found in the script.
    #[error("no envelopes found in script")]
    NoEnvelopesFound,

    /// Missing or invalid pubkey before `OP_CHECKSIG`.
    #[error("missing or invalid pubkey before OP_CHECKSIG")]
    MissingPubkey,

    /// Missing `OP_CHECKSIG` after the pubkey.
    #[error("missing OP_CHECKSIG after pubkey")]
    MissingChecksig,

    /// Missing OP_FALSE at the start of an envelope.
    #[error("missing OP_FALSE at envelope start")]
    MissingOpFalse,

    /// OP_FALSE not followed by OP_IF in envelope structure.
    #[error("OP_FALSE must be followed by OP_IF")]
    MissingOpIf,

    /// Non-push opcode found in envelope payload section.
    /// Only data push instructions are allowed between OP_IF and OP_ENDIF.
    #[error("unexpected opcode in payload section; only data pushes allowed")]
    UnexpectedOpcodeInPayload,

    /// Missing OP_ENDIF at the end of an envelope.
    #[error("missing OP_ENDIF at envelope end")]
    MissingOpEndif,

    /// Pubkey push in a signed envelope leaf has invalid length.
    ///
    /// Only raised by the strict leaf parser, which requires exactly
    /// [`SIGNED_LEAF_PUBKEY_LEN`](crate::SIGNED_LEAF_PUBKEY_LEN) bytes.
    /// Under BIP342 a tapscript pubkey that is neither empty nor x-only sized
    /// is an unknown public key type, for which `OP_CHECKSIG` succeeds without
    /// verifying any signature. Accepting such a leaf would void the
    /// authentication the envelope shape is meant to provide, so the strict
    /// parser rejects it rather than reporting a pubkey the caller might
    /// compare against.
    #[error("signed envelope leaf pubkey must be exactly {expected} bytes, found {found}")]
    InvalidPubkeyLength {
        /// The required pubkey length.
        expected: usize,

        /// Length of the offending pubkey push.
        found: usize,
    },

    /// Instructions remain after the envelope's OP_ENDIF.
    ///
    /// Only raised by the strict leaf parser, which requires the envelope to be
    /// the entire script. This rejects trailing opcodes that could discard or
    /// override the `OP_CHECKSIG` result, and additional envelopes beyond the
    /// first.
    #[error("unexpected instructions after envelope OP_ENDIF")]
    UnexpectedTrailingInstructions,

    /// Total envelope payload size exceeds the maximum allowed.
    #[error("total envelope payload size ({total_size} bytes) exceeds maximum ({max} bytes)")]
    PayloadTooLarge {
        /// Total payload size decoded before the limit was exceeded.
        total_size: usize,

        /// The maximum allowed size.
        max: usize,
    },

    /// Script could not be decoded into instructions.
    #[error("malformed script")]
    MalformedScript,
}

/// Errors that can occur when parsing a batch of transactions including commit and reveal txs.
#[derive(Debug, Error)]
pub enum CommitRevealParseError {
    /// Protocol marker in the anchor transaction is malformed.
    #[error("anchor OP_RETURN marker is malformed")]
    MalformedAnchorMarker,

    /// The marker tail has an unexpected length.
    #[error("unexpected marker tail array length (expected {expected} bytes, found {found})")]
    UnexpectedMarkerTailLength {
        /// Expected marker-tail length.
        expected: usize,

        /// Actual marker-tail length.
        found: usize,
    },

    /// A commit output run has no reveal slots.
    #[error("commit has no reveal slots")]
    MissingRevealSlots,

    /// A non-P2TR output is followed by a P2TR output.
    ///
    /// SPS-53 Layout A requires a run of P2TR outputs,
    /// optionally followed by a non-P2TR change output as the last.
    #[error("ambiguous P2TR change output at commit output {vout}")]
    AmbiguousTaprootChangeOutput {
        /// Output index.
        vout: u32,
    },

    /// No reveal transaction was found for a commit output.
    #[error("missing reveal for commit output {vout}")]
    MissingReveal {
        /// Output index.
        vout: u32,
    },

    /// Two reveal transactions claim the same commit output.
    #[error("duplicate reveal for commit output {vout}")]
    DuplicateReveal {
        /// Output index.
        vout: u32,
    },

    /// A reveal leaf uses a version other than tapscript.
    #[error("reveal leaf uses unsupported leaf version {version:#04x}")]
    UnsupportedRevealLeafVersion {
        /// Consensus encoding of the offending leaf version.
        version: u8,
    },

    /// A reveal input carries no taproot leaf script in its witness.
    #[error("reveal tx witness has no taproot leaf script")]
    RevealMissingLeafScript,

    /// The reveal pubkey does not match the key the caller expected.
    #[error("unexpected reveal pubkey (expected {expected:?}, found {found:?})")]
    UnexpectedRevealPubkey {
        /// Expected producer x-only pubkey.
        expected: [u8; SIGNED_LEAF_PUBKEY_LEN],

        /// Observed producer x-only pubkey.
        found: [u8; SIGNED_LEAF_PUBKEY_LEN],
    },

    /// The reveal pubkey does not match the key for other reveals in the same set.
    #[error("inconsitent reveal pubkeys in one commit-reveal set")]
    InconsistentRevealPubkey,

    /// A reveal transaction has no inputs.
    #[error("reveal tx has no inputs")]
    RevealMissingInputs,

    /// A reveal transaction spends the commit's marker output.
    #[error("reveal spends commit output 0 (the OP_RETURN marker)")]
    RevealSpendsMarker,

    /// A single reveal transaction spends more than one reveal slot.
    #[error("reveal spends multiple reveal slots of the commit tx")]
    RevealSpendsMultipleSlots,

    /// A reveal transaction spends a commit output outside the reveal-slot run.
    #[error("unexpected reveal for commit output {vout}")]
    UnexpectedReveal {
        /// Output index.
        vout: u32,
    },

    /// A reveal transaction has more than one input.
    #[error("reveal tx has multiple inputs")]
    RevealHasMultipleInputs,

    /// A reveal leaf carries an empty payload.
    #[error("reveal carries an empty payload")]
    EmptyRevealPayload,

    /// A reveal leaf did not match the strict signed envelope shape.
    #[error("failed to parse reveal envelope: {source}")]
    InvalidRevealEnvelope {
        /// The underlying envelope parse failure.
        #[from]
        source: EnvelopeParseError,
    },

    /// A reveal transaction spends reveal slots from more than one commit.
    #[error("reveal tx spends reveal slots of multiple commits")]
    RevealSpansMultipleCommits,
}
