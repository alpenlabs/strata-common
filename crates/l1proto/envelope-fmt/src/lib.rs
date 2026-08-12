//! Bitcoin script envelope format utilities for Strata L1 protocol.
//!
//! This crate provides functionality for creating and parsing Bitcoin script envelopes
//! that encapsulate arbitrary data within `OP_FALSE OP_IF ... OP_ENDIF` blocks.
//!
//! # Envelope Structure
//!
//! A basic envelope has the following structure:
//! ```text
//! OP_FALSE OP_IF <data_chunks> OP_ENDIF
//! ```
//!
//! Payloads larger than 520 bytes are automatically chunked to comply with Bitcoin's
//! consensus rules.
//!
//! # Envelope Container
//!
//! An envelope container wraps one or more envelopes with a pubkey and OP_CHECKSIG:
//! ```text
//! <pubkey>
//! OP_CHECKSIG
//! <envelope_0>
//! ...
//! <envelope_n>
//! ```
//!
//! The envelope container is carried in a transaction input's script context —
//! a tapscript leaf or a script_sig — allowing arbitrary data to be included in
//! Bitcoin transactions.
//!
//! # Lenient and strict parsing
//!
//! The **lenient** parsers scan for envelopes and ignore trailing opcodes —
//! fine for scripts whose only job is to carry data.
//! The **strict** [`parse_signed_envelope_leaf`] requires exactly
//! `<32-byte pubkey> OP_CHECKSIG` + one envelope and nothing else; use it where
//! the shape authenticates, since only then can no later opcode discard or
//! invert the `OP_CHECKSIG` result.
//!
//! # Examples
//!
//! Creating a single envelope:
//! ```
//! use strata_l1_envelope_fmt::build_envelope_script;
//!
//! let payload = vec![1, 2, 3, 4, 5];
//! let script = build_envelope_script(&payload).unwrap();
//! ```
//!
//! Using the builder for envelope container scripts with size validation:
//! ```
//! use strata_l1_envelope_fmt::EnvelopeScriptBuilder;
//!
//! let pubkey = vec![0x02; 33];
//! let payload1 = vec![1; 150];
//! let payload2 = vec![2; 150];
//!
//! let script = EnvelopeScriptBuilder::with_pubkey(&pubkey)
//!     .unwrap()
//!     .add_envelope(&payload1)
//!     .unwrap()
//!     .add_envelope(&payload2)
//!     .unwrap()
//!     .build()
//!     .unwrap();
//! ```

/// Required length of the x-only public key in a signed envelope leaf.
///
/// Any other non-zero length is a BIP342 unknown key type that `OP_CHECKSIG` accepts without
/// a signature (anyone-can-spend).
pub const SIGNED_LEAF_PUBKEY_LEN: usize = 32;

mod builder;
mod parser;

pub use builder::{
    EnvelopeBuildError, EnvelopeScriptBuilder, MAX_ENVELOPE_PAYLOAD_SIZE,
    MIN_ENVELOPE_PAYLOAD_SIZE, build_envelope_script, build_signed_envelope_leaf,
    split_payload_into_envelope_chunks,
};
pub use parser::{
    EnvelopeParseError, SignedEnvelopeLeaf, parse_envelope_container, parse_envelope_payload,
    parse_multi_envelope_payloads, parse_signed_envelope_leaf,
};
