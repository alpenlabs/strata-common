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
//! [`parser::parse_envelope_payload`], [`parser::parse_multi_envelope_payloads`],
//! and [`parser::parse_envelope_container`] are lenient: they scan forward for
//! an envelope, accept several per script, and ignore trailing opcodes. That
//! suits scripts whose only job is to carry data.
//!
//! [`parser::parse_exact_signed_envelope_leaf`] is strict: the script must be
//! exactly `<32-byte pubkey> OP_CHECKSIG` followed by one envelope and nothing
//! else. Use it where the envelope shape is load-bearing for authentication,
//! such as SPS-53 commit/reveal tapscript leaves, since only the strict form
//! guarantees no later opcode can discard or invert the `OP_CHECKSIG` result.
//!
//! # Examples
//!
//! Creating a single envelope:
//! ```
//! use strata_l1_envelope_fmt::builder::build_envelope_script;
//!
//! let payload = vec![1, 2, 3, 4, 5];
//! let script = build_envelope_script(&payload).unwrap();
//! ```
//!
//! Using the builder for envelope container scripts with size validation:
//! ```
//! use strata_l1_envelope_fmt::builder::EnvelopeScriptBuilder;
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
/// Under BIP342 a tapscript pubkey that is neither empty nor exactly this long
/// is an *unknown public key type*, for which `OP_CHECKSIG` succeeds without
/// verifying any signature. A leaf carrying one is spendable by anyone, so it
/// must be neither emitted nor accepted.
pub const SIGNED_LEAF_PUBKEY_LEN: usize = 32;

/// Bitcoin script envelope builder utilities.
pub mod builder;

/// Error types for envelope operations.
pub mod errors;

/// Bitcoin script envelope parser utilities.
pub mod parser;
