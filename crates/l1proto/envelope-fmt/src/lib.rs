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
//! An envelope container wraps one or more envelopes with a pubkey and CHECKSIGVERIFY:
//! ```text
//! <pubkey>
//! CHECKSIGVERIFY
//! <envelope_0>
//! ...
//! <envelope_n>
//! ```
//!
//! The envelope container is typically placed in a transaction input's script_sig,
//! allowing arbitrary data to be included in Bitcoin transactions.
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
//!     .add_envelope(&payload1).unwrap()
//!     .add_envelope(&payload2).unwrap()
//!     .build()
//!     .unwrap();
//! ```

/// Bitcoin script envelope builder utilities.
pub mod builder;

/// Error types for envelope operations.
pub mod errors;

/// Bitcoin script envelope parser utilities.
pub mod parser;
