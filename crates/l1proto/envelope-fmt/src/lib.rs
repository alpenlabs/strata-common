//! Bitcoin script envelope format utilities for Strata L1 protocol.
//!
//! This crate provides functionality for creating and parsing Bitcoin script envelopes
//! that encapsulate arbitrary data within `OP_FALSE OP_IF ... OP_ENDIF` blocks.
//! These envelopes are commonly used for embedding protocol-specific data in Bitcoin
//! transactions while maintaining script validity.
//!
//! # Structure
//!
//! An envelope has the following structure:
//! ```text
//! OP_FALSE OP_IF <data_chunks> OP_ENDIF
//! ```
//!
//! The payload data is split into chunks of up to 520 bytes (Bitcoin's maximum push size)
//! and pushed sequentially within the envelope.
//!
//! # Examples
//!
//! Creating an envelope:
//! ```
//! use strata_l1_envelope_fmt::builder::build_envelope_script;
//!
//! let payload = vec![1, 2, 3, 4, 5];
//! let script = build_envelope_script(&payload).unwrap();
//! ```
//!
//! Parsing an envelope:
//! ```
//! use strata_l1_envelope_fmt::parser::parse_envelope_payload;
//! use strata_l1_envelope_fmt::builder::build_envelope_script;
//!
//! let payload = vec![1, 2, 3, 4, 5];
//! let script = build_envelope_script(&payload).unwrap();
//! let extracted = parse_envelope_payload(&script).unwrap();
//! assert_eq!(payload, extracted);
//! ```

/// Bitcoin script envelope builder utilities.
pub mod builder;

/// Error types for envelope operations.
pub mod errors;

/// Bitcoin script envelope parser utilities.
pub mod parser;
