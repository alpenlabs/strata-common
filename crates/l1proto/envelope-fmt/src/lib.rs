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
//! Creating an envelope container:
//! ```
//! use strata_l1_envelope_fmt::builder::build_envelope_container;
//!
//! let pubkey = vec![0x02; 33];
//! let payloads = vec![vec![1, 2, 3], vec![4, 5, 6]];
//! let script = build_envelope_container(&pubkey, &payloads).unwrap();
//! ```

/// Bitcoin script envelope builder utilities.
pub mod builder;

/// Error types for envelope operations.
pub mod errors;

/// Bitcoin script envelope parser utilities.
pub mod parser;
