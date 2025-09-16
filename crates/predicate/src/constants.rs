//! Constants for predicate types and values.

/// Type alias for predicate type values.
pub type PredicateType = u8;

/// Never accepts any witness for any claim predicate type.
pub const NEVER_ACCEPT_PREDICATE_TYPE: PredicateType = 0;

/// Always accepts any witness for any claim predicate type.
pub const ALWAYS_ACCEPT_PREDICATE_TYPE: PredicateType = 1;

/// Schnorr signature verification using BIP-340 predicate type.
pub const BIP340_SCHNORR_PREDICATE_TYPE: PredicateType = 10;

/// SP1 Groth16 verifier program verification predicate type.
pub const SP1_GROTH16_PREDICATE_TYPE: PredicateType = 20;
