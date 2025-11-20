//! Helper module to suppress unused dependency warnings for dependencies used by other test files.

#![expect(unused_crate_dependencies, reason = "suppress warnings")]

// This file exists only to suppress the warning about unused test file
#[test]
fn dummy() {}