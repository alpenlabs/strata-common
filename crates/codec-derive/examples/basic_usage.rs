//! Example demonstrating basic usage of the Codec derive macro.

// Suppress unused dependency warnings for proc-macro dependencies
use quote as _;
use syn as _;

use strata_codec::{decode_buf_exact, encode_to_vec};
use strata_codec_derive::Codec;

/// A simple user struct with various field types.
#[derive(Debug, Clone, PartialEq, Eq, Codec)]
struct User {
    id: u32,
    name_hash: [u8; 32],
    age: u8,
    flags: u16,
}

/// A configuration struct.
#[derive(Debug, Clone, PartialEq, Eq, Codec)]
struct Config {
    version: u32,
    settings: Settings,
}

/// Nested settings struct.
#[derive(Debug, Clone, PartialEq, Eq, Codec)]
struct Settings {
    enabled: bool,
    threshold: u64,
}

fn main() {
    // Create a user instance
    let user = User {
        id: 12345,
        name_hash: [0x42; 32],
        age: 25,
        flags: 0b1010,
    };

    // Encode to bytes
    let encoded = encode_to_vec(&user).expect("encoding failed");
    println!("Encoded user ({} bytes): {:?}", encoded.len(), encoded);

    // Decode back from bytes
    let decoded: User = decode_buf_exact(&encoded).expect("decoding failed");
    assert_eq!(user, decoded);
    println!("Successfully decoded user: {:?}", decoded);

    // Example with nested structs
    let config = Config {
        version: 1,
        settings: Settings {
            enabled: true,
            threshold: 1000,
        },
    };

    let config_bytes = encode_to_vec(&config).expect("encoding failed");
    let decoded_config: Config = decode_buf_exact(&config_bytes).expect("decoding failed");
    assert_eq!(config, decoded_config);
    println!(
        "Successfully encoded and decoded config: {:?}",
        decoded_config
    );
}
