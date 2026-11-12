# Serialization

Crates here encode data in several formats. Each boundary already has its format, and the
formats are not interchangeable: a type that is SSZ on the wire stays SSZ there, even if it
also implements `Codec` or serde. See [architecture.md](architecture.md) for why encodings
here are cross-repo interfaces.

## Formats

| Format | Crates | Used for |
| --- | --- | --- |
| SSZ | `ssz`, `ssz_derive`, and `tree_hash` from [ssz-gen](https://github.com/alpenlabs/ssz-gen) | Consensus and proof types, and their tree hash roots |
| `strata-codec` | [`crates/codec`](../crates/codec) | Compact, explicitly laid-out binary messages |
| Borsh (deprecated) | `borsh`, behind the `borsh` feature | Older encodings that existing consumers still opt into |
| serde | `serde`, with shims in [`crates/serde-utils`](../crates/serde-utils) | JSON configs and RPC, and binary serde formats such as CBOR |

### SSZ

Some crates generate their SSZ types from schema files. Their `build.rs` runs
`ssz_codegen` over the `.ssz` files in the crate's `ssz/` directory and writes the result to
`OUT_DIR`:

- [`crates/btc-types/ssz`](../crates/btc-types/ssz)
- [`crates/crypto/ssz`](../crates/crypto/ssz)
- [`crates/merkle/ssz`](../crates/merkle/ssz), only with the `ssz` feature
- [`crates/ol-logs/ssz`](../crates/ol-logs/ssz), which imports types from
  `strata_identifiers`
- [`crates/predicate/ssz`](../crates/predicate/ssz)

For those types, edit the schema, not the generated code. Other SSZ types, such as the
buffers in `strata-identifiers`, derive their encoding in Rust with `ssz_derive`.

### strata-codec

`Codec` is a small trait with explicit `encode` and `decode` over a flat buffer. It is
meant for messages that fit in memory and whose layout should be obvious from the code.
`#[derive(Codec)]` covers structs whose fields are all `Codec`, encoded in declaration
order. It does not support enums. `Varint`
and `VarVec` give compact length prefixes. `decode_buf_exact` fails on trailing bytes.

### Borsh

Borsh is deprecated. It is off by default in every crate, and the `borsh` feature on a
crate brings back its Borsh implementations with the same bytes as before, so existing
consumers keep working. Don't add Borsh implementations to new types or use Borsh at a new
boundary; use SSZ or `strata-codec` instead. The
[README](../README.md#deprecated-borsh-support) lists which crates have the feature.

## Adapters

These let one format carry another. Each one defines its own bytes, so pick the one that
matches the boundary.

| Adapter | Crate | What it does |
| --- | --- | --- |
| `CodecSsz<T>` | [`codec-utils`](../crates/codec-utils/src/ssz_shim.rs) | Puts an SSZ value inside a `Codec` stream, with a varint length prefix |
| `CodecBorsh<T>` | [`codec-utils`](../crates/codec-utils/src/borsh_shim.rs) | Puts a Borsh value inside a `Codec` stream. Needs the `borsh` feature. Deprecated with Borsh |
| `SerdeSsz<T>` | [`serde-utils`](../crates/serde-utils/src/ssz_shim.rs) | Raw SSZ bytes in binary serde formats, hex in human-readable ones |
| `SerdeCodec<T>` | [`serde-utils`](../crates/serde-utils/src/codec_shim.rs) | The same for `Codec` bytes |

## Stored values

[`strata-db-schema-common`](../crates/db-schema-common) wraps stored values in a container
tagged with a schema version. `decl_schema_version!` ties a version to a format, `ssz` or
`codec`. The payload is the bare encoding with no length prefix, since the container
already delimits it, which is why it does not go through `CodecSsz`. A `Migrator` upgrades
a stored value from an older version, one version at a time. To change a stored type, add a
new version and a migration instead of changing an existing version's encoding.

## Changing an encoding

Changing an encoded field, its order, a tag, a length bound, or a hash input changes bytes
that another repo may already write, store, or prove. Treat it as a protocol change:

1. Mark the commit breaking with `!`, for example `feat(identifiers)!: ...`, and say in the
   PR which downstream repos read the type.
2. Add or update fixed vectors that pin the new bytes. Don't regenerate a vector just to
   make a test pass.
3. Check that the decoder rejects malformed, truncated, trailing, and oversized input. A
   decoder must not panic or allocate based on a length it has not bounded.

Round-trip tests alone miss an encoder and decoder that agree on the wrong bytes. Use them
together with fixed vectors.

## Test helpers

- `ssz_proptest!` from [`strata-ssz-tests`](../crates/ssz-tests) writes a round-trip test
  and a tree hash determinism test for an SSZ type. Its transparent wrapper variant also
  checks that the wrapper hashes like its inner type.
- `generate_codec_tests!` from [`strata-codec-tests`](../crates/codec-tests) writes
  round-trip, determinism, and distinct-input property tests for a `Codec` type.
- The `test-utils` feature on `strata-identifiers` provides proptest strategies for its
  types. Reuse them instead of writing new generators.
