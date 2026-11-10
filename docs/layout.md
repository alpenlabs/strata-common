# Repository layout

This page lists each crate and what it does. Every crate lives under [`crates/`](../crates),
and every package name starts with `strata-`. Package names are in parentheses where they
differ from the directory name. Each crate's `lib.rs` doc comment has more.

## Encoding

See [serialization.md](serialization.md) for how these fit together.

- [`codec`](../crates/codec) (`strata-codec`): the `Codec`, `Encoder`, and `Decoder`
  traits, `BufDecoder`, varints, and `VarVec`. The `derive` feature re-exports the derive
  macro.
- [`codec-derive`](../crates/codec-derive) (`strata-codec-derive`): `#[derive(Codec)]` for
  structs whose fields all implement `Codec`.
- [`codec-utils`](../crates/codec-utils) (`strata-codec-utils`): `CodecSsz` to carry an SSZ
  type through `Codec`, `ChunkIterDecoder`, and, with the `borsh` feature, `CodecBorsh`.
- [`serde-utils`](../crates/serde-utils) (`strata-serde-utils`): `SerdeSsz` and
  `SerdeCodec`, which expose SSZ and `Codec` types through serde.

## Identifiers and domain types

- [`identifiers`](../crates/identifiers) (`strata-identifiers`): `Buf20`, `Buf32`, `Buf64`,
  and typed IDs and commitments for L1 blocks, OL blocks, epochs, accounts, and execution.
  The `test-utils` feature adds proptest strategies.
- [`btc-types`](../crates/btc-types) (`strata-btc-types`): wrappers around rust-bitcoin
  types, such as amounts, txids, outpoints, outputs, scripts, and x-only keys, that add
  SSZ and other encodings. Also wraps the network params.
- [`crypto`](../crates/crypto) (`strata-crypto`): hashing, Schnorr signatures, even-parity
  keys, MuSig2 key aggregation, and threshold signature configs.
- [`predicate`](../crates/predicate) (`strata-predicate`): the SPS-predicate-fmt
  predicate keys and their verifiers. The default `all-verifiers` feature turns on Schnorr
  and SP1 Groth16.

## L1 protocol formats

- [`l1proto/txfmt`](../crates/l1proto/txfmt) (`strata-l1-txfmt`): SPS-50 transaction tags:
  the `OP_RETURN` at output 0 that carries the magic bytes, subprotocol ID, and transaction
  type.
- [`l1proto/envelope-fmt`](../crates/l1proto/envelope-fmt) (`strata-l1-envelope-fmt`):
  builds and parses `OP_FALSE OP_IF ... OP_ENDIF` envelopes and envelope containers, and
  authenticates SPS-51 signed envelopes at the spend level.
- [`msg-fmt`](../crates/msg-fmt) (`strata-msg-fmt`): the generic typed message format, a
  type ID followed by a body.
- [`ol-logs`](../crates/ol-logs) (`strata-ol-logs`): orchestration layer (OL) log payloads
  carried in checkpoint sidecars, and their decoder.

## Data structures

- [`merkle`](../crates/merkle) (`strata-merkle`): binary Merkle trees, the compact MMR, and
  their proofs, generic over a `MerkleHasher`. The `legacy_compact` feature keeps the old
  compact MMR for compatibility. `benches/` compares MMR implementations.
- [`merkle-store`](../crates/merkle-store) (`strata-merkle-node-store`): an MMR that stores
  every node through the `MmrNodeStore` trait, with an in-memory backend.

## Storage support

- [`db-schema-common`](../crates/db-schema-common) (`strata-db-schema-common`): versioned
  value containers, `decl_schema_version!`, and a `Migrator` that upgrades stored values
  across schema versions.
- [`db-macros`](../crates/db-macros) (`strata-db-macros`): `#[gen_proxy]`, which wraps a
  database trait in a handle that runs each call on a Tokio blocking task.

## Services and observability

- [`tasks`](../crates/tasks) (`strata-tasks`): `TaskManager` and `TaskExecutor` for
  spawning critical tasks, catching panics, and shutting down on signals.
- [`service`](../crates/service) (`strata-service`): a framework for async and blocking
  workers with command handles, status monitors, and graceful shutdown.
- [`retry`](../crates/retry) (`strata-retry`): retry with backoff for async calls, with a
  serde-friendly `RetryConfig`.
- [`logging`](../crates/logging) (`strata-logging`): process-level `tracing` setup for
  stdout, rolling files, and OTLP export.
- [`metrics`](../crates/metrics) (`strata-metrics`): process-level `metrics` recorder with
  Prometheus and OTLP exporters.
- [`rpc-tracing`](../crates/rpc-tracing) (`strata-rpc-tracing`): OpenTelemetry spans and
  W3C trace context propagation for jsonrpsee clients and servers.

## Test helpers

- [`codec-tests`](../crates/codec-tests) (`strata-codec-tests`):
  `generate_codec_tests!`, which writes round-trip property tests for a `Codec` type.
- [`ssz-tests`](../crates/ssz-tests) (`strata-ssz-tests`): `ssz_proptest!`, which writes
  round-trip and tree hash property tests for an SSZ type.

## Other

- [`.github/workflows`](../.github/workflows): lint, unit and doc tests, docs, security
  audit, `zizmor`, and release.
- [`.cargo/config.toml`](../.cargo/config.toml): the 14-day minimum publish age for
  crates.io dependencies.
- [`rust-toolchain.toml`](../rust-toolchain.toml): the pinned nightly toolchain.

External protocol libraries come from [ssz-gen](https://github.com/alpenlabs/ssz-gen),
[zkaleido](https://github.com/alpenlabs/zkaleido), and
[bitcoin-bosd](https://github.com/alpenlabs/bitcoin-bosd). All three are pinned by tag in
the root `Cargo.toml`.
