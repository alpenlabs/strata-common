# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project Overview

strata-common is a Rust library workspace of types, encodings, protocol formats, data
structures, and service plumbing shared by several Strata repos. It has no binaries.

Downstream repos depend on it by git tag: [asm](https://github.com/alpenlabs/asm),
[alpen](https://github.com/alpenlabs/alpen),
[strata-bridge](https://github.com/alpenlabs/strata-bridge), and
[moho](https://github.com/alpenlabs/moho) among them. Public APIs, feature flags, and
encodings are interfaces between repos. Changing one can break a repo you can't build
from here.

Contributor docs are in [`docs/`](docs/README.md). Read
[`docs/architecture.md`](docs/architecture.md) before adding a crate or moving code between
crates, and [`docs/serialization.md`](docs/serialization.md) before touching an encoding.

## Commands

```bash
just fmt                  # format Rust
just lints                # TOML and Rust format checks, taplo lint, clippy
just unit-test            # cargo nextest over the workspace, all features
just doctest
cargo nextest run --locked --all-features -p <crate>         # one crate
cargo hack --workspace --each-feature nextest run --locked    # as CI runs the tests
RUSTDOCFLAGS="-A rustdoc::private-doc-tests -D warnings" cargo doc --no-deps  # as CI builds docs
```

Run Cargo from the workspace root. `rust-toolchain.toml` pins a nightly toolchain;
`rustfmt.toml` uses options only nightly rustfmt supports. `just lints` needs `taplo`. The
tests need `cargo-nextest`, and the per-feature run needs `cargo-hack`. No test needs an
external process.

## Architecture

See [`docs/layout.md`](docs/layout.md) for every crate.

- `crates/codec`, `codec-derive`, `codec-utils`, `serde-utils`: `strata-codec` and the
  adapters between it, SSZ, Borsh, and serde.
- `crates/identifiers`, `btc-types`, `crypto`, `predicate`: buffers, typed IDs, Bitcoin
  and crypto types, and the predicate format.
- `crates/l1proto/txfmt`, `l1proto/envelope-fmt`, `msg-fmt`, `ol-logs`: SPS-50 tags,
  SPS-51 envelopes, typed messages, and OL log payloads.
- `crates/merkle`, `merkle-store`: Merkle trees, MMRs, and a node-storing MMR.
- `crates/db-schema-common`, `db-macros`: versioned stored values and DB proxy handles.
- `crates/tasks`, `service`, `retry`, `logging`, `metrics`, `rpc-tracing`: runtime and
  observability plumbing for downstream binaries.
- `crates/codec-tests`, `ssz-tests`: property-test macros.

## Testing

- Add a regression test for every bug fix and focused tests for new public behavior. Test
  public contracts and edge cases, not private details.
- Don't re-test what an upstream library already guarantees.
- Use property tests for codecs, parsers, identifiers, and data structures. Include
  boundary values and malformed input. `ssz_proptest!` and `generate_codec_tests!` write
  the round-trip tests for you.
- Pin stable encodings with fixed vectors as well as round trips. Never regenerate a vector
  just to make a test pass.
- Exercise the real encoding or assembly path together with its decoding or verification
  path.
- Reuse shared fixtures and generators, such as the `test-utils` features on
  `strata-identifiers`, `strata-crypto`, and `strata-l1-envelope-fmt`. Don't copy setup
  between crates.
- Make tests deterministic and independent of external processes. Prefer `assert_eq!` and
  `assert_matches!`-style assertions over `assert!` when comparing values.
- Run the affected crate first, then widen. If you touched feature-gated code, run the
  per-feature command above.

## Commit and PR Style

- Use Conventional Commits with the crate as scope, for example `fix(merkle): ...`. Add `!`
  for a breaking change, for example `feat(l1-envelope-fmt)!: ...`.
- Keep each commit to one logical change that builds on its own.
- Follow [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md).
- Keep PRs focused. Put unrelated refactors, migrations, and cleanup in their own PR.
  Update docs and tests in the same PR as the behavior they describe.
- Run `just fmt`, `just lints`, and the tests for what you changed. Don't add new warnings.
  `just lints` fails on clippy warnings, as CI does. CI also fails on `cargo doc` warnings,
  so build the docs as above if you changed doc comments. Not every docs-only change needs a
  Rust build. Say in the PR what you ran and what you skipped.
- Never weaken a lint or a test to make validation pass. Fix the cause, or explain why a
  narrow exception is needed.

## Notes

- **Cross-repo interfaces**: a public type, trait, feature flag, or encoding may be used by
  any downstream repo. Keep changes compatible unless the task calls for a break, and call
  out the effect in the PR. Downstream repos pick up a change only when they move to a new
  tag.
- **Encodings**: changing an encoded field, its order, a tag, a length bound, or a hash
  input is a protocol change. Mark it `!` and add vectors for the new bytes. See
  [`docs/serialization.md`](docs/serialization.md).
- **Borsh is deprecated**: it stays behind opt-in `borsh` features only for existing
  consumers. New encodings use SSZ or `strata-codec`.
- **SSZ schemas**: `crates/btc-types`, `crates/crypto`, `crates/merkle`, `crates/ol-logs`,
  and `crates/predicate` generate SSZ types in `build.rs` from the `.ssz` files in their
  `ssz/` directory. For those types, edit the schema, not the generated code.
- **Pure crates**: the encoding, identifier, protocol-format, and data-structure crates run
  in zkVM guests and consensus code downstream. Keep them free of I/O, async runtimes,
  global state, wall-clock time, and `HashMap` iteration order in outputs. Decoders must
  never panic or allocate unbounded memory on untrusted input.
- **Process-global setup**: `strata-logging` and `strata-metrics` install global state.
  Only a binary calls their `init`. Library code emits `tracing` events and `metrics`
  instruments.
- **Features**: CI runs the tests once per feature, so feature-gated code must build and
  pass with the feature on and off. Defaults differ between crates; check the crate's
  `Cargo.toml`. Keep optional dependencies behind `dep:` in the feature that uses them.
- **Unused dependencies**: the workspace denies `unused_crate_dependencies`. When a
  dev-dependency is used only by feature-gated tests, silence it in `lib.rs` with
  `#[cfg(all(test, not(feature = "...")))] use some_crate as _;`, as
  [`crates/predicate/src/lib.rs`](crates/predicate/src/lib.rs) does.
- **Workspace lints**: every crate sets `[lints] workspace = true`. `missing_docs`,
  `unreachable_pub`, `missing_debug_implementations`, and `rustdoc::all` warn, so they fail
  `just lints` and CI.
- **Dependencies**: declare versions in the root `Cargo.toml` and use `workspace = true`.
  The ssz-gen crates share one tag; bump them together. `.cargo/config.toml` refuses
  crates.io versions less than 14 days old.

## Code Style

### Design and API Boundaries

- Put code in the narrowest crate that owns the behavior, and don't create dependency
  cycles. Keep application policy, deployment, and repo-specific orchestration out of these
  crates.
- Give each crate, module, and type one focused job. Keep pure protocol and data processing
  independent of I/O, persistence, async runtimes, and operational policy.
- Take dependencies through narrow traits when callers need several implementations.
  Accept concrete types when an abstraction adds no real boundary.
- Encode invariants in types. Use typed IDs and domain values inside, and convert to
  strings or byte containers only at presentation or serialization boundaries.
- Don't expose public fields on nontrivial domain types. Provide constructors, accessors,
  borrowed views, and operations that keep invariants. Plain data carriers with no
  invariants may have public fields.
- Keep constructors to field assembly and cheap checks. Give substantial computation or
  I/O its own named function.
- Reuse existing primitives, codecs, test helpers, and error types instead of duplicating
  them at call sites.

### Serialization

- Use the format the boundary already uses. The workspace has SSZ, `strata-codec`, Borsh,
  and serde adapters; that doesn't make them interchangeable.
- Borsh is deprecated. Keep existing Borsh implementations behind their `borsh` features
  with unchanged bytes, but don't add Borsh to new types or boundaries.
- Keep domain types separate from wire or storage types when their fields or invariants
  differ. Convert and validate at the boundary.
- Decoders reject malformed, truncated, trailing, and oversized input.

### Ownership and Allocation

- Borrow to inspect, take ownership when you need it, and use `&mut` for in-place changes.
- Avoid needless clones, temporary collections, repeated encoding buffers, and `Arc` with
  no sharing need.

### Naming and Documentation

- `snake_case` for files, modules, and functions. `UpperCamelCase` for types and traits.
  `SCREAMING_SNAKE_CASE` for constants.
- Use precise verbs for functions that do work. Use bare nouns for cheap accessors, `as_`
  for cheap borrowed views, `to_` for allocating conversions, and `with_` for builders.
- Import with `use` declarations instead of repeating long qualified paths inline.
- Give public items a one-sentence summary. Use intra-doc links such as ``[`SomeType`]``.
  Document invariants, ordering, units, preconditions, and design reasons, and add
  `# Errors`, `# Panics`, and `# Safety` sections where they apply.
- Comments explain why, not what.
- Keep examples compilable, and update a crate's README when its public workflow changes.
- Implement `Default` only when the type has a real domain default. Add `const` only when
  compile-time use is part of the API.

### Error Handling

| Context | Approach |
| --- | --- |
| Invalid input or recoverable failure | `Result` with structured variants |
| Expected absence | `Option`, not a sentinel or default |
| Broken internal invariant | `assert!`, `unwrap()`, or `expect("the invariant")` |
| Library errors | an error `enum` or `struct` with `thiserror` |
| Application-like orchestration boundary | `anyhow` with context |

- Never panic on malformed or untrusted input.
- Keep error variants and source chains distinct across layers. Don't collapse failures
  into strings or catch-all variants.
- Error messages describe the failure without an `error` prefix.

### Async and Concurrency

- Never block an async executor thread. Use an async API or the runtime's blocking-task
  facility.
- Don't hold a lock guard across `.await`.
- Workers own their state. Expose commands and status through a handle.
- Make shutdown and cancellation explicit. Don't detach tasks whose failure or lifetime
  matters to the caller.

### Observability

- Use structured `tracing` fields, not interpolated strings. Include the IDs needed to
  correlate an event. Don't log secrets or repeat context the module or span already gives.
- `error!` for unrecoverable failures, `warn!` for unexpected conditions someone should act
  on, `info!` for lifecycle events, `debug!` for diagnostics, `trace!` for high-volume
  detail.
- Expected lag, graceful shutdown, irrelevant traffic, and rejected untrusted input should
  not warn.
- Keep pure processing code free of operational logs when the caller can report with
  better context.
- Use counters for totals, gauges for current values, and histograms for distributions such
  as latency or payload size.
