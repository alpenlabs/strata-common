# AGENTS.md

This file provides guidance to coding agents working in this repository.

## Repository Scope

`strata-common` is a Rust workspace for reusable types, codecs, cryptography, data
structures, observability, and service utilities shared by multiple Strata projects.
Treat public APIs, feature flags, and serialized representations as cross-repository
interfaces.

- Keep changes focused on the crate that owns the behavior. Put broadly reusable code in
  the narrowest appropriate crate and avoid creating dependency cycles.
- Preserve public API and wire-format compatibility unless the task explicitly calls for a
  breaking change. Call out unavoidable compatibility effects.
- Do not add application policy, deployment concerns, or repository-specific orchestration
  to a general-purpose crate.
- Reuse existing primitives, codecs, test helpers, and error types instead of duplicating
  their behavior at call sites.

## Development Workflow

Run Cargo commands from the workspace root and use the toolchain pinned in
`rust-toolchain.toml`. During iteration, prefer the smallest command that exercises the
changed crate; before handoff, run the applicable workspace checks.

```bash
cargo fmt --all --check
cargo clippy --examples --tests --benches --all-features --all-targets --locked
cargo hack --workspace --each-feature nextest run --locked
cargo test --doc --all-features
cargo doc --no-deps
taplo lint
taplo fmt --check
```

Not every documentation-only change needs a Rust build. Report which checks ran and which
were skipped. Never weaken a lint or test merely to make validation pass; address the cause
or document why a narrowly scoped exception is necessary.

Declare dependencies shared by workspace members in the root `Cargo.toml`, then inherit
them with `workspace = true`. Every crate should inherit the workspace lints. Keep optional
dependencies aligned with their feature flags, and test affected non-default feature
combinations.

## Rust Design and APIs

- Encode invariants in types and constructors so invalid states are hard to represent.
- Give each crate, module, and type a focused responsibility. Keep pure protocol and data
  processing independent of I/O, persistence, async runtimes, and operational policy.
- Express dependencies through narrow traits when callers need multiple implementations.
  Accept concrete types when abstraction does not provide a real boundary.
- Keep fields private on nontrivial domain types. Expose constructors, semantic accessors,
  borrowed views, and operations that preserve invariants. Public fields are appropriate
  for deliberately transparent data carriers with no invariants.
- Keep constructors to field assembly and inexpensive validation. Use explicitly named
  functions for substantial computation or I/O.
- Use typed identifiers and domain values internally. Convert to strings or generic byte
  containers only at presentation or serialization boundaries.
- Borrow values for inspection, consume them when ownership is required, and use `&mut` for
  in-place changes. Avoid unconditional clones, temporary collections, repeated encoding
  buffers, and `Arc` without an actual sharing requirement.
- Implement `Default` only when the type has a meaningful domain default. Use fixtures or
  generators for arbitrary test values.
- Add `const` only when compile-time use is meaningful and intended as an API guarantee.
- Import symbols with `use` declarations rather than repeating long qualified paths inline.

Use precise verbs for operations. Use a bare noun for a cheap accessor, `as_` for a cheap
borrowed view, `to_` for an allocating conversion, and `with_` for builder-style methods.
Follow Rust naming conventions: `snake_case` files and functions, `UpperCamelCase` types,
and `SCREAMING_SNAKE_CASE` constants.

## Documentation

- Give public items a concise first sentence that stands alone as a summary.
- Document non-obvious invariants, ordering requirements, units, preconditions, and design
  rationale. Explain why code exists instead of restating its implementation.
- Use intra-doc links such as ``[`SomeType`]`` when referring to Rust items.
- Include `# Errors`, `# Panics`, and `# Safety` sections where those contracts apply.
- Keep examples compilable and update crate READMEs when a public workflow changes.

## Error and Panic Semantics

- Return `Result` for invalid input and recoverable failures. Reusable library APIs should
  expose structured errors, normally using `thiserror`, and preserve useful distinctions at
  abstraction boundaries.
- Return `Option` for expected absence; do not invent sentinel values or silently substitute
  a default.
- Use `assert!`, `unwrap()`, or `expect()` only for programming bugs and clearly established
  internal invariants. An `expect()` message should name the invariant that was violated.
- Never panic on malformed or untrusted input. Propagate a descriptive error without an
  unnecessary `error` prefix.
- Use `anyhow` only at application-like orchestration boundaries where callers do not need
  to match individual error variants. Add context while preserving the underlying source.

## Async, Concurrency, and Services

- Never perform blocking I/O or expensive blocking work on an async executor thread. Use an
  async API or the runtime's blocking-task facility.
- Do not hold a lock guard across an `.await` point.
- Keep mutable worker state owned by the worker. Expose commands and status through a handle
  rather than sharing the worker's internals behind locks.
- Make shutdown and cancellation behavior explicit. Do not detach tasks whose failures or
  lifetimes matter to the caller.

## Logging and Metrics

Use structured `tracing` fields and include the identifiers needed to correlate an event.
Do not interpolate structured data into the message, log secrets, or add redundant component
fields when the module path or span already supplies that context.

- `error!`: an unrecoverable failure requiring attention
- `warn!`: an unexpected, actionable condition where processing can continue
- `info!`: a significant lifecycle event or milestone
- `debug!`: diagnostic detail useful during investigation
- `trace!`: high-volume step-by-step detail

Expected lag, graceful shutdown, irrelevant traffic, and rejected untrusted input should not
produce repetitive warnings. Keep pure processing code free of operational logging when the
caller can report the result with better context. Use counters for monotonic totals, gauges
for current values, and histograms for distributions such as latency or payload size.

## Serialization and Compatibility

- Treat changes to encodings, hashes, identifier layouts, and tree calculations as protocol
  changes. Check downstream compatibility and add regression vectors for intentional
  changes.
- Use the format already assigned to the boundary. This workspace includes SSZ,
  `strata-codec`, Borsh, JSON, and CBOR adapters; their presence does not make the formats
  interchangeable.
- Keep domain types separate from wire or storage types when their fields or invariants
  differ. Convert at the boundary.
- Decoders must reject malformed, truncated, trailing, and oversized input as appropriate.
  Avoid panics and unbounded allocation based on attacker-controlled lengths.
- Round-trip tests are necessary but not always sufficient. For stable formats, also use
  known encodings or cross-implementation vectors to catch mutually compatible encoder and
  decoder bugs.

## Testing

- Add a regression test for every bug fix and focused tests for new public behavior.
- Test public contracts and edge cases rather than private implementation details or
  guarantees already provided by upstream libraries.
- Prefer descriptive test names and `assert_eq!`/`assert_matches!`-style assertions that
  preserve useful failure output.
- Use property tests for codecs, parsers, identifiers, and data structures with broad input
  spaces. Include boundary values and malformed inputs.
- Exercise production encoding and assembly paths together with the matching decoding or
  verification paths.
- Keep unit tests deterministic and independent of external processes. Share fixtures and
  generators instead of copying setup logic between crates.

## Pull Requests

Read and follow [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md)
before preparing a pull request. Keep changes independently reviewable and separate
unrelated refactors or migrations. Update documentation and tests in the same change as the
behavior they describe.
