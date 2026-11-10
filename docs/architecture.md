# Architecture

strata-common is a library workspace. It has no binaries and runs nothing on its own. It
holds the types, encodings, protocol formats, data structures, and service plumbing that
more than one Strata repo needs, so those repos agree on them by sharing one copy.

## Who uses it

Downstream repos depend on these crates by git tag, not by path or branch. For example,
[asm](https://github.com/alpenlabs/asm),
[alpen](https://github.com/alpenlabs/alpen),
[strata-bridge](https://github.com/alpenlabs/strata-bridge), and
[moho](https://github.com/alpenlabs/moho) each pin a `vX.Y.Z` tag of this repo in their root
`Cargo.toml`. Repos can sit on different tags at the same time, and several crates here end
up inside zkVM guests in those repos.

This shapes what belongs here:

- A public type, trait, feature flag, or encoding is an interface between repos. Changing
  it can break a repo you can't see from this one.
- An encoding or hash that one repo writes and another reads must give the same bytes on
  both sides. See [serialization.md](serialization.md).
- Application policy, deployment concerns, and anything only one repo needs stay in that
  repo.

## How the crates layer

Most crates sit on one of a few foundations. In the diagram, each arrow points at the crate
being depended on.

```text
strata-codec-derive ◀── strata-codec ◀──┬── strata-identifiers ◀──┬── strata-btc-types
                                        │                         ├── strata-crypto
                                        │                         ├── strata-ol-logs ──▶ strata-msg-fmt
                                        │                         └── strata-l1-envelope-fmt ──▶ strata-l1-txfmt
                                        ├── strata-merkle ◀── strata-merkle-node-store
                                        ├── strata-codec-utils
                                        ├── strata-serde-utils
                                        ├── strata-db-schema-common
                                        └── strata-codec-tests

strata-tasks ◀── strata-service
```

These crates depend on no other crate in this workspace: `strata-predicate`,
`strata-retry`, `strata-logging`, `strata-metrics`, `strata-rpc-tracing`,
`strata-db-macros`, and `strata-ssz-tests`.

The groups, from the bottom up:

- **Encoding.** `strata-codec` is a small binary codec with explicit layouts. The adapter
  crates let SSZ, Borsh, and serde types pass through it and back. See
  [serialization.md](serialization.md).
- **Identifiers and domain types.** `strata-identifiers` defines the fixed-size buffers
  (`Buf32` and friends) and typed IDs for L1 blocks, OL blocks, epochs, and accounts.
  `strata-btc-types` and `strata-crypto` build on the same buffers.
- **L1 protocol formats.** `strata-l1-txfmt` parses SPS-50 transaction tags.
  `strata-l1-envelope-fmt` builds and parses the script envelopes that carry larger
  payloads, and authenticates signed envelopes at the spend level. `strata-predicate`
  implements the versioned predicate format used to verify signatures and proofs.
- **Data structures.** `strata-merkle` has Merkle trees and the compact Merkle mountain
  range (MMR) accumulator. `strata-merkle-node-store` stores every MMR node behind a
  storage trait, so proofs need no leaf replay.
- **Storage support.** `strata-db-schema-common` versions stored values and migrates them
  between versions. `strata-db-macros` generates async and blocking proxy handles for
  database traits.
- **Services and observability.** `strata-tasks` spawns and supervises tasks and handles
  shutdown. `strata-service` builds message-driven workers on top of it. `strata-logging`,
  `strata-metrics`, and `strata-rpc-tracing` set up process-wide tracing, metrics, and
  RPC trace propagation.

[layout.md](layout.md) lists every crate with a link.

## Pure and runtime code

The encoding, identifier, protocol-format, and data-structure crates are pure: no I/O, no
async runtime, no global state, and no logging the caller could do better. Downstream repos
run some of them in zkVM guests and inside consensus code, where determinism matters. Keep
it that way. If a change to one of these crates needs I/O or a runtime, the new code
probably belongs in a separate crate or in the downstream repo.

The service and observability crates are runtime code. Even so, `strata-logging` and
`strata-metrics` install process-global state, so only a binary should call their `init`.
Libraries emit `tracing` events and `metrics` instruments and leave export to the binary.

## Feature flags

Many crates gate optional formats and helpers behind features, and the defaults differ
from crate to crate. For example, the deprecated `borsh` feature is off everywhere, `ssz` is on by default in
`strata-identifiers` but off in `strata-merkle`, and `test-utils` exposes fixtures and
generators. Check the crate's `Cargo.toml` before assuming a feature is on.

Because downstream repos turn features on and off independently, CI runs the tests once
per feature with `cargo hack --workspace --each-feature`. Code behind a feature has to
build and pass both with and without it.

## Releases

A release is a `v*` tag on `main`. The [release workflow](../.github/workflows/release.yml)
creates the GitHub release with generated notes. Downstream repos consume the tag through
git dependencies, not crates.io, and move their pins to it in their own PRs.

A change that breaks an API or an encoding is marked with `!` in its commit title, so the
release notes call it out. Pre-release tags (`-rc.N`) let downstream repos try a release
before it is final.
