# Strata common crates

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache-blue.svg)](https://opensource.org/licenses/apache-2-0)
[![ci](https://github.com/alpenlabs/strata-common/actions/workflows/lint.yml/badge.svg?event=push)](https://github.com/alpenlabs/strata-common/actions)

Shared Rust crates for the Strata repos.

## What is strata-common?

Several Strata repos, such as [asm](https://github.com/alpenlabs/asm), [alpen](https://github.com/alpenlabs/alpen), [strata-bridge](https://github.com/alpenlabs/strata-bridge), and [moho](https://github.com/alpenlabs/moho), need to agree on the same types and bytes. This workspace holds the one copy they share: identifiers and buffers, Bitcoin and crypto types, the SPS-50 transaction tag and SPS-51 envelope formats, predicates, encodings and their adapters, Merkle trees and MMRs, schema versioning for stored values, and the task, service, logging, and metrics plumbing their binaries run on. Many of these crates implement upstream spec docs directly. Downstream repos depend on them by git tag.

## Goals

- **One copy.** Code that more than one repo needs lives here once, instead of drifting apart in each repo.
- **Stable interfaces.** Public types, feature flags, and encodings are contracts with other repos. A breaking change is marked as one.
- **Pure where it can be.** Encoding, protocol, and data structure crates do no I/O and keep no global state, so they can run in zkVM guests and consensus code.
- **Opt-in extras.** Optional formats and helpers sit behind feature flags, so consumers only pull in what they use.

## Deprecated Borsh support

Borsh is deprecated. It stays behind opt-in features only so existing consumers can keep reading and writing the encodings they already use. New types and new boundaries should use SSZ or `strata-codec` instead, and consumers still on Borsh should plan to move off it.

Borsh support is disabled by default. Consumers that still need it can enable the `borsh` feature on `strata-btc-types`, `strata-codec-utils`, `strata-crypto`, `strata-identifiers`, `strata-l1-txfmt`, `strata-merkle`, or `strata-predicate`:

```toml
strata-btc-types = { git = "https://github.com/alpenlabs/strata-common", tag = "v0.5.0", features = ["borsh"] }
```

Opting in restores the existing Borsh implementations and encodings. The `strata-btc-types` and `strata-crypto` features also enable Borsh support for their identifier fields. The `strata-codec-utils` feature exposes `CodecBorsh`, and `strata-crypto` exposes `compute_borsh_hash` when enabled. SSZ-backed Borsh implementations in `strata-identifiers` also require its `ssz` feature, which is enabled by default.

External dependencies can still pull in Borsh transitively. In particular, `zkaleido` enables it through its own defaults; this does not enable Borsh implementations on the types in this workspace.

## Contributing

Contributions are generally welcome. If you intend to make larger changes, please discuss them in an issue before opening a PR to avoid duplicate work and architectural mismatches.

[`CONTRIBUTING.md`](CONTRIBUTING.md) lists the tools you need and the commands to lint and test. For how the code fits together, see [`docs/`](docs/README.md): start with [`docs/architecture.md`](docs/architecture.md), then [`docs/layout.md`](docs/layout.md) for what each crate does.

## License

This work is dual-licensed under MIT and Apache 2.0.

You can choose between one of them if you use this work.
