# Strata common crates

This repo contains crates that are shared between the different Strata repos.

Initially, this will contain crates relevant for the core protocol, but in the
future it may include crates for APIs and messaging around the sides of the core
system.  Most crates here for now will be directly implementing upstream spec
docs.

More will be here in the future.

## Deposit descriptors

`strata-identifiers` exports `DepositDescriptor` and `DepositDescriptorError` for
wallet construction, admission-time syntax validation, and execution-layer decoding.
The compact wire format is unchanged from alpen's deposit descriptor. Decoding
checks syntax only; account existence and deposit routing remain execution-layer policy.
The type and its byte-vector encoding work without default features. Enable `codec`
for `encode_to_varvec()` and `arbitrary` for the `Arbitrary` implementation.

## Optional Borsh support

Borsh support is disabled by default. Consumers that need it can enable the
`borsh` feature on `strata-btc-types`, `strata-codec-utils`, `strata-crypto`,
`strata-identifiers`, `strata-l1-txfmt`, `strata-merkle`, or `strata-predicate`:

```toml
strata-btc-types = { version = "0.1", features = ["borsh"] }
```

Opting in restores the existing Borsh implementations and encodings. The
`strata-btc-types` and `strata-crypto` features also enable Borsh support for their
identifier fields. The `strata-codec-utils` feature exposes `CodecBorsh`, and
`strata-crypto` exposes `compute_borsh_hash` when enabled. SSZ-backed Borsh
implementations in `strata-identifiers` also require its `ssz` feature, which is
enabled by default.

External dependencies can still pull in Borsh transitively. In particular,
`zkaleido` enables it through its own defaults; this does not enable Borsh
implementations on the types in this workspace.

## Contributing

Contributions are generally welcome.
If you intend to make larger changes please discuss them in an issue
before opening a PR to avoid duplicate work and architectural mismatches.

For more information please see [`CONTRIBUTING.md`](/CONTRIBUTING.md).

## License

This work is dual-licensed under MIT and Apache 2.0.

You can choose between one of them if you use this work.
