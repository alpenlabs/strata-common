# Contributor docs

These pages explain how strata-common is put together, and link to the code for the details.

- [Architecture](architecture.md): how the crates layer, who uses them, and how releases
  reach downstream repos.
- [Repository layout](layout.md): what each crate is for.
- [Serialization](serialization.md): the encoding formats, the adapters between them, and
  the rules for changing one.

Crate-specific guides live next to the code:

- [`strata-codec`](../crates/codec/README.md)
- [`strata-codec-derive`](../crates/codec-derive/README.md)
- [`strata-db-macros`](../crates/db-macros/README.md)
- [`strata-rpc-tracing`](../crates/rpc-tracing/README.md)

If you change behavior a page describes, update the page in the same PR.
