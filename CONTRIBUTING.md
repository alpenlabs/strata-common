# Contribution Guidelines

:+1::tada: First off, thanks for taking the time to contribute! :tada::+1:

We accept contributions in the following forms (non-exhaustive):

- **Bug reports**: A good bug report includes a succinct,
  reproducible context and the intended behavior.
- **Feature requests**: Should be followed by a thorough explanation of why
  the feature is important. Please note that not all feature requests will be
  accepted. If in doubt, please consider opening a discussion first.
- **Pull requests**: Clear and correct code with explanatory documentation
  and comments if necessary. If adding new functionality or fixing bugs,
  we expect accompanying tests. Pull requests will undergo a review process,
  and if accepted, the changes will be incorporated into the codebase.
- **Discussions**: Contributions that cannot be framed as bug reports
  or pull requests are good candidates for discussions. Please be polite
  and present civilized arguments in discussions.
- **Security Reports**: If you believe you have found a vulnerability,
  please provide details [here](mailto:security@alpenlabs.io) instead.

## Development Tools

Please install the following tools in your development environment to make sure that
you can run the basic CI checks in your local environment:

- [`just`](https://github.com/casey/just):
  runs the commands in `.justfile`. `just` lists them.
- [`taplo`](https://taplo.tamasfe.dev/cli/installation/binary.html):
  used to lint and format `TOML` files.
- [`cargo-nextest`](https://nexte.st):
  modern test runner for Rust.
- [`cargo-hack`](https://github.com/taiki-e/cargo-hack):
  runs the tests once per feature, as CI does.
- [`cargo-audit`](https://docs.rs/cargo-audit/latest/cargo_audit/):
  tool to check `Cargo.lock` files for security vulnerabilities.

`rustup` installs the nightly toolchain pinned in `rust-toolchain.toml` the first time you
run Cargo in the repo.

## Linting and Testing

```sh
just lints  # TOML and Rust formatting checks, taplo lint, and clippy
just test   # unit tests with all features, and doc tests
```

`just lints` fails on clippy warnings, as CI does. CI also runs the tests once per feature,
and builds the docs with warnings denied. Run these before you open a PR if you touched
feature-gated code or doc comments:

```sh
cargo hack --workspace --each-feature nextest run --locked
RUSTDOCFLAGS="-A rustdoc::private-doc-tests -D warnings" cargo doc --no-deps
```

For how the code is organized, see [`docs/`](docs/README.md).
