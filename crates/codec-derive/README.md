# strata-codec-derive

Procedural macro for deriving the `Codec` trait from `strata-codec`.

## Overview

This crate provides a `#[derive(Codec)]` macro that automatically generates implementations of the `Codec` trait for structs. It eliminates the boilerplate of manually implementing `encode` and `decode` methods.

## Usage

Add the derive feature to your `strata-codec` dependency:

```toml
[dependencies]
strata-codec = { version = "0.1", features = ["derive"] }
```

Then use the derive macro on your structs:

```rust
use strata_codec::Codec;

#[derive(Codec)]
struct MyStruct {
    field1: u32,
    field2: [u8; 32],
    field3: bool,
}
```

## Supported Types

The derive macro supports:

- **Named structs**: Structs with named fields
- **Tuple structs**: Structs with unnamed fields
- **Unit structs**: Structs with no fields
- **Generic structs**: With appropriate trait bounds

All fields must implement the `Codec` trait.

## Field Encoding Order

Fields are encoded and decoded in declaration order. This ensures compatibility with manually implemented `Codec` traits that follow the same convention.

## Examples

### Named Struct

```rust
#[derive(Codec)]
struct User {
    id: u32,
    name_hash: [u8; 32],
    active: bool,
}
```

### Tuple Struct

```rust
#[derive(Codec)]
struct Point(i32, i32);
```

### Generic Struct

```rust
#[derive(Codec)]
struct Container<T: Codec> {
    value: T,
    count: u32,
}
```

## Limitations

Currently, the derive macro only supports structs. Enum support may be added in the future.

## License

This crate inherits the license from the parent workspace.