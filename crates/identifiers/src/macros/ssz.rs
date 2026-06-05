//! SSZ view trait macros for identifier and wrapper types.
//!
//! These macros generate the boilerplate trait implementations (`DecodeView`,
//! `SszTypeInfo`, `TreeHash`, `ToOwnedSsz`) that the SSZ view layer requires.
//! Three macros are provided, each targeting a different structural pattern:
//!
//! | Macro | Use when… |
//! |---|---|
//! | [`impl_ssz_fixed_container!`] | Multi-field struct with `#[ssz(struct_behaviour = "container")]` |
//! | [`impl_ssz_transparent_wrapper!`] | Newtype whose inner type already implements `DecodeView` |
//! | [`impl_ssz_transparent_byte_array_wrapper!`] | Newtype wrapping a raw `[u8; N]` (which lacks `DecodeView`) |
//!
//! ## Choosing the right macro
//!
//! ```text
//!  Is the type a multi-field container?
//!    ├─ Yes → impl_ssz_fixed_container!
//!    └─ No (newtype / transparent wrapper)
//!         ├─ Inner type has DecodeView? (Buf32, RBuf32, u64, …)
//!         │    └─ Yes → impl_ssz_transparent_wrapper!
//!         └─ Inner type is [u8; N]?
//!              └─ Yes → impl_ssz_transparent_byte_array_wrapper!
//! ```
//!
//! The split between the two transparent-wrapper macros exists because `[u8; N]`
//! does **not** implement `DecodeView` in the `ssz` crate — only
//! `FixedBytes<N>` does. Since both `[u8; N]` and `DecodeView` are foreign,
//! the orphan rule prevents adding that impl locally, so
//! `impl_ssz_transparent_byte_array_wrapper!` provides a manual `DecodeView`
//! via `TryInto` plus `From` conversions with `FixedBytes<N>`.

/// Generates SSZ view trait implementations for a fixed-size container type.
///
/// Use this for structs annotated with `#[ssz(struct_behaviour = "container")]`
/// whose fields are all fixed-size. Generates:
/// - `TreeHash` implementation
/// - `SszTypeInfo` implementation (computes fixed size from field types)
/// - A `{Type}Ref` view type with `DecodeView`, `SszTypeInfo`, `TreeHash`, and `ToOwnedSsz`
///
/// The `{Type}Ref` name is auto-generated via [`paste`].
///
/// # Example
///
/// ```ignore
/// #[derive(Encode, Decode)]
/// #[ssz(struct_behaviour = "container")]
/// pub struct MyContainer {
///     pub a: u64,
///     pub b: Buf32,
/// }
///
/// impl_ssz_fixed_container!(MyContainer, [a: u64, b: Buf32]);
/// // Generates: MyContainerRef<'a>
/// ```
#[macro_export]
macro_rules! impl_ssz_fixed_container {
    ($type:ident, [$($field:ident: $field_ty:ty),+ $(,)?]) => {
        ::paste::paste! {
            // TreeHash implementation
            impl ::tree_hash::TreeHash for $type {
                fn tree_hash_type() -> ::tree_hash::TreeHashType {
                    ::tree_hash::TreeHashType::Container
                }

                fn tree_hash_packed_encoding(&self) -> ::tree_hash::PackedEncoding {
                    unreachable!("Container should never be packed")
                }

                fn tree_hash_packing_factor() -> usize {
                    unreachable!("Container should never be packed")
                }

                fn tree_hash_root<H: ::tree_hash::TreeHashDigest>(&self) -> H::Output {
                    let mut hasher = ::tree_hash::MerkleHasher::<H>::with_leaves(
                        $crate::impl_ssz_fixed_container!(@count $($field),+)
                    );
                    $(
                        hasher
                            .write(
                                <$field_ty as ::tree_hash::TreeHash>::tree_hash_root::<H>(&self.$field)
                                    .as_ref(),
                            )
                            .expect("tree hash derive should not apply too many leaves");
                    )+
                    hasher
                        .finish()
                        .expect("tree hash derive should not have a remaining buffer")
                }
            }

            // SszTypeInfo implementation
            impl ::ssz::view::SszTypeInfo for $type {
                fn is_ssz_fixed_len() -> bool {
                    true
                }

                fn ssz_fixed_len() -> usize {
                    0 $(+ <$field_ty as ::ssz::view::SszTypeInfo>::ssz_fixed_len())+
                }
            }

            // Ref view type
            /// SSZ zero-copy view reference for the parent type.
            #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Default)]
            pub struct [<$type Ref>]<'a> {
                inner: $type,
                _phantom: ::std::marker::PhantomData<&'a ()>,
            }

            impl<'a> ::ssz::view::DecodeView<'a> for [<$type Ref>]<'a> {
                fn from_ssz_bytes(bytes: &'a [u8]) -> Result<Self, ::ssz::DecodeError> {
                    let inner = <$type as ::ssz::Decode>::from_ssz_bytes(bytes)?;
                    Ok(Self {
                        inner,
                        _phantom: ::std::marker::PhantomData,
                    })
                }
            }

            impl<'a> ::ssz::view::SszTypeInfo for [<$type Ref>]<'a> {
                fn is_ssz_fixed_len() -> bool {
                    <$type as ::ssz::view::SszTypeInfo>::is_ssz_fixed_len()
                }

                fn ssz_fixed_len() -> usize {
                    <$type as ::ssz::view::SszTypeInfo>::ssz_fixed_len()
                }
            }

            impl<'a> ::tree_hash::TreeHash for [<$type Ref>]<'a> {
                fn tree_hash_type() -> ::tree_hash::TreeHashType {
                    <$type as ::tree_hash::TreeHash>::tree_hash_type()
                }

                fn tree_hash_packed_encoding(&self) -> ::tree_hash::PackedEncoding {
                    <$type as ::tree_hash::TreeHash>::tree_hash_packed_encoding(&self.inner)
                }

                fn tree_hash_packing_factor() -> usize {
                    <$type as ::tree_hash::TreeHash>::tree_hash_packing_factor()
                }

                fn tree_hash_root<H: ::tree_hash::TreeHashDigest>(&self) -> H::Output {
                    <$type as ::tree_hash::TreeHash>::tree_hash_root::<H>(&self.inner)
                }
            }

            impl<'a> ::ssz_types::view::ToOwnedSsz<$type> for [<$type Ref>]<'a> {
                fn to_owned(&self) -> $type {
                    self.inner
                }
            }
        }
    };
    // Internal helper: count the number of fields
    (@count $head:ident $(, $tail:ident)*) => {
        1usize $(+ $crate::impl_ssz_fixed_container!(@count_one $tail))*
    };
    (@count_one $x:ident) => { 1usize };
}

/// Generates SSZ view trait implementations for transparent wrappers whose
/// inner type already implements `DecodeView`.
///
/// Use this for newtypes wrapping types like `Buf32`, `u64`, or other types
/// that already have `DecodeView`, `SszTypeInfo`, and `TreeHash` implementations.
/// All trait implementations delegate to the inner type.
///
/// For types wrapping raw `[u8; N]` arrays (which do *not* implement
/// `DecodeView`), use `impl_ssz_transparent_byte_array_wrapper!` instead.
///
/// # Example
///
/// ```ignore
/// #[derive(Copy, Clone, Eq, PartialEq, Encode, Decode)]
/// #[ssz(struct_behaviour = "transparent")]
/// pub struct OLBlockId(Buf32);
///
/// impl_ssz_transparent_wrapper!(OLBlockId, Buf32);
/// ```
#[macro_export]
macro_rules! impl_ssz_transparent_wrapper {
    ($wrapper:ty, $inner:ty) => {
        // Manual DecodeView implementation for transparent wrapper
        // Uses fully qualified path to avoid conflicts with Decode derive
        impl<'a> ::ssz::view::DecodeView<'a> for $wrapper {
            fn from_ssz_bytes(bytes: &'a [u8]) -> Result<Self, ::ssz::DecodeError> {
                Ok(Self(<$inner as ::ssz::view::DecodeView>::from_ssz_bytes(
                    bytes,
                )?))
            }
        }

        // SszTypeInfo implementation delegated to inner type
        impl ::ssz::view::SszTypeInfo for $wrapper {
            fn is_ssz_fixed_len() -> bool {
                <$inner as ::ssz::view::SszTypeInfo>::is_ssz_fixed_len()
            }

            fn ssz_fixed_len() -> usize {
                <$inner as ::ssz::view::SszTypeInfo>::ssz_fixed_len()
            }
        }

        // Manual TreeHash implementation for transparent wrapper
        impl ::tree_hash::TreeHash for $wrapper {
            fn tree_hash_type() -> ::tree_hash::TreeHashType {
                <$inner as ::tree_hash::TreeHash>::tree_hash_type()
            }

            fn tree_hash_packed_encoding(&self) -> ::tree_hash::PackedEncoding {
                <$inner as ::tree_hash::TreeHash>::tree_hash_packed_encoding(&self.0)
            }

            fn tree_hash_packing_factor() -> usize {
                <$inner as ::tree_hash::TreeHash>::tree_hash_packing_factor()
            }

            fn tree_hash_root<H: ::tree_hash::TreeHashDigest>(&self) -> H::Output {
                <$inner as ::tree_hash::TreeHash>::tree_hash_root::<H>(&self.0)
            }
        }
    };
}

/// Describes how a wrapper type's SSZ encoding is delegated to another,
/// well-defined SSZ type.
///
/// Implementing this trait and invoking [`impl_ssz_via_delegate!`] gives a
/// wrapper type [`ssz::Encode`]/[`ssz::Decode`] impls that are *correct by
/// construction*: the byte layout is determined entirely by the
/// [`Delegate`](SszDelegate::Delegate) type — a generated SSZ container,
/// `FixedBytes`, `VariableList`, a primitive, etc. — rather than by a
/// hand-written impl that could violate the SSZ fixed-part/variable-part rules.
///
/// The delegate is the encoded form: [`into_delegate`](SszDelegate::into_delegate)
/// projects a value into it for encoding, and
/// [`from_delegate`](SszDelegate::from_delegate) reconstructs a value from a
/// decoded delegate, validating any wrapper invariants the delegate type does
/// not itself enforce.
///
/// # Example
///
/// ```ignore
/// // `BitcoinOutPointSsz` is a derived/generated SSZ container.
/// impl SszDelegate for BitcoinOutPoint {
///     type Delegate = BitcoinOutPointSsz;
///
///     fn into_delegate(self) -> Self::Delegate {
///         BitcoinOutPointSsz { txid: self.0.txid.to_byte_array(), vout: self.0.vout }
///     }
///
///     fn from_delegate(d: Self::Delegate) -> Result<Self, ssz::DecodeError> {
///         Ok(Self(OutPoint { txid: Txid::from_byte_array(d.txid), vout: d.vout }))
///     }
/// }
///
/// impl_ssz_via_delegate!(BitcoinOutPoint);
/// ```
pub trait SszDelegate: Sized {
    /// The well-defined SSZ type this type's encoding delegates to.
    type Delegate: ::ssz::Encode + ::ssz::Decode + ::tree_hash::TreeHash;

    /// Projects `self` into its delegate representation for encoding.
    fn into_delegate(self) -> Self::Delegate;

    /// Reconstructs `Self` from a decoded delegate, validating any invariants
    /// the wrapper enforces that the delegate type does not.
    fn from_delegate(delegate: Self::Delegate) -> Result<Self, ::ssz::DecodeError>;
}

/// Generates [`ssz::Encode`], [`ssz::Decode`], and [`tree_hash::TreeHash`]
/// implementations for a type that implements [`SszDelegate`], delegating the
/// entire byte layout and merkleization to its
/// [`Delegate`](SszDelegate::Delegate) type.
///
/// This is the "correct by construction" replacement for hand-written
/// `Encode`/`Decode` impls: the wrapper supplies only the value-level conversion
/// to/from a well-defined SSZ type via [`SszDelegate`], and this macro wires up
/// the trait methods so the wrapper inherits the delegate's (spec-compliant)
/// layout and tree-hash root verbatim. Because the tree hash is delegated too,
/// the wrapper can be used as a field inside other SSZ containers.
///
/// # Requirements
///
/// The type must implement [`SszDelegate`] and [`Clone`] (the latter is used to
/// project `&self` into the delegate when encoding or tree-hashing).
///
/// # Example
///
/// ```ignore
/// impl SszDelegate for MyWrapper {
///     type Delegate = MyWrapperSsz;
///     fn into_delegate(self) -> Self::Delegate { /* … */ }
///     fn from_delegate(d: Self::Delegate) -> Result<Self, ssz::DecodeError> { /* … */ }
/// }
///
/// impl_ssz_via_delegate!(MyWrapper);
/// ```
#[macro_export]
macro_rules! impl_ssz_via_delegate {
    ($type:ty) => {
        impl ::ssz::Encode for $type {
            fn is_ssz_fixed_len() -> bool {
                <<$type as $crate::SszDelegate>::Delegate as ::ssz::Encode>::is_ssz_fixed_len()
            }

            fn ssz_fixed_len() -> usize {
                <<$type as $crate::SszDelegate>::Delegate as ::ssz::Encode>::ssz_fixed_len()
            }

            fn ssz_append(&self, buf: &mut ::std::vec::Vec<u8>) {
                ::ssz::Encode::ssz_append(
                    &$crate::SszDelegate::into_delegate(::core::clone::Clone::clone(self)),
                    buf,
                )
            }

            fn ssz_bytes_len(&self) -> usize {
                ::ssz::Encode::ssz_bytes_len(&$crate::SszDelegate::into_delegate(
                    ::core::clone::Clone::clone(self),
                ))
            }
        }

        impl ::ssz::Decode for $type {
            fn is_ssz_fixed_len() -> bool {
                <<$type as $crate::SszDelegate>::Delegate as ::ssz::Decode>::is_ssz_fixed_len()
            }

            fn ssz_fixed_len() -> usize {
                <<$type as $crate::SszDelegate>::Delegate as ::ssz::Decode>::ssz_fixed_len()
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ::ssz::DecodeError> {
                let delegate =
                    <<$type as $crate::SszDelegate>::Delegate as ::ssz::Decode>::from_ssz_bytes(
                        bytes,
                    )?;
                <$type as $crate::SszDelegate>::from_delegate(delegate)
            }
        }

        impl ::tree_hash::TreeHash for $type {
            fn tree_hash_type() -> ::tree_hash::TreeHashType {
                <<$type as $crate::SszDelegate>::Delegate as ::tree_hash::TreeHash>::tree_hash_type()
            }

            fn tree_hash_packed_encoding(&self) -> ::tree_hash::PackedEncoding {
                ::tree_hash::TreeHash::tree_hash_packed_encoding(
                    &$crate::SszDelegate::into_delegate(::core::clone::Clone::clone(self)),
                )
            }

            fn tree_hash_packing_factor() -> usize {
                <<$type as $crate::SszDelegate>::Delegate as ::tree_hash::TreeHash>::tree_hash_packing_factor()
            }

            fn tree_hash_root<H: ::tree_hash::TreeHashDigest>(&self) -> H::Output {
                ::tree_hash::TreeHash::tree_hash_root::<H>(&$crate::SszDelegate::into_delegate(
                    ::core::clone::Clone::clone(self),
                ))
            }
        }
    };
}

/// Generates SSZ view trait implementations for transparent wrappers around
/// raw `[u8; N]` arrays.
///
/// This exists because `[u8; N]` does not implement `DecodeView` in the `ssz`
/// crate (only `FixedBytes<N>` does), so [`impl_ssz_transparent_wrapper!`]
/// cannot be used. This macro provides:
/// - A manual `DecodeView` implementation via `bytes.try_into()`
/// - `SszTypeInfo` (fixed-length)
/// - `TreeHash` delegating to `[u8; N]`
/// - Bidirectional `From` conversions with `FixedBytes<N>` for SSZ codegen interop
///
/// # Example
///
/// ```ignore
/// #[derive(Copy, Clone, Eq, PartialEq, Encode, Decode)]
/// #[ssz(struct_behaviour = "transparent")]
/// pub struct Buf32(pub [u8; 32]);
///
/// impl_ssz_transparent_byte_array_wrapper!(Buf32, 32);
/// ```
#[macro_export]
macro_rules! impl_ssz_transparent_byte_array_wrapper {
    ($wrapper:ty, $len:expr) => {
        // Custom DecodeView implementation for byte array wrapper
        impl<'a> ::ssz::view::DecodeView<'a> for $wrapper {
            fn from_ssz_bytes(bytes: &'a [u8]) -> Result<Self, ::ssz::DecodeError> {
                let array: [u8; $len] =
                    bytes
                        .try_into()
                        .map_err(|_| ::ssz::DecodeError::InvalidByteLength {
                            len: bytes.len(),
                            expected: $len,
                        })?;
                Ok(Self(array))
            }
        }

        // SszTypeInfo implementation for transparent wrapper
        impl ::ssz::view::SszTypeInfo for $wrapper {
            fn is_ssz_fixed_len() -> bool {
                true
            }

            fn ssz_fixed_len() -> usize {
                $len
            }
        }

        // Manual TreeHash implementation for transparent wrapper
        impl ::tree_hash::TreeHash for $wrapper {
            fn tree_hash_type() -> ::tree_hash::TreeHashType {
                <[u8; $len] as ::tree_hash::TreeHash>::tree_hash_type()
            }

            fn tree_hash_packed_encoding(&self) -> ::tree_hash::PackedEncoding {
                <[u8; $len] as ::tree_hash::TreeHash>::tree_hash_packed_encoding(&self.0)
            }

            fn tree_hash_packing_factor() -> usize {
                <[u8; $len] as ::tree_hash::TreeHash>::tree_hash_packing_factor()
            }

            fn tree_hash_root<H: ::tree_hash::TreeHashDigest>(&self) -> H::Output {
                <[u8; $len] as ::tree_hash::TreeHash>::tree_hash_root::<H>(&self.0)
            }
        }

        // FixedBytes conversions for SSZ interop
        impl ::core::convert::From<::ssz_primitives::FixedBytes<$len>> for $wrapper {
            fn from(value: ::ssz_primitives::FixedBytes<$len>) -> Self {
                Self(value.0)
            }
        }

        impl ::core::convert::From<&::ssz_primitives::FixedBytes<$len>> for &$wrapper {
            fn from(value: &::ssz_primitives::FixedBytes<$len>) -> Self {
                // SAFETY: FixedBytes<N> and the wrapper have the same layout
                unsafe { &*(value as *const ::ssz_primitives::FixedBytes<$len> as *const $wrapper) }
            }
        }

        impl ::core::convert::From<$wrapper> for ::ssz_primitives::FixedBytes<$len> {
            fn from(value: $wrapper) -> Self {
                ::ssz_primitives::FixedBytes(value.0)
            }
        }

        impl ::core::convert::From<&$wrapper> for &::ssz_primitives::FixedBytes<$len> {
            fn from(value: &$wrapper) -> Self {
                // SAFETY: the wrapper and FixedBytes<N> have the same layout
                unsafe { &*(value as *const $wrapper as *const ::ssz_primitives::FixedBytes<$len>) }
            }
        }
    };
}
