//! Derive macro for the `Codec` trait from `strata-codec`.
//!
//! This crate provides a procedural macro to automatically derive implementations
//! of the `Codec` trait for simple structs where all fields implement `Codec`.
//!
//! # Examples
//!
//! ## Named struct
//! ```ignore
//! use strata_codec::Codec;
//! use strata_codec_derive::Codec;
//!
//! #[derive(Codec)]
//! struct MyStruct {
//!     field1: u32,
//!     field2: Vec<u8>,
//! }
//! ```
//!
//! ## Tuple struct
//! ```ignore
//! #[derive(Codec)]
//! struct TupleStruct(u32, u64);
//! ```
//!
//! ## Unit struct
//! ```ignore
//! #[derive(Codec)]
//! struct UnitStruct;
//! ```

// The strata-codec dev-dependency is used in tests
#[cfg(test)]
use strata_codec as _;

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, parse_macro_input};

/// Derives the `Codec` trait for structs.
///
/// This macro generates implementations of the `decode` and `encode` methods
/// required by the `Codec` trait. All fields of the struct must implement `Codec`.
///
/// Fields are encoded and decoded in declaration order.
#[proc_macro_derive(Codec)]
pub fn derive_codec(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    // Only support structs for now
    let Data::Struct(data_struct) = &input.data else {
        return syn::Error::new_spanned(&input, "Codec derive macro only supports structs")
            .to_compile_error()
            .into();
    };

    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    // Generate decode and encode implementations based on struct type
    let (decode_impl, encode_impl) = match &data_struct.fields {
        Fields::Named(fields) => {
            // Named struct: struct Foo { a: T, b: U }
            let field_names: Vec<_> = fields.named.iter().map(|f| &f.ident).collect();

            let decode_fields = field_names.iter().map(|ident| {
                quote! {
                    #ident: ::strata_codec::Codec::decode(dec)?
                }
            });

            let encode_fields = field_names.iter().map(|ident| {
                quote! {
                    ::strata_codec::Codec::encode(&self.#ident, enc)?;
                }
            });

            (
                quote! {
                    Ok(Self {
                        #(#decode_fields),*
                    })
                },
                quote! {
                    #(#encode_fields)*
                    Ok(())
                },
            )
        }
        Fields::Unnamed(fields) => {
            // Tuple struct: struct Foo(T, U)
            let field_count = fields.unnamed.len();
            let field_indices = 0..field_count;

            let decode_fields = (0..field_count).map(|_| {
                quote! {
                    ::strata_codec::Codec::decode(dec)?
                }
            });

            let encode_fields = field_indices.map(|i| {
                let index = syn::Index::from(i);
                quote! {
                    ::strata_codec::Codec::encode(&self.#index, enc)?;
                }
            });

            (
                quote! {
                    Ok(Self(#(#decode_fields),*))
                },
                quote! {
                    #(#encode_fields)*
                    Ok(())
                },
            )
        }
        Fields::Unit => {
            // Unit struct: struct Foo;
            (quote! { Ok(Self) }, quote! { Ok(()) })
        }
    };

    // Generate the final implementation
    // We need to handle both cases: when used from external crates and when used within strata_codec itself
    let expanded = quote! {
        #[automatically_derived]
        impl #impl_generics ::strata_codec::Codec for #name #ty_generics #where_clause {
            fn decode(dec: &mut impl ::strata_codec::Decoder) -> ::core::result::Result<Self, ::strata_codec::CodecError> {
                #decode_impl
            }

            fn encode(&self, enc: &mut impl ::strata_codec::Encoder) -> ::core::result::Result<(), ::strata_codec::CodecError> {
                #encode_impl
            }
        }
    };

    TokenStream::from(expanded)
}
