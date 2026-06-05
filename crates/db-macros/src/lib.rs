//! Procedural macro for generating async/blocking proxy handles around database traits.
//!
//! The [`macro@gen_proxy`] attribute is attached to a trait `Foo` and generates a
//! `FooProxy` handle that offloads each trait method onto a Tokio blocking task via
//! [`tokio::runtime::Handle::spawn_blocking`], exposing async, blocking, and
//! channel-style variants of every method.
//!
//! # Example
//!
//! ```ignore
//! use std::sync::Arc;
//!
//! use strata_db_macros::gen_proxy;
//! use tokio::runtime::Handle;
//!
//! type DbResult<T> = Result<T, DbError>;
//!
//! #[gen_proxy(error = DbError)]
//! pub trait TaskDb: Send + Sync + 'static {
//!     fn get_task(&self, key: Vec<u8>) -> DbResult<Option<Vec<u8>>>;
//!     fn count_tasks(&self) -> DbResult<usize>;
//! }
//!
//! // Generated:
//! //   pub struct TaskDbProxy { /* Handle + Arc<dyn TaskDb> */ }
//! //   pub struct TaskDbRecv<T, E> { /* wraps a JoinHandle */ }
//! //
//! //   impl TaskDbProxy {
//! //       pub fn new(handle: Handle, inner: Arc<dyn TaskDb + Send + Sync + 'static>) -> Self;
//! //       pub async fn get_task_async(&self, key: Vec<u8>) -> DbResult<Option<Vec<u8>>>;
//! //       pub fn get_task_blocking(&self, key: Vec<u8>) -> DbResult<Option<Vec<u8>>>;
//! //       pub fn get_task_chan(&self, key: Vec<u8>) -> TaskDbRecv<Option<Vec<u8>>, DbError>;
//! //       // ...same trio for count_tasks
//! //   }
//! ```
//!
//! # Requirements
//!
//! - The error type passed to `error = ...` must implement `From<`[`tokio::task::JoinError`]`>`
//!   (this surfaces a panic in the blocking task as an error from the async/channel variants).
//! - The generated code references `::tokio`, so the consuming crate must depend on `tokio`.
//! - Only methods that take `&self`, are non-`async`, have no method-level generics, use plain
//!   identifier argument patterns, and return a `Result`-shaped type (a path such as `Result<T, E>`
//!   or `DbResult<T>` carrying at least one generic type argument) get proxy variants. Other
//!   methods remain trait-only.

use proc_macro::TokenStream;
use syn::parse::{Parse, ParseStream};
use syn::{ItemTrait, Path, Token, parse_macro_input};
// `tokio` is a dev-dependency used only by the `tests/` integration target; this
// keeps the workspace `unused_crate_dependencies` lint happy for the lib-test build.
#[cfg(test)]
use tokio as _;

mod expand;

/// Generates a `FooProxy` handle (and `FooRecv` result wrapper) for the annotated
/// trait `Foo`.
///
/// Takes a single required argument, `error = <Path>`, naming the error type used by
/// the trait's methods. See the [crate-level docs](crate) for details and an example.
#[proc_macro_attribute]
pub fn gen_proxy(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as GenProxyArgs);
    let item_trait = parse_macro_input!(item as ItemTrait);

    expand::expand(&args.error, &item_trait)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Parsed arguments for the [`macro@gen_proxy`] attribute: `error = <Path>`.
struct GenProxyArgs {
    error: Path,
}

impl Parse for GenProxyArgs {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        if input.is_empty() {
            return Err(input.error("`#[gen_proxy]` requires an `error = <Type>` argument"));
        }

        let key: syn::Ident = input.parse()?;
        if key != "error" {
            return Err(syn::Error::new(
                key.span(),
                "expected `error = <Type>` argument",
            ));
        }

        input.parse::<Token![=]>()?;
        let error: Path = input.parse()?;

        // Tolerate an optional trailing comma.
        if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
        }

        if !input.is_empty() {
            return Err(input.error("unexpected tokens after `error = <Type>`"));
        }

        Ok(Self { error })
    }
}
