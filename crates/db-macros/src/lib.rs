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
//! # Arguments
//!
//! - `error = <Path>` (required): the error type used by the trait's methods.
//! - `tracing_component = <string>` (optional): when set, each method's blocking work is wrapped in
//!   a `#[tracing::instrument(level = "trace", fields(component = <string>))]` span (mirroring the
//!   legacy `inst_ops` shim instrumentation). For the async and channel variants, the caller's
//!   current span ([`tracing::Span::current`]) is captured and re-entered inside the
//!   `spawn_blocking` task, so the method's span is parented to the async task that issued the call
//!   rather than orphaned on the blocking thread. Requires the consuming crate to depend on
//!   `tracing`.
//!
//! # Requirements
//!
//! - The error type passed to `error = ...` must implement `From<`[`tokio::task::JoinError`]`>`
//!   (this surfaces a panic in the blocking task as an error from the async/channel variants).
//! - The generated code references `::tokio`, so the consuming crate must depend on `tokio`. When
//!   `tracing_component` is set, it also references `::tracing`.
//! - Only methods that take `&self`, are non-`async`, have no method-level generics, use plain
//!   identifier argument patterns, and return a `Result`-shaped type (a path such as `Result<T, E>`
//!   or `DbResult<T>` carrying at least one generic type argument) get proxy variants. Other
//!   methods remain trait-only.
//! - A qualifying method can be explicitly opted out of proxying by annotating it with
//!   `#[gen_proxy(skip)]`; the method then remains trait-only and the marker attribute is stripped
//!   from the emitted trait.

use proc_macro::TokenStream;
use syn::parse::{Parse, ParseStream};
use syn::{ItemTrait, LitStr, Path, Token, parse_macro_input};
// `tokio`/`tracing`/`tracing-subscriber` are dev-dependencies used only by the `tests/`
// integration target; these keep the workspace `unused_crate_dependencies` lint happy for
// the lib-test build.
#[cfg(test)]
use {tokio as _, tracing as _, tracing_subscriber as _};

mod expand;

/// Generates a `FooProxy` handle (and `FooRecv` result wrapper) for the annotated
/// trait `Foo`.
///
/// Takes a required `error = <Path>` argument naming the error type used by the trait's
/// methods, and an optional `tracing_component = <string>` argument that instruments each
/// method's blocking work. See the [crate-level docs](crate) for details and an example.
#[proc_macro_attribute]
pub fn gen_proxy(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as GenProxyArgs);
    let item_trait = parse_macro_input!(item as ItemTrait);

    expand::expand(&args.error, args.tracing_component.as_ref(), &item_trait)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Parsed arguments for the [`macro@gen_proxy`] attribute.
struct GenProxyArgs {
    /// Required `error = <Path>`: the error type used by the trait's methods.
    error: Path,
    /// Optional `tracing_component = <string>`: instruments each method's blocking work.
    tracing_component: Option<LitStr>,
}

impl Parse for GenProxyArgs {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut error: Option<Path> = None;
        let mut tracing_component: Option<LitStr> = None;

        while !input.is_empty() {
            let key: syn::Ident = input.parse()?;
            input.parse::<Token![=]>()?;

            if key == "error" {
                error = Some(input.parse()?);
            } else if key == "tracing_component" {
                tracing_component = Some(input.parse()?);
            } else {
                return Err(syn::Error::new(
                    key.span(),
                    "expected `error` or `tracing_component`",
                ));
            }

            if input.is_empty() {
                break;
            }
            input.parse::<Token![,]>()?;
        }

        let error = error.ok_or_else(|| {
            syn::Error::new(
                proc_macro2::Span::call_site(),
                "`#[gen_proxy]` requires an `error = <Type>` argument",
            )
        })?;

        Ok(Self {
            error,
            tracing_component,
        })
    }
}
