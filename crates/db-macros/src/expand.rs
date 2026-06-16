//! Code generation for the [`gen_proxy`](crate::gen_proxy) attribute.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::{
    Attribute, FnArg, GenericArgument, ItemTrait, LitStr, Pat, PatType, Path, PathArguments,
    ReturnType, Token, TraitItem, TraitItemFn, Type,
};

/// Parsed arguments for the [`macro@gen_proxy`] attribute.
pub(crate) struct GenProxyArgs {
    /// Required `error = <Path>`: the error type used by the trait's methods.
    pub(crate) error: Path,
    /// Optional `tracing_component = <string>`: instruments each method's blocking work.
    pub(crate) tracing_component: Option<LitStr>,
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

/// Expands the annotated trait into the original trait plus its proxy and receiver
/// types.
pub(crate) fn expand(
    error_ty: &Path,
    tracing_component: Option<&LitStr>,
    item: &ItemTrait,
) -> syn::Result<TokenStream> {
    if !item.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &item.generics,
            "`#[gen_proxy]` does not support generic traits",
        ));
    }

    let trait_ident = &item.ident;
    let vis = &item.vis;
    let proxy_ident = format_ident!("{}Proxy", trait_ident);
    let recv_ident = format_ident!("{}Fut", trait_ident);

    let mut methods = TokenStream::new();
    for trait_item in &item.items {
        if let TraitItem::Fn(method) = trait_item
            && let Some(tokens) = gen_method(
                method,
                trait_ident,
                &recv_ident,
                error_ty,
                tracing_component,
                vis,
            )
        {
            methods.extend(tokens);
        }
    }

    // Re-emit the trait with any `#[gen_proxy(skip)]` helper attributes stripped from its
    // methods. These are inert markers consumed above; leaving them in place would make the
    // compiler try to resolve `gen_proxy` as an attribute macro on the trait method and fail.
    let mut item = item.clone();
    for trait_item in &mut item.items {
        if let TraitItem::Fn(method) = trait_item {
            method.attrs.retain(|attr| !is_skip_attr(attr));
        }
    }

    let proxy_doc = format!(
        "Async/blocking proxy handle for the `{trait_ident}` trait.\n\n\
         Each method is offloaded onto a Tokio blocking task via `spawn_blocking`."
    );
    let new_doc = "Creates a new proxy from a runtime handle and a shared trait object.";
    let recv_doc =
        format!("Pending result of a `{proxy_ident}` call, awaitable via its `recv` method.");
    let recv_method_doc = "Awaits the spawned blocking task and returns its result, mapping a join failure \
         (for example a panic in the task) through `From<JoinError>`.";

    let expanded = quote! {
        #item

        #[doc = #proxy_doc]
        #[derive(Clone)]
        #vis struct #proxy_ident {
            handle: ::tokio::runtime::Handle,
            inner: ::std::sync::Arc<
                dyn #trait_ident + ::core::marker::Send + ::core::marker::Sync + 'static,
            >,
        }

        impl ::core::fmt::Debug for #proxy_ident {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(::core::stringify!(#proxy_ident)).finish_non_exhaustive()
            }
        }

        impl #proxy_ident {
            #[doc = #new_doc]
            #vis fn new(
                handle: ::tokio::runtime::Handle,
                inner: ::std::sync::Arc<
                    dyn #trait_ident + ::core::marker::Send + ::core::marker::Sync + 'static,
                >,
            ) -> Self {
                Self { handle, inner }
            }

            #methods
        }

        #[doc = #recv_doc]
        #[derive(Debug)]
        #vis struct #recv_ident<T, E> {
            inner: ::tokio::task::JoinHandle<::core::result::Result<T, E>>,
        }

        impl<T, E> #recv_ident<T, E>
        where
            E: ::core::convert::From<::tokio::task::JoinError>,
        {
            #[doc = #recv_method_doc]
            #vis async fn recv(self) -> ::core::result::Result<T, E> {
                match self.inner.await {
                    ::core::result::Result::Ok(v) => v,
                    ::core::result::Result::Err(join_err) => ::core::result::Result::Err(
                        <E as ::core::convert::From<::tokio::task::JoinError>>::from(join_err),
                    ),
                }
            }
        }
    };

    Ok(expanded)
}

/// Returns `true` if `pred` is a `where Self: Sized` predicate.
fn is_self_sized_predicate(pred: &syn::WherePredicate) -> bool {
    let syn::WherePredicate::Type(pt) = pred else {
        return false;
    };
    let syn::Type::Path(tp) = &pt.bounded_ty else {
        return false;
    };
    if tp.qself.is_some() || tp.path.segments.len() != 1 {
        return false;
    }
    if tp.path.segments[0].ident != "Self" {
        return false;
    }
    pt.bounds.iter().any(|b| {
        let syn::TypeParamBound::Trait(tb) = b else {
            return false;
        };
        tb.path
            .segments
            .last()
            .map_or(false, |s| s.ident == "Sized")
    })
}

/// Returns `true` if `method` qualifies for proxy generation.
///
/// A method qualifies when all of the following hold:
/// - no `#[gen_proxy(skip)]` attribute
/// - not `async`
/// - no method-level generic parameters
/// - no `where Self: Sized` constraint (such methods cannot be dispatched through `dyn Trait`)
/// - first parameter is `&self`
/// - return type is a path with at least one generic type argument (i.e. `Result`-shaped)
fn should_proxy_method(method: &TraitItemFn) -> bool {
    if method.attrs.iter().any(is_skip_attr) {
        return false;
    }
    let sig = &method.sig;
    if sig.asyncness.is_some() || !sig.generics.params.is_empty() {
        return false;
    }
    if let Some(wc) = &sig.generics.where_clause {
        if wc.predicates.iter().any(is_self_sized_predicate) {
            return false;
        }
    }
    match sig.inputs.iter().next() {
        Some(FnArg::Receiver(recv)) if recv.reference.is_some() && recv.mutability.is_none() => {}
        _ => return false,
    }
    let ReturnType::Type(_, ret_ty) = &sig.output else {
        return false;
    };
    get_first_generic_type(ret_ty).is_some()
}

/// Generates the `_blocking`, `_fut`, and `_async` proxy methods for a single trait
/// method, or [`None`] if the method does not qualify for proxying.
fn gen_method(
    method: &TraitItemFn,
    trait_ident: &syn::Ident,
    recv_ident: &syn::Ident,
    error_ty: &Path,
    tracing_component: Option<&LitStr>,
    vis: &syn::Visibility,
) -> Option<TokenStream> {
    if !should_proxy_method(method) {
        return None;
    }

    let sig = &method.sig;
    let mut inputs = sig.inputs.iter();
    inputs.next(); // skip `&self` receiver, already validated by `should_proxy_method`

    // Collect the remaining arguments, requiring simple identifier patterns.
    let mut arg_names = Vec::new();
    let mut arg_decls = Vec::new();
    for arg in inputs {
        let FnArg::Typed(PatType { pat, ty, .. }) = arg else {
            return None;
        };
        let Pat::Ident(pat_ident) = pat.as_ref() else {
            return None;
        };
        let ident = &pat_ident.ident;
        arg_names.push(ident.clone());
        arg_decls.push(quote! { #ident: #ty });
    }

    // The return type must be a `Result`-shaped path; extract its success type.
    let ReturnType::Type(_, ret_ty) = &sig.output else {
        return None;
    };
    let success_ty = get_first_generic_type(ret_ty)?;

    let name = &sig.ident;
    let blocking = format_ident!("{}_blocking", name);
    let fut = format_ident!("{}_fut", name);
    let asyncf = format_ident!("{}_async", name);

    let blocking_doc = format!("Blocking variant of `{trait_ident}::{name}`; runs inline.");
    let fut_doc = format!(
        "Spawns `{trait_ident}::{name}` on a blocking task, returning a `{recv_ident}` handle."
    );
    let async_doc =
        format!("Async variant of `{trait_ident}::{name}`; awaits a spawned blocking task.");

    // Both the blocking and channel variants invoke the underlying trait method on the
    // `dyn` instance. When a component is configured, that call goes through a private,
    // instrumented shim (associated function taking `&dyn Trait`) so a span is produced
    // for every variant while recording the method arguments and component field —
    // mirroring the legacy `inst_ops` shims. When not instrumented, the call is made
    // directly and `::tracing` is never referenced, keeping it an optional dependency.
    //
    // For the channel/async paths the shim runs on a `spawn_blocking` thread, so the
    // caller's current span is captured and re-entered inside the task, parenting the
    // method's span to the issuing async task rather than orphaning it on the blocking
    // thread.
    let name_str = name.to_string();
    let shim_ident = format_ident!("__{}_shim", name);

    let (shim_fn, blocking_body, fut_body) = if let Some(component) = tracing_component {
        let shim_fn = quote! {
            #[::tracing::instrument(
                level = "trace",
                name = #name_str,
                skip(inner),
                fields(component = #component),
            )]
            fn #shim_ident(
                inner: &(dyn #trait_ident + ::core::marker::Send + ::core::marker::Sync),
                #(#arg_decls),*
            ) -> #ret_ty {
                inner.#name(#(#arg_names),*)
            }
        };

        let blocking_body = quote! {
            Self::#shim_ident(self.inner.as_ref(), #(#arg_names),*)
        };

        let fut_body = quote! {
            let inner = ::std::sync::Arc::clone(&self.inner);
            let parent_span = ::tracing::Span::current();
            #recv_ident {
                inner: self.handle.spawn_blocking(move || {
                    parent_span.in_scope(move || Self::#shim_ident(inner.as_ref(), #(#arg_names),*))
                }),
            }
        };

        (Some(shim_fn), blocking_body, fut_body)
    } else {
        let blocking_body = quote! {
            self.inner.#name(#(#arg_names),*)
        };

        let fut_body = quote! {
            let inner = ::std::sync::Arc::clone(&self.inner);
            #recv_ident {
                inner: self.handle.spawn_blocking(move || inner.#name(#(#arg_names),*)),
            }
        };

        (None, blocking_body, fut_body)
    };

    Some(quote! {
        #shim_fn

        #[doc = #blocking_doc]
        #vis fn #blocking(&self, #(#arg_decls),*) -> #ret_ty {
            #blocking_body
        }

        #[doc = #fut_doc]
        #vis fn #fut(&self, #(#arg_decls),*) -> #recv_ident<#success_ty, #error_ty> {
            #fut_body
        }

        #[doc = #async_doc]
        #vis async fn #asyncf(&self, #(#arg_decls),*) -> #ret_ty {
            self.#fut(#(#arg_names),*).recv().await
        }
    })
}

/// Returns `true` if `attr` is the `#[gen_proxy(skip)]` opt-out marker.
fn is_skip_attr(attr: &Attribute) -> bool {
    if !attr.path().is_ident("gen_proxy") {
        return false;
    }
    let mut is_skip = false;
    let _ = attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("skip") {
            is_skip = true;
        }
        Ok(())
    });
    is_skip
}

/// Returns the first generic type argument of the last path segment of `ty`, used to
/// recover the success type `T` from a `Result<T, E>` / `DbResult<T>` return type.
fn get_first_generic_type(ty: &Type) -> Option<&Type> {
    let Type::Path(type_path) = ty else {
        return None;
    };
    let segment = type_path.path.segments.last()?;
    let PathArguments::AngleBracketed(args) = &segment.arguments else {
        return None;
    };
    args.args.iter().find_map(|arg| match arg {
        GenericArgument::Type(inner) => Some(inner),
        _ => None,
    })
}
