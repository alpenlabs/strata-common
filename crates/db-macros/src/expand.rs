//! Code generation for the [`gen_proxy`](crate::gen_proxy) attribute.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{
    FnArg, GenericArgument, ItemTrait, Pat, PatType, Path, PathArguments, ReturnType, TraitItem,
    TraitItemFn, Type,
};

/// Expands the annotated trait into the original trait plus its proxy and receiver
/// types.
pub(crate) fn expand(error_ty: &Path, item: &ItemTrait) -> syn::Result<TokenStream> {
    if !item.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &item.generics,
            "`#[gen_proxy]` does not support generic traits",
        ));
    }

    let trait_ident = &item.ident;
    let vis = &item.vis;
    let proxy_ident = format_ident!("{}Proxy", trait_ident);
    let recv_ident = format_ident!("{}Recv", trait_ident);

    let mut methods = TokenStream::new();
    for trait_item in &item.items {
        if let TraitItem::Fn(method) = trait_item
            && let Some(tokens) = gen_method(method, trait_ident, &recv_ident, error_ty, vis)
        {
            methods.extend(tokens);
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

/// Generates the `_blocking`, `_chan`, and `_async` proxy methods for a single trait
/// method, or [`None`] if the method does not qualify for proxying.
fn gen_method(
    method: &TraitItemFn,
    trait_ident: &syn::Ident,
    recv_ident: &syn::Ident,
    error_ty: &Path,
    vis: &syn::Visibility,
) -> Option<TokenStream> {
    let sig = &method.sig;

    // Only plain, non-generic, synchronous methods are proxied.
    if sig.asyncness.is_some() || !sig.generics.params.is_empty() {
        return None;
    }

    let mut inputs = sig.inputs.iter();

    // The receiver must be `&self`.
    match inputs.next() {
        Some(FnArg::Receiver(recv)) if recv.reference.is_some() && recv.mutability.is_none() => {}
        _ => return None,
    }

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
    let success_ty = first_generic_type(ret_ty)?;

    let name = &sig.ident;
    let blocking = format_ident!("{}_blocking", name);
    let chan = format_ident!("{}_chan", name);
    let asyncf = format_ident!("{}_async", name);

    let blocking_doc = format!("Blocking variant of `{trait_ident}::{name}`; runs inline.");
    let chan_doc = format!(
        "Spawns `{trait_ident}::{name}` on a blocking task, returning a `{recv_ident}` handle."
    );
    let async_doc =
        format!("Async variant of `{trait_ident}::{name}`; awaits a spawned blocking task.");

    Some(quote! {
        #[doc = #blocking_doc]
        #vis fn #blocking(&self, #(#arg_decls),*) -> #ret_ty {
            self.inner.#name(#(#arg_names),*)
        }

        #[doc = #chan_doc]
        #vis fn #chan(&self, #(#arg_decls),*) -> #recv_ident<#success_ty, #error_ty> {
            let inner = ::std::sync::Arc::clone(&self.inner);
            #recv_ident {
                inner: self.handle.spawn_blocking(move || inner.#name(#(#arg_names),*)),
            }
        }

        #[doc = #async_doc]
        #vis async fn #asyncf(&self, #(#arg_decls),*) -> #ret_ty {
            self.#chan(#(#arg_names),*).recv().await
        }
    })
}

/// Returns the first generic type argument of the last path segment of `ty`, used to
/// recover the success type `T` from a `Result<T, E>` / `DbResult<T>` return type.
fn first_generic_type(ty: &Type) -> Option<&Type> {
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
