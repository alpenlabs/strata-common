# Why `Rk` uses an unsafe marker trait and not `Pin`

Design note for `strata-rkyv-utils`. Written while fixing two soundness bugs in
`Rk` (PR #127); records why [`Pin`]/[`Unpin`] were evaluated and rejected as the
mechanism behind `StableBuf`/`CloneBuf`, so the question doesn't get reopened
from scratch.

**TL;DR** — `Pin` is built for self-referential values that must not move. `Rk`'s
problem is that a *borrowed view* must stay valid across moves and clones of an
ordinary, movable container. Different property. `Pin` addresses at most one of
`Rk`'s three obligations, and only under conditions that don't hold for any byte
buffer anyone would actually use.

[`Pin`]: https://doc.rust-lang.org/std/pin/index.html
[`Unpin`]: https://doc.rust-lang.org/std/marker/trait.Unpin.html

## The invariant `Rk` needs

`Rk::from_buf` validates a buffer exactly once — both its contents and its base
address's alignment — via `rkyv::access::<T>`. Every subsequent `AsRef<T>::as_ref`
then calls `rkyv::access_unchecked(self.as_slice())` with no re-validation.

> The bytes read later must be the bytes that were validated, at the address they
> were validated at.

Three separate things can break that, and a backing buffer must rule out all three:

1. **Nondeterministic `as_ref`** — a safe impl using `Cell`/`RefCell` to hand back a different
   slice on each call. Validate one buffer, read another.
2. **The bytes move with the value** — inline storage such as `[u8; N]`. `from_buf` validates the
   by-value parameter at its temporary address, then moves it into the returned `Rk`, which the
   caller can move again.
3. **`clone()` reallocates** — a `Vec<u8>`/`Box<[u8]>` backing that validated fine (because the
   allocator happened to return an aligned block) clones into a fresh allocation carrying only byte
   alignment, and the clone is re-wrapped without re-validation.

## What `Pin` actually guarantees

From the [`std::pin`] docs:

> From the moment a value is pinned by constructing a Pinning pointer to it, that
> value must remain, valid, at that same address in memory, until its drop handler
> is called.

Two components: the value doesn't move, and its memory isn't invalidated or
repurposed before `drop`. Note that it constrains the **pointee** of a pointer,
not an arbitrary value:

> Whether the `Ptr` type itself implements `Unpin` does not affect the behavior of
> a `Pin<Ptr>`. […] because `T` is the type of the pointee value, not `Box`.

[`std::pin`]: https://doc.rust-lang.org/std/pin/index.html

At a glance that looks like a match for obligation #2. It isn't, for three
independent reasons.

## Blocker 1 — everything here is `Unpin`, so `Pin` is a no-op

> When `T: Unpin`, `Pin<Box<T>>` functions identically to a non-pinning `Box<T>`;
> similarly, `Pin<&mut T>` would impose no additional restrictions above a regular
> `&mut T`.

Every type in play is `Unpin` — verified with a `fn assert_unpin<T: Unpin>()`
probe over `[u8; 64]`, `Vec<u8>`, `Box<[u8]>`, `AlignedVec`, `Arc<[u8]>`, and
`RkVec<Archived<u64>>` itself. So a `Pin` wrapper around any of them carries no
guarantee whatsoever. Demonstrated with no `unsafe` at all:

```rust
let pinned: Pin<Box<[u8; 64]>> = Box::pin([7u8; 64]);
let addr_pinned = pinned.as_ptr() as usize;

// Safe, and available *precisely because* the target is Unpin.
let unpinned: Box<[u8; 64]> = Pin::into_inner(pinned);
let moved_out: [u8; 64] = *unpinned;      // array now lives inline on the stack

assert_ne!(addr_pinned, moved_out.as_ptr() as usize);  // passes
```

Fixing that means making the backing `!Unpin`:

> It is the responsibility of the implementor of a type that relies upon pinning
> for soundness to ensure that type is *not* marked as `Unpin` by adding a
> `PhantomPinned` field.

Which means callers wrap their buffer in a crate-specific unmovable newtype.
That is strictly worse than a trait bound: it changes their *data type*, not just
what they satisfy. The whole point of evaluating `Pin` was better ergonomics.

## Blocker 2 — `Pin` says nothing about alignment

`Pin`'s guarantee is address-stability plus validity-until-drop. Obligation #3 is
that `clone()` produces a **new allocation** with a weaker alignment guarantee.
`Pin` has no opinion on the alignment of new allocations — the concept does not
appear in its documentation at all. So the clone bug needs the `CLONE_ALIGN`
const guard regardless of what `Pin` does. It is entirely outside `Pin`'s scope.

## Blocker 3 — `Pin` pins a value, it doesn't constrain what `as_ref` returns

Obligation #1 is untouched. Pinning a buffer does nothing to stop its `AsRef` impl
from returning a slice into somewhere else entirely; `Pin` governs where the value
lives, not what its methods hand out.

## Structural dead end

Even setting the above aside: to pin an *inline* `[u8; N]` you must pin the `Rk`
itself, because the array is part of the `Rk`. That requires

- `PhantomPinned` on `Rk`, making **every** `Rk` unmovable — including `RkVec`, which needs no
  pinning at all; and
- `fn as_ref(self: Pin<&Self>)`, which **cannot** be an `AsRef<T>` impl.

The entire value-semantics surface (`Eq`, `Ord`, `Hash`, `Clone`, `Debug`) assumes
a movable type. This would not be a refinement of the API; it would be a different
crate.

## Scorecard

| `Rk` obligation | Does `Pin` deliver it? |
| --- | --- |
| `as_ref` deterministic across calls | No — out of scope |
| Address survives a move of the container | Only if `!Unpin`, i.e. `PhantomPinned` newtypes |
| Clone preserves the validated alignment | No — out of scope |

## The `Deref` near-miss (also rejected)

A related idea: bound on `Deref<Target = [u8]>` instead of `AsRef<[u8]>`, on the
theory that "derefs to a slice" implies "the bytes live behind an indirection."
It does exclude bare `[u8; N]` (`the trait Deref is not implemented for [u8; 32]`),
but that is an accident of stdlib impls, not a principle. Inline-capable
containers implement `Deref` and move their bytes anyway. Measured data-pointer
addresses before and after moving each container into a `Box`:

```text
ArrayVec<u8, 32>            0x744662ffe420 -> 0x74465c000c44   MOVED
SmallVec<[u8; 32]> inline   0x74465bffe3a1 -> 0x74464c000ce1   MOVED
SmallVec<[u8; 32]> spilled  0x744650000ce0 -> 0x744650000ce0   stable
bytes::Bytes                0x744654000c40 -> 0x744654000c40   stable
```

Note the two `SmallVec` rows: stability there is a property of the **value**, not
the type, so no correct blanket impl for it exists at all. Note also the inline
address `..e3a1`, which is not even 2-aligned — a live UB path in the default
aligned mode.

Other findings from that evaluation, for the record:

- **No performance difference.** With `-O`, LLVM emitted the `Deref` monomorphizations as `.set`
  aliases to the `AsRef` ones — identical-code-folding, byte-for-byte the same machine code. Both
  lower to `movq (%rdi), %rax; movq 8(%rdi), %rdx; retq`. Neither trait has a by-value path, so
  neither can introduce a copy.
- **The two bounds are not nested.** `Deref` additionally rejects `&Vec<u8>`, `&Box<[u8]>`,
  `&Arc<[u8]>` (`<&Vec<u8> as Deref>::Target == Vec<u8>`, not `[u8]`), while accepting `Deref`-only
  smart pointers that don't bother with an `AsRef` impl.
- `bytes::Bytes` and `BytesMut` implement both and are unaffected either way.

Since `Deref` cannot retire the marker trait, switching to it would be churn that
also costs `&Vec<u8>` support. We kept `AsRef<[u8]>`.

## Ecosystem precedent

The established answer to this exact problem is
[`stable_deref_trait::StableDeref`](https://docs.rs/stable_deref_trait) — an
*unsafe marker trait*, layered on top of `Deref` precisely because `Deref` alone
is insufficient. `yoke`/`zerovec` (ICU4X) use it for zero-copy deserialization,
as do `owning_ref` and `rental`. `yoke` depends on `stable_deref_trait ^1.2.0`
and bounds its backing storage as `C: StableDeref` on `Yoke::attach_to_cart`, for
the same stated reason: dereferencing the cart must always yield the same address,
even after the cart is moved or cloned.

Nobody in this space reaches for `Pin`.

## What we did instead

`StableBuf` and `CloneBuf` (`src/stable_buf.rs`), kept as public `unsafe` traits so
downstream crates can add their own backings, with the `SmallVec`/`ArrayVec` trap
documented in the safety sections as an explicit counter-example. `CloneBuf`
carries a `CLONE_ALIGN` associated const that `Rk::clone` checks against
`align_of::<T>()` in a `const {}` block, mirroring the pre-existing
`assert_backing_align_suffices` guard.

Reproducing the measurements: the probes were throwaway integration tests against
`bytes 1.11`, `smallvec 1.15`, `arrayvec 0.7` and `tinyvec 1.11`; the codegen
comparison was `rustc -O --emit asm` on a two-struct file bounded on `AsRef<[u8]>`
and `Deref<Target = [u8]>` respectively.
