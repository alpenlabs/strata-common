# strata-db-macros

Procedural macros for generating async/blocking proxy handles around database traits.

## `#[gen_proxy]`

Attach `#[gen_proxy(error = <ErrorType>)]` to a trait `Foo` to generate:

- a `FooProxy` handle that owns a [`tokio::runtime::Handle`] and an
  `Arc<dyn Foo + Send + Sync + 'static>`, and
- a `FooRecv<T, E>` wrapper around the spawned task's join handle.

For each qualifying trait method `foo(&self, args..) -> Result<T, E>`, the proxy
exposes three variants:

| Variant            | Behavior                                                            |
| ------------------ | ------------------------------------------------------------------- |
| `foo_blocking`     | Calls the underlying method inline on the current thread.           |
| `foo_async`        | Offloads the call to a blocking task via `spawn_blocking`, awaited.  |
| `foo_chan`         | Spawns the blocking task and returns a `FooRecv` to await later.     |

```rust
use std::sync::Arc;

use strata_db_macros::gen_proxy;
use tokio::runtime::Handle;

type DbResult<T> = Result<T, DbError>;

#[gen_proxy(error = DbError)]
pub trait TaskDb: Send + Sync + 'static {
    fn get_task(&self, key: Vec<u8>) -> DbResult<Option<Vec<u8>>>;
    fn count_tasks(&self) -> DbResult<usize>;
}

// let proxy = TaskDbProxy::new(Handle::current(), db);
// let n = proxy.count_tasks_async().await?;
```

## Requirements & constraints

- The `error = ...` type must implement `From<tokio::task::JoinError>` (a panic in
  the blocking task surfaces as that error from the `_async`/`_chan` variants).
- The consuming crate must depend on `tokio` (the generated code references
  `::tokio`).
- The trait must be object-safe (the proxy holds a `dyn Foo`). Non-`&self` helper
  methods need `where Self: Sized`.
- Only methods that take `&self`, are non-`async`, have no method-level generics,
  use plain identifier argument patterns, and return a `Result`-shaped type get
  proxy variants. Other methods remain trait-only.
- For the `_async`/`_chan` variants, arguments and the success type must be
  `Send + 'static` (a `spawn_blocking` requirement). `_blocking` has no such bound.
