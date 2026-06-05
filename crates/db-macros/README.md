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

## Tracing instrumentation

Pass an optional `tracing_component = <string>` argument to instrument each call:

```rust
#[gen_proxy(error = DbError, tracing_component = "storage:task")]
pub trait TaskDb: Send + Sync + 'static {
    fn get_task(&self, key: Vec<u8>) -> DbResult<Option<Vec<u8>>>;
}
```

When set, the underlying call is routed through a private, instrumented shim
(`#[tracing::instrument(level = "trace", fields(component = "storage:task"))]`), so
a span is produced for every variant, recording the method arguments and the
component field — mirroring the legacy `inst_ops` shim instrumentation.

For the `_async`/`_chan` variants the shim runs on a `spawn_blocking` thread, so the
caller's current span (`tracing::Span::current()`) is captured and re-entered inside
the task. The method's span is therefore parented to the async task that issued the
call rather than orphaned on the blocking thread. Setting `tracing_component`
requires the consuming crate to depend on `tracing`.

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
