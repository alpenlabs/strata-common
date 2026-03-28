#![allow(
    missing_debug_implementations,
    reason = "none of these make sense to be debug"
)]
#![allow(
    clippy::manual_async_fn,
    reason = "clippy is just wrong about this, the types don't work"
)]

mod async_sync;
mod iter;
mod mpsc;
mod select;
mod stream;
mod sync_async;
mod ticking;
mod vec;
mod watch;

pub use async_sync::AsyncSyncInput;
pub use iter::IterInput;
pub use mpsc::TokioMpscInput;
pub use select::{Either, SelectInput};
pub use stream::StreamInput;
pub use sync_async::SyncAsyncInput;
pub use ticking::{TickMsg, TickingInput};
pub use vec::VecInput;
pub use watch::TokioWatchInput;
