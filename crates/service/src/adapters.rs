#![allow(
    missing_debug_implementations,
    reason = "none of these make sense to be debug"
)]
#![allow(
    clippy::manual_async_fn,
    reason = "clippy is just wrong about this, the types don't work"
)]

use std::{any::Any, collections::*, fmt::Debug, future::Future, sync::Arc};

use futures::stream::{Stream, StreamExt};
use tokio::sync::{mpsc, Mutex};

use crate::{AsyncServiceInput, ServiceError, ServiceInput, ServiceMsg, SyncServiceInput};

/// Adapter for using an [`Iterator`] as a [`SyncServiceInput`].
pub struct IterInput<I> {
    iter: I,
    closed: bool,
}

impl<I> IterInput<I> {
    pub fn new(iter: I) -> Self {
        Self {
            iter,
            closed: false,
        }
    }
}

impl<I: Iterator + Sync + Send + 'static> ServiceInput for IterInput<I>
where
    I::Item: ServiceMsg,
{
    type Msg = I::Item;
}

impl<I: Iterator + Sync + Send + 'static> SyncServiceInput for IterInput<I>
where
    I::Item: ServiceMsg,
{
    fn recv_next(&mut self) -> anyhow::Result<Option<Self::Msg>> {
        // We fuse it off ourselves just in case, it'd be weird not to.
        if self.closed {
            return Ok(None);
        }

        let item = self.iter.next();
        self.closed |= item.is_none();
        Ok(item)
    }
}

/// Adapter for using an async service input as a sync one.
pub struct SyncAsyncInput<I> {
    inner: I,
    handle: tokio::runtime::Handle,
}

impl<I> SyncAsyncInput<I> {
    pub fn new(inner: I, handle: tokio::runtime::Handle) -> Self {
        Self { inner, handle }
    }
}

impl<I: ServiceInput> ServiceInput for SyncAsyncInput<I>
where
    I::Msg: ServiceMsg,
{
    type Msg = I::Msg;
}

impl<I: AsyncServiceInput> SyncServiceInput for SyncAsyncInput<I> {
    fn recv_next(&mut self) -> anyhow::Result<Option<Self::Msg>> {
        self.handle.block_on(self.inner.recv_next())
    }
}

/// Adapter for using a sync service input as an async one.
pub struct AsyncSyncInput<I> {
    // This is really annoying that it has to work this way.  Hopefully we won't
    // ever have to use this impl.
    inner: Arc<Mutex<I>>,
}

impl<I> AsyncSyncInput<I> {
    pub fn new(inner: I) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

impl<I: ServiceInput> ServiceInput for AsyncSyncInput<I>
where
    I::Msg: ServiceMsg,
{
    type Msg = I::Msg;
}

impl<I: SyncServiceInput> AsyncServiceInput for AsyncSyncInput<I>
where
    I::Msg: ServiceMsg,
{
    fn recv_next(&mut self) -> impl Future<Output = anyhow::Result<Option<Self::Msg>>> + Send {
        let inner = self.inner.clone();
        async move {
            let res = tokio::task::spawn_blocking(move || {
                let mut inner_lock = inner.blocking_lock();
                inner_lock.recv_next()
            })
            .await;

            match res {
                Ok(res) => res,
                Err(je) => {
                    let e = if je.is_cancelled() {
                        // How could this ever happen?
                        ServiceError::WaitCancelled
                    } else if je.is_panic() {
                        let panic = je.into_panic();
                        ServiceError::BlockingThreadPanic(
                            try_conv_panic(&panic).unwrap_or_default(),
                        )
                    } else {
                        ServiceError::UnknownInputErr
                    };

                    Err(e.into())
                }
            }
        }
    }
}

fn try_conv_panic(panic: &dyn Any) -> Option<String> {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&String>().cloned().cloned())
        .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
}

/// Adapter for using a mpsc receiver as a input.
///
/// This is needed because [``mpsc::Receiver``] does not natively implement
/// [``Stream``] and it avoids having to use the Tokio wrapper.
pub struct TokioMpscInput<T> {
    rx: mpsc::Receiver<T>,
    closed: bool,
}

impl<T> TokioMpscInput<T> {
    pub fn new(rx: mpsc::Receiver<T>) -> Self {
        Self { rx, closed: false }
    }
}

impl<T: ServiceMsg> ServiceInput for TokioMpscInput<T> {
    type Msg = T;
}

impl<T: ServiceMsg> AsyncServiceInput for TokioMpscInput<T> {
    fn recv_next(&mut self) -> impl Future<Output = anyhow::Result<Option<Self::Msg>>> + Send {
        async move {
            // We fuse it off ourselves just in case, it'd be weird not to.
            if self.closed {
                return Ok(None);
            }

            let item = self.rx.recv().await;
            self.closed |= item.is_none();
            Ok(item)
        }
    }
}

/// This impl is technically redundant since we can use the type as an
/// [``Iterator``], but someone might find it useful and it's easy enough to
/// implement.
impl<T: ServiceMsg> SyncServiceInput for TokioMpscInput<T> {
    fn recv_next(&mut self) -> anyhow::Result<Option<Self::Msg>> {
        // We fuse it off ourselves just in case, it'd be weird not to.
        if self.closed {
            return Ok(None);
        }

        let item = self.rx.blocking_recv();
        self.closed |= item.is_none();
        Ok(item)
    }
}

/// Adapter for using an arbitrary [``Stream``] impl as an input.
pub struct StreamInput<S> {
    stream: S,
    closed: bool,
}

impl<S> StreamInput<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            closed: false,
        }
    }
}

impl<S: Stream + Sync + Send + 'static> ServiceInput for StreamInput<S>
where
    S::Item: ServiceMsg,
{
    type Msg = S::Item;
}

impl<S: Stream + Unpin + Sync + Send + 'static> AsyncServiceInput for StreamInput<S>
where
    S::Item: ServiceMsg,
{
    fn recv_next(&mut self) -> impl Future<Output = anyhow::Result<Option<Self::Msg>>> + Send {
        async move {
            // We fuse it off ourselves just in case, it'd be weird not to.
            if self.closed {
                return Ok(None);
            }

            let item = self.stream.next().await;
            self.closed |= item.is_none();
            Ok(item)
        }
    }
}

/// A simple queue of inputs, primarily for testing services in isolation.
///
/// Yields each item in the queue and then indicates that the queue is empty,
/// unless and until more are somehow added.
#[derive(Clone, Debug)]
pub struct VecInput<T> {
    items: VecDeque<T>,
}

impl<T> VecInput<T> {
    pub fn new(items: VecDeque<T>) -> Self {
        Self { items }
    }

    /// Inserts a new item.
    pub fn insert(&mut self, item: T) {
        self.items.push_back(item);
    }

    /// Returns the number of items in the queue.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl<T: ServiceMsg> ServiceInput for VecInput<T> {
    type Msg = T;
}

impl<T: ServiceMsg> SyncServiceInput for VecInput<T> {
    fn recv_next(&mut self) -> anyhow::Result<Option<Self::Msg>> {
        Ok(self.items.pop_front())
    }
}

impl<T: ServiceMsg> AsyncServiceInput for VecInput<T> {
    fn recv_next(&mut self) -> impl Future<Output = anyhow::Result<Option<Self::Msg>>> + Send {
        async { Ok(self.items.pop_front()) }
    }
}

impl<T> FromIterator<T> for VecInput<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self::new(VecDeque::from_iter(iter))
    }
}

#[cfg(test)]
mod tests {
    use futures::stream;
    use tokio::sync::mpsc;

    use super::*;

    #[tokio::test]
    async fn test_stream_input() {
        let v = 3;
        let stream = stream::repeat(v);
        let mut inp = StreamInput::new(stream);

        let rv = inp
            .recv_next()
            .await
            .expect("test: recv input")
            .expect("test: have input");

        assert_eq!(rv, v, "test: input match");
    }

    #[tokio::test]
    async fn test_mpsc_input_async() {
        let v = 3;

        let (tx, rx) = mpsc::channel(10);
        let mut inp = TokioMpscInput::new(rx);

        tx.send(v).await.expect("test: send input");

        let rv = AsyncServiceInput::recv_next(&mut inp)
            .await
            .expect("test: recv input")
            .expect("test: have input");

        assert_eq!(rv, v, "test: input match");
    }

    #[test]
    fn test_mpsc_input_blocking() {
        let v = 3;

        let (tx, rx) = mpsc::channel(10);
        let mut inp = TokioMpscInput::new(rx);

        tx.blocking_send(v).expect("test: send input");

        let rv = SyncServiceInput::recv_next(&mut inp)
            .expect("test: recv input")
            .expect("test: have input");

        assert_eq!(rv, v, "test: input match");
    }

    #[tokio::test]
    async fn test_vec_input_async() {
        let v = [1, 2, 3];
        let mut inp = VecInput::from_iter(v);

        let vv = [Some(1), Some(2), Some(3), None];
        for e in vv {
            let res = AsyncServiceInput::recv_next(&mut inp)
                .await
                .expect("test: recv input");
            assert_eq!(res, e);
        }
    }

    #[test]
    fn test_vec_input_blocking() {
        let v = [1, 2, 3];
        let mut inp = VecInput::from_iter(v);

        let vv = [Some(1), Some(2), Some(3), None];
        for e in vv {
            let res = SyncServiceInput::recv_next(&mut inp).expect("test: recv input");
            assert_eq!(res, e);
        }
    }
}
