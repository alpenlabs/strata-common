use crate::{AsyncServiceInput, ServiceInput, ServiceMsg, SyncServiceInput};

/// Adapter for using an async service input as a sync one.
pub struct SyncAsyncInput<I> {
    inner: I,
    handle: tokio::runtime::Handle,
}

impl<I> SyncAsyncInput<I> {
    /// Constructs a new instance using a runtime handle.
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
