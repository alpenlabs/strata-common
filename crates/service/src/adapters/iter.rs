use crate::{AsyncGuard, ServiceInput, ServiceMsg, SyncServiceInput};

/// Adapter for using an [`Iterator`] as a [`SyncServiceInput`].
///
/// This does not observe shutdown while waiting for input. If `next()` can
/// block, such as on a channel receiver's iterator, an idle worker keeps
/// running through a shutdown until the next item arrives.
pub struct IterInput<I> {
    iter: I,
    closed: bool,
}

impl<I> IterInput<I> {
    /// Constructs a new unclosed instance from an iterator.
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
    fn recv_next(&mut self, _shutdown: &impl AsyncGuard) -> anyhow::Result<Option<Self::Msg>> {
        // We fuse it off ourselves just in case, it'd be weird not to.
        if self.closed {
            return Ok(None);
        }

        let item = self.iter.next();
        self.closed |= item.is_none();
        Ok(item)
    }
}
