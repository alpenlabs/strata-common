use std::collections::VecDeque;
use std::future::Future;

use crate::{AsyncServiceInput, ServiceInput, ServiceMsg, SyncServiceInput};

/// A simple preconfigured queue of input messages.  This would be useful
/// primarily for testing services in isolation.
///
/// Yields each item in the queue and then indicates that the queue is empty,
/// unless and until more are (*somehow*) added.
#[derive(Clone, Debug)]
pub struct VecInput<T> {
    items: VecDeque<T>,
}

impl<T> VecInput<T> {
    /// Constructs a new instance from an existing [`VecDeque`].
    pub fn new(items: VecDeque<T>) -> Self {
        Self { items }
    }

    /// Constructs a new empty instance.
    pub fn new_empty() -> Self {
        Self::new(VecDeque::new())
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
    use super::*;

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
