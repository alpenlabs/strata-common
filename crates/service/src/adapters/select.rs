//! Multi-input combinator that merges two async input sources.
//!
//! [`SelectInput`] waits on two input sources simultaneously and yields
//! whichever is ready first, wrapped in [`Either`]. This enables services
//! that need to react to multiple event sources (e.g., commands + status
//! updates, or commands + periodic ticks).
//!
//! # Example
//!
//! ```rust,ignore
//! use strata_service::*;
//!
//! let cmd_input = TokioMpscInput::new(rx);
//! let tick_input = TickingInput::new(Duration::from_secs(10));
//! let combined = SelectInput::new(cmd_input, tick_input);
//! // Service::Msg = Either<MyCommand, TickMsg>
//! ```

use std::fmt;
use std::future::Future;

use crate::{AsyncServiceInput, ServiceInput, ServiceMsg};

/// A value from one of two input sources.
#[derive(Clone, Debug)]
pub enum Either<A, B> {
    /// Value from the first (left) input source.
    Left(A),
    /// Value from the second (right) input source.
    Right(B),
}

/// Combines two [`AsyncServiceInput`] sources into one.
///
/// Waits on both inputs simultaneously and yields whichever message arrives
/// first, wrapped in [`Either`]. When either input closes (`None`), the
/// combinator closes.
pub struct SelectInput<L, R> {
    left: L,
    right: R,
}

impl<L, R> SelectInput<L, R> {
    /// Creates a new combinator from two input sources.
    pub fn new(left: L, right: R) -> Self {
        Self { left, right }
    }
}

impl<L, R> fmt::Debug for SelectInput<L, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SelectInput").finish()
    }
}

impl<L, R> ServiceInput for SelectInput<L, R>
where
    L: AsyncServiceInput,
    R: AsyncServiceInput,
    L::Msg: ServiceMsg,
    R::Msg: ServiceMsg,
{
    type Msg = Either<L::Msg, R::Msg>;
}

impl<L, R> AsyncServiceInput for SelectInput<L, R>
where
    L: AsyncServiceInput,
    R: AsyncServiceInput,
    L::Msg: ServiceMsg,
    R::Msg: ServiceMsg,
{
    fn recv_next(
        &mut self,
    ) -> impl Future<Output = anyhow::Result<Option<Self::Msg>>> + Send {
        async {
            tokio::select! {
                result = self.left.recv_next() => {
                    match result {
                        Ok(Some(msg)) => Ok(Some(Either::Left(msg))),
                        Ok(None) => Ok(None),
                        Err(e) => Err(e),
                    }
                }
                result = self.right.recv_next() => {
                    match result {
                        Ok(Some(msg)) => Ok(Some(Either::Right(msg))),
                        Ok(None) => Ok(None),
                        Err(e) => Err(e),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;

    use super::*;
    use crate::TokioMpscInput;

    #[tokio::test]
    async fn test_select_input_left_ready() {
        let (tx_l, rx_l) = mpsc::channel(10);
        let (tx_r, rx_r) = mpsc::channel::<u64>(10);

        let left = TokioMpscInput::new(rx_l);
        let right = TokioMpscInput::new(rx_r);
        let mut combined = SelectInput::new(left, right);

        tx_l.send(42u32).await.unwrap();

        let result = combined.recv_next().await.unwrap().unwrap();
        assert!(matches!(result, Either::Left(42)));

        drop(tx_l);
        drop(tx_r);
    }

    #[tokio::test]
    async fn test_select_input_right_ready() {
        let (tx_l, rx_l) = mpsc::channel::<u32>(10);
        let (tx_r, rx_r) = mpsc::channel(10);

        let left = TokioMpscInput::new(rx_l);
        let right = TokioMpscInput::new(rx_r);
        let mut combined = SelectInput::new(left, right);

        tx_r.send(99u64).await.unwrap();

        let result = combined.recv_next().await.unwrap().unwrap();
        assert!(matches!(result, Either::Right(99)));

        drop(tx_l);
        drop(tx_r);
    }

    #[tokio::test]
    async fn test_select_input_closes_on_left_close() {
        let (tx_l, rx_l) = mpsc::channel::<u32>(10);
        let (_tx_r, rx_r) = mpsc::channel::<u64>(10);

        let left = TokioMpscInput::new(rx_l);
        let right = TokioMpscInput::new(rx_r);
        let mut combined = SelectInput::new(left, right);

        drop(tx_l);

        let result = combined.recv_next().await.unwrap();
        assert!(result.is_none());
    }
}
