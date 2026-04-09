//! A "dumb ticking" input that *only* has wakeup ticks.

use std::future::Future;
use std::time::Duration;

use futures::channel::oneshot;
use futures::future::{select, Either};
use futures::pin_mut;
use tokio::time::{interval, Interval, MissedTickBehavior};

use crate::{AsyncServiceInput, ServiceInput};

/// Handle for stopping a service using a [`DumbTickingInput`].
pub struct DumbTickHandle {
    stop_tx: oneshot::Sender<()>,
}

impl DumbTickHandle {
    /// Sends the stop signal.
    ///
    /// Returns false if the service was already stopping.
    pub fn stop(self) -> bool {
        self.stop_tx.send(()).is_ok()
    }
}

/// A "dumb ticking" input that *only* has wakeup ticks and doesn't pass through
/// another source.
///
/// You might want to use this when adapting a legacy task that relies on
/// polling.  This is acceptable to use as a transitional measure until the
/// input handling code can be rewritten to handle structured inputs.
pub struct DumbTickingInput {
    interval: Interval,
    stop_rx: oneshot::Receiver<()>,
    closed: bool,
}

impl DumbTickingInput {
    /// Creates a new instance using the providing tick interval, returning the
    /// input and a handle to stop the service.
    pub fn new(duration: Duration) -> (DumbTickHandle, DumbTickingInput) {
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut interval = interval(duration);

        // See comment in ticking.rs.
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let handle = DumbTickHandle { stop_tx };
        let inp = Self {
            interval,
            stop_rx,
            closed: false,
        };

        (handle, inp)
    }

    /// Sets the internal [`Interval`]'s `MissedTickBehavior`.
    ///
    /// By default, we set it to `Skip`.  See source comment for more info.
    pub fn set_missed_tick_behavior(&mut self, behavior: MissedTickBehavior) {
        self.interval.set_missed_tick_behavior(behavior);
    }
}

impl ServiceInput for DumbTickingInput {
    type Msg = ();
}

impl AsyncServiceInput for DumbTickingInput {
    fn recv_next(&mut self) -> impl Future<Output = anyhow::Result<Option<Self::Msg>>> + Send {
        async move {
            // Fuse it off ourselves.
            if self.closed {
                return Ok(None);
            }

            let tick_fut = self.interval.tick();
            let recv_fut = &mut self.stop_rx;
            pin_mut!(tick_fut);
            pin_mut!(recv_fut);

            Ok(match select(tick_fut, recv_fut).await {
                Either::Left(_) => Some(()),
                Either::Right(_) => {
                    self.closed = true;
                    None
                }
            })
        }
    }
}
