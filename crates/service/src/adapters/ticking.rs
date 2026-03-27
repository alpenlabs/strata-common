use std::{future::Future, time::Duration};

use futures::future::{select, Either};
use futures::pin_mut;
use tokio::time::{interval, Interval, MissedTickBehavior};

use crate::{AsyncServiceInput, ServiceInput, ServiceMsg};

/// An input produced by [`TickingInput`] which could be either the regular
/// wakeup tick or a message from the inner input being wrapped.
#[derive(Clone, Debug)]
pub enum TickMsg<T: ServiceMsg> {
    /// Regular wakeup tick.
    Tick,

    /// Real message from outside.
    Msg(T),
}

/// Wraps an [`AsyncServiceInput`] and produces regular wakeup ticks.
pub struct TickingInput<T: AsyncServiceInput> {
    interval: Interval,
    inner: T,
}

impl<T: AsyncServiceInput> TickingInput<T> {
    /// Creates a new instance.
    pub fn new(duration: Duration, inner: T) -> Self {
        let mut interval = interval(duration);

        // By my interpretation of how we currently use this pattern in the
        // context of polling, the default `Burst` strategy is actually not
        // optimal since we'll spam bunch when no progress is likely to have
        // been made.
        //
        // I'm choosing `Skip` here since that is most effective for
        // polling-based scenarios.  Ideally, any service that uses this to
        // implement polling should be reworked to fetch the input being polled
        // as part of a `ServiceInput` so that we can more easily swap out the
        // input with a push-based input later.
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        Self { interval, inner }
    }

    /// Sets the internal [`Interval`]'s `MissedTickBehavior`.
    ///
    /// By default, we set it to `Skip`.  See source comment for more info.
    pub fn set_missed_tick_behavior(&mut self, behavior: MissedTickBehavior) {
        self.interval.set_missed_tick_behavior(behavior);
    }
}

impl<T: AsyncServiceInput> ServiceInput for TickingInput<T> {
    type Msg = TickMsg<T::Msg>;
}

impl<T: AsyncServiceInput> AsyncServiceInput for TickingInput<T> {
    fn recv_next(&mut self) -> impl Future<Output = anyhow::Result<Option<Self::Msg>>> + Send {
        async move {
            let tick_fut = self.interval.tick();
            let recv_fut = self.inner.recv_next();
            pin_mut!(tick_fut);
            pin_mut!(recv_fut);

            Ok(match select(tick_fut, recv_fut).await {
                Either::Left(_) => Some(TickMsg::Tick),
                Either::Right((inp, _)) => inp?.map(TickMsg::Msg),
            })
        }
    }
}
