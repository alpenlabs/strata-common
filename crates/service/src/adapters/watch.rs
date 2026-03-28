use std::future::Future;

use tokio::sync::watch;

use crate::{AsyncServiceInput, ServiceInput, ServiceMsg};

/// Adapter for using a watch receiver as a input.
///
/// Can be used by listener service (to construct an input to listen) or if watch is used.
pub struct TokioWatchInput<T> {
    rx: watch::Receiver<T>,
    closed: bool,
}

impl<T> TokioWatchInput<T> {
    /// Creates a new status monitor input from a service monitor.
    ///
    /// This is the primary way to create a listener that watches another service's status.
    /// The listener will receive status updates whenever the monitored service's state changes.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let listener_input = TokioWatchInput::from_receiver(
    ///     monitored_monitor.status_rx.clone()
    /// );
    /// ```
    pub fn from_receiver(rx: watch::Receiver<T>) -> Self {
        Self { rx, closed: false }
    }
}

impl<S: ServiceMsg> ServiceInput for TokioWatchInput<S> {
    type Msg = S;
}

impl<S: ServiceMsg + Clone> AsyncServiceInput for TokioWatchInput<S> {
    fn recv_next(&mut self) -> impl Future<Output = anyhow::Result<Option<Self::Msg>>> + Send {
        async move {
            // If already closed, don't try to receive again
            if self.closed {
                return Ok(None);
            }

            // Wait for the next status change
            match self.rx.changed().await {
                Ok(()) => {
                    // Get the new status value
                    let status = self.rx.borrow_and_update().clone();
                    Ok(Some(status))
                }
                Err(_) => {
                    // Channel closed - monitored service has exited
                    self.closed = true;
                    Ok(None)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::Serialize;
    use tokio::sync::mpsc;

    use super::*;
    use crate::{AsyncService, Response, Service, ServiceBuilder, ServiceState, TokioMpscInput};

    // Test service for status monitor input testing
    #[derive(Clone, Debug)]
    struct TestMonitoredService;

    #[derive(Clone, Debug, Serialize)]
    struct TestStatus {
        counter: u32,
    }

    struct TestMonitoredState {
        counter: u32,
    }

    impl ServiceState for TestMonitoredState {
        fn name(&self) -> &str {
            "test_monitored"
        }
    }

    impl Service for TestMonitoredService {
        type State = TestMonitoredState;
        type Msg = u32;
        type Status = TestStatus;

        fn get_status(state: &Self::State) -> Self::Status {
            TestStatus {
                counter: state.counter,
            }
        }
    }

    impl AsyncService for TestMonitoredService {
        async fn process_input(
            state: &mut Self::State,
            input: Self::Msg,
        ) -> anyhow::Result<Response> {
            state.counter += input;
            Ok(Response::Continue)
        }
    }

    // Test listener service
    #[derive(Clone, Debug)]
    struct TestListenerService;

    #[derive(Clone, Debug, Serialize)]
    struct TestListenerStatus {
        last_seen: Option<u32>,
        updates: usize,
    }

    struct TestListenerState {
        last_seen: Option<u32>,
        updates: usize,
    }

    impl ServiceState for TestListenerState {
        fn name(&self) -> &str {
            "test_listener"
        }
    }

    impl Service for TestListenerService {
        type State = TestListenerState;
        type Msg = TestStatus;
        type Status = TestListenerStatus;

        fn get_status(state: &Self::State) -> Self::Status {
            TestListenerStatus {
                last_seen: state.last_seen,
                updates: state.updates,
            }
        }
    }

    impl AsyncService for TestListenerService {
        async fn process_input(
            state: &mut Self::State,
            input: Self::Msg,
        ) -> anyhow::Result<Response> {
            state.last_seen = Some(input.counter);
            state.updates += 1;
            Ok(Response::Continue)
        }
    }

    #[tokio::test]
    async fn test_status_monitor_input() {
        let handle = tokio::runtime::Handle::current();
        let task_manager = strata_tasks::TaskManager::new(handle);
        let texec = task_manager.create_executor();

        // Launch monitored service
        let (tx, rx) = mpsc::channel(10);
        let monitored_state = TestMonitoredState { counter: 0 };
        let monitored_input = TokioMpscInput::new(rx);

        let monitored_monitor = ServiceBuilder::<TestMonitoredService, _>::new()
            .with_state(monitored_state)
            .with_input(monitored_input)
            .launch_async("test_monitored", &texec)
            .await
            .expect("test: launch monitored service");

        // Create listener using the monitored service's status
        let listener_input =
            TokioWatchInput::<TestStatus>::from_receiver(monitored_monitor.status_rx.clone());
        let listener_state = TestListenerState {
            last_seen: None,
            updates: 0,
        };

        let listener_monitor = ServiceBuilder::<TestListenerService, _>::new()
            .with_state(listener_state)
            .with_input(listener_input)
            .launch_async("test_listener", &texec)
            .await
            .expect("test: launch listener service");

        // Send some updates to the monitored service
        tx.send(5).await.expect("test: send 5");
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        tx.send(10).await.expect("test: send 10");
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Check that listener received the updates
        let listener_status = listener_monitor.get_current();
        assert_eq!(listener_status.last_seen, Some(15));
        assert!(listener_status.updates >= 1); // At least one update

        // Drop the sender to close the monitored service
        drop(tx);
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // The listener should also exit when the monitored service exits
        // This is tested implicitly by the test completing without hanging
    }
}
