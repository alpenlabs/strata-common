//! Core service worker types.

use std::any::Any;
use std::fmt::Debug;
use std::future::Future;

use serde::Serialize;

use crate::AsyncGuard;

/// Response from handling an input.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Response {
    /// Normal case, should continue.
    Continue,

    /// Service should exit early.
    ShouldExit,
}

/// Abstract service trait.
pub trait Service: Sync + Send + 'static {
    /// The in-memory state of the service.
    type State: ServiceState;

    /// The input message type that the service operates on.
    type Msg: ServiceMsg;

    /// The status type derived from the state.
    type Status: ServiceStatus;

    /// Gets the status from the current state.
    fn get_status(s: &Self::State) -> Self::Status;
}

/// Trait for service states which exposes common properties.
pub trait ServiceState: Sync + Send + 'static {
    /// Name for a service that can be printed in logs.
    ///
    /// This SHOULD NOT change after the service worker has been started.
    fn name(&self) -> &str;

    /// Span prefix for OpenTelemetry tracing.
    ///
    /// This is used to create semantic span names like "asm.lifecycle", "csm.lifecycle", etc.
    fn span_prefix(&self) -> &str {
        "service"
    }
}

/// Trait for service messages, which we want to treat like simple dumb data
/// containers.
///
/// This is also `Debug` for debug purposes.
pub trait ServiceMsg: Debug + Sync + Send + 'static {
    // nothing yet
}

/// Blanket auto-impl for any type that impls these traits.
impl<T: Debug + Sync + Send + 'static> ServiceMsg for T {}

/// Trait for service status.
///
/// This implements [``Serialize``] so that we can unify different types of
/// services into a single metrics collection system.
pub trait ServiceStatus: Any + Clone + Debug + Sync + Send + Serialize + 'static {
    // nothing yet
}

/// Blanket auto-impl for any type that impls these traits.
impl<T: Any + Clone + Debug + Sync + Send + Serialize + 'static> ServiceStatus for T {}

/// Trait for async service impls to define their per-input logic.
pub trait AsyncService: Service {
    /// Called in the worker task after launching.
    fn on_launch(_state: &mut Self::State) -> impl Future<Output = anyhow::Result<()>> + Send {
        async { Ok(()) }
    }

    /// Called for each input.
    ///
    /// Takes owned input so handlers can move data (e.g. completion senders)
    /// into spawned tasks without cloning.
    fn process_input(
        _state: &mut Self::State,
        _input: Self::Msg,
    ) -> impl Future<Output = anyhow::Result<Response>> + Send {
        async { Ok(Response::Continue) }
    }

    /// Called when about to shut down, for whatever reason.
    ///
    /// Passed an error, if shutting down due to input handling error.
    fn before_shutdown(
        _state: &mut Self::State,
        _err: Option<&anyhow::Error>,
    ) -> impl Future<Output = anyhow::Result<()>> + Send {
        async { Ok(()) }
    }
}

/// Trait for blocking service impls to define their per-input logic.
pub trait SyncService: Service {
    /// Called in the worker thread after launching.
    fn on_launch(_state: &mut Self::State) -> anyhow::Result<()> {
        Ok(())
    }

    /// Called for each input.
    ///
    /// Takes owned input so handlers can move data into processing
    /// without cloning.
    fn process_input(_state: &mut Self::State, _input: Self::Msg) -> anyhow::Result<Response> {
        Ok(Response::Continue)
    }

    /// Called when about to shut down, for whatever reason.
    ///
    /// Passed an error, if shutting down due to input handling error.
    fn before_shutdown(
        _state: &mut Self::State,
        _err: Option<&anyhow::Error>,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Generic service input trait.
pub trait ServiceInput: Sync + Send + 'static {
    /// The message type.
    type Msg: ServiceMsg;
}

/// Common inputs for async service input sources.
pub trait AsyncServiceInput: ServiceInput {
    /// Receives the "next input".  If returns `Ok(None)` then there is no more
    /// input and we should exit.
    ///
    /// This is like a specialized `TryStream`.
    fn recv_next(&mut self) -> impl Future<Output = anyhow::Result<Option<Self::Msg>>> + Send;
}

/// Common inputs for blocking service input sources.
pub trait SyncServiceInput: ServiceInput {
    /// Receives the "next input".  If returns `Ok(None)` then there is no more
    /// input and we should exit.
    ///
    /// This is like a specialized `TryIterator`.
    fn recv_next(&mut self) -> anyhow::Result<Option<Self::Msg>>;

    /// Receives the "next input", giving up and returning `Ok(None)` if
    /// `shutdown` fires while we are waiting.
    ///
    /// A sync worker runs on its own thread and cannot be cancelled from
    /// outside, so an input that parks indefinitely in [`recv_next`] would sit
    /// through a shutdown until the next message happens to arrive.  Any input
    /// that can block without bound should override this so the worker stops
    /// when asked.
    ///
    /// The default ignores `shutdown` and defers to [`recv_next`], which is
    /// correct for inputs that never block indefinitely (an in-memory queue, a
    /// finite iterator).
    fn recv_next_until_shutdown(
        &mut self,
        _shutdown: &(impl AsyncGuard + Sync),
    ) -> anyhow::Result<Option<Self::Msg>> {
        self.recv_next()
    }
}
