//! Error types.

use thiserror::Error;

/// Schema error types.
#[derive(Debug, Error)]
pub enum SchemaError {
    /// Not yet implemented.
    #[error("not yet implemented")]
    Unimplemented,
}
