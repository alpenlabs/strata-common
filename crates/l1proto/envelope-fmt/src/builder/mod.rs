mod envelope;
mod errors;

pub use envelope::{
    EnvelopeScriptBuilder, MAX_ENVELOPE_PAYLOAD_SIZE, MIN_ENVELOPE_PAYLOAD_SIZE,
    build_envelope_script, build_signed_envelope_leaf, split_payload_into_envelope_chunks,
};
pub use errors::EnvelopeBuildError;
