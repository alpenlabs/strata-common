use bitcoin::{
    ScriptBuf,
    blockdata::script,
    opcodes::{
        OP_FALSE,
        all::{OP_ENDIF, OP_IF},
    },
    script::PushBytesBuf,
};

use crate::errors::EnvelopeParseError;
// Generates a [`ScriptBuf`] that consists of `OP_IF .. OP_ENDIF` block
pub fn build_envelope_script(payload: &[u8]) -> Result<ScriptBuf, EnvelopeParseError> {
    let mut builder = script::Builder::new()
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF);

    // Insert actual data
    for chunk in payload.chunks(520) {
        builder = builder.push_slice(PushBytesBuf::try_from(chunk.to_vec()).unwrap()); // FIXME: remove unwrap
    }
    builder = builder.push_opcode(OP_ENDIF);
    Ok(builder.into_script())
}
