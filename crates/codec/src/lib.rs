//! Special purpose binary encoding framework.

mod buf_decoder;
mod errors;
mod macros;
mod types;
mod util;
mod varint;
mod varint_vec;

pub use buf_decoder::BufDecoder;
pub use errors::CodecError;
pub use types::{Codec, Decoder, Encoder};
pub use util::{decode_buf_exact, encode_to_vec};
pub use varint::{VARINT_MAX, Varint, VarintInner, VarintWidth};
pub use varint_vec::VarVec;

#[cfg(test)]
mod tests;
