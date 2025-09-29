//! Special purpose binary encoding framework.

mod buf_decoder;
mod errors;
mod macros;
mod types;
mod util;

pub use buf_decoder::BufDecoder;
pub use errors::CodecError;
pub use types::{Codec, Decoder, Encoder};
pub use util::{decode_buf_exact, encode_to_vec};

#[cfg(test)]
mod tests;
