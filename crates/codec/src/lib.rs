//! Special purpose binary encoding framework.

mod errors;
pub use errors::CodecError;

mod types;
pub use types::{BufDecoder, Codec, Decoder, Encoder};

mod macros;

mod util;
pub use util::{decode_buf_exact, encode_to_vec};

#[cfg(test)]
mod tests;
