//! Compact big-endian varint with a canonical shortest-layout encoding.
//!
//! The varints are optimized to short lengths, since most payloads will be
//! small.  Below are the permitted layouts, always encoded big-endian.
//!
//! ```txt
//! 0bbbbbbb
//! 10bbbbbb_bbbbbbbb
//! 11bbbbbb_bbbbbbbb_bbbbbbbb_bbbbbbbb
//! ```
//!
//! The encoding is canonical: a value is always written in the shortest
//! layout that holds it, and decoding rejects a longer layout for a value a
//! shorter one would hold.  Every value therefore has exactly one byte
//! representation, so bytes covered by a hash or a signature cannot be
//! rewritten without changing what they decode to.

use crate::errors::CodecError;
use crate::types::{Codec, Decoder, Encoder};

/// The max value one of these varints can have, which is about 1 billion.
pub const VARINT_MAX: u32 = 0x3fffffff;

/// Inner type used to represent a varint in memory.
pub type VarintInner = u32;

/// Internal varint type.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Varint(VarintInner);

impl Varint {
    const fn new_unchecked(v: VarintInner) -> Self {
        Self(v)
    }

    /// Construct a new instance.
    pub const fn new(v: VarintInner) -> Option<Self> {
        if v > VARINT_MAX {
            return None;
        }
        Some(Self::new_unchecked(v))
    }

    /// Constructs a new instance from a usize.
    pub const fn new_usize(v: usize) -> Option<Self> {
        // This is implemented as a separate function from `new` just we don't
        // have to trust LLVM will optimize out the bounds checks.
        if v > VARINT_MAX as usize {
            return None;
        }

        Some(Self::new_unchecked(v as VarintInner))
    }

    /// Converts to inner value.
    pub const fn inner(self) -> VarintInner {
        self.0
    }

    /// Gets the "width type" of the varint.
    pub const fn width(&self) -> VarintWidth {
        if self.0 < 128 {
            VarintWidth::U8
        } else if self.0 < 16384 {
            VarintWidth::U16
        } else {
            VarintWidth::U32
        }
    }

    /// Convenience function for returning the encoded length in bytes.
    pub const fn byte_len(&self) -> usize {
        self.width().byte_len()
    }

    /// # Panics
    ///
    /// If out of bounds.
    #[cfg(test)]
    fn sanity_check(&self) {
        assert!(self.0 <= VARINT_MAX, "varint_vec: varint out of bounds");
    }
}

impl TryFrom<usize> for Varint {
    type Error = CodecError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::new_usize(value).ok_or(CodecError::OobInteger)
    }
}

impl From<Varint> for usize {
    fn from(value: Varint) -> Self {
        value.inner() as usize
    }
}

impl Codec for Varint {
    fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError> {
        let first_byte = u8::decode(dec)?;

        let (value, width) = match first_byte >> 6 {
            // 0b00xxxxxx or 0b01xxxxxx: single byte encoding
            0 | 1 => (first_byte as u32, VarintWidth::U8),

            // 0b10xxxxxx: two-byte encoding
            2 => {
                let second_byte = u8::decode(dec)?;
                let bytes = [first_byte & 0x3f, second_byte];
                (u16::from_be_bytes(bytes) as u32, VarintWidth::U16)
            }

            // 0b11xxxxxx: four-byte encoding
            3 => {
                let mut bytes = [first_byte & 0x3f, 0, 0, 0];
                dec.read_buf(&mut bytes[1..4])?;
                (u32::from_be_bytes(bytes), VarintWidth::U32)
            }

            _ => unreachable!(),
        };

        let vi = Varint::new_unchecked(value);

        // Only the shortest layout for the value is valid, the one `encode`
        // emits.  A longer layout for the same value would give it a second
        // byte representation (see the module docs).
        if vi.width() != width {
            return Err(CodecError::MalformedField("varint"));
        }

        #[cfg(test)]
        vi.sanity_check();

        Ok(vi)
    }

    fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError> {
        #[cfg(test)]
        self.sanity_check();

        match self.width() {
            VarintWidth::U8 => (self.0 as u8).encode(enc),
            VarintWidth::U16 => {
                let val = (self.0 as u16) | 0x8000;
                let bytes = val.to_be_bytes();
                enc.write_buf(&bytes)
            }
            VarintWidth::U32 => {
                let val = self.0 | 0xc0000000;
                let bytes = val.to_be_bytes();
                enc.write_buf(&bytes)
            }
        }
    }
}

/// Describes the width that a varint will be encoded as, by referring to the
/// unsigned integer type with that width.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum VarintWidth {
    /// 1 byte
    U8,

    /// 2 bytes
    U16,

    /// 4 bytes
    U32,
}

impl VarintWidth {
    /// Returns the number of bytes to encode the varint.
    pub const fn byte_len(&self) -> usize {
        match self {
            VarintWidth::U8 => 1,
            VarintWidth::U16 => 2,
            VarintWidth::U32 => 4,
        }
    }
}

#[cfg(test)]
mod tests {
    // Most of these tests were written by Claude.

    use super::*;
    use crate::{decode_buf_exact, encode_to_vec};

    #[test]
    fn test_varint_new() {
        assert!(Varint::new(0).is_some());
        assert!(Varint::new(127).is_some());
        assert!(Varint::new(128).is_some());
        assert!(Varint::new(16383).is_some());
        assert!(Varint::new(16384).is_some());
        assert!(Varint::new(VARINT_MAX).is_some());
        assert!(Varint::new(VARINT_MAX + 1).is_none());
    }

    #[test]
    fn test_varint_width() {
        assert_eq!(Varint::new(0).unwrap().width(), VarintWidth::U8);
        assert_eq!(Varint::new(127).unwrap().width(), VarintWidth::U8);
        assert_eq!(Varint::new(128).unwrap().width(), VarintWidth::U16);
        assert_eq!(Varint::new(16383).unwrap().width(), VarintWidth::U16);
        assert_eq!(Varint::new(16384).unwrap().width(), VarintWidth::U32);
        assert_eq!(Varint::new(VARINT_MAX).unwrap().width(), VarintWidth::U32);
    }

    #[test]
    fn test_varint_encode_decode_u8() {
        for val in [0u32, 1, 42, 127] {
            let varint = Varint::new(val).unwrap();
            let buf = encode_to_vec(&varint).unwrap();

            assert_eq!(buf.len(), 1, "U8 varint should be 1 byte");

            let decoded: Varint = decode_buf_exact(&buf).unwrap();
            assert_eq!(decoded.inner(), val);
        }
    }

    #[test]
    fn test_varint_encode_decode_u16() {
        for val in [128u32, 200, 1000, 16383] {
            let varint = Varint::new(val).unwrap();
            let buf = encode_to_vec(&varint).unwrap();

            assert_eq!(buf.len(), 2, "U16 varint should be 2 bytes");
            assert_eq!(buf[0] >> 6, 2, "U16 varint should start with 0b10");

            let decoded: Varint = decode_buf_exact(&buf).unwrap();
            assert_eq!(decoded.inner(), val);
        }
    }

    #[test]
    fn test_varint_encode_decode_u32() {
        for val in [16384u32, 100000, 1000000, VARINT_MAX] {
            let varint = Varint::new(val).unwrap();
            let buf = encode_to_vec(&varint).unwrap();

            assert_eq!(buf.len(), 4, "U32 varint should be 4 bytes");
            assert_eq!(buf[0] >> 6, 3, "U32 varint should start with 0b11");

            let decoded: Varint = decode_buf_exact(&buf).unwrap();
            assert_eq!(decoded.inner(), val);
        }
    }

    #[test]
    fn test_varint_boundaries() {
        // Test boundary values
        let boundaries = [0, 127, 128, 16383, 16384, VARINT_MAX];

        for val in boundaries {
            let varint = Varint::new(val).unwrap();
            let buf = encode_to_vec(&varint).unwrap();

            let decoded: Varint = decode_buf_exact(&buf).unwrap();
            assert_eq!(decoded.inner(), val);
        }
    }

    #[test]
    fn test_varint_rejects_noncanonical_encodings() {
        // Each value below fits a shorter layout than the one it is written in.
        let noncanonical: [&[u8]; 6] = [
            &[0x80, 0x00],             // 0 in two bytes
            &[0x80, 0x7f],             // 127 in two bytes
            &[0xc0, 0x00, 0x00, 0x00], // 0 in four bytes
            &[0xc0, 0x00, 0x00, 0x7f], // 127 in four bytes
            &[0xc0, 0x00, 0x00, 0x80], // 128 in four bytes
            &[0xc0, 0x00, 0x3f, 0xff], // 16383 in four bytes
        ];

        for buf in noncanonical {
            let res = decode_buf_exact::<Varint>(buf);
            assert!(
                matches!(res, Err(CodecError::MalformedField("varint"))),
                "{buf:02x?} must be rejected, got {res:?}"
            );
        }
    }

    #[test]
    fn test_varint_every_accepted_encoding_is_the_one_it_reencodes_to() {
        // Sweep the whole one- and two-byte input space, and the four-byte
        // space at every value that sits on a layout boundary plus a stride
        // through the rest: every byte string either fails to decode as a
        // noncanonical layout or re-encodes to exactly itself.
        fn check(buf: &[u8]) {
            match decode_buf_exact::<Varint>(buf) {
                Ok(v) => assert_eq!(
                    encode_to_vec(&v).unwrap(),
                    buf,
                    "{buf:02x?} is not canonical"
                ),
                Err(CodecError::MalformedField("varint")) => {
                    assert!(
                        v_fits_shorter(buf),
                        "{buf:02x?} was rejected but has no shorter layout"
                    );
                }
                Err(e) => panic!("{buf:02x?}: unexpected error {e:?}"),
            }
        }

        // Does the value spelled by `buf` fit a shorter layout than `buf` uses?
        fn v_fits_shorter(buf: &[u8]) -> bool {
            let value = match buf.len() {
                1 => (buf[0] & 0x7f) as u32,
                2 => u16::from_be_bytes([buf[0] & 0x3f, buf[1]]) as u32,
                4 => u32::from_be_bytes([buf[0] & 0x3f, buf[1], buf[2], buf[3]]),
                _ => unreachable!(),
            };
            Varint::new(value).unwrap().byte_len() < buf.len()
        }

        for b in 0x00u8..=0x7f {
            check(&[b]);
        }
        for w in 0x8000u16..=0xbfff {
            check(&w.to_be_bytes());
        }
        let mut four_byte = vec![0u32, 1, 127, 128, 16383, 16384, 16385, VARINT_MAX];
        four_byte.extend((0..VARINT_MAX).step_by(0x1_0007));
        for value in four_byte {
            check(&(value | 0xc000_0000).to_be_bytes());
        }
    }

    #[test]
    fn test_varint_accepts_shortest_layout_at_each_boundary() {
        // The smallest value of each layout decodes; it has no shorter layout.
        let canonical: [(&[u8], u32); 3] = [
            (&[0x7f], 127),
            (&[0x80, 0x80], 128),
            (&[0xc0, 0x00, 0x40, 0x00], 16384),
        ];

        for (buf, val) in canonical {
            let decoded: Varint = decode_buf_exact(buf).unwrap();
            assert_eq!(decoded.inner(), val, "{buf:02x?}");
            assert_eq!(encode_to_vec(&decoded).unwrap(), buf);
        }
    }
}
