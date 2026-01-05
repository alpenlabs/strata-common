use std::fmt;
use std::str;

/// Length of magic bytes in bytes.
pub const MAGIC_BYTES_LEN: usize = 4;

/// Magic bytes identifier ([`MAGIC_BYTES_LEN`]-byte ASCII string).
///
/// This type wraps a [`MAGIC_BYTES_LEN`]-byte array and provides convenient conversion to/from
/// ASCII strings for readability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MagicBytes([u8; MAGIC_BYTES_LEN]);

impl MagicBytes {
    /// Creates a new `MagicBytes` from a [`MAGIC_BYTES_LEN`]-byte array.
    pub const fn new(bytes: [u8; MAGIC_BYTES_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the magic bytes as a byte slice.
    pub const fn as_bytes(&self) -> &[u8; MAGIC_BYTES_LEN] {
        &self.0
    }

    /// Returns the magic bytes as a string slice if valid ASCII.
    pub fn as_str(&self) -> Option<&str> {
        str::from_utf8(&self.0).ok()
    }

    /// Converts to the inner byte array.
    pub const fn into_inner(self) -> [u8; MAGIC_BYTES_LEN] {
        self.0
    }
}

impl From<[u8; MAGIC_BYTES_LEN]> for MagicBytes {
    fn from(bytes: [u8; MAGIC_BYTES_LEN]) -> Self {
        Self(bytes)
    }
}

impl From<MagicBytes> for [u8; MAGIC_BYTES_LEN] {
    fn from(magic: MagicBytes) -> Self {
        magic.0
    }
}

impl AsRef<[u8]> for MagicBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for MagicBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Some(s) => write!(f, "{}", s),
            None => write!(f, "{:?}", self.0),
        }
    }
}

impl str::FromStr for MagicBytes {
    type Err = InvalidMagicBytes;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != MAGIC_BYTES_LEN {
            return Err(InvalidMagicBytes::InvalidLength);
        }
        if !s.is_ascii() {
            return Err(InvalidMagicBytes::NotAscii);
        }
        let mut bytes = [0u8; MAGIC_BYTES_LEN];
        bytes.copy_from_slice(s.as_bytes());
        Ok(Self(bytes))
    }
}

/// Error type for invalid magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidMagicBytes {
    /// The input string is not exactly [`MAGIC_BYTES_LEN`] bytes long.
    InvalidLength,
    /// The input string contains non-ASCII characters.
    NotAscii,
}

impl fmt::Display for InvalidMagicBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(
                f,
                "magic bytes must be exactly {} characters",
                MAGIC_BYTES_LEN
            ),
            Self::NotAscii => write!(f, "magic bytes must be ASCII"),
        }
    }
}

impl std::error::Error for InvalidMagicBytes {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_str() {
        let magic: MagicBytes = "STRA".parse().unwrap();
        assert_eq!(magic.as_bytes(), b"STRA");
    }

    #[test]
    fn test_from_str_invalid_length() {
        assert!("STR".parse::<MagicBytes>().is_err());
        assert!("STRAT".parse::<MagicBytes>().is_err());
    }

    #[test]
    fn test_from_str_non_ascii() {
        assert!("STR🔥".parse::<MagicBytes>().is_err());
    }

    #[test]
    fn test_display() {
        let magic = MagicBytes::new(*b"STRA");
        assert_eq!(format!("{}", magic), "STRA");
    }

    #[test]
    fn test_conversions() {
        let bytes = [b'S', b'T', b'R', b'A'];
        let magic: MagicBytes = bytes.into();
        let back: [u8; 4] = magic.into();
        assert_eq!(bytes, back);
    }
}
