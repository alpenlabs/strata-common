use std::fmt;

/// Magic bytes identifier (4-byte ASCII string).
///
/// This type wraps a 4-byte array and provides convenient conversion to/from
/// ASCII strings for readability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MagicBytes([u8; 4]);

impl MagicBytes {
    /// Creates a new `MagicBytes` from a 4-byte array.
    pub const fn new(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    /// Creates a new `MagicBytes` from a 4-character ASCII string.
    ///
    /// Returns `None` if the input is not exactly 4 ASCII characters.
    pub fn from_str(s: &str) -> Option<Self> {
        if s.len() != 4 || !s.is_ascii() {
            return None;
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(s.as_bytes());
        Some(Self(bytes))
    }

    /// Returns the magic bytes as a byte slice.
    pub const fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    /// Returns the magic bytes as a string slice if valid ASCII.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// Converts to the inner byte array.
    pub const fn into_inner(self) -> [u8; 4] {
        self.0
    }
}

impl From<[u8; 4]> for MagicBytes {
    fn from(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }
}

impl From<MagicBytes> for [u8; 4] {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_str() {
        let magic = MagicBytes::from_str("STRA").unwrap();
        assert_eq!(magic.as_bytes(), b"STRA");
    }

    #[test]
    fn test_from_str_invalid_length() {
        assert!(MagicBytes::from_str("STR").is_none());
        assert!(MagicBytes::from_str("STRAT").is_none());
    }

    #[test]
    fn test_from_str_non_ascii() {
        assert!(MagicBytes::from_str("STR🔥").is_none());
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
