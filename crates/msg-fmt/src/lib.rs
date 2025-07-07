//! Implements the generic Strata typed message format.
//!
//! This is intended to be used in various subcomponents within the Strata
//! proctocol.

use thiserror::Error;

/// The maximum type representable.
pub const MAX_TYPE: TypeId = 0x7fff;

/// Alias for type IDs.
///
/// This exists in case we decide to change it later.
pub type TypeId = u16;

/// Error types from parsing messages.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Error)]
pub enum Error {
    /// Type provided is out of bounds.
    #[error("invalid type (ty {0})")]
    TypeOutOfBounds(TypeId),

    /// Message provided is empty.
    #[error("empty buffer")]
    BufEmpty,

    /// Message buffer too short.
    #[error("buffer too short")]
    BufTooShort,

    /// Buffer type prefix had nonminimal encoding.
    #[error("nonminimal type encoding (ty {0})")]
    NonminimalEncoding(TypeId),
}

/// A formatted message.
pub trait Msg {
    /// Gets the type.
    fn ty(&self) -> TypeId;

    /// Gets a slice of the body.
    fn body(&self) -> &[u8];

    /// Encodes the message into a vec.
    fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Surely there's a better way to represent copying from our body.
        encode_into_buf_unchecked(self.ty(), self.body().iter().copied(), &mut buf);
        buf
    }
}

/// Parsed formatted message.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct MsgRef<'b> {
    ty: TypeId,
    body: &'b [u8],
}

impl<'b> MsgRef<'b> {
    /// Constructs a new instance from type and body.
    ///
    /// Checks that the type is in-bounds.
    pub fn new(ty: TypeId, body: &'b [u8]) -> Result<Self, Error> {
        check_type(ty)?;
        Ok(Self { ty, body })
    }

    /// Converts to a [`OwnedMsg`].
    pub fn to_owned(&self) -> OwnedMsg {
        OwnedMsg {
            ty: self.ty,
            body: self.body.to_vec(),
        }
    }
}

impl<'b> TryFrom<&'b [u8]> for MsgRef<'b> {
    type Error = Error;

    fn try_from(value: &'b [u8]) -> Result<Self, Self::Error> {
        let (ty, body) = try_decode_msg(value)?;
        Ok(Self { ty, body })
    }
}

impl<'b> Msg for MsgRef<'b> {
    fn ty(&self) -> TypeId {
        self.ty
    }

    fn body(&self) -> &[u8] {
        self.body
    }
}

/// Parsed formatted message.  Owns its contents.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct OwnedMsg {
    ty: TypeId,
    body: Vec<u8>,
}

impl OwnedMsg {
    /// Constructs a new instance from type and body.
    ///
    /// Checks that the type is in-bounds.
    pub fn new(ty: TypeId, body: Vec<u8>) -> Result<Self, Error> {
        check_type(ty)?;
        Ok(Self { ty, body })
    }

    /// Returns a [`MsgRef`] instance, borrowing the body of this message
    /// instance.
    // Is there a way to do this with like `AsRef`?
    pub fn as_borrowed(&self) -> MsgRef<'_> {
        MsgRef {
            ty: self.ty,
            body: &self.body,
        }
    }
}

impl<'b> TryFrom<&'b [u8]> for OwnedMsg {
    type Error = Error;

    fn try_from(value: &'b [u8]) -> Result<Self, Self::Error> {
        let (ty, body) = try_decode_msg(value)?;
        Ok(Self {
            ty,
            body: body.to_vec(),
        })
    }
}

impl Msg for OwnedMsg {
    fn ty(&self) -> TypeId {
        self.ty
    }

    fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Checks that a type is in-bounds.
pub fn check_type(ty: TypeId) -> Result<(), Error> {
    if ty > MAX_TYPE {
        return Err(Error::TypeOutOfBounds(ty));
    }

    Ok(())
}

/// Tries to decode a message from a buffer.
///
/// Prefer [`Msg`] or [`OwnedMsg`].
fn try_decode_msg(buf: &[u8]) -> Result<(TypeId, &[u8]), Error> {
    if buf.is_empty() {
        return Err(Error::BufEmpty);
    }

    let i = buf[0] as u16;
    if i & 0x80 == 0 {
        Ok((i, &buf[1..]))
    } else {
        if buf.len() < 2 {
            return Err(Error::BufTooShort);
        }

        let j = buf[1] as u16;
        let ty = ((i & 0x7f) << 8) | j;

        if ty < 0x80 {
            return Err(Error::NonminimalEncoding(ty));
        }

        Ok((ty, &buf[2..]))
    }
}

/// Tries to decode a message into a vec from parts.
pub fn try_encode_into_buf(
    ty: TypeId,
    body: impl IntoIterator<Item = u8>,
    into: &mut Vec<u8>,
) -> Result<(), Error> {
    check_type(ty)?;
    encode_into_buf_unchecked(ty, body, into);
    Ok(())
}

fn encode_into_buf_unchecked(ty: TypeId, body: impl IntoIterator<Item = u8>, into: &mut Vec<u8>) {
    if ty < 0x80 {
        into.push(ty as u8);
    } else {
        let i = (ty >> 8) | 0x80;
        let j = ty & 0xff;
        into.push(i as u8);
        into.push(j as u8);
    }

    into.extend(body);
}

#[cfg(test)]
mod tests {
    use crate::{Error, Msg, MsgRef, OwnedMsg};

    #[test]
    fn test_vectors() {
        const TESTS: &[(u16, &[u8], &[u8])] = &[
            (0, "hello".as_bytes(), &[0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f]),
            (1, &[], &[0x01]),
            (0x7f, &[0x00, 0xff], &[0x7f, 0x00, 0xff]),
            (0x80, "abc".as_bytes(), &[0x80, 0x80, 0x61, 0x62, 0x63]),
            (0x1234, "xyz".as_bytes(), &[0x92, 0x34, 0x78, 0x79, 0x7a]),
            (0x7fff, &[0x10, 0x20], &[0xff, 0xff, 0x10, 0x20]),
        ];

        for (ty, body, exp_enc) in TESTS {
            eprintln!("trying type ID {ty}");

            // Encode from ref.
            let buf_ref = MsgRef::new(*ty, body).expect("test: type in bounds");
            assert_eq!(buf_ref.to_vec(), exp_enc.to_vec());

            // Encode from owned.
            let buf_owned = OwnedMsg::new(*ty, body.to_vec()).expect("test: type in bounds");
            assert_eq!(buf_owned.to_vec(), exp_enc.to_vec());

            // Decode from ref.
            let m_ref = MsgRef::try_from(*exp_enc).expect("test: parse test vector");
            assert_eq!(m_ref.ty(), *ty);
            assert_eq!(m_ref.body(), *body);

            // Decode from owned.
            let m_owned = OwnedMsg::try_from(*exp_enc).expect("test: parse test vector");
            assert_eq!(m_owned.ty(), *ty);
            assert_eq!(m_owned.body(), *body);
        }
    }

    #[test]
    fn test_decode_errors() {
        const TESTS: &[(&[u8], Error)] = &[
            (&[], Error::BufEmpty),
            (&[0x80], Error::BufTooShort),
            (&[0x80, 0x00], Error::NonminimalEncoding(0)),
            (&[0x80, 0x7f], Error::NonminimalEncoding(0x7f)),
        ];

        for (buf, exp_err) in TESTS {
            let m1 = OwnedMsg::try_from(*buf);
            assert_eq!(m1, Err(*exp_err));
        }
    }
}
