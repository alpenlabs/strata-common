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
#[derive(Debug, Error)]
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
    if buf.len() < 1 {
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
