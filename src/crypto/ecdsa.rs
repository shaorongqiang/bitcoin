// SPDX-License-Identifier: CC0-1.0

//! ECDSA Bitcoin signatures.
//!
//! This module provides ECDSA signatures used Bitcoin that can be roundtrip (de)serialized.

use core::fmt;

use internals::write_err;

use crate::prelude::*;
use crate::script::PushBytes;
use crate::sighash::NonStandardSighashTypeError;

const MAX_SIG_LEN: usize = 73;

/// Holds signature serialized in-line (not in `Vec`).
///
/// This avoids allocation and allows proving maximum size of the signature (73 bytes).
/// The type can be used largely as a byte slice. It implements all standard traits one would
/// expect and has familiar methods.
/// However, the usual use case is to push it into a script. This can be done directly passing it
/// into [`push_slice`](crate::script::ScriptBuf::push_slice).
#[derive(Copy, Clone)]
pub struct SerializedSignature {
    data: [u8; MAX_SIG_LEN],
    len: usize,
}

impl SerializedSignature {
    /// Returns an iterator over bytes of the signature.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, u8> {
        self.into_iter()
    }
}

impl core::ops::Deref for SerializedSignature {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.data[..self.len]
    }
}

impl core::ops::DerefMut for SerializedSignature {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data[..self.len]
    }
}

impl AsRef<[u8]> for SerializedSignature {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl AsMut<[u8]> for SerializedSignature {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self
    }
}

impl AsRef<PushBytes> for SerializedSignature {
    #[inline]
    fn as_ref(&self) -> &PushBytes {
        &<&PushBytes>::from(&self.data)[..self.len()]
    }
}

impl core::borrow::Borrow<[u8]> for SerializedSignature {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self
    }
}

impl core::borrow::BorrowMut<[u8]> for SerializedSignature {
    #[inline]
    fn borrow_mut(&mut self) -> &mut [u8] {
        self
    }
}

impl fmt::Debug for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl fmt::LowerHex for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&(**self).as_hex(), f)
    }
}

impl fmt::UpperHex for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&(**self).as_hex(), f)
    }
}

impl PartialEq for SerializedSignature {
    #[inline]
    fn eq(&self, other: &SerializedSignature) -> bool {
        **self == **other
    }
}

impl Eq for SerializedSignature {}

impl core::hash::Hash for SerializedSignature {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::hash::Hash::hash(&**self, state)
    }
}

impl<'a> IntoIterator for &'a SerializedSignature {
    type IntoIter = core::slice::Iter<'a, u8>;
    type Item = &'a u8;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        (*self).iter()
    }
}

/// An ECDSA signature-related error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Hex decoding error.
    Hex(hex::HexToBytesError),
    /// Non-standard sighash type.
    SighashType(NonStandardSighashTypeError),
    /// Signature was empty.
    EmptySignature,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            Hex(ref e) => write_err!(f, "signature hex decoding error"; e),
            SighashType(ref e) => write_err!(f, "non-standard signature hash type"; e),
            EmptySignature => write!(f, "empty ECDSA signature"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            Hex(ref e) => Some(e),
            Secp256k1(ref e) => Some(e),
            SighashType(ref e) => Some(e),
            EmptySignature => None,
        }
    }
}

impl From<NonStandardSighashTypeError> for Error {
    fn from(err: NonStandardSighashTypeError) -> Self {
        Error::SighashType(err)
    }
}

impl From<hex::HexToBytesError> for Error {
    fn from(err: hex::HexToBytesError) -> Self {
        Error::Hex(err)
    }
}
