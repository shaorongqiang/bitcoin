// SPDX-License-Identifier: CC0-1.0

//! Bitcoin taproot keys.
//!
//! This module provides taproot keys used in Bitcoin (including reexporting secp256k1 keys).
//!

use core::fmt;

use internals::write_err;

use crate::sighash::InvalidSighashTypeError;

/// An error constructing a [`taproot::Signature`] from a byte slice.
///
/// [`taproot::Signature`]: crate::crypto::taproot::Signature
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigFromSliceError {
    /// Invalid signature hash type.
    SighashType(InvalidSighashTypeError),
    /// Invalid taproot signature size
    InvalidSignatureSize(usize),
}

impl fmt::Display for SigFromSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use SigFromSliceError::*;

        match *self {
            SighashType(ref e) => write_err!(f, "sighash"; e),
            InvalidSignatureSize(sz) => write!(f, "invalid taproot signature size: {}", sz),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SigFromSliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use SigFromSliceError::*;

        match *self {
            Secp256k1(ref e) => Some(e),
            SighashType(ref e) => Some(e),
            InvalidSignatureSize(_) => None,
        }
    }
}

impl From<InvalidSighashTypeError> for SigFromSliceError {
    fn from(err: InvalidSighashTypeError) -> Self {
        Self::SighashType(err)
    }
}
