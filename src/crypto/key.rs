// SPDX-License-Identifier: CC0-1.0

//! Bitcoin keys.
//!
//! This module provides keys used in Bitcoin that can be roundtrip
//! (de)serialized.

use core::fmt;

use hashes::hash160;
use internals::write_err;

use crate::base58;

/// An opaque return type for PublicKey::to_sort_key
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct SortKey(u8, [u8; 32], [u8; 32]);

hashes::hash_newtype! {
    /// A hash of a public key.
    pub struct PubkeyHash(hash160::Hash);
    /// SegWit version of a public key hash.
    pub struct WPubkeyHash(hash160::Hash);
}
crate::hash_types::impl_asref_push_bytes!(PubkeyHash, WPubkeyHash);

/// A key-related error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A base58 error.
    Base58(base58::Error),
    /// Invalid key prefix error.
    InvalidKeyPrefix(u8),
    /// Hex decoding error.
    Hex(hex::HexToArrayError),
    /// `PublicKey` hex should be 66 or 130 digits long.
    InvalidHexLength(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            Base58(ref e) => write_err!(f, "base58"; e),
            InvalidKeyPrefix(ref b) => write!(f, "key prefix invalid: {}", b),
            Hex(ref e) => write_err!(f, "hex"; e),
            InvalidHexLength(got) => write!(
                f,
                "pubkey hex should be 66 or 130 digits long, got: {}",
                got
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            Base58(ref e) => Some(e),
            Secp256k1(ref e) => Some(e),
            Hex(ref e) => Some(e),
            InvalidKeyPrefix(_) | InvalidHexLength(_) => None,
        }
    }
}

impl From<base58::Error> for Error {
    fn from(e: base58::Error) -> Error {
        Error::Base58(e)
    }
}

impl From<hex::HexToArrayError> for Error {
    fn from(e: hex::HexToArrayError) -> Self {
        Error::Hex(e)
    }
}
