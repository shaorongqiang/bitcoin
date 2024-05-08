// SPDX-License-Identifier: CC0-1.0

//! BIP32 implementation.
//!
//! Implementation of BIP32 hierarchical deterministic wallets, as defined
//! at <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>.
//!

#![allow(deprecated)] // Remove once we remove XpubIdentifier.

use core::convert::TryInto;
use core::default::Default;
use core::ops::Index;
use core::str::FromStr;
use core::{fmt, slice};

use hashes::{hash160, hash_newtype, sha512, Hash, HashEngine, Hmac, HmacEngine};
use internals::{impl_array_newtype, write_err};
#[cfg(feature = "serde")]
use serde;

use crate::base58;
use crate::internal_macros::impl_bytes_newtype;
use crate::io::Write;
use crate::network::Network;
use crate::prelude::*;

/// Version bytes for extended public keys on the Bitcoin network.
const VERSION_BYTES_MAINNET_PUBLIC: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
/// Version bytes for extended private keys on the Bitcoin network.
const VERSION_BYTES_MAINNET_PRIVATE: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];
/// Version bytes for extended public keys on any of the testnet networks.
const VERSION_BYTES_TESTNETS_PUBLIC: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];
/// Version bytes for extended private keys on any of the testnet networks.
const VERSION_BYTES_TESTNETS_PRIVATE: [u8; 4] = [0x04, 0x35, 0x83, 0x94];

/// A chain code
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainCode([u8; 32]);
impl_array_newtype!(ChainCode, u8, 32);
impl_bytes_newtype!(ChainCode, 32);

impl ChainCode {
    fn from_hmac(hmac: Hmac<sha512::Hash>) -> Self {
        hmac[32..]
            .try_into()
            .expect("half of hmac is guaranteed to be 32 bytes")
    }
}

/// A fingerprint
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Fingerprint([u8; 4]);
impl_array_newtype!(Fingerprint, u8, 4);
impl_bytes_newtype!(Fingerprint, 4);

hash_newtype! {
    /// XpubIdentifier as defined in BIP-32.
    #[deprecated(since = "0.0.0-NEXT-RELEASE", note = "use XKeyIdentifier instead")]
    pub struct XpubIdentifier(hash160::Hash);

    /// Extended key identifier as defined in BIP-32.
    pub struct XKeyIdentifier(hash160::Hash);
}

/// A child number for a derived key
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub enum ChildNumber {
    /// Non-hardened key
    Normal {
        /// Key index, within [0, 2^31 - 1]
        index: u32,
    },
    /// Hardened key
    Hardened {
        /// Key index, within [0, 2^31 - 1]
        index: u32,
    },
}

impl ChildNumber {
    /// Create a [`Normal`] from an index, returns an error if the index is not within
    /// [0, 2^31 - 1].
    ///
    /// [`Normal`]: #variant.Normal
    pub fn from_normal_idx(index: u32) -> Result<Self, Error> {
        if index & (1 << 31) == 0 {
            Ok(ChildNumber::Normal { index })
        } else {
            Err(Error::InvalidChildNumber(index))
        }
    }

    /// Create a [`Hardened`] from an index, returns an error if the index is not within
    /// [0, 2^31 - 1].
    ///
    /// [`Hardened`]: #variant.Hardened
    pub fn from_hardened_idx(index: u32) -> Result<Self, Error> {
        if index & (1 << 31) == 0 {
            Ok(ChildNumber::Hardened { index })
        } else {
            Err(Error::InvalidChildNumber(index))
        }
    }

    /// Returns `true` if the child number is a [`Normal`] value.
    ///
    /// [`Normal`]: #variant.Normal
    pub fn is_normal(&self) -> bool {
        !self.is_hardened()
    }

    /// Returns `true` if the child number is a [`Hardened`] value.
    ///
    /// [`Hardened`]: #variant.Hardened
    pub fn is_hardened(&self) -> bool {
        match self {
            ChildNumber::Hardened { .. } => true,
            ChildNumber::Normal { .. } => false,
        }
    }

    /// Returns the child number that is a single increment from this one.
    pub fn increment(self) -> Result<ChildNumber, Error> {
        match self {
            ChildNumber::Normal { index: idx } => ChildNumber::from_normal_idx(idx + 1),
            ChildNumber::Hardened { index: idx } => ChildNumber::from_hardened_idx(idx + 1),
        }
    }
}

impl From<u32> for ChildNumber {
    fn from(number: u32) -> Self {
        if number & (1 << 31) != 0 {
            ChildNumber::Hardened {
                index: number ^ (1 << 31),
            }
        } else {
            ChildNumber::Normal { index: number }
        }
    }
}

impl From<ChildNumber> for u32 {
    fn from(cnum: ChildNumber) -> Self {
        match cnum {
            ChildNumber::Normal { index } => index,
            ChildNumber::Hardened { index } => index | (1 << 31),
        }
    }
}

impl fmt::Display for ChildNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ChildNumber::Hardened { index } => {
                fmt::Display::fmt(&index, f)?;
                let alt = f.alternate();
                f.write_str(if alt { "h" } else { "'" })
            }
            ChildNumber::Normal { index } => fmt::Display::fmt(&index, f),
        }
    }
}

impl FromStr for ChildNumber {
    type Err = Error;

    fn from_str(inp: &str) -> Result<ChildNumber, Error> {
        let is_hardened = inp.chars().last().map_or(false, |l| l == '\'' || l == 'h');
        Ok(if is_hardened {
            ChildNumber::from_hardened_idx(
                inp[0..inp.len() - 1]
                    .parse()
                    .map_err(|_| Error::InvalidChildNumberFormat)?,
            )?
        } else {
            ChildNumber::from_normal_idx(inp.parse().map_err(|_| Error::InvalidChildNumberFormat)?)?
        })
    }
}

impl AsRef<[ChildNumber]> for ChildNumber {
    fn as_ref(&self) -> &[ChildNumber] {
        slice::from_ref(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ChildNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        u32::deserialize(deserializer).map(ChildNumber::from)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ChildNumber {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        u32::from(*self).serialize(serializer)
    }
}

/// Trait that allows possibly failable conversion from a type into a
/// derivation path
pub trait IntoDerivationPath {
    /// Convers a given type into a [`DerivationPath`] with possible error
    fn into_derivation_path(self) -> Result<DerivationPath, Error>;
}

/// A BIP-32 derivation path.
#[derive(Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct DerivationPath(Vec<ChildNumber>);

#[cfg(feature = "serde")]
crate::serde_utils::serde_string_impl!(DerivationPath, "a BIP-32 derivation path");

impl<I> Index<I> for DerivationPath
where
    Vec<ChildNumber>: Index<I>,
{
    type Output = <Vec<ChildNumber> as Index<I>>::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        &self.0[index]
    }
}

impl Default for DerivationPath {
    fn default() -> DerivationPath {
        DerivationPath::master()
    }
}

impl<T> IntoDerivationPath for T
where
    T: Into<DerivationPath>,
{
    fn into_derivation_path(self) -> Result<DerivationPath, Error> {
        Ok(self.into())
    }
}

impl IntoDerivationPath for String {
    fn into_derivation_path(self) -> Result<DerivationPath, Error> {
        self.parse()
    }
}

impl<'a> IntoDerivationPath for &'a str {
    fn into_derivation_path(self) -> Result<DerivationPath, Error> {
        self.parse()
    }
}

impl From<Vec<ChildNumber>> for DerivationPath {
    fn from(numbers: Vec<ChildNumber>) -> Self {
        DerivationPath(numbers)
    }
}

impl From<DerivationPath> for Vec<ChildNumber> {
    fn from(path: DerivationPath) -> Self {
        path.0
    }
}

impl<'a> From<&'a [ChildNumber]> for DerivationPath {
    fn from(numbers: &'a [ChildNumber]) -> Self {
        DerivationPath(numbers.to_vec())
    }
}

impl core::iter::FromIterator<ChildNumber> for DerivationPath {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = ChildNumber>,
    {
        DerivationPath(Vec::from_iter(iter))
    }
}

impl<'a> core::iter::IntoIterator for &'a DerivationPath {
    type Item = &'a ChildNumber;
    type IntoIter = slice::Iter<'a, ChildNumber>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl AsRef<[ChildNumber]> for DerivationPath {
    fn as_ref(&self) -> &[ChildNumber] {
        &self.0
    }
}

impl FromStr for DerivationPath {
    type Err = Error;

    fn from_str(path: &str) -> Result<DerivationPath, Error> {
        let mut parts = path.split('/');
        // First parts must be `m`.
        if parts.next().unwrap() != "m" {
            return Err(Error::InvalidDerivationPathFormat);
        }

        let ret: Result<Vec<ChildNumber>, Error> = parts.map(str::parse).collect();
        Ok(DerivationPath(ret?))
    }
}

/// An iterator over children of a [DerivationPath].
///
/// It is returned by the methods [DerivationPath::children_from],
/// [DerivationPath::normal_children] and [DerivationPath::hardened_children].
pub struct DerivationPathIterator<'a> {
    base: &'a DerivationPath,
    next_child: Option<ChildNumber>,
}

impl<'a> DerivationPathIterator<'a> {
    /// Start a new [DerivationPathIterator] at the given child.
    pub fn start_from(path: &'a DerivationPath, start: ChildNumber) -> DerivationPathIterator<'a> {
        DerivationPathIterator {
            base: path,
            next_child: Some(start),
        }
    }
}

impl<'a> Iterator for DerivationPathIterator<'a> {
    type Item = DerivationPath;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = self.next_child?;
        self.next_child = ret.increment().ok();
        Some(self.base.child(ret))
    }
}

impl DerivationPath {
    /// Returns length of the derivation path
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the derivation path is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns derivation path for a master key (i.e. empty derivation path)
    pub fn master() -> DerivationPath {
        DerivationPath(vec![])
    }

    /// Returns whether derivation path represents master key (i.e. it's length
    /// is empty). True for `m` path.
    pub fn is_master(&self) -> bool {
        self.0.is_empty()
    }

    /// Create a new [DerivationPath] that is a child of this one.
    pub fn child(&self, cn: ChildNumber) -> DerivationPath {
        let mut path = self.0.clone();
        path.push(cn);
        DerivationPath(path)
    }

    /// Convert into a [DerivationPath] that is a child of this one.
    pub fn into_child(self, cn: ChildNumber) -> DerivationPath {
        let mut path = self.0;
        path.push(cn);
        DerivationPath(path)
    }

    /// Get an [Iterator] over the children of this [DerivationPath]
    /// starting with the given [ChildNumber].
    pub fn children_from(&self, cn: ChildNumber) -> DerivationPathIterator {
        DerivationPathIterator::start_from(self, cn)
    }

    /// Get an [Iterator] over the unhardened children of this [DerivationPath].
    pub fn normal_children(&self) -> DerivationPathIterator {
        DerivationPathIterator::start_from(self, ChildNumber::Normal { index: 0 })
    }

    /// Get an [Iterator] over the hardened children of this [DerivationPath].
    pub fn hardened_children(&self) -> DerivationPathIterator {
        DerivationPathIterator::start_from(self, ChildNumber::Hardened { index: 0 })
    }

    /// Concatenate `self` with `path` and return the resulting new path.
    ///
    /// ```
    /// use bitcoin::bip32::{DerivationPath, ChildNumber};
    /// use std::str::FromStr;
    ///
    /// let base = DerivationPath::from_str("m/42").unwrap();
    ///
    /// let deriv_1 = base.extend(DerivationPath::from_str("m/0/1").unwrap());
    /// let deriv_2 = base.extend(&[
    ///     ChildNumber::from_normal_idx(0).unwrap(),
    ///     ChildNumber::from_normal_idx(1).unwrap()
    /// ]);
    ///
    /// assert_eq!(deriv_1, deriv_2);
    /// ```
    pub fn extend<T: AsRef<[ChildNumber]>>(&self, path: T) -> DerivationPath {
        let mut new_path = self.clone();
        new_path.0.extend_from_slice(path.as_ref());
        new_path
    }

    /// Returns the derivation path as a vector of u32 integers.
    /// Unhardened elements are copied as is.
    /// 0x80000000 is added to the hardened elements.
    ///
    /// ```
    /// use bitcoin::bip32::DerivationPath;
    /// use std::str::FromStr;
    ///
    /// let path = DerivationPath::from_str("m/84'/0'/0'/0/1").unwrap();
    /// const HARDENED: u32 = 0x80000000;
    /// assert_eq!(path.to_u32_vec(), vec![84 + HARDENED, HARDENED, HARDENED, 0, 1]);
    /// ```
    pub fn to_u32_vec(&self) -> Vec<u32> {
        self.into_iter().map(|&el| el.into()).collect()
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("m")?;
        for cn in self.0.iter() {
            f.write_str("/")?;
            fmt::Display::fmt(cn, f)?;
        }
        Ok(())
    }
}

impl fmt::Debug for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

/// Full information on the used extended public key: fingerprint of the
/// master extended public key and a derivation path from it.
pub type KeySource = (Fingerprint, DerivationPath);

/// A BIP32 error
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A pk->pk derivation was attempted on a hardened key
    CannotDeriveFromHardenedKey,
    /// A child number was provided that was out of range
    InvalidChildNumber(u32),
    /// Invalid childnumber format.
    InvalidChildNumberFormat,
    /// Invalid derivation path format.
    InvalidDerivationPathFormat,
    /// Unknown version magic bytes
    UnknownVersion([u8; 4]),
    /// Encoded extended key data has wrong length
    WrongExtendedKeyLength(usize),
    /// Base58 encoding error
    Base58(base58::Error),
    /// Hexadecimal decoding error
    Hex(hex::HexToArrayError),
    /// `PublicKey` hex should be 66 or 130 digits long.
    InvalidPublicKeyHexLength(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            CannotDeriveFromHardenedKey => {
                f.write_str("cannot derive hardened key from public key")
            }
            InvalidChildNumber(ref n) => write!(
                f,
                "child number {} is invalid (not within [0, 2^31 - 1])",
                n
            ),
            InvalidChildNumberFormat => f.write_str("invalid child number format"),
            InvalidDerivationPathFormat => f.write_str("invalid derivation path format"),
            UnknownVersion(ref bytes) => write!(f, "unknown version magic bytes: {:?}", bytes),
            WrongExtendedKeyLength(ref len) => {
                write!(f, "encoded extended key data has wrong length {}", len)
            }
            Base58(ref e) => write_err!(f, "base58 encoding error"; e),
            Hex(ref e) => write_err!(f, "Hexadecimal decoding error"; e),
            InvalidPublicKeyHexLength(got) => write!(
                f,
                "PublicKey hex should be 66 or 130 digits long, got: {}",
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
            Secp256k1(ref e) => Some(e),
            Base58(ref e) => Some(e),
            Hex(ref e) => Some(e),
            CannotDeriveFromHardenedKey
            | InvalidChildNumber(_)
            | InvalidChildNumberFormat
            | InvalidDerivationPathFormat
            | UnknownVersion(_)
            | WrongExtendedKeyLength(_)
            | InvalidPublicKeyHexLength(_) => None,
        }
    }
}

impl From<base58::Error> for Error {
    fn from(err: base58::Error) -> Self {
        Error::Base58(err)
    }
}
