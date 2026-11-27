// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Secret octets: cleared on drop, compared in constant time, and never
//! printed (ADR 0069, rule 5).

use core::fmt;

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 32-octet shared secret: the output of X25519 and of ML-KEM-768's
/// encapsulation and decapsulation.
///
/// It is cleared on drop, compared in constant time, and its `Debug`
/// prints `..` in place of its octets. It is neither `Clone` nor `Copy`.
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// Wraps 32 octets the caller already holds as a shared secret.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(*bytes)
    }

    /// The secret's octets.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SharedSecret {}

impl ConstantTimeEq for SharedSecret {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[..].ct_eq(&other.0[..])
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SharedSecret {}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret(..)")
    }
}

/// `N` secret octets, for the crate's own key types: HKDF's pseudorandom
/// keys, the seeds the key types keep, such as ML-KEM-768's d ‖ z, and
/// the 64-octet secret of the hybrid key exchange.
///
/// It has the same guarantees as [`SharedSecret`]. The types that hold one
/// give it their own name in `Debug`.
#[cfg(any(feature = "sha2", feature = "ml-kem"))]
pub(crate) struct Secret<const N: usize>([u8; N]);

#[cfg(any(feature = "sha2", feature = "ml-kem"))]
impl<const N: usize> Secret<N> {
    /// Copies `bytes` in.
    pub(crate) fn new(bytes: &[u8; N]) -> Self {
        Self(*bytes)
    }

    /// Copies `bytes` in, which must be `N` octets long. The library's
    /// outputs come as slices; the caller clears its copy.
    #[cfg(feature = "sha2")]
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        let mut s = Self([0; N]);
        s.0.copy_from_slice(bytes);
        s
    }

    pub(crate) fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

#[cfg(any(feature = "sha2", feature = "ml-kem"))]
impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(any(feature = "sha2", feature = "ml-kem"))]
impl<const N: usize> ZeroizeOnDrop for Secret<N> {}

#[cfg(any(feature = "sha2", feature = "ml-kem"))]
impl<const N: usize> ConstantTimeEq for Secret<N> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[..].ct_eq(&other.0[..])
    }
}

/// Implements the secret-type traits for a newtype over [`Secret`]:
/// `ZeroizeOnDrop` (the field clears itself), `ConstantTimeEq`, `PartialEq`
/// and `Eq` through it, and a `Debug` that prints only the type's name.
#[cfg(any(feature = "sha2", feature = "hybrid"))]
macro_rules! secret_newtype {
    ($name:ident) => {
        impl zeroize::ZeroizeOnDrop for $name {}

        impl subtle::ConstantTimeEq for $name {
            fn ct_eq(&self, other: &Self) -> subtle::Choice {
                subtle::ConstantTimeEq::ct_eq(&self.0, &other.0)
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                subtle::ConstantTimeEq::ct_eq(self, other).into()
            }
        }

        impl Eq for $name {}

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

#[cfg(any(feature = "sha2", feature = "hybrid"))]
pub(crate) use secret_newtype;
