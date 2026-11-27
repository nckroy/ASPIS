// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! X25519 (RFC 7748), the classical half of ASPIS's key exchange (ADR
//! 0003, rule 1; feature `x25519`).
//!
//! A secret key is the caller's 32 octets (ADR 0069, rule 3). RFC 7748,
//! section 5 clamps them when they are used, so every 32 octets are a key.
//! A public key is any 32 octets: the RFC accepts every u-coordinate and
//! masks its top bit, so the only check at decoding is the length (rule
//! 5). The check that matters comes at the exchange: a shared secret of
//! all zeros, which a small-order peer key forces, is refused (RFC 7748,
//! section 6.1; rule 5).

use x25519_dalek::{PublicKey, StaticSecret};

use crate::{Error, SharedSecret};

/// A key's length in octets, secret or public.
pub const KEY_LEN: usize = 32;

/// An X25519 secret key.
///
/// It is a secret: the library clears it on drop, and the type isn't
/// `Clone` and has no equality. Nothing needs to compare secret keys.
pub struct X25519SecretKey(StaticSecret);

impl X25519SecretKey {
    /// The key from 32 octets, which the caller takes from the entropy
    /// service (ADR 0069, rule 3). They are clamped when used (RFC 7748,
    /// section 5, decodeScalar25519).
    pub fn from_seed(seed: &[u8; KEY_LEN]) -> Self {
        Self(StaticSecret::from(*seed))
    }

    /// The public key, X25519(k, 9) (RFC 7748, section 6.1).
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey(PublicKey::from(&self.0).to_bytes())
    }

    /// The shared secret with `peer`, X25519(k, u) (RFC 7748, section 5).
    ///
    /// An all-zero result gives [`Error::NonContributory`]: the peer's key
    /// is of small order, and the exchange must be abandoned (RFC 7748,
    /// section 6.1; ADR 0069, rule 5). The library tests for zero in
    /// constant time.
    pub fn diffie_hellman(&self, peer: &X25519PublicKey) -> Result<SharedSecret, Error> {
        // The library's shared secret clears itself on drop.
        let shared = self.0.diffie_hellman(&PublicKey::from(peer.0));
        if !shared.was_contributory() {
            return Err(Error::NonContributory);
        }
        Ok(SharedSecret::from_bytes(shared.as_bytes()))
    }
}

// The library's key clears itself on drop; this checks that it says so.
const _: () = {
    fn clears<T: zeroize::ZeroizeOnDrop>() {}
    let _ = clears::<StaticSecret>;
};

impl zeroize::ZeroizeOnDrop for X25519SecretKey {}

impl core::fmt::Debug for X25519SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("X25519SecretKey(..)")
    }
}

/// An X25519 public key: a u-coordinate, as 32 octets (RFC 7748, section
/// 5).
#[derive(Clone, PartialEq, Eq)]
pub struct X25519PublicKey([u8; KEY_LEN]);

impl X25519PublicKey {
    /// Decodes a public key. Any length but 32 gives [`Error::Length`].
    /// Every 32 octets are a key (RFC 7748, section 5), and they are kept
    /// as given, so [`Self::to_bytes`] returns them unchanged.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        bytes.try_into().map(Self).map_err(|_| Error::Length)
    }

    /// The key's octets.
    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.0
    }

    /// The key's octets, borrowed.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("X25519PublicKey(32 octets)")
    }
}
