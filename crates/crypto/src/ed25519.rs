// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Ed25519 (RFC 8032), verified strictly (feature `ed25519`).
//!
//! ASPIS's own signatures are the composite of ADR 0020, rule 2, whose
//! components are never used alone. So this module gives out only what
//! verifying a standalone Ed25519 signature needs: C28 verifies outside
//! certificates with it, and C37 outside JWTs (`alg` "Ed25519"). Signing
//! is crate-private, for the composite and the known-answer tests.
//!
//! Decoding and verification refuse every malleable or weak form (ADR
//! 0069, rule 5):
//!
//! - a public key must be the canonical encoding of a curve point (RFC
//!   8032, section 5.1.3), and not of small order;
//! - a signature's R must be a canonical point encoding, and its s must be
//!   below the group order ℓ (RFC 8032, section 5.1.7);
//! - verification is the library's strict mode, which also refuses a
//!   small-order R.
//!
//! The library on its own decodes keys by ZIP-215's rules, which accept
//! non-canonical encodings, so the canonical checks are made here with
//! curve25519-dalek.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::Signer;

use crate::{COMPOSITE_PREFIX, Error};

/// A public key's length in octets.
pub const PUBLIC_KEY_LEN: usize = 32;
/// A signature's length in octets.
pub const SIGNATURE_LEN: usize = 64;
/// A seed's length in octets: the private key of RFC 8032, section 5.1.5.
pub const SEED_LEN: usize = 32;

/// Decompresses `bytes` as a point only if they are its canonical
/// encoding: y below p, and no sign bit on x = 0 (RFC 8032, section
/// 5.1.3). Re-compressing the point gives the canonical form, so any other
/// form differs from it.
fn canonical_point(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    let compressed = CompressedEdwardsY(*bytes);
    let point = compressed.decompress()?;
    (point.compress() == compressed).then_some(point)
}

/// An Ed25519 signing key, from its 32-octet seed (RFC 8032, section
/// 5.1.5). Signing is deterministic, as pure Ed25519 is.
///
/// It is crate-private: only the composite signs with Ed25519 (ADR 0020,
/// rule 2; RFC 10073, section 3.1, which forbids using component keys
/// alone). The library clears the seed on drop.
pub(crate) struct Ed25519SigningKey(ed25519_dalek::SigningKey);

impl Ed25519SigningKey {
    /// The key from its seed, which the caller takes from the entropy
    /// service (ADR 0069, rule 3).
    pub(crate) fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// The public key.
    pub(crate) fn verifying_key(&self) -> Ed25519VerifyingKey {
        Ed25519VerifyingKey(self.0.verifying_key())
    }

    /// Signs `msg` (RFC 8032, section 5.1.6).
    pub(crate) fn sign(&self, msg: &[u8]) -> Ed25519Signature {
        Ed25519Signature(self.0.sign(msg).to_bytes())
    }
}

// The library's key clears its seed on drop; this checks that it says so.
const _: () = {
    fn clears<T: zeroize::ZeroizeOnDrop>() {}
    let _ = clears::<ed25519_dalek::SigningKey>;
};

impl zeroize::ZeroizeOnDrop for Ed25519SigningKey {}

impl core::fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ed25519SigningKey(..)")
    }
}

/// An Ed25519 public key: the canonical encoding of a point that isn't of
/// small order.
#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519VerifyingKey(ed25519_dalek::VerifyingKey);

impl Ed25519VerifyingKey {
    /// Decodes a public key (ADR 0069, rule 5):
    ///
    /// - a length other than 32 gives [`Error::Length`];
    /// - octets that aren't a point's canonical encoding give
    ///   [`Error::Encoding`];
    /// - a point of small order gives [`Error::WeakKey`].
    ///
    /// An accepted key's [`Self::to_bytes`] returns the input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; PUBLIC_KEY_LEN] = bytes.try_into().map_err(|_| Error::Length)?;
        let point = canonical_point(bytes).ok_or(Error::Encoding)?;
        if point.is_small_order() {
            return Err(Error::WeakKey);
        }
        // The library decompresses again; it can't fail where ours didn't.
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| Error::Encoding)
    }

    /// The key's octets.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Verifies `sig` over `msg`, strictly. A signature that doesn't
    /// verify gives [`Error::Verification`].
    ///
    /// A message that starts with the composite's prefix is refused too:
    /// it can only be the message representative of an RFC 10073
    /// composite, whose Ed25519 half must not verify alone (RFC 10073,
    /// section 9.4; ADR 0020, rule 2). The guard refuses no certificate,
    /// whose DER starts with 0x30, and no conforming JWT: a JWS signing
    /// input starts with the base64url of a JSON header, and the prefix's
    /// first four characters decode to 0x0A 0x89 0xA9, which isn't UTF-8,
    /// so no JSON text encodes to it.
    pub fn verify(&self, msg: &[u8], sig: &Ed25519Signature) -> Result<(), Error> {
        if msg.starts_with(COMPOSITE_PREFIX) {
            return Err(Error::Verification);
        }
        self.verify_any(msg, sig)
    }

    /// Verifies `sig` over `msg` strictly, whatever `msg` starts with: the
    /// composite's check of its own half (RFC 10073, section 3.3).
    ///
    /// The library's strict mode refuses a small-order R or key, and an R
    /// other than the one recomputed, compared as octets (RFC 8032,
    /// section 5.1.7). s was checked when the signature was decoded.
    pub(crate) fn verify_any(&self, msg: &[u8], sig: &Ed25519Signature) -> Result<(), Error> {
        let sig = ed25519_dalek::Signature::from_bytes(&sig.0);
        self.0
            .verify_strict(msg, &sig)
            .map_err(|_| Error::Verification)
    }
}

impl core::fmt::Debug for Ed25519VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ed25519VerifyingKey(32 octets)")
    }
}

/// An Ed25519 signature, R ‖ s (RFC 8032, section 5.1.6), with R a
/// canonical point encoding and s below ℓ.
#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519Signature([u8; SIGNATURE_LEN]);

impl Ed25519Signature {
    /// Decodes a signature (ADR 0069, rule 5):
    ///
    /// - a length other than 64 gives [`Error::Length`];
    /// - an R that isn't a point's canonical encoding, or an s that isn't
    ///   below ℓ, gives [`Error::Encoding`] (RFC 8032, section 5.1.7).
    ///
    /// A small-order R is refused when the signature is verified. An
    /// accepted signature's [`Self::to_bytes`] returns the input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; SIGNATURE_LEN] = bytes.try_into().map_err(|_| Error::Length)?;
        let (r, s) = bytes.split_at(32);
        let r: &[u8; 32] = r.try_into().map_err(|_| Error::Length)?;
        let s: [u8; 32] = s.try_into().map_err(|_| Error::Length)?;
        canonical_point(r).ok_or(Error::Encoding)?;
        if bool::from(Scalar::from_canonical_bytes(s).is_none()) {
            return Err(Error::Encoding);
        }
        Ok(Self(bytes))
    }

    /// The signature's octets.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.0
    }
}

impl core::fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ed25519Signature(64 octets)")
    }
}
