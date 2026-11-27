// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! ML-DSA-65 (FIPS 204; feature `ml-dsa`).
//!
//! ASPIS's own signatures are the composite of ADR 0020, rule 2, whose
//! components are never used alone. So this module gives out only what
//! verifying a standalone ML-DSA-65 signature needs: C28 verifies outside
//! certificates with it, and C37 outside JWTs (`alg` "ML-DSA-65", RFC
//! 9964). Signing is crate-private, for the composite and the known-answer
//! tests.
//!
//! - **Key generation** takes the 32-octet seed ξ (FIPS 204, Algorithm 6,
//!   ML-DSA.KeyGen_internal), from the caller (ADR 0069, rule 3).
//! - **Signing** is hedged with 32 random octets from the caller (FIPS
//!   204, Algorithm 2, ML-DSA.Sign, with rnd given). The deterministic
//!   variant is the same algorithm with rnd = 32 zero octets (Algorithm
//!   2's "optional deterministic variant"). It is for known-answer tests
//!   only (rule 3).
//! - **A context** of at most 255 octets is bound into the signature; a
//!   longer one gives [`Error::ContextTooLong`].
//! - **Decoding a signature** refuses a malformed hint (FIPS 204,
//!   Algorithm 21, HintBitUnpack) and a z outside the norm bound, so an
//!   accepted signature re-encodes to itself (rule 5).
//! - **Standalone verification** refuses a message that starts with
//!   RFC 10073's prefix, so a composite's ML-DSA half doesn't verify alone
//!   (RFC 10073, section 9.4; ADR 0020, rule 2).

use ml_dsa::{ExpandedSigningKey, MlDsa65};

use crate::rng::OneShot;
use crate::{COMPOSITE_PREFIX, Error};

/// A seed's length in octets: ξ.
pub const SEED_LEN: usize = 32;
/// A verifying key's length in octets.
pub const VERIFYING_KEY_LEN: usize = 1952;
/// A signature's length in octets.
pub const SIGNATURE_LEN: usize = 3309;
/// The longest context in octets (FIPS 204, Algorithms 2 and 3).
pub const MAX_CONTEXT: usize = 255;
/// The length in octets of hedged signing's random input rnd.
pub const RANDOMNESS_LEN: usize = 32;

/// Copies a library array of `N` octets into a plain array.
fn to_array<const N: usize>(octets: &[u8]) -> [u8; N] {
    let mut out = [0; N];
    out.copy_from_slice(octets);
    out
}

/// Signs `msg` with `esk` under `ctx`, hedged with `rnd` (FIPS 204,
/// Algorithm 2). It is the one signing path, for the signing key and the
/// known-answer tests of expanded keys.
///
/// `rnd` of 32 zero octets gives FIPS 204's deterministic variant, which
/// is for known-answer tests only (ADR 0069, rule 3). A context over 255
/// octets gives [`Error::ContextTooLong`], and a library failure
/// [`Error::SigningFailed`].
pub(crate) fn sign_with(
    esk: &ExpandedSigningKey<MlDsa65>,
    msg: &[u8],
    ctx: &[u8],
    rnd: &[u8; RANDOMNESS_LEN],
) -> Result<MlDsa65Signature, Error> {
    if ctx.len() > MAX_CONTEXT {
        return Err(Error::ContextTooLong);
    }
    esk.sign_randomized(msg, ctx, &mut OneShot::new(rnd))
        .map(MlDsa65Signature)
        .map_err(|_| Error::SigningFailed)
}

/// An ML-DSA-65 signing key, from its seed ξ.
///
/// It is crate-private: only the composite signs with ML-DSA (ADR 0020,
/// rule 2; RFC 10073, section 3.1, which forbids using component keys
/// alone). It holds the library's expanded key, which clears itself on
/// drop, and the verifying key, computed once. It keeps no copy of ξ: the
/// composite keeps its own seed.
pub(crate) struct MlDsa65SigningKey {
    esk: ExpandedSigningKey<MlDsa65>,
    vk: MlDsa65VerifyingKey,
}

impl MlDsa65SigningKey {
    /// The key from its seed ξ (FIPS 204, Algorithm 6), which the caller
    /// takes from the entropy service (ADR 0069, rule 3).
    pub(crate) fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let esk = ExpandedSigningKey::<MlDsa65>::from_seed(seed.into());
        let vk = MlDsa65VerifyingKey(esk.verifying_key());
        Self { esk, vk }
    }

    /// The verifying key.
    pub(crate) fn verifying_key(&self) -> &MlDsa65VerifyingKey {
        &self.vk
    }

    /// Signs `msg` under `ctx`, hedged with the caller's 32 random octets
    /// `rnd`, as [`sign_with`] does.
    pub(crate) fn sign(
        &self,
        msg: &[u8],
        ctx: &[u8],
        rnd: &[u8; RANDOMNESS_LEN],
    ) -> Result<MlDsa65Signature, Error> {
        sign_with(&self.esk, msg, ctx, rnd)
    }
}

// The library's key clears itself on drop; this checks that it says so.
const _: () = {
    fn clears<T: zeroize::ZeroizeOnDrop>() {}
    let _ = clears::<ExpandedSigningKey<MlDsa65>>;
};

impl zeroize::ZeroizeOnDrop for MlDsa65SigningKey {}

impl core::fmt::Debug for MlDsa65SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MlDsa65SigningKey(..)")
    }
}

/// An ML-DSA-65 verifying key. Every 1,952 octets are one (FIPS 204,
/// Algorithm 23, pkDecode, checks nothing more).
#[derive(Clone, PartialEq)]
pub struct MlDsa65VerifyingKey(ml_dsa::VerifyingKey<MlDsa65>);

// The library derives only `PartialEq`, over the key's fields, which is an
// equivalence.
impl Eq for MlDsa65VerifyingKey {}

impl MlDsa65VerifyingKey {
    /// Decodes a verifying key. A length other than 1,952 gives
    /// [`Error::Length`]. An accepted key's [`Self::to_bytes`] returns the
    /// input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let key = bytes.try_into().map_err(|_| Error::Length)?;
        Ok(Self(ml_dsa::VerifyingKey::decode(key)))
    }

    /// The key's octets (FIPS 204, Algorithm 22, pkEncode).
    pub fn to_bytes(&self) -> [u8; VERIFYING_KEY_LEN] {
        to_array(self.0.encode().as_slice())
    }

    /// Verifies `sig` over `msg` under `ctx` (FIPS 204, Algorithm 3,
    /// ML-DSA.Verify). A context over 255 octets gives
    /// [`Error::ContextTooLong`], and a signature that doesn't verify
    /// [`Error::Verification`].
    ///
    /// A message that starts with the composite's prefix is refused too,
    /// as [`crate::ed25519::Ed25519VerifyingKey::verify`] refuses it: it
    /// can only be an RFC 10073 message representative, whose ML-DSA half
    /// must not verify alone, even under the composite's label as context
    /// (RFC 10073, sections 9.2.3 and 9.4; ADR 0020, rule 2). The guard
    /// refuses no certificate, whose DER starts with 0x30, and no
    /// conforming JWT: a JWS signing input starts with the base64url of a
    /// JSON header, and the prefix's first four characters decode to 0x0A
    /// 0x89 0xA9, which isn't UTF-8, so no JSON text encodes to it.
    pub fn verify(&self, msg: &[u8], ctx: &[u8], sig: &MlDsa65Signature) -> Result<(), Error> {
        if ctx.len() > MAX_CONTEXT {
            return Err(Error::ContextTooLong);
        }
        if msg.starts_with(COMPOSITE_PREFIX) {
            return Err(Error::Verification);
        }
        self.verify_any(msg, ctx, sig)
    }

    /// Verifies `sig` over `msg` under `ctx`, whatever `msg` starts with:
    /// the composite's check of its own half (RFC 10073, section 3.3).
    pub(crate) fn verify_any(
        &self,
        msg: &[u8],
        ctx: &[u8],
        sig: &MlDsa65Signature,
    ) -> Result<(), Error> {
        if ctx.len() > MAX_CONTEXT {
            return Err(Error::ContextTooLong);
        }
        if self.0.verify_with_context(msg, ctx, &sig.0) {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }
}

impl core::fmt::Debug for MlDsa65VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MlDsa65VerifyingKey(1952 octets)")
    }
}

/// An ML-DSA-65 signature with a well-formed hint and z.
#[derive(Clone, PartialEq)]
pub struct MlDsa65Signature(ml_dsa::Signature<MlDsa65>);

// As for the verifying key: the library's `PartialEq` is an equivalence.
impl Eq for MlDsa65Signature {}

impl MlDsa65Signature {
    /// Decodes a signature (ADR 0069, rule 5):
    ///
    /// - a length other than 3,309 gives [`Error::Length`];
    /// - a malformed hint (FIPS 204, Algorithm 21) or a z whose norm
    ///   reaches γ1 − β gives [`Error::Encoding`]. Neither could verify.
    ///
    /// So an accepted signature's [`Self::to_bytes`] returns the input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let sig = bytes.try_into().map_err(|_| Error::Length)?;
        ml_dsa::Signature::decode(sig)
            .map(Self)
            .ok_or(Error::Encoding)
    }

    /// The signature's octets (FIPS 204, Algorithm 26, sigEncode).
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        to_array(self.0.encode().as_slice())
    }
}

impl core::fmt::Debug for MlDsa65Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MlDsa65Signature(3309 octets)")
    }
}
