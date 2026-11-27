// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! ASPIS's signature: the composite `id-MLDSA65-Ed25519-SHA512` (OID
//! 1.3.6.1.5.5.7.6.48) of RFC 10073, sections 2 to 4 (ADR 0020, rule 2;
//! ADR 0069, rule 4; feature `composite`).
//!
//! A composite signature is an ML-DSA-65 signature and an Ed25519
//! signature over the same message representative
//!
//! ```text
//! M′ = Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ SHA-512(M)
//! ```
//!
//! with [`PREFIX`] and [`LABEL`] fixed, and ctx the caller's context of at
//! most 255 octets (RFC 10073, section 2.2). ML-DSA-65 signs M′ with the
//! label as its own context; Ed25519 signs M′ as pure Ed25519 (section
//! 3.2). Verification succeeds only if both halves verify (section 3.3).
//!
//! **The components stay inside** (rule 4; ADR 0020, rule 2; RFC 10073,
//! section 3.1). The types' fields are private, and nothing here gives out
//! a component key, a component signature, or a component's octets. The
//! only octet forms are the composite's own: the 64-octet private key, the
//! 1,984-octet public key and the 3,373-octet signature (section 4). The
//! standalone verifiers of [`crate::ed25519`] and [`crate::ml_dsa`] refuse
//! messages that start with [`PREFIX`], so a half sliced out of a
//! composite's octets doesn't verify alone either (section 9.4).
//!
//! **Not strongly unforgeable** (RFC 10073, section 9.2.2). Ed25519 is
//! deterministic, so two signatures over the same message and context
//! share their Ed25519 half, and recombining the halves of two of them
//! gives nothing new. But ML-DSA-65 is hedged, so one message has many
//! valid signatures, and a quantum adversary who can forge Ed25519 breaks
//! SUF-CMA. The RFC says applications that need SUF-CMA SHOULD NOT use the
//! composite. C25, C27 and C37 must never use signature octets as
//! identifiers, deduplication keys or replay keys. Identify a signed
//! object by its content instead.
//!
//! **Randomness is an input** (ADR 0069, rule 3). A private key is 64
//! octets from the entropy service: ML-DSA's seed ξ, then Ed25519's seed
//! (RFC 10073, section 4.2). Generating a key is decoding fresh octets
//! (section 3.1), so both component keys are always fresh. Signing takes
//! ML-DSA's 32-octet hedge from the caller. Ed25519 is deterministic.

use crate::ed25519::{Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey};
use crate::hash::sha512;
use crate::ml_dsa::{MlDsa65Signature, MlDsa65SigningKey, MlDsa65VerifyingKey};
use crate::secret::Secret;
use crate::{COMPOSITE_PREFIX, Error, Zeroizing, ed25519, ml_dsa};

/// The prefix of every message representative: the ASCII string
/// "CompositeAlgorithmSignatures2025" (RFC 10073, section 2.2).
pub const PREFIX: &[u8; 32] = COMPOSITE_PREFIX;
/// The signature label of `id-MLDSA65-Ed25519-SHA512` (RFC 10073, section
/// 6). It is also ML-DSA-65's context (section 3.2).
pub const LABEL: &[u8; 30] = b"COMPSIG-MLDSA65-Ed25519-SHA512";
/// A public key's length in octets: ML-DSA-65's key, then Ed25519's
/// (RFC 10073, section 4.1).
pub const PUBLIC_KEY_LEN: usize = ml_dsa::VERIFYING_KEY_LEN + ed25519::PUBLIC_KEY_LEN;
/// A private key's length in octets: ML-DSA-65's seed ξ, then Ed25519's
/// seed (RFC 10073, section 4.2).
pub const PRIVATE_KEY_LEN: usize = ml_dsa::SEED_LEN + ed25519::SEED_LEN;
/// A signature's length in octets: ML-DSA-65's signature, then Ed25519's
/// (RFC 10073, section 4.3).
pub const SIGNATURE_LEN: usize = ml_dsa::SIGNATURE_LEN + ed25519::SIGNATURE_LEN;
/// The longest context in octets (RFC 10073, section 2.2).
pub const MAX_CONTEXT: usize = 255;
/// The pre-hash's length in octets: SHA-512's (RFC 10073, section 6).
pub const PREHASH_LEN: usize = 64;
/// The length in octets of the hedge for the ML-DSA half.
pub const RANDOMNESS_LEN: usize = ml_dsa::RANDOMNESS_LEN;

/// The longest message representative in octets: the prefix, the label,
/// the context's length and the longest context, and the pre-hash.
const MAX_REPRESENTATIVE: usize = PREFIX.len() + LABEL.len() + 1 + MAX_CONTEXT + PREHASH_LEN;

/// The pre-hash PH(M), SHA-512 of the message (RFC 10073, section 10.5's
/// Prehash). A signer that is handed only a digest, such as C25's key
/// service signing for a client, signs it with
/// [`CompositeSigningKey::sign_prehashed`].
pub fn prehash(msg: &[u8]) -> [u8; PREHASH_LEN] {
    sha512(msg)
}

/// A message representative M′, on the stack.
pub(crate) struct Representative {
    buf: [u8; MAX_REPRESENTATIVE],
    len: usize,
}

impl Representative {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// M′ = Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ PH(M) (RFC 10073, sections 2.2
/// and 3.2, step 2), with len(ctx) a single octet. A context over 255
/// octets gives [`Error::ContextTooLong`] (step 1).
pub(crate) fn representative(ph: &[u8; PREHASH_LEN], ctx: &[u8]) -> Result<Representative, Error> {
    let ctx_len = u8::try_from(ctx.len()).map_err(|_| Error::ContextTooLong)?;
    let mut m = Representative {
        buf: [0; MAX_REPRESENTATIVE],
        len: 0,
    };
    for part in [&PREFIX[..], &LABEL[..], &[ctx_len], ctx, &ph[..]] {
        m.buf[m.len..m.len + part.len()].copy_from_slice(part);
        m.len += part.len();
    }
    Ok(m)
}

/// A composite private key: ML-DSA-65's seed ξ and Ed25519's seed (RFC
/// 10073, section 4.2), with both component keys derived from them.
///
/// It is a secret: it clears itself on drop, isn't `Clone`, prints `..`,
/// and its equality compares the 64 octets in constant time.
pub struct CompositeSigningKey {
    /// ξ ‖ the Ed25519 seed, kept for [`Self::to_bytes`] and equality.
    seed: Secret<PRIVATE_KEY_LEN>,
    mldsa: MlDsa65SigningKey,
    ed25519: Ed25519SigningKey,
    vk: CompositeVerifyingKey,
}

impl CompositeSigningKey {
    /// The key from its 64 octets: ξ, then the Ed25519 seed (RFC 10073,
    /// section 4.2). Every 64 octets are a key.
    ///
    /// This is also key generation (RFC 10073, section 3.1): pass 64 fresh
    /// octets from the entropy service (ADR 0069, rule 3; ADR 0021, rule
    /// 1). Both component keys then come from fresh octets, as section 3.1
    /// requires. Never build a key from octets used for another key.
    pub fn from_bytes(bytes: &[u8; PRIVATE_KEY_LEN]) -> Self {
        let (xi, ed) = bytes.split_at(ml_dsa::SEED_LEN);
        let xi: &[u8; ml_dsa::SEED_LEN] = xi.try_into().expect("ξ is 32 octets");
        let ed: &[u8; ed25519::SEED_LEN] = ed.try_into().expect("the Ed25519 seed is 32 octets");
        let mldsa = MlDsa65SigningKey::from_seed(xi);
        let ed25519 = Ed25519SigningKey::from_seed(ed);
        // A key made from a seed is canonical and of large order, so the
        // verifying key needs none of from_bytes's checks.
        let vk = CompositeVerifyingKey {
            mldsa: mldsa.verifying_key().clone(),
            ed25519: ed25519.verifying_key(),
        };
        Self {
            seed: Secret::new(bytes),
            mldsa,
            ed25519,
            vk,
        }
    }

    /// The key's 64 octets, for storage (C25). The buffer clears itself on
    /// drop.
    pub fn to_bytes(&self) -> Zeroizing<[u8; PRIVATE_KEY_LEN]> {
        Zeroizing::new(*self.seed.as_bytes())
    }

    /// The public key.
    pub fn verifying_key(&self) -> &CompositeVerifyingKey {
        &self.vk
    }

    /// Signs `msg` under the context `ctx` (RFC 10073, section 3.2),
    /// hedging the ML-DSA half with the caller's 32 random octets `rnd`.
    ///
    /// `rnd` must be fresh from the entropy service for every signature
    /// (ADR 0069, rule 3). Thirty-two zero octets would select FIPS 204's
    /// deterministic variant, which is for known-answer tests only, so
    /// they are refused with [`Error::SigningFailed`]: a zeroed buffer
    /// from an unchecked entropy read must not silently lose the hedge. A
    /// context over 255 octets gives [`Error::ContextTooLong`], and a
    /// failure of the ML-DSA library [`Error::SigningFailed`].
    pub fn sign(
        &self,
        msg: &[u8],
        ctx: &[u8],
        rnd: &[u8; RANDOMNESS_LEN],
    ) -> Result<CompositeSignature, Error> {
        if ctx.len() > MAX_CONTEXT {
            return Err(Error::ContextTooLong);
        }
        self.sign_prehashed(&prehash(msg), ctx, rnd)
    }

    /// Signs the pre-hash `ph` = [`prehash`]`(M)` under `ctx`, as
    /// [`Self::sign`] signs M (RFC 10073, section 10.5's Sign_ph). With the
    /// same `rnd`, it gives the same octets as [`Self::sign`].
    pub fn sign_prehashed(
        &self,
        ph: &[u8; PREHASH_LEN],
        ctx: &[u8],
        rnd: &[u8; RANDOMNESS_LEN],
    ) -> Result<CompositeSignature, Error> {
        let m = representative(ph, ctx)?;
        // Rule 3: deterministic signing is for known-answer tests only.
        // The comparison is constant time, since rnd is secret.
        if bool::from(subtle::ConstantTimeEq::ct_eq(
            &rnd[..],
            &[0u8; RANDOMNESS_LEN][..],
        )) {
            return Err(Error::SigningFailed);
        }
        // Section 3.2, step 4: ML-DSA-65 with the label as its context,
        // and pure Ed25519. Step 5: an error in either is an error.
        let mldsa = self.mldsa.sign(m.as_bytes(), LABEL, rnd)?;
        let ed25519 = self.ed25519.sign(m.as_bytes());
        Ok(CompositeSignature { mldsa, ed25519 })
    }
}

impl zeroize::ZeroizeOnDrop for CompositeSigningKey {}

impl subtle::ConstantTimeEq for CompositeSigningKey {
    /// The key is determined by its 64 octets, so comparing them compares
    /// keys.
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.seed.ct_eq(&other.seed)
    }
}

impl PartialEq for CompositeSigningKey {
    fn eq(&self, other: &Self) -> bool {
        subtle::ConstantTimeEq::ct_eq(self, other).into()
    }
}

impl Eq for CompositeSigningKey {}

impl core::fmt::Debug for CompositeSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CompositeSigningKey(..)")
    }
}

/// A composite public key: an ML-DSA-65 key and an Ed25519 key that is
/// canonical and not of small order.
#[derive(Clone, PartialEq, Eq)]
pub struct CompositeVerifyingKey {
    mldsa: MlDsa65VerifyingKey,
    ed25519: Ed25519VerifyingKey,
}

impl CompositeVerifyingKey {
    /// Decodes a public key (RFC 10073, section 4.1; ADR 0069, rule 5):
    ///
    /// - a length other than 1,984 gives [`Error::Length`];
    /// - an Ed25519 half that isn't a point's canonical encoding gives
    ///   [`Error::Encoding`], and one of small order [`Error::WeakKey`].
    ///
    /// Every 1,952 octets are an ML-DSA-65 key. An accepted key's
    /// [`Self::to_bytes`] returns the input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(Error::Length);
        }
        let (mldsa, ed) = bytes.split_at(ml_dsa::VERIFYING_KEY_LEN);
        Ok(Self {
            mldsa: MlDsa65VerifyingKey::from_bytes(mldsa)?,
            ed25519: Ed25519VerifyingKey::from_bytes(ed)?,
        })
    }

    /// The key's octets: ML-DSA-65's, then Ed25519's.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        let mut out = [0; PUBLIC_KEY_LEN];
        let (mldsa, ed) = out.split_at_mut(ml_dsa::VERIFYING_KEY_LEN);
        mldsa.copy_from_slice(&self.mldsa.to_bytes());
        ed.copy_from_slice(&self.ed25519.to_bytes());
        out
    }

    /// Verifies `sig` over `msg` under the context `ctx` (RFC 10073,
    /// section 3.3). A context over 255 octets gives
    /// [`Error::ContextTooLong`]. Otherwise the result is `Ok` only if
    /// the ML-DSA-65 half verifies over M′ with the label as its context
    /// and the Ed25519 half verifies over M′ strictly; anything else gives
    /// [`Error::Verification`].
    pub fn verify(&self, msg: &[u8], ctx: &[u8], sig: &CompositeSignature) -> Result<(), Error> {
        if ctx.len() > MAX_CONTEXT {
            return Err(Error::ContextTooLong);
        }
        self.verify_prehashed(&prehash(msg), ctx, sig)
    }

    /// Verifies `sig` over the pre-hash `ph` = [`prehash`]`(M)`, as
    /// [`Self::verify`] verifies it over M (RFC 10073, section 10.5).
    pub fn verify_prehashed(
        &self,
        ph: &[u8; PREHASH_LEN],
        ctx: &[u8],
        sig: &CompositeSignature,
    ) -> Result<(), Error> {
        let m = representative(ph, ctx)?;
        // Section 3.3, step 4. Both halves are checked even when the first
        // fails: no secret is involved, and the work doesn't depend on
        // which half is bad.
        let mldsa = self.mldsa.verify_any(m.as_bytes(), LABEL, &sig.mldsa);
        let ed25519 = self.ed25519.verify_any(m.as_bytes(), &sig.ed25519);
        match (mldsa, ed25519) {
            (Ok(()), Ok(())) => Ok(()),
            _ => Err(Error::Verification),
        }
    }
}

impl core::fmt::Debug for CompositeVerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CompositeVerifyingKey(1984 octets)")
    }
}

/// A composite signature: an ML-DSA-65 signature with a well-formed hint
/// and z, and an Ed25519 signature with a canonical R and an s below ℓ.
#[derive(Clone, PartialEq, Eq)]
pub struct CompositeSignature {
    mldsa: MlDsa65Signature,
    ed25519: Ed25519Signature,
}

impl CompositeSignature {
    /// Decodes a signature (RFC 10073, section 4.3; ADR 0069, rule 5):
    ///
    /// - a length other than 3,373 gives [`Error::Length`];
    /// - a malformed ML-DSA-65 hint or z, a non-canonical Ed25519 R, or an
    ///   s not below ℓ gives [`Error::Encoding`].
    ///
    /// An accepted signature's [`Self::to_bytes`] returns the input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SIGNATURE_LEN {
            return Err(Error::Length);
        }
        let (mldsa, ed) = bytes.split_at(ml_dsa::SIGNATURE_LEN);
        Ok(Self {
            mldsa: MlDsa65Signature::from_bytes(mldsa)?,
            ed25519: Ed25519Signature::from_bytes(ed)?,
        })
    }

    /// The signature's octets: ML-DSA-65's, then Ed25519's.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        let mut out = [0; SIGNATURE_LEN];
        let (mldsa, ed) = out.split_at_mut(ml_dsa::SIGNATURE_LEN);
        mldsa.copy_from_slice(&self.mldsa.to_bytes());
        ed.copy_from_slice(&self.ed25519.to_bytes());
        out
    }
}

impl core::fmt::Debug for CompositeSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CompositeSignature(3373 octets)")
    }
}
