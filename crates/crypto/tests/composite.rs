// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The composite `id-MLDSA65-Ed25519-SHA512` against RFC 10073's
//! Appendices D and E (ADR 0069, rules 4 and 7), and its refusals (rule
//! 5): one bad half, a half spliced from elsewhere, a weak Ed25519 key, a
//! long context and wrong lengths.
//!
//! Some tests build halves with the libraries directly, as an attacker
//! could, since aspis-crypto gives out no component signer.

mod common;

use aspis_crypto::Error;
use aspis_crypto::composite::{
    CompositeSignature, CompositeSigningKey, CompositeVerifyingKey, LABEL, MAX_CONTEXT, PREFIX,
    PRIVATE_KEY_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN, prehash,
};
use aspis_crypto::ed25519::{Ed25519Signature, Ed25519VerifyingKey};
use aspis_crypto::hash::sha512;
use aspis_crypto::ml_dsa::{MlDsa65Signature, MlDsa65VerifyingKey};
use common::{Value, base64, field, hex, vectors};
use ed25519_dalek::Signer;

const RFC10073: &str = include_str!("data/rfc10073.json");

/// ML-DSA-65's part of the composite octets.
const MLDSA_PK: usize = 1952;
const MLDSA_SIG: usize = 3309;

/// Appendix E: the message, the context and the one test object.
struct Vector {
    m: Vec<u8>,
    ctx: Vec<u8>,
    pk: Vec<u8>,
    sk: [u8; 64],
    s: Vec<u8>,
    s_ctx: Vec<u8>,
}

fn vector() -> Vector {
    let v = vectors(RFC10073);
    let e = v.get("appendixE");
    let tests = e.get("tests").as_array();
    assert_eq!(tests.len(), 1);
    let t = &tests[0];
    assert_eq!(t.get("tcId").as_str(), "id-MLDSA65-Ed25519-SHA512");
    let b = |v: &Value, k: &str| base64(v.get(k).as_str());
    Vector {
        m: b(e, "m"),
        ctx: b(e, "ctx"),
        pk: b(t, "pk"),
        sk: b(t, "sk").try_into().unwrap(),
        s: b(t, "s"),
        s_ctx: b(t, "sWithContext"),
    }
}

/// M′ = Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ SHA-512(M) (RFC 10073, section
/// 2.2), built independently of the crate.
fn m_prime(m: &[u8], ctx: &[u8]) -> Vec<u8> {
    let mut out = PREFIX.to_vec();
    out.extend_from_slice(LABEL);
    out.push(u8::try_from(ctx.len()).unwrap());
    out.extend_from_slice(ctx);
    out.extend_from_slice(&sha512(m));
    out
}

fn splice(mldsa: &[u8], ed: &[u8]) -> Vec<u8> {
    let mut out = mldsa.to_vec();
    out.extend_from_slice(ed);
    out
}

/// Verifies octets as a composite signature: decoding errors and
/// verification errors alike.
fn check(pk: &CompositeVerifyingKey, m: &[u8], ctx: &[u8], sig: &[u8]) -> Result<(), Error> {
    pk.verify(m, ctx, &CompositeSignature::from_bytes(sig)?)
}

/// Appendix D: the pre-hash of 00…09, the prefix, and the layout of
/// len(ctx) ‖ ctx ‖ PH(M) after the label. Its examples are for another
/// composite, so only the label differs from ours.
#[test]
fn rfc10073_appendix_d() {
    let v = vectors(RFC10073);
    let tests = v.get("appendixD").get("tests").as_array();
    assert_eq!(tests.len(), 2);
    for t in tests {
        let m = field(t, "message");
        let ctx = field(t, "context");
        assert_eq!(prehash(&m).as_slice(), field(t, "preHash").as_slice());
        assert_eq!(PREFIX.as_slice(), field(t, "prefix").as_slice());
        let their = field(t, "messageRepresentative");
        let label = t.get("label").as_str().as_bytes();
        let tail = &their[PREFIX.len() + label.len()..];
        assert_eq!(&m_prime(&m, &ctx)[PREFIX.len() + LABEL.len()..], tail);
    }
    assert_eq!(
        PREFIX.as_slice(),
        hex("436F6D706F73697465416C676F726974686D5369676E61747572657332303235").as_slice()
    );
}

/// Appendix E: sk gives pk (RFC 10073, section 4.2), and decoding and
/// encoding keep every octet.
#[test]
fn rfc10073_keys() {
    let v = vector();
    let sk = CompositeSigningKey::from_bytes(&v.sk);
    assert_eq!(sk.verifying_key().to_bytes().as_slice(), v.pk.as_slice());
    assert_eq!(*sk.to_bytes(), v.sk);
    let pk = CompositeVerifyingKey::from_bytes(&v.pk).unwrap();
    assert_eq!(&pk, sk.verifying_key());
    for s in [&v.s, &v.s_ctx] {
        let sig = CompositeSignature::from_bytes(s).unwrap();
        assert_eq!(sig.to_bytes().as_slice(), s.as_slice());
    }
}

/// Appendix E, test 1: s verifies over m with the empty context, and
/// sWithContext with ctx; neither verifies under the other's context.
#[test]
fn rfc10073_verify() {
    let v = vector();
    let pk = CompositeVerifyingKey::from_bytes(&v.pk).unwrap();
    assert_eq!(check(&pk, &v.m, b"", &v.s), Ok(()));
    assert_eq!(check(&pk, &v.m, &v.ctx, &v.s_ctx), Ok(()));
    assert_eq!(check(&pk, &v.m, &v.ctx, &v.s), Err(Error::Verification));
    assert_eq!(check(&pk, &v.m, b"", &v.s_ctx), Err(Error::Verification));
    assert_eq!(check(&pk, b"another", b"", &v.s), Err(Error::Verification));
    // The pre-hashed form agrees (RFC 10073, section 10.5).
    let s = CompositeSignature::from_bytes(&v.s).unwrap();
    assert_eq!(pk.verify_prehashed(&prehash(&v.m), b"", &s), Ok(()));
}

/// Signing with the RFC's key reproduces the Ed25519 halves, which are
/// deterministic. The RFC's ML-DSA halves were hedged, so they don't
/// reproduce; ours, with a hedge of our own, verify instead.
#[test]
fn rfc10073_ed25519_half_reproduces() {
    let v = vector();
    let sk = CompositeSigningKey::from_bytes(&v.sk);
    for (ctx, published) in [(&b""[..], &v.s), (&v.ctx[..], &v.s_ctx)] {
        let ours = sk.sign(&v.m, ctx, &[0x5a; 32]).unwrap().to_bytes();
        assert_eq!(&ours[MLDSA_SIG..], &published[MLDSA_SIG..]);
        assert_ne!(&ours[..MLDSA_SIG], &published[..MLDSA_SIG]);
        assert_eq!(check(sk.verifying_key(), &v.m, ctx, &ours), Ok(()));
    }
}

/// Appendix E, test 3: sign with sk and verify with pk, with two hedges.
#[test]
fn sign_then_verify() {
    let v = vector();
    let sk = CompositeSigningKey::from_bytes(&v.sk);
    let pk = CompositeVerifyingKey::from_bytes(&v.pk).unwrap();
    for rnd in [[0x01; 32], [0x77; 32]] {
        for ctx in [&b""[..], &v.ctx[..]] {
            let sig = sk.sign(&v.m, ctx, &rnd).unwrap();
            assert_eq!(pk.verify(&v.m, ctx, &sig), Ok(()));
        }
    }
    // A fresh key from other octets.
    let other = CompositeSigningKey::from_bytes(&[0x42; PRIVATE_KEY_LEN]);
    let sig = other.sign(b"hello", b"ctx", &[1; 32]).unwrap();
    assert_eq!(other.verifying_key().verify(b"hello", b"ctx", &sig), Ok(()));
    assert_eq!(pk.verify(b"hello", b"ctx", &sig), Err(Error::Verification));
}

/// Signing a pre-hash gives the same octets as signing the message with
/// the same hedge (RFC 10073, section 10.5).
#[test]
fn prehashed_matches() {
    let v = vector();
    let sk = CompositeSigningKey::from_bytes(&v.sk);
    let a = sk.sign(&v.m, &v.ctx, &[9; 32]).unwrap();
    let b = sk.sign_prehashed(&prehash(&v.m), &v.ctx, &[9; 32]).unwrap();
    assert_eq!(a, b);
    let pk = sk.verifying_key();
    assert_eq!(pk.verify_prehashed(&prehash(&v.m), &v.ctx, &a), Ok(()));
    assert_eq!(
        pk.verify_prehashed(&prehash(b"x"), &v.ctx, &a),
        Err(Error::Verification)
    );
}

/// Flipped bits in either half are refused, at decoding or verification.
#[test]
fn flipped_bits_fail() {
    let v = vector();
    let pk = CompositeVerifyingKey::from_bytes(&v.pk).unwrap();
    // The ML-DSA half's first and last octets, the Ed25519 half's R and
    // its s.
    let positions = [
        0,
        1000,
        MLDSA_SIG - 1,
        MLDSA_SIG,
        MLDSA_SIG + 31,
        MLDSA_SIG + 32,
        SIGNATURE_LEN - 1,
    ];
    for pos in positions {
        for bit in [0, 7] {
            let mut s = v.s.clone();
            s[pos] ^= 1 << bit;
            let r = check(&pk, &v.m, b"", &s);
            assert!(
                matches!(r, Err(Error::Encoding | Error::Verification)),
                "octet {pos} bit {bit}: {r:?}"
            );
        }
    }
    // A flipped bit in the public key's Ed25519 half.
    let mut bad = v.pk.clone();
    bad[MLDSA_PK] ^= 1;
    match CompositeVerifyingKey::from_bytes(&bad) {
        Ok(k) => assert_eq!(check(&k, &v.m, b"", &v.s), Err(Error::Verification)),
        Err(e) => assert!(matches!(e, Error::Encoding | Error::WeakKey), "{e:?}"),
    }
    let mut bad = v.pk.clone();
    bad[0] ^= 1;
    let k = CompositeVerifyingKey::from_bytes(&bad).unwrap();
    assert_eq!(check(&k, &v.m, b"", &v.s), Err(Error::Verification));
}

/// Each half valid for its own M′ isn't enough: the ML-DSA half of s with
/// the Ed25519 half of sWithContext, and the reverse, are refused (RFC
/// 10073, section 3.3: both must verify over the same M′).
#[test]
fn one_half_valid_fails() {
    let v = vector();
    let pk = CompositeVerifyingKey::from_bytes(&v.pk).unwrap();
    let a = splice(&v.s[..MLDSA_SIG], &v.s_ctx[MLDSA_SIG..]);
    let b = splice(&v.s_ctx[..MLDSA_SIG], &v.s[MLDSA_SIG..]);
    for ctx in [&b""[..], &v.ctx[..]] {
        assert_eq!(check(&pk, &v.m, ctx, &a), Err(Error::Verification));
        assert_eq!(check(&pk, &v.m, ctx, &b), Err(Error::Verification));
    }
}

/// An Ed25519 signature over M itself, not over M′, spliced in with a good
/// ML-DSA half, is refused.
#[test]
fn standalone_ed25519_over_m_fails() {
    let v = vector();
    let pk = CompositeVerifyingKey::from_bytes(&v.pk).unwrap();
    let ed = ed25519_dalek::SigningKey::from_bytes(&v.sk[32..].try_into().unwrap());
    let over_m = ed.sign(&v.m).to_bytes();
    let s = splice(&v.s[..MLDSA_SIG], &over_m);
    assert_eq!(check(&pk, &v.m, b"", &s), Err(Error::Verification));
}

/// The ML-DSA half must be made with the label as its context (RFC 10073,
/// section 3.2): a raw ML-DSA-65 signature over M′ with an empty context,
/// with a good Ed25519 half, is refused.
#[test]
fn mldsa_half_without_label_fails() {
    let v = vector();
    let pk = CompositeVerifyingKey::from_bytes(&v.pk).unwrap();
    let esk = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa65>::from_seed(
        (&<[u8; 32]>::try_from(&v.sk[..32]).unwrap()).into(),
    );
    let mp = m_prime(&v.m, b"");
    let no_label = esk.sign_deterministic(&mp, b"").unwrap();
    let with_label = esk.sign_deterministic(&mp, LABEL).unwrap();
    let ed = &v.s[MLDSA_SIG..];
    let bad = splice(no_label.encode().as_slice(), ed);
    assert_eq!(check(&pk, &v.m, b"", &bad), Err(Error::Verification));
    // The same construction with the label verifies.
    let good = splice(with_label.encode().as_slice(), ed);
    assert_eq!(check(&pk, &v.m, b"", &good), Ok(()));
}

/// Neither half verifies alone under the standalone verifiers, which
/// refuse messages that start with the prefix (RFC 10073, section 9.4;
/// ADR 0020, rule 2), though the libraries alone would take them.
#[test]
fn halves_refused_standalone() {
    let v = vector();
    let mp = m_prime(&v.m, b"");

    let ed_pk = Ed25519VerifyingKey::from_bytes(&v.pk[MLDSA_PK..]).unwrap();
    let ed_sig = Ed25519Signature::from_bytes(&v.s[MLDSA_SIG..]).unwrap();
    assert_eq!(ed_pk.verify(&mp, &ed_sig), Err(Error::Verification));
    let raw = ed25519_dalek::VerifyingKey::from_bytes(&v.pk[MLDSA_PK..].try_into().unwrap());
    let raw_sig = ed25519_dalek::Signature::from_bytes(&v.s[MLDSA_SIG..].try_into().unwrap());
    assert!(raw.unwrap().verify_strict(&mp, &raw_sig).is_ok());

    let ml_pk = MlDsa65VerifyingKey::from_bytes(&v.pk[..MLDSA_PK]).unwrap();
    let ml_sig = MlDsa65Signature::from_bytes(&v.s[..MLDSA_SIG]).unwrap();
    assert_eq!(ml_pk.verify(&mp, LABEL, &ml_sig), Err(Error::Verification));
    assert_eq!(ml_pk.verify(&mp, b"", &ml_sig), Err(Error::Verification));
}

/// The composite isn't strongly unforgeable (RFC 10073, section 9.2.2):
/// hedging gives one message many valid signatures, which differ in their
/// ML-DSA halves. Ed25519 is deterministic, so their Ed25519 halves are
/// the same, and recombining halves gives back only the originals.
/// Signature octets are therefore no identifier (C25, C27, C37).
#[test]
fn hedged_signatures_share_ed25519_half() {
    let v = vector();
    let sk = CompositeSigningKey::from_bytes(&v.sk);
    let a = sk.sign(&v.m, &v.ctx, &[1; 32]).unwrap().to_bytes();
    let b = sk.sign(&v.m, &v.ctx, &[2; 32]).unwrap().to_bytes();
    assert_ne!(a[..MLDSA_SIG], b[..MLDSA_SIG]);
    assert_eq!(a[MLDSA_SIG..], b[MLDSA_SIG..]);
    assert_eq!(a[MLDSA_SIG..], v.s_ctx[MLDSA_SIG..]);
    let mixed = splice(&a[..MLDSA_SIG], &v.s_ctx[MLDSA_SIG..]);
    let mixed2 = splice(&b[..MLDSA_SIG], &a[MLDSA_SIG..]);
    assert_eq!(mixed, a);
    assert_eq!(mixed2, b);
    for s in [&a[..], &b[..], &v.s_ctx[..]] {
        assert_eq!(check(sk.verifying_key(), &v.m, &v.ctx, s), Ok(()));
    }
}

#[test]
fn wrong_context_fails() {
    let v = vector();
    let pk = CompositeVerifyingKey::from_bytes(&v.pk).unwrap();
    let mut ctx = v.ctx.clone();
    ctx.pop();
    assert_eq!(check(&pk, &v.m, &ctx, &v.s_ctx), Err(Error::Verification));
    assert_eq!(check(&pk, &v.m, b"\0", &v.s), Err(Error::Verification));
}

/// A context of 255 octets is the most (RFC 10073, section 3.2, step 1).
#[test]
fn context_limit() {
    let sk = CompositeSigningKey::from_bytes(&[5; PRIVATE_KEY_LEN]);
    let long = [0xc7; MAX_CONTEXT + 1];
    let sig = sk.sign(b"m", &long[..MAX_CONTEXT], &[1; 32]).unwrap();
    let pk = sk.verifying_key();
    assert_eq!(pk.verify(b"m", &long[..MAX_CONTEXT], &sig), Ok(()));
    assert_eq!(pk.verify(b"m", &long, &sig), Err(Error::ContextTooLong));
    assert_eq!(sk.sign(b"m", &long, &[0; 32]), Err(Error::ContextTooLong));
    let ph = prehash(b"m");
    assert_eq!(
        sk.sign_prehashed(&ph, &long, &[0; 32]),
        Err(Error::ContextTooLong)
    );
    assert_eq!(
        pk.verify_prehashed(&ph, &long, &sig),
        Err(Error::ContextTooLong)
    );
}

/// An all-zero hedge would select FIPS 204's deterministic variant, which
/// is for known-answer tests only, so the composite refuses it (ADR 0069,
/// rule 3). One nonzero octet is enough.
#[test]
fn zero_hedge_refused() {
    let sk = CompositeSigningKey::from_bytes(&[5; PRIVATE_KEY_LEN]);
    assert_eq!(sk.sign(b"m", b"", &[0; 32]), Err(Error::SigningFailed));
    assert_eq!(
        sk.sign_prehashed(&prehash(b"m"), b"", &[0; 32]),
        Err(Error::SigningFailed)
    );
    let mut rnd = [0; 32];
    rnd[31] = 1;
    let sig = sk.sign(b"m", b"", &rnd).unwrap();
    assert_eq!(sk.verifying_key().verify(b"m", b"", &sig), Ok(()));
}

#[test]
fn lengths() {
    let v = vector();
    for n in [0, PUBLIC_KEY_LEN - 1, PUBLIC_KEY_LEN + 1] {
        let mut pk = v.pk.clone();
        pk.resize(n, 0);
        assert_eq!(
            CompositeVerifyingKey::from_bytes(&pk),
            Err(Error::Length),
            "{n}"
        );
    }
    for n in [0, SIGNATURE_LEN - 1, SIGNATURE_LEN + 1] {
        let mut s = v.s.clone();
        s.resize(n, 0);
        assert_eq!(
            CompositeSignature::from_bytes(&s),
            Err(Error::Length),
            "{n}"
        );
    }
    assert_eq!(
        (PUBLIC_KEY_LEN, PRIVATE_KEY_LEN, SIGNATURE_LEN),
        (1984, 64, 3373)
    );
}

/// A public key whose Ed25519 half is of small order, or not canonical,
/// is refused (ADR 0069, rule 5).
#[test]
fn weak_ed25519_half_refused() {
    let v = vector();
    let mut pk = v.pk.clone();
    // The identity point, of order 1.
    pk[MLDSA_PK..].copy_from_slice(&hex(
        "0100000000000000000000000000000000000000000000000000000000000000",
    ));
    assert_eq!(CompositeVerifyingKey::from_bytes(&pk), Err(Error::WeakKey));
    // y = 1 + p, the identity's non-canonical encoding.
    pk[MLDSA_PK..].copy_from_slice(&hex(
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ));
    assert_eq!(CompositeVerifyingKey::from_bytes(&pk), Err(Error::Encoding));
}

/// The private key's 64 octets are a secret: redacted, compared in
/// constant time.
#[test]
fn signing_key_secret() {
    let a = CompositeSigningKey::from_bytes(&[1; 64]);
    let mut other = [1; 64];
    other[63] = 2;
    assert_eq!(a, CompositeSigningKey::from_bytes(&[1; 64]));
    assert_ne!(a, CompositeSigningKey::from_bytes(&other));
    assert_eq!(format!("{a:?}"), "CompositeSigningKey(..)");
    let pk = a.verifying_key();
    assert_eq!(format!("{pk:?}"), "CompositeVerifyingKey(1984 octets)");
}
