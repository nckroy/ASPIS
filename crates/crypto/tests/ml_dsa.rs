// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Known answers for ML-DSA-65 verification (FIPS 204), from NIST's ACVP
//! vectors in `tests/data/acvp/` (ADR 0069, rule 7), and the checks of
//! rule 5. Signing and key generation are crate-private; their known
//! answers are in `src/kat.rs`.

mod common;

use aspis_crypto::Error;
use aspis_crypto::ml_dsa::{
    MAX_CONTEXT, MlDsa65Signature, MlDsa65VerifyingKey, SIGNATURE_LEN, VERIFYING_KEY_LEN,
};
use common::{Value, field, vectors};

const SIGGEN: &str = include_str!("data/acvp/ml-dsa-65-siggen.json");
const SIGVER: &str = include_str!("data/acvp/ml-dsa-65-sigver.json");

/// Every test of every group.
fn tests(v: &Value) -> Vec<Value> {
    v.get("testGroups")
        .as_array()
        .iter()
        .flat_map(|g| g.get("tests").as_array().to_vec())
        .collect()
}

/// Decodes the test's key and signature, and verifies.
fn decode_and_verify(t: &Value) -> Result<(), Error> {
    let key = MlDsa65VerifyingKey::from_bytes(&field(t, "pk"))?;
    let sig = MlDsa65Signature::from_bytes(&field(t, "signature"))?;
    key.verify(&field(t, "message"), &field(t, "context"), &sig)
}

/// Decoding, then verifying, succeeds exactly when the vector passes. A
/// modified z or hint may already fail at decoding, as `Encoding`; a
/// modified commitment or message decodes and fails to verify.
#[test]
fn acvp_sigver() {
    let v = vectors(SIGVER);
    let tests = tests(&v);
    assert_eq!(tests.len(), 15);
    let mut passed = 0;
    for t in &tests {
        let r = decode_and_verify(t);
        let id = t.get("tcId").as_u64();
        let reason = t.get("reason").as_str();
        if t.get("testPassed").as_bool() {
            assert_eq!(r, Ok(()), "tcId {id}");
            passed += 1;
            // An accepted key and signature re-encode to themselves.
            let pk = field(t, "pk");
            let sig = field(t, "signature");
            let key = MlDsa65VerifyingKey::from_bytes(&pk).unwrap();
            let s = MlDsa65Signature::from_bytes(&sig).unwrap();
            assert_eq!(key.to_bytes().as_slice(), pk.as_slice());
            assert_eq!(s.to_bytes().as_slice(), sig.as_slice());
        } else if reason.contains("commitment") || reason.contains("message") {
            assert_eq!(r, Err(Error::Verification), "tcId {id}: {reason}");
        } else {
            assert!(
                matches!(r, Err(Error::Encoding | Error::Verification)),
                "tcId {id}: {reason}: {r:?}"
            );
        }
    }
    assert_eq!(passed, 3);
}

/// Every sigGen vector's signature verifies under its key, message and
/// context, hedged or not.
#[test]
fn acvp_siggen_verifies() {
    let v = vectors(SIGGEN);
    let tests = tests(&v);
    assert_eq!(tests.len(), 10);
    for t in &tests {
        assert_eq!(
            decode_and_verify(t),
            Ok(()),
            "tcId {}",
            t.get("tcId").as_u64()
        );
    }
}

/// A signature verifies only under its own context, and a context over 255
/// octets is refused as such.
#[test]
fn context() {
    let v = vectors(SIGGEN);
    let t = &tests(&v)[0];
    let key = MlDsa65VerifyingKey::from_bytes(&field(t, "pk")).unwrap();
    let sig = MlDsa65Signature::from_bytes(&field(t, "signature")).unwrap();
    let msg = field(t, "message");
    let mut ctx = field(t, "context");
    assert!(!ctx.is_empty());
    assert_eq!(key.verify(&msg, &ctx, &sig), Ok(()));
    ctx[0] ^= 1;
    assert_eq!(key.verify(&msg, &ctx, &sig), Err(Error::Verification));
    assert_eq!(key.verify(&msg, &[], &sig), Err(Error::Verification));
    assert_eq!(
        key.verify(&msg, &[0; MAX_CONTEXT], &sig),
        Err(Error::Verification)
    );
    assert_eq!(
        key.verify(&msg, &[0; MAX_CONTEXT + 1], &sig),
        Err(Error::ContextTooLong)
    );
}

#[test]
fn lengths() {
    let v = vectors(SIGGEN);
    let t = &tests(&v)[0];
    let (pk, sig) = (field(t, "pk"), field(t, "signature"));
    assert_eq!((pk.len(), sig.len()), (VERIFYING_KEY_LEN, SIGNATURE_LEN));
    for n in [0, VERIFYING_KEY_LEN - 1, VERIFYING_KEY_LEN + 1] {
        let mut k = pk.clone();
        k.resize(n, 0);
        assert_eq!(MlDsa65VerifyingKey::from_bytes(&k), Err(Error::Length));
    }
    for n in [0, SIGNATURE_LEN - 1, SIGNATURE_LEN + 1] {
        let mut s = sig.clone();
        s.resize(n, 0);
        assert_eq!(MlDsa65Signature::from_bytes(&s), Err(Error::Length));
    }
}
