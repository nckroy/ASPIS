// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Known answers for Ed25519 verification (RFC 8032, section 7.1), from
//! `tests/data/rfc8032.json` (ADR 0069, rule 7), and the refusal of every
//! non-canonical or weak form (rule 5). Signing is crate-private; its
//! known answers are in `src/kat.rs`.

mod common;

use aspis_crypto::Error;
use aspis_crypto::ed25519::{Ed25519Signature, Ed25519VerifyingKey};
use common::{field, hex, vectors};
use curve25519_dalek::constants::EIGHT_TORSION;
use curve25519_dalek::edwards::CompressedEdwardsY;

const RFC8032: &str = include_str!("data/rfc8032.json");

/// ℓ, the order of the prime-order subgroup (RFC 8032, section 5.1),
/// little-endian.
const L: &str = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";

/// a + b, little-endian, for values that fit in 256 bits.
fn add_le(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let s = a[i] as u16 + b[i] as u16 + carry;
        out[i] = s as u8;
        carry = s >> 8;
    }
    assert_eq!(carry, 0);
    out
}

/// A test of the RFC's: its name, key, message and signature.
type Case = (String, Vec<u8>, Vec<u8>, Vec<u8>);

/// The RFC's tests.
fn rfc_tests() -> Vec<Case> {
    let v = vectors(RFC8032);
    v.get("tests")
        .as_array()
        .iter()
        .map(|t| {
            (
                t.get("tcId").as_str().to_string(),
                field(t, "publicKey"),
                field(t, "message"),
                field(t, "signature"),
            )
        })
        .collect()
}

#[test]
fn rfc8032_7_1() {
    let tests = rfc_tests();
    assert_eq!(tests.len(), 5);
    for (id, pk, msg, sig) in tests {
        let key = Ed25519VerifyingKey::from_bytes(&pk).unwrap();
        let s = Ed25519Signature::from_bytes(&sig).unwrap();
        assert_eq!(key.verify(&msg, &s), Ok(()), "{id}");
        assert_eq!(key.to_bytes().as_slice(), pk.as_slice(), "{id}");
        assert_eq!(s.to_bytes().as_slice(), sig.as_slice(), "{id}");
    }
}

/// A flipped bit anywhere fails: in the message, R or s. A flip in R or s
/// may already fail at decoding; it never verifies.
#[test]
fn tampering() {
    for (id, pk, msg, sig) in rfc_tests() {
        let key = Ed25519VerifyingKey::from_bytes(&pk).unwrap();
        let good = Ed25519Signature::from_bytes(&sig).unwrap();
        let mut m = msg.clone();
        match m.first_mut() {
            Some(b) => *b ^= 1,
            None => m.push(0),
        }
        assert_eq!(key.verify(&m, &good), Err(Error::Verification), "{id}");
        for i in [0, 17, 31, 32, 45, 63] {
            for bit in [0, 6] {
                let mut s = sig.clone();
                s[i] ^= 1 << bit;
                let r = Ed25519Signature::from_bytes(&s).and_then(|s| key.verify(&msg, &s));
                assert!(
                    matches!(r, Err(Error::Encoding | Error::Verification)),
                    "{id}, octet {i}, bit {bit}: {r:?}"
                );
            }
        }
    }
}

/// The eight points of small order, in their canonical encodings, are
/// weak keys (rule 5).
#[test]
fn small_order_keys_refused() {
    for p in EIGHT_TORSION {
        let enc = p.compress().to_bytes();
        assert_eq!(
            Ed25519VerifyingKey::from_bytes(&enc),
            Err(Error::WeakKey),
            "{enc:02x?}"
        );
    }
}

/// Non-canonical encodings of points are refused (RFC 8032, section
/// 5.1.3): y + p for the small y on the curve, either sign, and x = 0 with
/// the sign bit set. Each is first shown to decompress under the plain
/// rules that the library would otherwise accept.
#[test]
fn non_canonical_keys_refused() {
    let p: [u8; 32] = hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
        .try_into()
        .unwrap();
    let mut found = 0;
    for v in 0..19u8 {
        let mut y = p;
        y[0] += v;
        for sign in [0, 0x80] {
            let mut enc = y;
            enc[31] |= sign;
            if CompressedEdwardsY(enc).decompress().is_none() {
                continue;
            }
            found += 1;
            assert_eq!(
                Ed25519VerifyingKey::from_bytes(&enc),
                Err(Error::Encoding),
                "y = p + {v}, sign {sign:#x}"
            );
        }
    }
    // y = 0 and y = 1 are on the curve, so at least those forms exist.
    assert!(found >= 2, "{found}");

    // x = 0 with the sign bit set: y = 1 and y = p − 1.
    for enc in [
        "0100000000000000000000000000000000000000000000000000000000000080",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ] {
        let enc: [u8; 32] = hex(enc).try_into().unwrap();
        assert!(CompressedEdwardsY(enc).decompress().is_some());
        assert_eq!(Ed25519VerifyingKey::from_bytes(&enc), Err(Error::Encoding));
    }
}

/// s at or above ℓ is refused (RFC 8032, section 5.1.7).
#[test]
fn non_canonical_s_refused() {
    let l: [u8; 32] = hex(L).try_into().unwrap();
    for (id, _, _, sig) in rfc_tests() {
        let s: [u8; 32] = sig[32..].try_into().unwrap();
        for bad in [add_le(&s, &l), l] {
            let mut forged = sig.clone();
            forged[32..].copy_from_slice(&bad);
            assert_eq!(
                Ed25519Signature::from_bytes(&forged),
                Err(Error::Encoding),
                "{id}"
            );
        }
    }
}

/// An R that isn't a canonical point encoding is refused at decoding: a
/// non-canonical form of a point, or a y that isn't on the curve.
#[test]
fn non_canonical_r_refused() {
    let (_, _, _, sig) = &rfc_tests()[0];
    // y = 1 + p, a non-canonical form of the identity.
    let non_canonical = hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    let off_curve = (2..=255u8)
        .map(|y| {
            let mut enc = [0; 32];
            enc[0] = y;
            enc
        })
        .find(|enc| CompressedEdwardsY(*enc).decompress().is_none())
        .unwrap();
    for r in [non_canonical.as_slice(), off_curve.as_slice()] {
        let mut forged = sig.clone();
        forged[..32].copy_from_slice(r);
        assert_eq!(Ed25519Signature::from_bytes(&forged), Err(Error::Encoding));
    }
}

/// A small-order R decodes, since its encoding is canonical, but never
/// verifies: strict verification refuses it.
#[test]
fn small_order_r_refused() {
    let (_, pk, msg, _) = &rfc_tests()[0];
    let key = Ed25519VerifyingKey::from_bytes(pk).unwrap();
    for p in EIGHT_TORSION {
        let mut forged = [0; 64];
        forged[..32].copy_from_slice(p.compress().as_bytes());
        let sig = Ed25519Signature::from_bytes(&forged).unwrap();
        assert_eq!(key.verify(msg, &sig), Err(Error::Verification));
    }
}

#[test]
fn lengths() {
    let (_, pk, _, sig) = &rfc_tests()[0];
    for n in [0, 31, 33] {
        let mut k = pk.clone();
        k.resize(n, 0);
        assert_eq!(Ed25519VerifyingKey::from_bytes(&k), Err(Error::Length));
    }
    for n in [0, 63, 65] {
        let mut s = sig.clone();
        s.resize(n, 0);
        assert_eq!(Ed25519Signature::from_bytes(&s), Err(Error::Length));
    }
}
