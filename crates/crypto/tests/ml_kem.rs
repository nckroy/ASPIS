// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Known answers for ML-KEM-768 (FIPS 203), from NIST's ACVP vectors in
//! `tests/data/acvp/` (ADR 0069, rule 7), and the checks of rule 5. The
//! decapsulation vectors use expanded keys, which the public API never
//! takes; they run in `src/kat.rs`.

mod common;

use aspis_crypto::Error;
use aspis_crypto::hash::shake256;
use aspis_crypto::ml_kem::{
    CIPHERTEXT_LEN, ENCAPSULATION_KEY_LEN, MlKem768Ciphertext, MlKem768DecapsulationKey,
    MlKem768EncapsulationKey,
};
use common::{Value, array, field, vectors};

const KEYGEN: &str = include_str!("data/acvp/ml-kem-768-keygen.json");
const ENCAP_DECAP: &str = include_str!("data/acvp/ml-kem-768-encapdecap.json");

/// The tests of every group whose `function` is `function`, or of every
/// group if it is `None`.
fn tests(v: &Value, function: Option<&str>) -> Vec<Value> {
    v.get("testGroups")
        .as_array()
        .iter()
        .filter(|g| function.is_none_or(|f| g.get("function").as_str() == f))
        .flat_map(|g| g.get("tests").as_array().to_vec())
        .collect()
}

/// The keyGen vectors' seeds d ‖ z (FIPS 203, Algorithm 16).
fn seed(t: &Value) -> [u8; 64] {
    let mut s = field(t, "d");
    s.extend(field(t, "z"));
    s.try_into().unwrap()
}

#[test]
fn acvp_keygen() {
    let v = vectors(KEYGEN);
    let tests = tests(&v, None);
    assert_eq!(tests.len(), 5);
    for t in &tests {
        let dk = MlKem768DecapsulationKey::from_seed(&seed(t));
        assert_eq!(
            dk.encapsulation_key().to_bytes().as_slice(),
            field(t, "ek").as_slice(),
            "tcId {}",
            t.get("tcId").as_u64()
        );
        assert_eq!(*dk.to_seed(), seed(t));
    }
}

#[test]
fn acvp_encapsulation() {
    let v = vectors(ENCAP_DECAP);
    let tests = tests(&v, Some("encapsulation"));
    assert_eq!(tests.len(), 5);
    for t in &tests {
        let ek = MlKem768EncapsulationKey::from_bytes(&field(t, "ek")).unwrap();
        let (ct, k) = ek.encapsulate(&array(t, "m"));
        let id = t.get("tcId").as_u64();
        assert_eq!(
            ct.to_bytes().as_slice(),
            field(t, "c").as_slice(),
            "tcId {id}"
        );
        assert_eq!(k.as_bytes(), &array::<32>(t, "k"), "tcId {id}");
    }
}

/// FIPS 203, section 7.2's modulus check: a key is accepted exactly when
/// the vector says it passes, and a refused one is `Modulus`.
#[test]
fn acvp_encapsulation_key_check() {
    let v = vectors(ENCAP_DECAP);
    let tests = tests(&v, Some("encapsulationKeyCheck"));
    assert_eq!(tests.len(), 10);
    let mut refused = 0;
    for t in &tests {
        let ek = field(t, "ek");
        let r = MlKem768EncapsulationKey::from_bytes(&ek);
        let id = t.get("tcId").as_u64();
        if t.get("testPassed").as_bool() {
            assert_eq!(r.unwrap().to_bytes().as_slice(), ek.as_slice(), "tcId {id}");
        } else {
            assert_eq!(r, Err(Error::Modulus), "tcId {id}");
            refused += 1;
        }
    }
    assert_eq!(refused, 5);
}

#[test]
fn round_trip() {
    let v = vectors(KEYGEN);
    for (i, t) in tests(&v, None).iter().enumerate() {
        let dk = MlKem768DecapsulationKey::from_seed(&seed(t));
        let (ct, k) = dk.encapsulation_key().encapsulate(&[i as u8; 32]);
        assert_eq!(dk.decapsulate(&ct), k);
        let again = MlKem768Ciphertext::from_bytes(&ct.to_bytes()).unwrap();
        assert_eq!(again, ct);
    }
}

/// A ciphertext with one bit flipped decapsulates to J(z ‖ c′), the first
/// 32 octets of SHAKE256(z ‖ c′) (FIPS 203, Algorithm 18, implicit
/// rejection), which differs from the secret.
#[test]
fn implicit_rejection() {
    let v = vectors(KEYGEN);
    let t = &tests(&v, None)[0];
    let dk = MlKem768DecapsulationKey::from_seed(&seed(t));
    let (ct, k) = dk.encapsulation_key().encapsulate(&[7; 32]);
    for i in [0, 500, CIPHERTEXT_LEN - 1] {
        let mut c = ct.to_bytes();
        c[i] ^= 0x10;
        let forged = MlKem768Ciphertext::from_bytes(&c).unwrap();
        let mut input = field(t, "z");
        input.extend_from_slice(&c);
        let mut expected = [0; 32];
        shake256(&input, &mut expected);
        let got = dk.decapsulate(&forged);
        assert_eq!(got.as_bytes(), &expected, "octet {i}");
        assert_ne!(got, k);
    }
}

#[test]
fn lengths() {
    let v = vectors(KEYGEN);
    let ek = field(&tests(&v, None)[0], "ek");
    assert_eq!(ek.len(), ENCAPSULATION_KEY_LEN);
    for n in [0, ENCAPSULATION_KEY_LEN - 1, ENCAPSULATION_KEY_LEN + 1] {
        let mut k = ek.clone();
        k.resize(n, 0);
        assert_eq!(MlKem768EncapsulationKey::from_bytes(&k), Err(Error::Length));
    }
    for n in [0, CIPHERTEXT_LEN - 1, CIPHERTEXT_LEN + 1] {
        assert_eq!(
            MlKem768Ciphertext::from_bytes(&vec![0; n]),
            Err(Error::Length)
        );
    }
}
