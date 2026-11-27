// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The hybrid key exchange X25519MLKEM768 (RFC 10024; ADR 0069, rules 5
//! and 7).
//!
//! RFC 10024 has no test vectors. So the known answers come by
//! composition: with fixed inputs, each share and the secret must equal
//! the concatenation, ML-KEM first, of the component wrappers' outputs,
//! which match NIST's ACVP ML-KEM-768 vectors and RFC 7748's X25519
//! vectors (`tests/ml_kem.rs`, `tests/x25519.rs`). The inputs are taken
//! from those vector files. The rest checks RFC 10024's refusals and
//! ML-KEM's implicit rejection through the hybrid.

mod common;

use aspis_crypto::Error;
use aspis_crypto::hash::shake256;
use aspis_crypto::hybrid::{
    CLIENT_SHARE_LEN, SERVER_SHARE_LEN, SHARED_SECRET_LEN, X25519MlKem768ClientShare,
    X25519MlKem768DecapsulationKey, X25519MlKem768ServerShare,
};
use aspis_crypto::ml_kem::{
    CIPHERTEXT_LEN, ENCAPSULATION_KEY_LEN, MlKem768Ciphertext, MlKem768DecapsulationKey,
};
use aspis_crypto::x25519::{KEY_LEN, X25519PublicKey, X25519SecretKey};
use common::{Value, array, field, hex, vectors};

const RFC7748: &str = include_str!("data/rfc7748.json");
const KEYGEN: &str = include_str!("data/acvp/ml-kem-768-keygen.json");
const ENCAP_DECAP: &str = include_str!("data/acvp/ml-kem-768-encapdecap.json");

/// The tests of every group whose `function` is `function`, or of every
/// group if it is `None`.
fn acvp(text: &str, function: Option<&str>) -> Vec<Value> {
    vectors(text)
        .get("testGroups")
        .as_array()
        .iter()
        .filter(|g| function.is_none_or(|f| g.get("function").as_str() == f))
        .flat_map(|g| g.get("tests").as_array().to_vec())
        .collect()
}

/// A keyGen vector's seed d ‖ z (FIPS 203, Algorithm 16).
fn seed(t: &Value) -> [u8; 64] {
    let mut s = field(t, "d");
    s.extend(field(t, "z"));
    s.try_into().unwrap()
}

/// RFC 7748, section 6.1's test object: Alice's and Bob's keys and their
/// shared secret.
fn rfc7748_6_1() -> Value {
    vectors(RFC7748)
        .get("tests")
        .as_array()
        .iter()
        .find(|t| t.get("tcId").as_str() == "Section 6.1")
        .unwrap()
        .clone()
}

/// `a` ‖ `b`.
fn cat(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = a.to_vec();
    out.extend_from_slice(b);
    out
}

/// The u-coordinates of small order, as in `tests/x25519.rs`: X25519 of
/// each is zero for every scalar.
const SMALL_ORDER: [&str; 7] = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

/// The sizes of RFC 10024, sections 4.1 to 4.3.
#[test]
fn sizes() {
    assert_eq!(CLIENT_SHARE_LEN, 1216);
    assert_eq!(SERVER_SHARE_LEN, 1120);
    assert_eq!(SHARED_SECRET_LEN, 64);
}

/// The client share is ACVP's encapsulation key for d ‖ z, then RFC 7748,
/// section 6.1's public key for the X25519 secret key (RFC 10024, section
/// 4.1).
#[test]
fn client_share_by_composition() {
    let x = rfc7748_6_1();
    let tests = acvp(KEYGEN, None);
    assert_eq!(tests.len(), 5);
    for (i, t) in tests.iter().enumerate() {
        let (sk, pk) = if i % 2 == 0 {
            ("alicePrivateKey", "alicePublicKey")
        } else {
            ("bobPrivateKey", "bobPublicKey")
        };
        let dk = X25519MlKem768DecapsulationKey::from_seed(&seed(t), &array(&x, sk));
        let share = dk.client_share().to_bytes();
        assert_eq!(
            share.as_slice(),
            cat(&field(t, "ek"), &field(&x, pk)).as_slice(),
            "tcId {}",
            t.get("tcId").as_u64()
        );
    }
}

/// The server's side: ACVP's encapsulation vectors (ek, m, c, k) with RFC
/// 7748, section 6.1's keys, Alice's in the client share and Bob's as the
/// server's ephemeral. The server share is c ‖ Bob's public key, and the
/// secret k ‖ K (RFC 10024, sections 4.2 and 4.3).
#[test]
fn encapsulation_by_composition() {
    let x = rfc7748_6_1();
    let tests = acvp(ENCAP_DECAP, Some("encapsulation"));
    assert_eq!(tests.len(), 5);
    for t in &tests {
        let id = t.get("tcId").as_u64();
        let client = cat(&field(t, "ek"), &field(&x, "alicePublicKey"));
        let client = X25519MlKem768ClientShare::from_bytes(&client).unwrap();
        let (server, secret) = client
            .encapsulate(&array(t, "m"), &array(&x, "bobPrivateKey"))
            .unwrap();
        assert_eq!(
            server.to_bytes().as_slice(),
            cat(&field(t, "c"), &field(&x, "bobPublicKey")).as_slice(),
            "tcId {id}"
        );
        assert_eq!(
            secret.as_bytes().as_slice(),
            cat(&field(t, "k"), &field(&x, "sharedSecret")).as_slice(),
            "tcId {id}"
        );
    }
}

/// The client's side: for each ACVP keyGen seed with Alice's X25519 key,
/// a server share made by the component wrappers, with Bob's key,
/// decapsulates to ML-KEM's secret ‖ RFC 7748, section 6.1's K.
#[test]
fn decapsulation_by_composition() {
    let x = rfc7748_6_1();
    for (i, t) in acvp(KEYGEN, None).iter().enumerate() {
        let ml_kem = MlKem768DecapsulationKey::from_seed(&seed(t));
        let (ct, k) = ml_kem.encapsulation_key().encapsulate(&[i as u8 + 1; 32]);
        let bob = X25519SecretKey::from_seed(&array(&x, "bobPrivateKey"));
        let server = cat(&ct.to_bytes(), &bob.public_key().to_bytes());
        let server = X25519MlKem768ServerShare::from_bytes(&server).unwrap();
        let client =
            X25519MlKem768DecapsulationKey::from_seed(&seed(t), &array(&x, "alicePrivateKey"));
        let secret = client.decapsulate(&server).unwrap();
        assert_eq!(
            secret.as_bytes().as_slice(),
            cat(k.as_bytes(), &field(&x, "sharedSecret")).as_slice(),
            "tcId {}",
            t.get("tcId").as_u64()
        );
    }
}

/// Both sides reach the same secret, and the shares re-encode to
/// themselves.
#[test]
fn round_trip() {
    for i in 0..8u8 {
        let client = X25519MlKem768DecapsulationKey::from_seed(&[i; 64], &[i ^ 0x80; 32]);
        let share = client.client_share();
        let decoded = X25519MlKem768ClientShare::from_bytes(&share.to_bytes()).unwrap();
        assert_eq!(decoded, share);
        let (server, secret) = decoded
            .encapsulate(&[i ^ 0x33; 32], &[i ^ 0x44; 32])
            .unwrap();
        let decoded = X25519MlKem768ServerShare::from_bytes(&server.to_bytes()).unwrap();
        assert_eq!(decoded, server);
        assert_eq!(client.decapsulate(&decoded).unwrap(), secret);
    }
}

/// Every length but the exact one is refused, at each boundary: empty,
/// each component's own length, one short and one long (RFC 10024,
/// sections 4.1 and 4.2).
#[test]
fn lengths() {
    let client = X25519MlKem768DecapsulationKey::from_seed(&[1; 64], &[2; 32]);
    let share = client.client_share().to_bytes();
    for n in [
        0,
        KEY_LEN,
        ENCAPSULATION_KEY_LEN - 1,
        ENCAPSULATION_KEY_LEN,
        ENCAPSULATION_KEY_LEN + 1,
        CLIENT_SHARE_LEN - 1,
        CLIENT_SHARE_LEN + 1,
        CLIENT_SHARE_LEN + KEY_LEN,
    ] {
        let mut s = share.to_vec();
        s.resize(n, 0);
        assert_eq!(
            X25519MlKem768ClientShare::from_bytes(&s),
            Err(Error::Length),
            "client share of {n}"
        );
    }
    let (server, _) = client
        .client_share()
        .encapsulate(&[3; 32], &[4; 32])
        .unwrap();
    let server = server.to_bytes();
    for n in [
        0,
        KEY_LEN,
        CIPHERTEXT_LEN - 1,
        CIPHERTEXT_LEN,
        CIPHERTEXT_LEN + 1,
        SERVER_SHARE_LEN - 1,
        SERVER_SHARE_LEN + 1,
        CLIENT_SHARE_LEN,
    ] {
        let mut s = server.to_vec();
        s.resize(n, 0);
        assert_eq!(
            X25519MlKem768ServerShare::from_bytes(&s),
            Err(Error::Length),
            "server share of {n}"
        );
    }
    // A server share isn't a client share, nor the reverse.
    assert_eq!(
        X25519MlKem768ClientShare::from_bytes(&server),
        Err(Error::Length)
    );
    assert_eq!(
        X25519MlKem768ServerShare::from_bytes(&share),
        Err(Error::Length)
    );
}

/// The server's modulus check on the client's encapsulation key (RFC
/// 10024, section 4.2; FIPS 203, section 7.2): ACVP's key-check vectors,
/// each in a client share with a valid X25519 key, are accepted exactly
/// when the vector passes, and refused with `Modulus` otherwise.
#[test]
fn modulus_check() {
    let x = rfc7748_6_1();
    let tests = acvp(ENCAP_DECAP, Some("encapsulationKeyCheck"));
    assert_eq!(tests.len(), 10);
    let mut refused = 0;
    for t in &tests {
        let share = cat(&field(t, "ek"), &field(&x, "alicePublicKey"));
        let r = X25519MlKem768ClientShare::from_bytes(&share);
        let id = t.get("tcId").as_u64();
        if t.get("testPassed").as_bool() {
            assert_eq!(
                r.unwrap().to_bytes().as_slice(),
                share.as_slice(),
                "tcId {id}"
            );
        } else {
            assert_eq!(r, Err(Error::Modulus), "tcId {id}");
            refused += 1;
        }
    }
    assert_eq!(refused, 5);
}

/// A small-order X25519 key in either share gives an all-zero X25519
/// secret, which is refused with `NonContributory` on both sides (RFC
/// 10024, section 4.3). Its form with the top bit set is refused too.
#[test]
fn all_zero_refused() {
    let client = X25519MlKem768DecapsulationKey::from_seed(&[5; 64], &[6; 32]);
    let share = client.client_share().to_bytes();
    let (server, _) = client
        .client_share()
        .encapsulate(&[7; 32], &[8; 32])
        .unwrap();
    let server = server.to_bytes();
    for u in SMALL_ORDER {
        let mut u: [u8; 32] = hex(u).try_into().unwrap();
        for _ in 0..2 {
            let c = cat(&share[..ENCAPSULATION_KEY_LEN], &u);
            let c = X25519MlKem768ClientShare::from_bytes(&c).unwrap();
            assert_eq!(
                c.encapsulate(&[7; 32], &[8; 32]).map(|_| ()),
                Err(Error::NonContributory),
                "client share with {u:02x?}"
            );
            let s = cat(&server[..CIPHERTEXT_LEN], &u);
            let s = X25519MlKem768ServerShare::from_bytes(&s).unwrap();
            assert_eq!(
                client.decapsulate(&s).map(|_| ()),
                Err(Error::NonContributory),
                "server share with {u:02x?}"
            );
            u[31] |= 0x80;
        }
    }
}

/// Tampering with either half of the server share changes the secret, in
/// that half only. A changed ciphertext gives ML-KEM's implicit rejection,
/// J(z ‖ c′), the first 32 octets of SHAKE256(z ‖ c′) (FIPS 203,
/// Algorithm 18). A changed X25519 key gives another X25519 secret.
#[test]
fn tampering_changes_the_secret() {
    let t = &acvp(KEYGEN, None)[0];
    let x = rfc7748_6_1();
    let client = X25519MlKem768DecapsulationKey::from_seed(&seed(t), &array(&x, "alicePrivateKey"));
    let (server, secret) = client
        .client_share()
        .encapsulate(&[9; 32], &array(&x, "bobPrivateKey"))
        .unwrap();
    let server = server.to_bytes();
    let (ml_kem, x25519) = secret.as_bytes().split_at(32);
    for i in [0, 500, CIPHERTEXT_LEN - 1] {
        let mut s = server;
        s[i] ^= 0x10;
        let got = client
            .decapsulate(&X25519MlKem768ServerShare::from_bytes(&s).unwrap())
            .unwrap();
        assert_ne!(got, secret, "ciphertext octet {i}");
        let mut expected = [0; 32];
        shake256(&cat(&field(t, "z"), &s[..CIPHERTEXT_LEN]), &mut expected);
        assert_eq!(&got.as_bytes()[..32], &expected, "ciphertext octet {i}");
        assert_eq!(&got.as_bytes()[32..], x25519, "ciphertext octet {i}");
    }
    for i in [CIPHERTEXT_LEN, CIPHERTEXT_LEN + 16, SERVER_SHARE_LEN - 1] {
        let mut s = server;
        s[i] ^= 0x02;
        let got = client
            .decapsulate(&X25519MlKem768ServerShare::from_bytes(&s).unwrap())
            .unwrap();
        assert_ne!(got, secret, "X25519 octet {i}");
        assert_eq!(&got.as_bytes()[..32], ml_kem, "X25519 octet {i}");
        let bob = X25519PublicKey::from_bytes(&s[CIPHERTEXT_LEN..]).unwrap();
        let alice = X25519SecretKey::from_seed(&array(&x, "alicePrivateKey"));
        let k = alice.diffie_hellman(&bob).unwrap();
        assert_eq!(&got.as_bytes()[32..], k.as_bytes(), "X25519 octet {i}");
    }
    // The ciphertext alone decapsulates to the same ML-KEM half.
    let ct = MlKem768Ciphertext::from_bytes(&server[..CIPHERTEXT_LEN]).unwrap();
    let k = MlKem768DecapsulationKey::from_seed(&seed(t)).decapsulate(&ct);
    assert_eq!(k.as_bytes().as_slice(), ml_kem);
}

/// A server share made for one client key gives another client key a
/// secret that differs in its ML-KEM half (implicit rejection), even with
/// the same X25519 key.
#[test]
fn wrong_client_key() {
    let a = X25519MlKem768DecapsulationKey::from_seed(&[1; 64], &[2; 32]);
    let b = X25519MlKem768DecapsulationKey::from_seed(&[3; 64], &[2; 32]);
    let (server, secret) = a.client_share().encapsulate(&[4; 32], &[5; 32]).unwrap();
    let got = b.decapsulate(&server).unwrap();
    assert_ne!(got, secret);
    assert_ne!(got.as_bytes()[..32], secret.as_bytes()[..32]);
    assert_eq!(got.as_bytes()[32..], secret.as_bytes()[32..]);
}
