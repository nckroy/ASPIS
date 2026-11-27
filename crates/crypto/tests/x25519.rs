// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Known answers for X25519 (RFC 7748, sections 5.2 and 6.1), from
//! `tests/data/rfc7748.json` (ADR 0069, rule 7), and the refusal of an
//! all-zero shared secret (rule 5).

mod common;

use aspis_crypto::Error;
use aspis_crypto::x25519::{X25519PublicKey, X25519SecretKey};
use common::{array, hex, vectors};

const RFC7748: &str = include_str!("data/rfc7748.json");

/// RFC 7748's X25519(k, u), through the public API.
fn x25519(k: &[u8; 32], u: &[u8; 32]) -> Result<[u8; 32], Error> {
    let peer = X25519PublicKey::from_bytes(u)?;
    X25519SecretKey::from_seed(k)
        .diffie_hellman(&peer)
        .map(|s| *s.as_bytes())
}

#[test]
fn rfc7748_5_2() {
    let v = vectors(RFC7748);
    let mut n = 0;
    for t in v.get("tests").as_array() {
        if t.try_get("inputScalar").is_none() {
            continue;
        }
        n += 1;
        let k = array::<32>(t, "inputScalar");
        let u = array::<32>(t, "inputUCoordinate");
        assert_eq!(
            x25519(&k, &u).unwrap(),
            array::<32>(t, "outputUCoordinate"),
            "{}",
            t.get("tcId").as_str()
        );
    }
    assert_eq!(n, 2);
}

/// RFC 7748, section 5.2's iterated test: k and u start at 9; each round
/// sets k to X25519(k, u) and u to the old k. The 1,000,000-round result is
/// in the file but not run per change: it takes minutes.
#[test]
fn rfc7748_iterated_1_and_1000() {
    let v = vectors(RFC7748);
    let mut ran = 0;
    for t in v.get("tests").as_array() {
        let Some(rounds) = t.try_get("iterations").map(|n| n.as_u64()) else {
            continue;
        };
        if rounds > 1000 {
            continue;
        }
        let mut k = array::<32>(t, "initialK");
        let mut u = array::<32>(t, "initialU");
        for _ in 0..rounds {
            let next = x25519(&k, &u).unwrap();
            u = k;
            k = next;
        }
        assert_eq!(k, array::<32>(t, "result"), "{}", t.get("tcId").as_str());
        ran += 1;
    }
    assert_eq!(ran, 2);
}

#[test]
fn rfc7748_6_1() {
    let v = vectors(RFC7748);
    let t = v
        .get("tests")
        .as_array()
        .iter()
        .find(|t| t.get("tcId").as_str() == "Section 6.1")
        .unwrap();
    let alice = X25519SecretKey::from_seed(&array(t, "alicePrivateKey"));
    let bob = X25519SecretKey::from_seed(&array(t, "bobPrivateKey"));
    assert_eq!(
        alice.public_key().to_bytes(),
        array::<32>(t, "alicePublicKey")
    );
    assert_eq!(bob.public_key().to_bytes(), array::<32>(t, "bobPublicKey"));
    let k = array::<32>(t, "sharedSecret");
    let alice_bob = X25519PublicKey::from_bytes(&array::<32>(t, "bobPublicKey")).unwrap();
    let bob_alice = X25519PublicKey::from_bytes(&array::<32>(t, "alicePublicKey")).unwrap();
    assert_eq!(alice.diffie_hellman(&alice_bob).unwrap().as_bytes(), &k);
    assert_eq!(bob.diffie_hellman(&bob_alice).unwrap().as_bytes(), &k);
}

/// The u-coordinates of small order, and their forms with the top bit set
/// (which RFC 7748, section 5 masks): 0, 1, the two points of order 8,
/// and p − 1, p and p + 1. X25519 of each is zero for every scalar, so the
/// exchange is refused (RFC 7748, section 6.1; ADR 0069, rule 5). These are
/// the values of libsodium's and Wycheproof's lists; that each gives zero
/// is checked here, not taken on trust.
#[test]
fn all_zero_refused() {
    let small = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];
    let v = vectors(RFC7748);
    let t = &v.get("tests").as_array()[0];
    let k = array::<32>(t, "inputScalar");
    for u in small {
        let mut u: [u8; 32] = hex(u).try_into().unwrap();
        assert_eq!(x25519(&k, &u), Err(Error::NonContributory), "{u:02x?}");
        u[31] |= 0x80;
        assert_eq!(x25519(&k, &u), Err(Error::NonContributory), "{u:02x?}");
    }
}

#[test]
fn public_key_lengths() {
    for n in [0, 31, 33, 64] {
        assert_eq!(
            X25519PublicKey::from_bytes(&vec![9; n]),
            Err(Error::Length),
            "{n}"
        );
    }
    // Every 32 octets are a key, kept as given, top bit and all.
    let mut b = [0xff; 32];
    b[0] = 9;
    let key = X25519PublicKey::from_bytes(&b).unwrap();
    assert_eq!(key.to_bytes(), b);
}
