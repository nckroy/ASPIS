// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Known answers for HMAC (RFC 4231, section 4) and HKDF (RFC 5869,
//! Appendix A), from `tests/data/` (ADR 0069, rule 7).

mod common;

use aspis_crypto::Error;
use aspis_crypto::mac::{
    HmacSha256, HmacSha384, HmacSha512, Prk256, Prk384, hkdf_sha256_extract, hkdf_sha384_extract,
    hmac_sha256, hmac_sha384, hmac_sha512,
};
use common::{field, vectors};

const RFC4231: &str = include_str!("data/rfc4231.json");
const RFC5869: &str = include_str!("data/rfc5869.json");

#[test]
fn rfc4231_hmac() {
    let v = vectors(RFC4231);
    let tests = v.get("tests").as_array();
    assert_eq!(tests.len(), 7);
    for t in tests {
        let (key, data) = (field(t, "key"), field(t, "data"));
        // Test Case 5 gives only the first 128 bits of each tag.
        let n = t.try_get("truncatedTo").map(|n| n.as_u64() as usize);
        let cut = |tag: &[u8]| tag[..n.unwrap_or(tag.len())].to_vec();
        let id = t.get("tcId").as_str();
        assert_eq!(
            cut(&hmac_sha256(&key, &data)),
            field(t, "hmacSha256"),
            "{id}"
        );
        assert_eq!(
            cut(&hmac_sha384(&key, &data)),
            field(t, "hmacSha384"),
            "{id}"
        );
        assert_eq!(
            cut(&hmac_sha512(&key, &data)),
            field(t, "hmacSha512"),
            "{id}"
        );

        // The incremental states agree, split anywhere.
        let mid = data.len() / 3;
        let mut h = HmacSha256::new(&key);
        h.update(&data[..mid]);
        h.update(&data[mid..]);
        assert_eq!(h.finalize(), hmac_sha256(&key, &data));
        let mut h = HmacSha384::new(&key);
        h.update(&data[..mid]);
        h.update(&data[mid..]);
        assert_eq!(h.finalize(), hmac_sha384(&key, &data));
        let mut h = HmacSha512::new(&key);
        h.update(&data[..mid]);
        h.update(&data[mid..]);
        assert_eq!(h.finalize(), hmac_sha512(&key, &data));
    }
}

#[test]
fn hmac_verify() {
    let v = vectors(RFC4231);
    let t = &v.get("tests").as_array()[1];
    let (key, data) = (field(t, "key"), field(t, "data"));
    let check256 = |tag: &[u8]| {
        let mut h = HmacSha256::new(&key);
        h.update(&data);
        h.verify(tag)
    };
    let good = field(t, "hmacSha256");
    assert_eq!(check256(&good), Ok(()));
    for bit in [0, 7, 100, 255] {
        let mut bad = good.clone();
        bad[bit / 8] ^= 1 << (bit % 8);
        assert_eq!(check256(&bad), Err(Error::Verification));
    }
    // A truncated or extended tag doesn't verify, even when it is a
    // prefix of the right one.
    assert_eq!(check256(&good[..16]), Err(Error::Verification));
    assert_eq!(check256(&[]), Err(Error::Verification));
    let mut long = good.clone();
    long.push(0);
    assert_eq!(check256(&long), Err(Error::Verification));

    let good = field(t, "hmacSha384");
    let mut h = HmacSha384::new(&key);
    h.update(&data);
    assert_eq!(h.verify(&good), Ok(()));
    let mut h = HmacSha384::new(&key);
    h.update(&data);
    assert_eq!(h.verify(&good[..47]), Err(Error::Verification));

    let good = field(t, "hmacSha512");
    let mut h = HmacSha512::new(&key);
    h.update(&data);
    assert_eq!(h.verify(&good), Ok(()));
    let mut bad = good.clone();
    bad[63] ^= 0x80;
    let mut h = HmacSha512::new(&key);
    h.update(&data);
    assert_eq!(h.verify(&bad), Err(Error::Verification));
}

#[test]
fn rfc5869_hkdf_sha256() {
    let v = vectors(RFC5869);
    let tests = v.get("tests").as_array();
    assert_eq!(tests.len(), 3);
    for t in tests {
        let id = t.get("tcId").as_str();
        assert_eq!(t.get("hash").as_str(), "SHA-256");
        let (ikm, salt, info) = (field(t, "ikm"), field(t, "salt"), field(t, "info"));
        let prk = hkdf_sha256_extract(Some(&salt), &ikm);
        assert_eq!(prk.as_bytes().to_vec(), field(t, "prk"), "{id}");
        let mut okm = vec![0u8; t.get("l").as_u64() as usize];
        prk.expand(&info, &mut okm).unwrap();
        assert_eq!(okm, field(t, "okm"), "{id}");

        // A PRK given directly expands the same way (RFC 5869, section 3.3).
        let again = Prk256::from_bytes(prk.as_bytes());
        assert_eq!(again, prk);
        let mut okm2 = vec![0u8; okm.len()];
        again.expand(&info, &mut okm2).unwrap();
        assert_eq!(okm2, okm);
    }
    // Test Case 3's empty salt is the same as no salt: HashLen zeros
    // (RFC 5869, section 2.2).
    let t = &tests[2];
    let ikm = field(t, "ikm");
    assert_eq!(
        hkdf_sha256_extract(None, &ikm).as_bytes().to_vec(),
        field(t, "prk")
    );
    assert_eq!(
        hkdf_sha256_extract(Some(&[0; 32]), &ikm)
            .as_bytes()
            .to_vec(),
        field(t, "prk")
    );
}

#[test]
fn hkdf_output_limit() {
    let prk = hkdf_sha256_extract(None, b"ikm");
    assert_eq!(Prk256::MAX_OUTPUT, 255 * 32);
    let mut okm = vec![0u8; Prk256::MAX_OUTPUT];
    assert_eq!(prk.expand(b"", &mut okm), Ok(()));
    let mut okm = vec![0xAAu8; Prk256::MAX_OUTPUT + 1];
    assert_eq!(prk.expand(b"", &mut okm), Err(Error::OutputLength));
    assert!(okm.iter().all(|&b| b == 0xAA), "okm left untouched");

    let prk = hkdf_sha384_extract(None, b"ikm");
    assert_eq!(Prk384::MAX_OUTPUT, 255 * 48);
    let mut okm = vec![0u8; Prk384::MAX_OUTPUT];
    assert_eq!(prk.expand(b"", &mut okm), Ok(()));
    let mut okm = vec![0u8; Prk384::MAX_OUTPUT + 1];
    assert_eq!(prk.expand(b"", &mut okm), Err(Error::OutputLength));
    // Zero octets of output are allowed.
    assert_eq!(prk.expand(b"", &mut []), Ok(()));
}

/// The clearing forms of HKDF-Expand give the same octets as `expand`.
#[test]
fn hkdf_expand_into_secrets() {
    let prk = hkdf_sha256_extract(Some(b"salt"), b"ikm");
    let mut okm = [0u8; 44];
    prk.expand(b"info", &mut okm).unwrap();
    assert_eq!(*prk.expand_array::<44>(b"info").unwrap(), okm);
    assert_eq!(prk.expand_prk(b"info").as_bytes()[..], okm[..32]);
    assert_eq!(
        prk.expand_array::<{ Prk256::MAX_OUTPUT + 1 }>(b"")
            .map(|_| ()),
        Err(Error::OutputLength)
    );

    let prk = hkdf_sha384_extract(Some(b"salt"), b"ikm");
    let mut okm = [0u8; 48];
    prk.expand(b"info", &mut okm).unwrap();
    assert_eq!(prk.expand_prk(b"info").as_bytes(), &okm);
}

/// RFC 5869 has no SHA-384 vector, so HKDF-SHA-384 is checked against its
/// definition built from HMAC-SHA-384, whose RFC 4231 answers pass above:
/// PRK = HMAC(salt, IKM), and T(i) = HMAC(PRK, T(i-1) ‖ info ‖ i)
/// (RFC 5869, sections 2.2 and 2.3). C71's differential tests cover it
/// against libcrux too.
#[test]
fn hkdf_sha384_construction() {
    let (salt, ikm, info) = (
        b"salt octets".as_slice(),
        [0x0bu8; 22],
        b"context".as_slice(),
    );
    let prk = hkdf_sha384_extract(Some(salt), &ikm);
    assert_eq!(*prk.as_bytes(), hmac_sha384(salt, &ikm));
    // An absent salt is HashLen zero octets.
    assert_eq!(
        *hkdf_sha384_extract(None, &ikm).as_bytes(),
        hmac_sha384(&[0; 48], &ikm)
    );

    let len = 3 * 48 + 5;
    let mut expect = Vec::new();
    let mut prev: Vec<u8> = Vec::new();
    for i in 1..=4u8 {
        let mut h = HmacSha384::new(prk.as_bytes());
        h.update(&prev);
        h.update(info);
        h.update(&[i]);
        prev = h.finalize().to_vec();
        expect.extend_from_slice(&prev);
    }
    expect.truncate(len);
    let mut okm = vec![0u8; len];
    prk.expand(info, &mut okm).unwrap();
    assert_eq!(okm, expect);
}
