// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Known answers for the AEADs (ADR 0069, rule 7): RFC 8439's
//! ChaCha20-Poly1305 vectors (section 2.8.2 and Appendix A.5, from
//! `tests/data/rfc8439.json`), and test cases 1 to 4 and 13 to 16 of the
//! GCM specification, the AES-128 and AES-256 cases with a 96-bit IV: D.
//! McGrew and J. Viega, "The Galois/Counter Mode of Operation (GCM)",
//! revised 2005, Appendix B. The specification states no license or
//! notice; its values are copied below with this citation. Cases 5, 6, 17
//! and 18 use 64-bit and 480-bit IVs, which the 96-bit-only API doesn't
//! take. RFC 9001's AES-128-GCM vectors are in `quic.rs`.

mod common;

use aspis_crypto::Error;
use aspis_crypto::aead::{Aes128GcmKey, Aes256GcmKey, ChaCha20Poly1305Key, TAG_LEN};
use common::{array, field, hex, vectors};

const RFC8439: &str = include_str!("data/rfc8439.json");

/// A test case: key, nonce, aad, plaintext, ciphertext and tag.
struct Case {
    key: Vec<u8>,
    nonce: [u8; 12],
    aad: Vec<u8>,
    pt: Vec<u8>,
    ct: Vec<u8>,
    tag: [u8; 16],
}

/// Any of the AEADs, so each check runs over all three. AES-GCM's key
/// schedule is far larger than ChaCha20's key, which doesn't matter in a
/// test.
#[allow(clippy::large_enum_variant)]
enum Key {
    ChaCha(ChaCha20Poly1305Key),
    Aes(Aes256GcmKey),
    Aes128(Aes128GcmKey),
}

impl Key {
    fn chacha(k: &[u8]) -> Self {
        Key::ChaCha(ChaCha20Poly1305Key::from_bytes(k.try_into().unwrap()))
    }
    /// AES-128-GCM or AES-256-GCM, by the key's length.
    fn aes(k: &[u8]) -> Self {
        match k.len() {
            16 => Key::Aes128(Aes128GcmKey::from_bytes(k.try_into().unwrap())),
            _ => Key::Aes(Aes256GcmKey::from_bytes(k.try_into().unwrap())),
        }
    }
    /// Every AEAD under keys of `octet`.
    fn all(octet: u8) -> [Self; 3] {
        [
            Key::chacha(&[octet; 32]),
            Key::aes(&[octet; 32]),
            Key::aes(&[octet; 16]),
        ]
    }
    fn seal_in_place(&self, n: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> Result<[u8; 16], Error> {
        match self {
            Key::ChaCha(k) => k.seal_in_place(n, aad, buf),
            Key::Aes(k) => k.seal_in_place(n, aad, buf),
            Key::Aes128(k) => k.seal_in_place(n, aad, buf),
        }
    }
    fn open_in_place(
        &self,
        n: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), Error> {
        match self {
            Key::ChaCha(k) => k.open_in_place(n, aad, buf, tag),
            Key::Aes(k) => k.open_in_place(n, aad, buf, tag),
            Key::Aes128(k) => k.open_in_place(n, aad, buf, tag),
        }
    }
    fn seal(&self, n: &[u8; 12], aad: &[u8], pt: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        match self {
            Key::ChaCha(k) => k.seal(n, aad, pt, out),
            Key::Aes(k) => k.seal(n, aad, pt, out),
            Key::Aes128(k) => k.seal(n, aad, pt, out),
        }
    }
    fn open(&self, n: &[u8; 12], aad: &[u8], ct: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        match self {
            Key::ChaCha(k) => k.open(n, aad, ct, out),
            Key::Aes(k) => k.open(n, aad, ct, out),
            Key::Aes128(k) => k.open(n, aad, ct, out),
        }
    }
}

fn rfc8439_cases() -> Vec<Case> {
    let v = vectors(RFC8439);
    v.get("tests")
        .as_array()
        .iter()
        .map(|t| Case {
            key: field(t, "key"),
            nonce: array(t, "nonce"),
            aad: field(t, "aad"),
            pt: field(t, "plaintext"),
            ct: field(t, "ciphertext"),
            tag: array(t, "tag"),
        })
        .collect()
}

/// The GCM specification's test cases 1 to 4 (AES-128) and 13 to 16
/// (AES-256), from Appendix B.
fn gcm_cases() -> Vec<Case> {
    let k128 = "feffe9928665731c6d6a8f9467308308";
    let k = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
    let p = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
    let c128 = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";
    let c = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad";
    let iv = "cafebabefacedbaddecaf888";
    let aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
    let case = |key: &str, nonce: &str, aad: &str, pt: &str, ct: &str, tag: &str| Case {
        key: hex(key),
        nonce: hex(nonce).try_into().unwrap(),
        aad: hex(aad),
        pt: hex(pt),
        ct: hex(ct),
        tag: hex(tag).try_into().unwrap(),
    };
    vec![
        // Test Case 1: the zero key, no plaintext.
        case(
            &"00".repeat(16),
            &"00".repeat(12),
            "",
            "",
            "",
            "58e2fccefa7e3061367f1d57a4e7455a",
        ),
        // Test Case 2: the zero key, one zero block.
        case(
            &"00".repeat(16),
            &"00".repeat(12),
            "",
            &"00".repeat(16),
            "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf",
        ),
        // Test Case 3: four blocks, no aad.
        case(k128, iv, "", p, c128, "4d5c2af327cd64a62cf35abd2ba6fab4"),
        // Test Case 4: 60 octets with 20 of aad.
        case(
            k128,
            iv,
            aad,
            &p[..120],
            &c128[..120],
            "5bc94fbc3221a5db94fae95ae7121a47",
        ),
        // Test Case 13: the zero key, no plaintext.
        case(
            &"00".repeat(32),
            &"00".repeat(12),
            "",
            "",
            "",
            "530f8afbc74536b9a963b4f1c4cb738b",
        ),
        // Test Case 14: the zero key, one zero block.
        case(
            &"00".repeat(32),
            &"00".repeat(12),
            "",
            &"00".repeat(16),
            "cea7403d4d606b6e074ec5d3baf39d18",
            "d0d1c8a799996bf0265b98b5d48ab919",
        ),
        // Test Case 15: four blocks, no aad.
        case(k, iv, "", p, c, "b094dac5d93471bdec1a502270e3cc6c"),
        // Test Case 16: 60 octets with 20 of aad.
        case(
            k,
            iv,
            aad,
            &p[..120],
            &c[..120],
            "76fc6ece0f4e1768cddf8853bb2d551b",
        ),
    ]
}

/// Seals and opens `case` both ways, and checks the answers.
fn check(key: &Key, case: &Case) {
    // In place, the tag apart.
    let mut buf = case.pt.clone();
    let tag = key.seal_in_place(&case.nonce, &case.aad, &mut buf).unwrap();
    assert_eq!(buf, case.ct);
    assert_eq!(tag, case.tag);
    key.open_in_place(&case.nonce, &case.aad, &mut buf, &tag)
        .unwrap();
    assert_eq!(buf, case.pt);

    // Buffer to buffer, ciphertext then tag.
    let mut sealed = vec![0u8; case.pt.len() + TAG_LEN];
    let n = key
        .seal(&case.nonce, &case.aad, &case.pt, &mut sealed)
        .unwrap();
    assert_eq!(n, sealed.len());
    assert_eq!(&sealed[..case.pt.len()], case.ct.as_slice());
    assert_eq!(&sealed[case.pt.len()..], case.tag.as_slice());
    let mut opened = vec![0u8; case.pt.len()];
    let n = key
        .open(&case.nonce, &case.aad, &sealed, &mut opened)
        .unwrap();
    assert_eq!(n, case.pt.len());
    assert_eq!(opened, case.pt);
}

#[test]
fn rfc8439_seal_and_open() {
    let cases = rfc8439_cases();
    assert_eq!(cases.len(), 2);
    // Section 2.8.2 is given as a seal, and A.5 as an open; both run
    // both ways.
    for case in &cases {
        check(&Key::chacha(&case.key), case);
    }
}

#[test]
fn gcm_spec_cases_1_to_4_and_13_to_16() {
    let cases = gcm_cases();
    assert_eq!(cases.iter().filter(|c| c.key.len() == 16).count(), 4);
    assert_eq!(cases.iter().filter(|c| c.key.len() == 32).count(), 4);
    for case in &cases {
        check(&Key::aes(&case.key), case);
    }
}

/// A flipped bit in the ciphertext, the tag, the aad or the nonce fails
/// with `Verification`, and the output comes back zeroed.
#[test]
fn tamper_fails() {
    let all: Vec<(Key, Case)> = rfc8439_cases()
        .into_iter()
        .map(|c| (Key::chacha(&c.key), c))
        .chain(gcm_cases().into_iter().map(|c| (Key::aes(&c.key), c)))
        .collect();
    for (key, case) in &all {
        let mut sealed = case.ct.clone();
        sealed.extend_from_slice(&case.tag);
        let flips: Vec<usize> = (0..sealed.len() * 8).step_by(13).collect();
        for &bit in &flips {
            let mut bad = sealed.clone();
            bad[bit / 8] ^= 1 << (bit % 8);
            let mut out = vec![0xAAu8; case.pt.len()];
            assert_eq!(
                key.open(&case.nonce, &case.aad, &bad, &mut out),
                Err(Error::Verification)
            );
            assert!(out.iter().all(|&b| b == 0), "out zeroed");

            let (ct, tag) = bad.split_at(case.ct.len());
            let mut buf = ct.to_vec();
            assert_eq!(
                key.open_in_place(&case.nonce, &case.aad, &mut buf, tag.try_into().unwrap()),
                Err(Error::Verification)
            );
            assert!(buf.iter().all(|&b| b == 0), "buf zeroed");
        }
        // The aad and the nonce are bound too.
        let mut aad = case.aad.clone();
        aad.push(0);
        let mut out = vec![0u8; case.pt.len()];
        assert_eq!(
            key.open(&case.nonce, &aad, &sealed, &mut out),
            Err(Error::Verification)
        );
        let mut nonce = case.nonce;
        nonce[11] ^= 1;
        assert_eq!(
            key.open(&nonce, &case.aad, &sealed, &mut out),
            Err(Error::Verification)
        );
    }
}

#[test]
fn buffer_errors() {
    for key in Key::all(7) {
        let nonce = [1u8; 12];
        let pt = [0x55u8; 40];
        // `out` must hold the plaintext and the tag.
        let mut out = [0u8; 40 + TAG_LEN - 1];
        assert_eq!(
            key.seal(&nonce, b"", &pt, &mut out),
            Err(Error::OutputLength)
        );
        // A longer `out` is fine; only the first part is written.
        let mut out = [0u8; 100];
        assert_eq!(key.seal(&nonce, b"", &pt, &mut out), Ok(40 + TAG_LEN));
        let sealed = out[..40 + TAG_LEN].to_vec();
        // Input shorter than a tag can't be opened.
        for n in 0..TAG_LEN {
            assert_eq!(
                key.open(&nonce, b"", &sealed[..n], &mut out),
                Err(Error::Length)
            );
        }
        // `out` must hold the plaintext.
        let mut short = [0u8; 39];
        assert_eq!(
            key.open(&nonce, b"", &sealed, &mut short),
            Err(Error::OutputLength)
        );
        let mut opened = [0u8; 64];
        assert_eq!(key.open(&nonce, b"", &sealed, &mut opened), Ok(40));
        assert_eq!(opened[..40], pt);
    }
}

#[test]
fn empty_plaintext() {
    for key in Key::all(9) {
        let nonce = [2u8; 12];
        let mut out = [0u8; TAG_LEN];
        assert_eq!(key.seal(&nonce, b"header", b"", &mut out), Ok(TAG_LEN));
        let mut nothing = [0u8; 0];
        assert_eq!(key.open(&nonce, b"header", &out, &mut nothing), Ok(0));
        let tag = key.seal_in_place(&nonce, b"header", &mut []).unwrap();
        assert_eq!(tag, out);
        assert_eq!(key.open_in_place(&nonce, b"header", &mut [], &tag), Ok(()));
        assert_eq!(
            key.open(&nonce, b"other", &out, &mut nothing),
            Err(Error::Verification)
        );
    }
}
