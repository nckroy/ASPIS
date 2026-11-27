// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Known answers for QUIC v1's packet protection (ADR 0069, rule 7): RFC
//! 9001, Appendix A, from `tests/data/rfc9001.json`. They exercise
//! AES-128-GCM and ChaCha20-Poly1305 with keys derived through
//! aspis-crypto's HKDF, and the header-protection masks of
//! `aspis_crypto::quic` (RFC 9001, section 5.4). Both need the crate's
//! `quic` feature, which isn't a default one.
//!
//! HKDF-Expand-Label (RFC 9846, section 7.1) is the record layer's (C29).
//! The tests build it here from `Prk256::expand`, as C29 will, and check
//! its labels against Appendix A.1.
//!
//! The AES-256 mask has no RFC 9001 vector. It is checked against the
//! example vectors for AES-128 and AES-256 of FIPS 197, as updated in 2023
//! (Appendix C.1 and C.3), a work of the US government with no notice,
//! copied below with this citation. The ChaCha20 mask is also checked, at every kind of counter,
//! against the block function of RFC 8439, section 2.3, written out here.

mod common;

use aspis_crypto::Error;
use aspis_crypto::aead::{Aes128GcmKey, ChaCha20Poly1305Key, TAG_LEN};
use aspis_crypto::mac::{Prk256, hkdf_sha256_extract};
use aspis_crypto::quic::{
    Aes128HeaderProtectionKey, Aes256HeaderProtectionKey, ChaCha20HeaderProtectionKey, MASK_LEN,
    SAMPLE_LEN,
};
use common::{Value, array, field, hex, vectors};

const RFC9001: &str = include_str!("data/rfc9001.json");

fn tests() -> Vec<Value> {
    vectors(RFC9001).get("tests").as_array().to_vec()
}

/// The test whose `tcId` starts with `id`.
fn test(id: &str) -> Value {
    tests()
        .into_iter()
        .find(|t| t.get("tcId").as_str().starts_with(id))
        .unwrap()
}

/// TLS 1.3's HkdfLabel with an empty context: the output length, then
/// "tls13 " ‖ label and an empty context, each after a one-octet length
/// (RFC 9846, section 7.1).
fn hkdf_label(label: &str, len: u16) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut out = len.to_be_bytes().to_vec();
    out.push(u8::try_from(full.len()).unwrap());
    out.extend_from_slice(full.as_bytes());
    out.push(0);
    out
}

/// HKDF-Expand-Label(secret, label, "", len), with SHA-256.
fn expand_label(secret: &[u8], label: &str, len: u16) -> Vec<u8> {
    let prk = Prk256::from_bytes(secret.try_into().unwrap());
    let mut out = vec![0; usize::from(len)];
    prk.expand(&hkdf_label(label, len), &mut out).unwrap();
    out
}

/// The AEAD nonce: the IV XOR the packet number, left-padded (RFC 9001,
/// section 5.3).
fn nonce(iv: &[u8; 12], pn: u64) -> [u8; 12] {
    let mut n = *iv;
    for (a, b) in n[4..].iter_mut().zip(pn.to_be_bytes()) {
        *a ^= b;
    }
    n
}

/// Applies (or removes) header protection: the low 4 bits of a long
/// header's first octet, or the low 5 of a short header's, and the
/// packet-number octets at `pn_offset` (RFC 9001, section 5.4.1).
fn protect_header(header: &mut [u8], pn_offset: usize, pn_len: usize, mask: &[u8; MASK_LEN]) {
    let long = header[0] & 0x80 != 0;
    header[0] ^= mask[0] & if long { 0x0f } else { 0x1f };
    for (h, m) in header[pn_offset..pn_offset + pn_len]
        .iter_mut()
        .zip(&mask[1..])
    {
        *h ^= m;
    }
}

/// The sample: the 16 octets that start 4 after the packet number's
/// offset (RFC 9001, section 5.4.2).
fn sample(packet: &[u8], pn_offset: usize) -> [u8; SAMPLE_LEN] {
    packet[pn_offset + 4..pn_offset + 4 + SAMPLE_LEN]
        .try_into()
        .unwrap()
}

/// Appendix A.1's HkdfLabel values are those built here.
#[test]
fn rfc9001_a1_hkdf_labels() {
    let v = vectors(RFC9001);
    let labels = v.get("hkdfLabels").as_array();
    assert_eq!(labels.len(), 5);
    for l in labels {
        let name = l.get("label").as_str();
        let len = match name {
            "client in" | "server in" => 32,
            "quic key" | "quic hp" => 16,
            _ => 12,
        };
        assert_eq!(hkdf_label(name, len), field(l, "hkdfLabel"), "{name}");
    }
}

/// Appendix A.1: the initial secret from the salt and the Destination
/// Connection ID, then each side's secret, key, IV and header-protection
/// key.
#[test]
fn rfc9001_a1_keys() {
    let salt = hex(vectors(RFC9001).get("initialSalt").as_str());
    for (id, side, label) in [
        ("A.1 and A.2", "clientInitialSecret", "client in"),
        ("A.1 and A.3", "serverInitialSecret", "server in"),
    ] {
        let t = test(id);
        let initial = hkdf_sha256_extract(Some(&salt), &field(&t, "dcid"));
        assert_eq!(initial.as_bytes().to_vec(), field(&t, "initialSecret"));
        let secret = expand_label(initial.as_bytes(), label, 32);
        assert_eq!(secret, field(&t, side));
        assert_eq!(expand_label(&secret, "quic key", 16), field(&t, "key"));
        assert_eq!(expand_label(&secret, "quic iv", 12), field(&t, "iv"));
        assert_eq!(expand_label(&secret, "quic hp", 16), field(&t, "hp"));
    }
}

/// Protects an Initial packet with AES-128-GCM and AES-128 header
/// protection, checks every step against the vector, and then removes the
/// protection again.
fn initial_packet(t: &Value, payload: &[u8], pn_len: usize) {
    let key = Aes128GcmKey::from_bytes(&array(t, "key"));
    let hp = Aes128HeaderProtectionKey::from_bytes(&array(t, "hp"));
    let iv: [u8; 12] = array(t, "iv");
    let pn = t.get("packetNumber").as_u64();
    let header = field(t, "header");
    let packet = field(t, "packet");
    let pn_offset = header.len() - pn_len;

    // The payload, sealed with the header as aad.
    let mut sealed = vec![0; payload.len() + TAG_LEN];
    let n = key
        .seal(&nonce(&iv, pn), &header, payload, &mut sealed)
        .unwrap();
    assert_eq!(n, sealed.len());
    assert_eq!(sealed, packet[header.len()..]);

    // The header, protected with the mask of the sample.
    let mut unprotected = header.clone();
    unprotected.extend_from_slice(&sealed);
    let s = sample(&unprotected, pn_offset);
    assert_eq!(s.to_vec(), field(t, "sample"));
    let mask = hp.mask(&s);
    assert_eq!(mask.to_vec(), field(t, "mask"));
    let mut protected = header.clone();
    protect_header(&mut protected, pn_offset, pn_len, &mask);
    assert_eq!(protected, field(t, "protectedHeader"));
    protected.extend_from_slice(&sealed);
    assert_eq!(protected, packet);

    // And back: the same mask, read from the protected packet, removes
    // header protection, and the payload opens.
    let mask = hp.mask(&sample(&packet, pn_offset));
    let mut h = packet[..header.len()].to_vec();
    protect_header(&mut h, pn_offset, pn_len, &mask);
    assert_eq!(h, header);
    let mut opened = vec![0; payload.len()];
    assert_eq!(
        key.open(&nonce(&iv, pn), &h, &packet[header.len()..], &mut opened),
        Ok(payload.len())
    );
    assert_eq!(opened, payload);
}

/// Appendix A.2: the client's Initial packet, a CRYPTO frame padded to
/// 1,162 octets with PADDING frames (zero octets), under a 4-octet packet
/// number.
#[test]
fn rfc9001_a2_client_initial() {
    let t = test("A.1 and A.2");
    let mut payload = field(&t, "cryptoFrame");
    payload.resize(usize::try_from(t.get("payloadLength").as_u64()).unwrap(), 0);
    initial_packet(&t, &payload, 4);
}

/// Appendix A.3: the server's Initial packet, under a 2-octet packet
/// number, so the sample starts 2 octets into the protected payload.
#[test]
fn rfc9001_a3_server_initial() {
    let t = test("A.1 and A.3");
    initial_packet(&t, &field(&t, "payload"), 2);
}

/// Appendix A.4 and section 5.8: the Retry integrity tag is AES-128-GCM's
/// tag over the Retry pseudo-packet, with an empty plaintext, under the
/// key and nonce that section 5.8 derives from its secret.
#[test]
fn rfc9001_a4_retry() {
    let t = test("A.4");
    let secret = field(&t, "secret");
    assert_eq!(expand_label(&secret, "quic key", 16), field(&t, "key"));
    assert_eq!(expand_label(&secret, "quic iv", 12), field(&t, "nonce"));

    let key = Aes128GcmKey::from_bytes(&array(&t, "key"));
    let n: [u8; 12] = array(&t, "nonce");
    let packet = field(&t, "packet");
    let (retry, tag) = packet.split_at(packet.len() - TAG_LEN);
    let odcid = field(&t, "odcid");
    let mut pseudo = vec![u8::try_from(odcid.len()).unwrap()];
    pseudo.extend_from_slice(&odcid);
    pseudo.extend_from_slice(retry);

    assert_eq!(key.seal_in_place(&n, &pseudo, &mut []).unwrap(), tag);
    let tag: [u8; TAG_LEN] = tag.try_into().unwrap();
    assert_eq!(key.open_in_place(&n, &pseudo, &mut [], &tag), Ok(()));
    // The original Destination Connection ID is bound in: another one
    // fails.
    let mut other = pseudo.clone();
    other[1] ^= 1;
    assert_eq!(
        key.open_in_place(&n, &other, &mut [], &tag),
        Err(Error::Verification)
    );
}

/// Appendix A.5: a short-header packet under ChaCha20-Poly1305 and
/// ChaCha20 header protection, with a 3-octet packet number, so one octet
/// of ciphertext is skipped before the sample.
#[test]
fn rfc9001_a5_chacha20_short_header() {
    let t = test("A.5");
    let secret = field(&t, "secret");
    assert_eq!(expand_label(&secret, "quic key", 32), field(&t, "key"));
    assert_eq!(expand_label(&secret, "quic iv", 12), field(&t, "iv"));
    assert_eq!(expand_label(&secret, "quic hp", 32), field(&t, "hp"));
    assert_eq!(expand_label(&secret, "quic ku", 32), field(&t, "ku"));

    let key = ChaCha20Poly1305Key::from_bytes(&array(&t, "key"));
    let hp = ChaCha20HeaderProtectionKey::from_bytes(&array(&t, "hp"));
    let pn = t.get("packetNumber").as_u64();
    let n = nonce(&array(&t, "iv"), pn);
    assert_eq!(n.to_vec(), field(&t, "nonce"));
    let header = field(&t, "header");
    let pt = field(&t, "plaintext");
    let mut sealed = vec![0; pt.len() + TAG_LEN];
    key.seal(&n, &header, &pt, &mut sealed).unwrap();
    assert_eq!(sealed, field(&t, "ciphertext"));

    let pn_offset = 1;
    let mut packet = header.clone();
    packet.extend_from_slice(&sealed);
    let s = sample(&packet, pn_offset);
    assert_eq!(s.to_vec(), field(&t, "sample"));
    let mask = hp.mask(&s);
    assert_eq!(mask.to_vec(), field(&t, "mask"));
    protect_header(&mut packet[..header.len()], pn_offset, 3, &mask);
    assert_eq!(packet[..header.len()], field(&t, "protectedHeader"));
    assert_eq!(packet, field(&t, "packet"));
}

/// The AES masks are the first five octets of one AES block: FIPS 197's
/// example vectors (Appendix C.1 for AES-128 and C.3 for AES-256), with
/// the plaintext as the sample.
#[test]
fn aes_masks_are_aes_ecb() {
    let sample: [u8; 16] = hex("00112233445566778899aabbccddeeff").try_into().unwrap();
    let k128: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
    let k256: [u8; 32] = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .try_into()
        .unwrap();
    // FIPS 197, C.1: 69c4e0d86a7b0430d8cdb78070b4c55a.
    assert_eq!(
        Aes128HeaderProtectionKey::from_bytes(&k128)
            .mask(&sample)
            .to_vec(),
        hex("69c4e0d86a")
    );
    // FIPS 197, C.3: 8ea2b7ca516745bfeafc49904b496089.
    assert_eq!(
        Aes256HeaderProtectionKey::from_bytes(&k256)
            .mask(&sample)
            .to_vec(),
        hex("8ea2b7ca51")
    );
}

/// The ChaCha20 block function of RFC 8439, section 2.3: 64 octets of
/// keystream for `key`, `counter` and `nonce`.
fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(16);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(12);
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(8);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(7);
    }
    let word = |b: &[u8]| u32::from_le_bytes(b.try_into().unwrap());
    let mut state = [0u32; 16];
    // "expand 32-byte k".
    state[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    for i in 0..8 {
        state[4 + i] = word(&key[4 * i..4 * i + 4]);
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = word(&nonce[4 * i..4 * i + 4]);
    }
    let mut s = state;
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&s[i].wrapping_add(state[i]).to_le_bytes());
    }
    out
}

/// The ChaCha20 mask is the first five octets of RFC 8439's block for the
/// sample's counter and nonce, at every kind of counter: zero, one, the
/// top bit, and 0xFFFFFFFF, the last block, which the library's stream
/// refuses (see `stream_refuses_the_last_block`).
#[test]
fn chacha20_mask_matches_rfc8439_block() {
    // The reference reproduces Appendix A.5's mask first.
    let t = test("A.5");
    let hp_bytes: [u8; 32] = array(&t, "hp");
    let s: [u8; 16] = array(&t, "sample");
    let block = chacha20_block(
        &hp_bytes,
        u32::from_le_bytes(s[..4].try_into().unwrap()),
        s[4..].try_into().unwrap(),
    );
    assert_eq!(block[..MASK_LEN].to_vec(), field(&t, "mask"));

    let hp = ChaCha20HeaderProtectionKey::from_bytes(&hp_bytes);
    for counter in [0u32, 1, 2, 0x8000_0000, 0xffff_fffe, 0xffff_ffff] {
        for fill in [0x00u8, 0x5a, 0xff] {
            let mut sample = [fill; 16];
            sample[..4].copy_from_slice(&counter.to_le_bytes());
            let nonce: [u8; 12] = sample[4..].try_into().unwrap();
            assert_eq!(
                hp.mask(&sample),
                chacha20_block(&hp_bytes, counter, &nonce)[..MASK_LEN],
                "counter {counter:#x}"
            );
        }
    }
}

/// Why the ChaCha20 mask doesn't use the library's stream: at block
/// 0xFFFFFFFF it refuses to produce even five octets.
#[test]
fn stream_refuses_the_last_block() {
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    let mut c = chacha20::ChaCha20::new(&[7u8; 32].into(), &[9u8; 12].into());
    c.seek(0xffff_fffeu64 * 64);
    assert!(c.try_apply_keystream(&mut [0; MASK_LEN]).is_ok());
    let mut c = chacha20::ChaCha20::new(&[7u8; 32].into(), &[9u8; 12].into());
    c.seek(0xffff_ffffu64 * 64);
    assert!(c.try_apply_keystream(&mut [0; MASK_LEN]).is_err());
}

/// A mask depends on every octet of the sample and of the key.
#[test]
fn masks_depend_on_key_and_sample() {
    fn check(mask: impl Fn(&[u8; 32], &[u8; 16]) -> [u8; MASK_LEN]) {
        let (key, sample) = ([0x11; 32], [0x22; 16]);
        let base = mask(&key, &sample);
        for i in 0..16 {
            let mut s = sample;
            s[i] ^= 1;
            assert_ne!(mask(&key, &s), base, "sample octet {i}");
        }
        for i in 0..32 {
            let mut k = key;
            k[i] ^= 1;
            assert_ne!(mask(&k, &sample), base, "key octet {i}");
        }
    }
    check(|k, s| ChaCha20HeaderProtectionKey::from_bytes(k).mask(s));
    check(|k, s| Aes256HeaderProtectionKey::from_bytes(k).mask(s));
    // AES-128 takes the first 16 octets of the key; change only those.
    let base = Aes128HeaderProtectionKey::from_bytes(&[0x11; 16]).mask(&[0x22; 16]);
    for i in 0..16 {
        let mut k = [0x11; 16];
        k[i] ^= 1;
        assert_ne!(
            Aes128HeaderProtectionKey::from_bytes(&k).mask(&[0x22; 16]),
            base
        );
        let mut s = [0x22; 16];
        s[i] ^= 1;
        assert_ne!(
            Aes128HeaderProtectionKey::from_bytes(&[0x11; 16]).mask(&s),
            base
        );
    }
}
