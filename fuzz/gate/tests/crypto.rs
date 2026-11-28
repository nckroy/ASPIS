// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The libcrux oracle of `crypto-differential` (ADR 0069, rule 8;
//! docs/design/call-language.md, "Differential tests"): it is wired to the
//! right libcrux functions (the standards' known answers come back through
//! each method, and the boundary lengths the entry reaches agree with
//! `aspis-crypto`), every answer it gives is compared (an oracle that
//! corrupts any one output makes the entry panic), and [`Recording`]
//! forwards every method of `aspis_crypto::fuzz::Oracle`, so a method C08
//! adds can't default to `None` unseen. And the `crypto-` targets: which
//! primitives `crypto-differential` actually compares, seed by seed;
//! which entry and scheme each `crypto-decode` seed reaches; and each
//! target's `max_len`, against `aspis_crypto::fuzz`'s module doc.
//!
//! Each test runs on a 16 MiB thread: the lattice schemes keep their state
//! on the stack. The file's tests take about 0.1 s together at opt-level
//! 1 (measured on an 18-core Mac), so they stay in every
//! `cargo xtask test --host`.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};

use aspis_crypto::aead::{Aes128GcmKey, Aes256GcmKey, ChaCha20Poly1305Key};
use aspis_crypto::fuzz::{DIFFERENTIAL_PRIMITIVES, Oracle, differential};
use aspis_crypto::mac::{Prk256, Prk384, hkdf_sha256_extract, hkdf_sha384_extract};
use aspis_crypto::ml_dsa::{MlDsa65Signature, MlDsa65VerifyingKey};
use common::on_big_stack;
use fuzz_gate::crypto_oracle::{COMPARED, Libcrux, NOT_COMPARED, RECORDED, Recording};
use fuzz_gate::crypto_repo::{
    self, FIPS197_C1, FIPS197_C3, acvp, ctx_field, rfc, rfc10073, tc_name, vectors::field, with,
};
use fuzz_gate::crypto_targets::{
    self, AEAD_LENGTHS, COMPOSITE, DIFFERENTIAL_KINDS, aead_kinds, composite_context_len,
    decode_kinds, differential_compared, differential_kinds, split_entry, zero_hedge,
};
use fuzz_gate::{CRYPTO_AEAD, CRYPTO_DIFFERENTIAL};

/// Held while the panic hook is swapped: the hook is global, and the
/// tests run on several threads.
static HOOK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Whether `f` panics, with the panic's message kept off the test output.
fn panics(f: impl FnOnce()) -> bool {
    let _held = HOOK.lock().unwrap_or_else(|e| e.into_inner());
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = catch_unwind(AssertUnwindSafe(f)).is_err();
    std::panic::set_hook(hook);
    r
}

/// `N` octets of a hex field.
fn array<const N: usize>(t: &crypto_repo::vectors::Value, key: &str) -> [u8; N] {
    crypto_repo::vectors::array(t, key)
}

/// The names of the methods of `pub trait Oracle` in aspis-crypto's
/// source, in order.
fn trait_methods() -> Vec<String> {
    const SOURCE: &str = include_str!("../../../crates/crypto/src/fuzz.rs");
    let start = SOURCE
        .find("pub trait Oracle {")
        .expect("aspis_crypto::fuzz has `pub trait Oracle {`");
    let body = &SOURCE[start..];
    let end = body.find("\n}\n").expect("the trait's closing brace");
    body[..end]
        .lines()
        .filter_map(|l| l.trim().strip_prefix("fn "))
        .map(|l| l.split('(').next().unwrap().to_string())
        .collect()
}

/// `Recording` forwards every method of the trait, so
/// none is left to its `None` default, and `NOT_COMPARED` names only
/// methods the trait has. A method C08 adds, which would default to
/// `None` in both `Libcrux` and `Recording`, fails here by name.
#[test]
fn recording_forwards_every_oracle_method() {
    let methods = trait_methods();
    assert_eq!(methods.len(), 25, "{methods:?}");
    assert_eq!(
        methods, RECORDED,
        "Recording's forwarded methods and the trait's"
    );
    for m in NOT_COMPARED {
        assert!(methods.iter().any(|x| x == m), "NOT_COMPARED names {m}");
    }
    // Every method a COMPARED row names is the trait's.
    for (sel, name, needs) in COMPARED {
        for m in *needs {
            assert!(RECORDED.contains(m), "{sel} {name}: {m}");
        }
    }
    assert_eq!(COMPARED.len(), usize::from(DIFFERENTIAL_PRIMITIVES));
    for (i, (sel, _, _)) in COMPARED.iter().enumerate() {
        assert_eq!(
            usize::from(*sel),
            i,
            "COMPARED's rows are in selector order"
        );
    }
}

/// One output component of one oracle method, which [`Flip`] corrupts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Part {
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Shake256Out,
    HmacSha256,
    HmacSha384,
    HmacSha512,
    HkdfSha256Out,
    HkdfSha384Out,
    ChaCha20Poly1305Tag,
    ChaCha20Poly1305Ct,
    Aes256GcmTag,
    Aes256GcmCt,
    Aes128GcmTag,
    Aes128GcmCt,
    Aes128Ecb,
    Aes256Ecb,
    X25519,
    Ed25519Public,
    Ed25519Sign,
    Ed25519Verify,
    MlKem768Public,
    MlKem768EncapsulateCt,
    MlKem768EncapsulateSs,
    MlKem768EncapsulateOk,
    MlKem768Decapsulate,
    MlDsa65Public,
    MlDsa65Sign,
    MlDsa65Verify,
}

/// Every output component, each with the oracle method it comes from.
const PARTS: &[(Part, &str)] = &[
    (Part::Sha256, "sha256"),
    (Part::Sha384, "sha384"),
    (Part::Sha512, "sha512"),
    (Part::Sha3_256, "sha3_256"),
    (Part::Shake256Out, "shake256"),
    (Part::HmacSha256, "hmac_sha256"),
    (Part::HmacSha384, "hmac_sha384"),
    (Part::HmacSha512, "hmac_sha512"),
    (Part::HkdfSha256Out, "hkdf_sha256"),
    (Part::HkdfSha384Out, "hkdf_sha384"),
    (Part::ChaCha20Poly1305Tag, "chacha20poly1305_seal"),
    (Part::ChaCha20Poly1305Ct, "chacha20poly1305_seal"),
    (Part::Aes256GcmTag, "aes256gcm_seal"),
    (Part::Aes256GcmCt, "aes256gcm_seal"),
    (Part::Aes128GcmTag, "aes128gcm_seal"),
    (Part::Aes128GcmCt, "aes128gcm_seal"),
    (Part::Aes128Ecb, "aes128_ecb"),
    (Part::Aes256Ecb, "aes256_ecb"),
    (Part::X25519, "x25519"),
    (Part::Ed25519Public, "ed25519_public"),
    (Part::Ed25519Sign, "ed25519_sign"),
    (Part::Ed25519Verify, "ed25519_verify"),
    (Part::MlKem768Public, "ml_kem_768_public"),
    (Part::MlKem768EncapsulateCt, "ml_kem_768_encapsulate"),
    (Part::MlKem768EncapsulateSs, "ml_kem_768_encapsulate"),
    (Part::MlKem768EncapsulateOk, "ml_kem_768_encapsulate"),
    (Part::MlKem768Decapsulate, "ml_kem_768_decapsulate"),
    (Part::MlDsa65Public, "ml_dsa_65_public"),
    (Part::MlDsa65Sign, "ml_dsa_65_sign"),
    (Part::MlDsa65Verify, "ml_dsa_65_verify"),
];

/// [`Libcrux`], with one output component corrupted: bit 0 of its octet
/// 0 flipped, or a verdict negated. Octet 0 is inside the 5-octet
/// header-protection mask, so every comparison of the entry sees it.
struct Flip(Part);

fn flip(b: &mut [u8]) {
    if let Some(x) = b.first_mut() {
        *x ^= 1;
    }
}

impl Flip {
    /// `a`, corrupted if `part` is the one this oracle corrupts.
    fn out<const N: usize>(&self, part: Part, mut a: [u8; N]) -> [u8; N] {
        if self.0 == part {
            flip(&mut a);
        }
        a
    }

    fn slice(&self, part: Part, b: &mut [u8]) {
        if self.0 == part {
            flip(b);
        }
    }

    fn verdict(&self, part: Part, v: bool) -> bool {
        v ^ (self.0 == part)
    }
}

impl Oracle for Flip {
    fn sha256(&self, m: &[u8]) -> Option<[u8; 32]> {
        Some(self.out(Part::Sha256, Libcrux.sha256(m)?))
    }
    fn sha384(&self, m: &[u8]) -> Option<[u8; 48]> {
        Some(self.out(Part::Sha384, Libcrux.sha384(m)?))
    }
    fn sha512(&self, m: &[u8]) -> Option<[u8; 64]> {
        Some(self.out(Part::Sha512, Libcrux.sha512(m)?))
    }
    fn sha3_256(&self, m: &[u8]) -> Option<[u8; 32]> {
        Some(self.out(Part::Sha3_256, Libcrux.sha3_256(m)?))
    }
    fn shake256(&self, m: &[u8], out: &mut [u8]) -> Option<()> {
        Libcrux.shake256(m, out)?;
        self.slice(Part::Shake256Out, out);
        Some(())
    }
    fn hmac_sha256(&self, key: &[u8], m: &[u8]) -> Option<[u8; 32]> {
        Some(self.out(Part::HmacSha256, Libcrux.hmac_sha256(key, m)?))
    }
    fn hmac_sha384(&self, key: &[u8], m: &[u8]) -> Option<[u8; 48]> {
        Some(self.out(Part::HmacSha384, Libcrux.hmac_sha384(key, m)?))
    }
    fn hmac_sha512(&self, key: &[u8], m: &[u8]) -> Option<[u8; 64]> {
        Some(self.out(Part::HmacSha512, Libcrux.hmac_sha512(key, m)?))
    }
    fn hkdf_sha256(&self, salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Option<()> {
        Libcrux.hkdf_sha256(salt, ikm, info, out)?;
        self.slice(Part::HkdfSha256Out, out);
        Some(())
    }
    fn hkdf_sha384(&self, salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Option<()> {
        Libcrux.hkdf_sha384(salt, ikm, info, out)?;
        self.slice(Part::HkdfSha384Out, out);
        Some(())
    }
    fn chacha20poly1305_seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
    ) -> Option<[u8; 16]> {
        let tag = Libcrux.chacha20poly1305_seal(key, nonce, aad, pt, ct)?;
        self.slice(Part::ChaCha20Poly1305Ct, ct);
        Some(self.out(Part::ChaCha20Poly1305Tag, tag))
    }
    fn aes256gcm_seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
    ) -> Option<[u8; 16]> {
        let tag = Libcrux.aes256gcm_seal(key, nonce, aad, pt, ct)?;
        self.slice(Part::Aes256GcmCt, ct);
        Some(self.out(Part::Aes256GcmTag, tag))
    }
    fn aes128gcm_seal(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 12],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
    ) -> Option<[u8; 16]> {
        let tag = Libcrux.aes128gcm_seal(key, nonce, aad, pt, ct)?;
        self.slice(Part::Aes128GcmCt, ct);
        Some(self.out(Part::Aes128GcmTag, tag))
    }
    fn aes128_ecb(&self, key: &[u8; 16], block: &[u8; 16]) -> Option<[u8; 16]> {
        Some(self.out(Part::Aes128Ecb, Libcrux.aes128_ecb(key, block)?))
    }
    fn aes256_ecb(&self, key: &[u8; 32], block: &[u8; 16]) -> Option<[u8; 16]> {
        Some(self.out(Part::Aes256Ecb, Libcrux.aes256_ecb(key, block)?))
    }
    fn x25519(&self, k: &[u8; 32], u: &[u8; 32]) -> Option<[u8; 32]> {
        Some(self.out(Part::X25519, Libcrux.x25519(k, u)?))
    }
    fn ed25519_public(&self, seed: &[u8; 32]) -> Option<[u8; 32]> {
        Some(self.out(Part::Ed25519Public, Libcrux.ed25519_public(seed)?))
    }
    fn ed25519_sign(&self, seed: &[u8; 32], m: &[u8]) -> Option<[u8; 64]> {
        Some(self.out(Part::Ed25519Sign, Libcrux.ed25519_sign(seed, m)?))
    }
    fn ed25519_verify(&self, pk: &[u8; 32], m: &[u8], sig: &[u8; 64]) -> Option<bool> {
        Some(self.verdict(Part::Ed25519Verify, Libcrux.ed25519_verify(pk, m, sig)?))
    }
    fn ml_kem_768_public(&self, seed: &[u8; 64]) -> Option<[u8; 1184]> {
        Some(self.out(Part::MlKem768Public, Libcrux.ml_kem_768_public(seed)?))
    }
    fn ml_kem_768_encapsulate(
        &self,
        ek: &[u8; 1184],
        m: &[u8; 32],
        ct: &mut [u8; 1088],
        ss: &mut [u8; 32],
    ) -> Option<bool> {
        let ok = Libcrux.ml_kem_768_encapsulate(ek, m, ct, ss)?;
        self.slice(Part::MlKem768EncapsulateCt, ct);
        self.slice(Part::MlKem768EncapsulateSs, ss);
        Some(self.verdict(Part::MlKem768EncapsulateOk, ok))
    }
    fn ml_kem_768_decapsulate(&self, seed: &[u8; 64], ct: &[u8; 1088]) -> Option<[u8; 32]> {
        Some(self.out(
            Part::MlKem768Decapsulate,
            Libcrux.ml_kem_768_decapsulate(seed, ct)?,
        ))
    }
    fn ml_dsa_65_public(&self, xi: &[u8; 32]) -> Option<[u8; 1952]> {
        Some(self.out(Part::MlDsa65Public, Libcrux.ml_dsa_65_public(xi)?))
    }
    fn ml_dsa_65_sign(
        &self,
        xi: &[u8; 32],
        m: &[u8],
        ctx: &[u8],
        rnd: &[u8; 32],
    ) -> Option<[u8; 3309]> {
        Some(self.out(Part::MlDsa65Sign, Libcrux.ml_dsa_65_sign(xi, m, ctx, rnd)?))
    }
    fn ml_dsa_65_verify(
        &self,
        pk: &[u8; 1952],
        m: &[u8],
        ctx: &[u8],
        sig: &[u8; 3309],
    ) -> Option<bool> {
        Some(self.verdict(
            Part::MlDsa65Verify,
            Libcrux.ml_dsa_65_verify(pk, m, ctx, sig)?,
        ))
    }
}

/// Every answer the oracle gives is compared, not only fetched, in every
/// primitive that asks for it ("Differential tests" in
/// docs/design/call-language.md). For each row of `COMPARED` and each
/// output component of a method the row needs, an oracle that corrupts
/// that component makes the entry panic on some input of that row's
/// selector (the inputs of `crypto_repo::differential_inputs`), while
/// libcrux itself passes that input. So a primitive that fetched an
/// answer and dropped its comparison fails here by row and component,
/// even when another primitive compares the same method. The components
/// cover every method the oracle answers.
#[test]
fn every_oracle_answer_is_checked() {
    on_big_stack(|| {
        let methods: BTreeSet<&str> = PARTS.iter().map(|(_, m)| *m).collect();
        let answered: BTreeSet<&str> = RECORDED
            .iter()
            .copied()
            .filter(|m| !NOT_COMPARED.contains(m))
            .collect();
        assert_eq!(methods, answered, "PARTS names every answered method");

        let inputs = crypto_repo::differential_inputs();
        for &(_, method) in PARTS {
            assert!(
                COMPARED.iter().any(|(_, _, needs)| needs.contains(&method)),
                "{method}: no selector compares it"
            );
        }
        let mut checked = 0usize;
        for &(sel, row, needs) in COMPARED {
            for &(part, method) in PARTS.iter().filter(|(_, m)| needs.contains(m)) {
                let caught = inputs
                    .iter()
                    .filter(|(_, d)| d.first() == Some(&sel))
                    .find(|(_, d)| panics(|| differential(&Flip(part), d)));
                let Some((name, d)) = caught else {
                    panic!(
                        "{row}: {part:?} ({method}) isn't compared on any input of selector {sel}"
                    );
                };
                assert!(
                    !panics(|| differential(&Libcrux, d)),
                    "{row}: libcrux itself fails {name}"
                );
                checked += 1;
            }
        }
        eprintln!("{checked} (primitive, component) pairs caught");
    });
}

/// RFC 7748, section 5.2's vectors and section 6.1's exchange.
fn x25519_known_answers() {
    for t in rfc("rfc7748.json") {
        let id = tc_name(&t);
        if t.try_get("inputScalar").is_some() {
            let (k, u) = (array(&t, "inputScalar"), array(&t, "inputUCoordinate"));
            assert_eq!(
                Libcrux.x25519(&k, &u),
                Some(array(&t, "outputUCoordinate")),
                "{id}"
            );
        } else if t.try_get("iterations").is_some_and(|n| n.as_u64() == 1) {
            let (k, u) = (array(&t, "initialK"), array(&t, "initialU"));
            assert_eq!(Libcrux.x25519(&k, &u), Some(array(&t, "result")), "{id}");
        } else if t.try_get("sharedSecret").is_some() {
            let (a, b) = (array(&t, "alicePrivateKey"), array(&t, "bobPrivateKey"));
            let base = {
                let mut u = [0; 32];
                u[0] = 9;
                u
            };
            assert_eq!(Libcrux.x25519(&a, &base), Some(array(&t, "alicePublicKey")));
            assert_eq!(
                Libcrux.x25519(&a, &array(&t, "bobPublicKey")),
                Some(array(&t, "sharedSecret"))
            );
            assert_eq!(
                Libcrux.x25519(&b, &array(&t, "alicePublicKey")),
                Some(array(&t, "sharedSecret"))
            );
        }
    }
}

/// RFC 8032, section 7.1's Ed25519 tests: key, signature, verification,
/// and a changed message refused.
fn ed25519_known_answers() {
    for t in rfc("rfc8032.json") {
        let id = tc_name(&t);
        let seed = array(&t, "secretKey");
        let pk = array(&t, "publicKey");
        let sig = array(&t, "signature");
        let m = field(&t, "message");
        assert_eq!(Libcrux.ed25519_public(&seed), Some(pk), "{id}");
        assert_eq!(Libcrux.ed25519_sign(&seed, &m), Some(sig), "{id}");
        assert_eq!(Libcrux.ed25519_verify(&pk, &m, &sig), Some(true), "{id}");
        let mut changed = m.clone();
        changed.push(0);
        assert_eq!(
            Libcrux.ed25519_verify(&pk, &changed, &sig),
            Some(false),
            "{id}"
        );
    }
}

/// RFC 4231's HMAC cases and RFC 5869's HKDF cases.
fn mac_known_answers() {
    for t in rfc("rfc4231.json") {
        let id = tc_name(&t);
        let (key, m) = (field(&t, "key"), field(&t, "data"));
        let n = t.try_get("truncatedTo").map_or(64, |n| n.as_u64() as usize);
        let cut = |b: &[u8]| b[..n.min(b.len())].to_vec();
        assert_eq!(
            cut(&Libcrux.hmac_sha256(&key, &m).unwrap()),
            field(&t, "hmacSha256"),
            "{id}"
        );
        assert_eq!(
            cut(&Libcrux.hmac_sha384(&key, &m).unwrap()),
            field(&t, "hmacSha384"),
            "{id}"
        );
        assert_eq!(
            cut(&Libcrux.hmac_sha512(&key, &m).unwrap()),
            field(&t, "hmacSha512"),
            "{id}"
        );
    }
    for t in rfc("rfc5869.json") {
        let mut okm = vec![0; t.get("l").as_u64() as usize];
        Libcrux
            .hkdf_sha256(
                &field(&t, "salt"),
                &field(&t, "ikm"),
                &field(&t, "info"),
                &mut okm,
            )
            .unwrap();
        assert_eq!(okm, field(&t, "okm"), "{}", tc_name(&t));
    }
}

/// RFC 8439's AEAD vectors, and FIPS 197's AES examples.
fn cipher_known_answers() {
    for t in rfc("rfc8439.json") {
        let pt = field(&t, "plaintext");
        let mut ct = vec![0; pt.len()];
        let tag = Libcrux.chacha20poly1305_seal(
            &array(&t, "key"),
            &array(&t, "nonce"),
            &field(&t, "aad"),
            &pt,
            &mut ct,
        );
        assert_eq!(tag, Some(array(&t, "tag")), "{}", tc_name(&t));
        assert_eq!(ct, field(&t, "ciphertext"), "{}", tc_name(&t));
    }
    assert_eq!(
        Libcrux.aes128_ecb(&FIPS197_C1.0, &FIPS197_C1.1),
        Some(FIPS197_C1.2)
    );
    assert_eq!(
        Libcrux.aes256_ecb(&FIPS197_C3.0, &FIPS197_C3.1),
        Some(FIPS197_C3.2)
    );
    // RFC 9001, Appendix A's header-protection masks are the first five
    // octets of AES-128 of the sample.
    for t in rfc("rfc9001.json") {
        if let Some(mask) = t.try_get("mask")
            && t.try_get("hp").is_some_and(|hp| hp.as_str().len() == 32)
        {
            let block = Libcrux
                .aes128_ecb(&array(&t, "hp"), &array(&t, "sample"))
                .unwrap();
            assert_eq!(
                block[..5],
                crypto_repo::vectors::hex(mask.as_str())[..],
                "{}",
                tc_name(&t)
            );
        }
    }
}

/// ACVP ML-KEM-768: keyGen's keys from d ‖ z, encapsulation's ciphertexts
/// and secrets from ek and m, the key check's verdicts, and decapsulation
/// under a keyGen seed of what libcrux encapsulated to its key.
fn ml_kem_known_answers() {
    for (_, t) in acvp("ml-kem-768-keygen") {
        let mut seed = [0; 64];
        seed[..32].copy_from_slice(&field(&t, "d"));
        seed[32..].copy_from_slice(&field(&t, "z"));
        let ek = Libcrux.ml_kem_768_public(&seed).unwrap();
        assert_eq!(ek[..], field(&t, "ek")[..], "keyGen {}", tc_name(&t));
        let (mut ct, mut ss) = ([0; 1088], [0; 32]);
        assert_eq!(
            Libcrux.ml_kem_768_encapsulate(&ek, &[0x33; 32], &mut ct, &mut ss),
            Some(true)
        );
        assert_eq!(Libcrux.ml_kem_768_decapsulate(&seed, &ct), Some(ss));
    }
    for (g, t) in acvp("ml-kem-768-encapdecap") {
        let id = tc_name(&t);
        let ek: [u8; 1184] = array(&t, "ek");
        let (mut ct, mut ss) = ([0; 1088], [0; 32]);
        match g.get("function").as_str() {
            "encapsulation" => {
                let ok = Libcrux.ml_kem_768_encapsulate(&ek, &array(&t, "m"), &mut ct, &mut ss);
                assert_eq!(ok, Some(true), "{id}");
                assert_eq!(ct[..], field(&t, "c")[..], "{id}");
                assert_eq!(ss[..], field(&t, "k")[..], "{id}");
            }
            "encapsulationKeyCheck" => {
                let ok = Libcrux.ml_kem_768_encapsulate(&ek, &[1; 32], &mut ct, &mut ss);
                assert_eq!(ok, Some(t.get("testPassed").as_bool()), "{id}");
            }
            // Decapsulation's vectors give the expanded key, which the
            // oracle doesn't take; the keyGen round trip above covers it.
            _ => {}
        }
    }
}

/// ACVP ML-DSA-65: keyGen's keys from ξ, every sigGen signature and the
/// sigVer verdicts through `ml_dsa_65_verify`, and hedged signing with a
/// context. ACVP's sigGen vectors give the expanded key, not ξ, which the
/// oracle's `ml_dsa_65_sign` takes; aspis-crypto's own tests reproduce
/// them from the expanded keys, and here libcrux's hedged signatures under
/// a keyGen seed, with the sigGen vectors' rnd, message and context,
/// verify under both verifiers, and equal `aspis-crypto`'s through the
/// entry (selector 18).
fn ml_dsa_known_answers() {
    let keygen = acvp("ml-dsa-65-keygen");
    for (_, t) in &keygen {
        let pk = Libcrux.ml_dsa_65_public(&array(t, "seed")).unwrap();
        assert_eq!(pk[..], field(t, "pk")[..], "keyGen {}", tc_name(t));
    }
    for (_, t) in acvp("ml-dsa-65-siggen") {
        let pk = array(&t, "pk");
        let (m, ctx) = (field(&t, "message"), field(&t, "context"));
        assert_eq!(
            Libcrux.ml_dsa_65_verify(&pk, &m, &ctx, &array(&t, "signature")),
            Some(true),
            "sigGen {}",
            tc_name(&t)
        );
    }
    for (_, t) in acvp("ml-dsa-65-sigver") {
        let ok = Libcrux.ml_dsa_65_verify(
            &array(&t, "pk"),
            &field(&t, "message"),
            &field(&t, "context"),
            &array(&t, "signature"),
        );
        assert_eq!(
            ok,
            Some(t.get("testPassed").as_bool()),
            "sigVer {}",
            tc_name(&t)
        );
    }
    let xi: [u8; 32] = array(&keygen[0].1, "seed");
    let pk = Libcrux.ml_dsa_65_public(&xi).unwrap();
    let vk = MlDsa65VerifyingKey::from_bytes(&pk).unwrap();
    let hedged: Vec<_> = acvp("ml-dsa-65-siggen")
        .into_iter()
        .filter(|(_, t)| t.try_get("rnd").is_some())
        .collect();
    assert!(!hedged.is_empty());
    for (_, t) in hedged {
        let id = tc_name(&t);
        let rnd: [u8; 32] = array(&t, "rnd");
        let (m, ctx) = (field(&t, "message"), field(&t, "context"));
        let sig = Libcrux.ml_dsa_65_sign(&xi, &m, &ctx, &rnd).unwrap();
        assert_eq!(
            Libcrux.ml_dsa_65_verify(&pk, &m, &ctx, &sig),
            Some(true),
            "{id}"
        );
        assert_eq!(
            vk.verify(&m, &ctx, &MlDsa65Signature::from_bytes(&sig).unwrap()),
            Ok(()),
            "{id}"
        );
        // The hedge is used: another rnd gives another signature.
        let mut other = rnd;
        other[0] ^= 1;
        assert_ne!(
            Libcrux.ml_dsa_65_sign(&xi, &m, &ctx, &other).unwrap(),
            sig,
            "{id}"
        );
        // And the entry finds libcrux's signature equal to aspis-crypto's,
        // with the same rnd and context (a message cut to 1 KiB keeps the
        // input short).
        let rec = Recording::new(&Libcrux);
        let ctx_len = [u8::try_from(ctx.len()).unwrap()];
        differential(
            &rec,
            &with(18, &[&xi, &rnd, &ctx_len, &ctx, &m[..m.len().min(1024)]]),
        );
        assert!(rec.compared(18), "{id}: {:?}", rec.answered());
    }
}

/// The boundary lengths the entry reaches, through libcrux, each equal to
/// aspis-crypto's answer: HKDF output of 0 and 255 × HashLen octets,
/// SHAKE256 into an empty buffer, and each AEAD sealing an empty
/// plaintext under an empty aad.
fn boundary_lengths() {
    let (salt, ikm, info) = (b"salt".as_slice(), b"ikm".as_slice(), b"info".as_slice());
    for n in [0, Prk256::MAX_OUTPUT] {
        let (mut ours, mut theirs) = (vec![0; n], vec![1; n]);
        hkdf_sha256_extract(Some(salt), ikm)
            .expand(info, &mut ours)
            .unwrap();
        assert_eq!(Libcrux.hkdf_sha256(salt, ikm, info, &mut theirs), Some(()));
        assert_eq!(ours, theirs, "HKDF-SHA-256 of {n} octets");
    }
    for n in [0, Prk384::MAX_OUTPUT] {
        let (mut ours, mut theirs) = (vec![0; n], vec![1; n]);
        hkdf_sha384_extract(Some(salt), ikm)
            .expand(info, &mut ours)
            .unwrap();
        assert_eq!(Libcrux.hkdf_sha384(salt, ikm, info, &mut theirs), Some(()));
        assert_eq!(ours, theirs, "HKDF-SHA-384 of {n} octets");
    }
    assert_eq!(Libcrux.shake256(b"abc", &mut []), Some(()));
    let (nonce, key) = ([7; 12], [9; 32]);
    let key_128: [u8; 16] = key[..16].try_into().unwrap();
    let ours = ChaCha20Poly1305Key::from_bytes(&key)
        .seal_in_place(&nonce, b"", &mut [])
        .unwrap();
    assert_eq!(
        Libcrux.chacha20poly1305_seal(&key, &nonce, b"", b"", &mut []),
        Some(ours)
    );
    let ours = Aes256GcmKey::from_bytes(&key)
        .seal_in_place(&nonce, b"", &mut [])
        .unwrap();
    assert_eq!(
        Libcrux.aes256gcm_seal(&key, &nonce, b"", b"", &mut []),
        Some(ours)
    );
    let ours = Aes128GcmKey::from_bytes(&key_128)
        .seal_in_place(&nonce, b"", &mut [])
        .unwrap();
    assert_eq!(
        Libcrux.aes128gcm_seal(&key_128, &nonce, b"", b"", &mut []),
        Some(ours)
    );
}

/// The oracle's wiring, against the standards'
/// vectors directly, and the boundary lengths of the entry's inputs.
#[test]
fn libcrux_known_answers() {
    on_big_stack(|| {
        x25519_known_answers();
        ed25519_known_answers();
        mac_known_answers();
        cipher_known_answers();
        ml_kem_known_answers();
        ml_dsa_known_answers();
        boundary_lengths();
        // The composite's halves: RFC 10073's key gives its public key
        // through the two key methods.
        let (t, _, _) = rfc10073();
        let sk = crypto_repo::vectors::base64(t.get("sk").as_str());
        let pk = crypto_repo::vectors::base64(t.get("pk").as_str());
        let ml = Libcrux
            .ml_dsa_65_public(sk[..32].try_into().unwrap())
            .unwrap();
        let ed = Libcrux
            .ed25519_public(sk[32..].try_into().unwrap())
            .unwrap();
        assert_eq!([&ml[..], &ed[..]].concat(), pk);
        // ctx_field is the entry's u16 context framing.
        assert_eq!(ctx_field(b"ab"), [0, 2, b'a', b'b']);
    });
}

/// Every embedded differential input runs through the entry with libcrux
/// as the oracle, and the inputs' names are valid and unique.
#[test]
fn libcrux_agrees_on_every_input() {
    on_big_stack(|| {
        let mut names = BTreeSet::new();
        for (name, d) in crypto_repo::differential_inputs() {
            assert!(fuzz_gate::harness::valid_name(&name), "{name}");
            assert!(names.insert(name.clone()), "{name} twice");
            differential(&Libcrux, &d);
        }
    });
}

/// Whether a `crypto-differential` seed may leave its primitive
/// partly compared, as `crypto_targets::DIFFERENTIAL_KINDS` documents: a
/// composite with a context over 255 octets, or under an all-zero hedge,
/// which the entry refuses to sign after comparing the public keys; and
/// an Ed25519 or ML-DSA-65 verification `aspis-crypto` refuses, where the
/// oracle isn't asked: random filler, sigVer's failing vectors, and
/// ML-DSA-65 vectors cut to `max_len`, whose messages changed. The
/// generator names them so; every other seed must be compared in full.
fn may_skip(name: &str, selector: u8, data: &[u8]) -> bool {
    (selector == COMPOSITE && (composite_context_len(data) > 255 || zero_hedge(data)))
        || ([14, 19].contains(&selector) && name.contains("-filler-"))
        || (selector == 19 && (name.ends_with("-cut") || name.contains("-fail")))
}

/// Which primitives libcrux actually compares, seed by
/// seed. A seed is its primitive's kind only when every oracle method of
/// its `COMPARED` row answered; any other seed must be one of the
/// documented partial cases ([`may_skip`]). Every selector has a seed
/// compared in full, every method of the trait outside `NOT_COMPARED`
/// answers on some seed, and `NOT_COMPARED` is empty. So a `None`, today
/// or after a libcrux bump, fails here by the method's name.
#[test]
fn libcrux_compares_every_primitive() {
    on_big_stack(|| {
        assert_eq!(COMPARED.len(), usize::from(DIFFERENTIAL_PRIMITIVES));
        let mut full = vec![0usize; COMPARED.len()];
        let mut partial = vec![0usize; COMPARED.len()];
        let mut answered = BTreeSet::new();
        for (name, d) in common::all_seeds(&CRYPTO_DIFFERENTIAL) {
            let Some(&first) = d.first() else {
                assert_eq!(differential_kinds(&d), ["empty"], "{name}");
                continue;
            };
            let sel = first % DIFFERENTIAL_PRIMITIVES;
            let (kind, methods) = differential_compared(&d);
            answered.extend(methods.iter().copied());
            let row = COMPARED[usize::from(sel)];
            if kind == row.1 {
                full[usize::from(sel)] += 1;
                for m in row.2 {
                    assert!(methods.contains(m), "{name}: {m} didn't answer");
                }
            } else {
                partial[usize::from(sel)] += 1;
                assert!(
                    may_skip(&name, sel, &d),
                    "{name}: {kind}, but it should compare {} in full; answered {methods:?}",
                    row.1
                );
                let want = if sel == COMPOSITE && composite_context_len(&d) > 255 {
                    "composite-context-too-long"
                } else if sel == COMPOSITE && zero_hedge(&d) {
                    "composite-zero-hedge"
                } else {
                    "not-compared"
                };
                assert_eq!(kind, want, "{name}");
            }
        }
        eprintln!("selector  primitive               compared  partial");
        for (i, (sel, kind, _)) in COMPARED.iter().enumerate() {
            eprintln!("{sel:>8}  {kind:<22}  {:>8}  {:>7}", full[i], partial[i]);
        }
        for i in 0..usize::from(DIFFERENTIAL_PRIMITIVES) {
            assert!(full[i] > 0, "no seed compares {} in full", COMPARED[i].1);
        }
        let want: BTreeSet<&str> = RECORDED
            .iter()
            .copied()
            .filter(|m| !NOT_COMPARED.contains(m))
            .collect();
        assert_eq!(answered, want, "the methods that answered on some seed");
        assert!(
            NOT_COMPARED.is_empty(),
            "a method libcrux can't answer: update the docs ({NOT_COMPARED:?})"
        );
        // The kinds table is `empty`, `not-compared`,
        // `composite-context-too-long`, `composite-zero-hedge` and
        // COMPARED's names, in order.
        let names: Vec<&str> = COMPARED.iter().map(|r| r.1).collect();
        assert_eq!(
            DIFFERENTIAL_KINDS,
            [
                &[
                    "empty",
                    "not-compared",
                    "composite-context-too-long",
                    "composite-zero-hedge",
                ][..],
                &names
            ]
            .concat()
        );
    });
}

/// The kind a failing sigVer vector reaches in `verify`, by its reason,
/// as `crates/crypto/tests/ml_dsa.rs` classifies it: a changed message or
/// commitment fails verification; a changed hint or z may already fail
/// at decoding.
fn sigver_kinds(reason: &str) -> &'static [&'static str] {
    if reason.contains("message") || reason.contains("commitment") {
        &["verify-ml-dsa-verification"]
    } else {
        assert!(reason.contains("hint") || reason.contains("z"), "{reason}");
        &["verify-ml-dsa-encoding", "verify-ml-dsa-verification"]
    }
}

/// Each `crypto-decode` seed reaches the entry and
/// scheme its name gives, and the ML-DSA-65 verification seeds reach what
/// their vectors say: a sigGen or passing sigVer vector that fits is
/// accepted, one cut to `max_len` (its message changed) fails
/// verification, and a failing sigVer vector fails as its reason says.
#[test]
fn decode_seeds_reach_their_entries() {
    on_big_stack(|| {
        let reasons: BTreeMap<String, String> = acvp("ml-dsa-65-sigver")
            .into_iter()
            .filter_map(|(_, t)| {
                let r = t.try_get("reason")?.as_str().to_string();
                Some((tc_name(&t), r))
            })
            .collect();
        let (mut ok, mut cut) = (0, 0);
        for (name, d) in crypto_targets::decode_seeds() {
            let kinds = decode_kinds(&d);
            assert_eq!(kinds.len(), 1, "{name}");
            let kind = kinds[0];
            let Some((e, rest)) = split_entry(&d) else {
                assert_eq!((name.as_str(), kind), ("empty", "empty"));
                continue;
            };
            if name.ends_with("-alone") {
                assert!(
                    kind == "empty" || kind == format!("{}-length", e.name),
                    "{name}: {kind}"
                );
                continue;
            }
            let prefix = match rest.first() {
                Some(&b) if !e.schemes.is_empty() => {
                    format!(
                        "{}-{}-",
                        e.name,
                        e.schemes[usize::from(b) % e.schemes.len()]
                    )
                }
                _ => format!("{}-", e.name),
            };
            assert!(name.starts_with(&prefix), "{name} isn't framed as {prefix}");
            assert!(kind.starts_with(&prefix), "{name} reaches {kind}");
            for file in ["siggen", "sigver"] {
                let Some(id) = name.strip_prefix(&format!("verify-ml-dsa-{file}-")) else {
                    continue;
                };
                let was_cut = id.ends_with("-cut");
                cut += usize::from(was_cut);
                let id = id.trim_end_matches("-cut");
                let want: &[&str] = if let Some(tc) = id.strip_suffix("-fail") {
                    sigver_kinds(&reasons[tc])
                } else if was_cut {
                    &["verify-ml-dsa-verification"]
                } else {
                    ok += 1;
                    &["verify-ml-dsa-ok"]
                };
                assert!(want.contains(&kind), "{name}: {kind}, not {want:?}");
            }
        }
        // 5 sigGen and 1 passing sigVer vector fit, and 3 failing sigVer
        // vectors; the other 16 of the 25 are cut.
        assert_eq!((ok, cut), (6, 16));
    });
}

/// Each `crypto-aead` seed reaches the outcome its name gives, as
/// `crypto_targets::aead_seeds` documents: a message sealed under the
/// fixed key opens, at every length up to 2^14 octets, with a 255-octet
/// aad, and with one octet past `MAX_CIPHERTEXT` that the entry cuts off;
/// one sealed octet longer still is cut inside its tag and fails
/// verification; a ciphertext shorter than a tag is refused for its
/// length; and RFC 9001's packets, under the RFC's keys, fail
/// verification. Every seed matches one rule, and each rule is counted,
/// so a renamed or dropped seed fails here, and a regression in opening
/// long records or in the cut can't pass as another seed's kind.
#[test]
fn aead_seeds_reach_their_kinds() {
    const AEADS: [&str; 3] = ["chacha20-poly1305", "aes-256-gcm", "aes-128-gcm"];
    let mut counts: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    let seeds = crypto_targets::aead_seeds();
    for (name, d) in &seeds {
        let kinds = aead_kinds(d);
        if name == "empty" {
            assert_eq!(kinds, ["empty"]);
            continue;
        }
        let aead = AEADS
            .iter()
            .copied()
            .find(|a| name.starts_with(&format!("{a}-")))
            .unwrap_or_else(|| panic!("{name}: no AEAD"));
        let rest = &name[aead.len() + 1..];
        let (rule, outcome) = if rest.starts_with("rfc9001-") {
            ("rfc9001", "verification")
        } else if let Some(n) = rest.strip_prefix("short-") {
            assert!(n.parse::<usize>().unwrap() < 16, "{name}");
            ("short", "length")
        } else if rest == "sealed-aad-255" {
            ("aad-255", "ok")
        } else if let Some(n) = rest.strip_prefix("sealed-") {
            if let Some(n) = n.strip_suffix("-and-1") {
                assert_eq!(n, "16624", "{name}");
                ("and-1", "ok")
            } else if let Some(n) = n.strip_suffix("-cut") {
                assert_eq!(n, "16625", "{name}");
                ("cut", "verification")
            } else {
                let n: usize = n.parse().unwrap_or_else(|_| panic!("{name}"));
                assert!(AEAD_LENGTHS.contains(&n), "{name}");
                ("sealed", "ok")
            }
        } else {
            panic!("{name}: no rule says what it reaches");
        };
        assert_eq!(kinds, [format!("{aead}-{outcome}")], "{name}");
        *counts.entry((aead, rule)).or_default() += 1;
    }
    for aead in AEADS {
        let n = |rule| counts.get(&(aead, rule)).copied().unwrap_or(0);
        assert_eq!(n("sealed"), AEAD_LENGTHS.len(), "{aead}");
        assert!(AEAD_LENGTHS.contains(&(1 << 14)), "a 2^14-octet record");
        for rule in ["aad-255", "and-1", "cut"] {
            assert_eq!(n(rule), 1, "{aead} {rule}");
        }
        assert_eq!(n("short"), 2, "{aead}");
    }
    // RFC 9001's ChaCha20-Poly1305 packet (A.5) and its AES-128-GCM
    // packets and Retry tag.
    assert!(counts.get(&("chacha20-poly1305", "rfc9001")) > Some(&0));
    assert!(counts.get(&("aes-128-gcm", "rfc9001")) > Some(&0));
    let total: usize = counts.values().sum();
    assert_eq!(
        total + 1,
        seeds.len(),
        "every seed but `empty` matched a rule"
    );
}

/// Each entry's `max_len` is its figure in
/// `aspis_crypto::fuzz`'s module doc, and the targets' rows use them.
#[test]
fn max_lens_follow_the_module_doc() {
    use fuzz_gate::crypto_targets::*;
    assert_eq!(PUBLIC_KEY_MAX, 1 + 1984 + 1024);
    assert_eq!(PUBLIC_KEY_MAX, 3009);
    assert_eq!(CIPHERTEXT_MAX, 1088 + 1024);
    assert_eq!(KEY_SHARE_MAX, 1 + 1216 + 1024);
    assert_eq!(SIGNATURE_MAX, 1 + 3373 + 1024);
    assert_eq!(VERIFY_MAX, 1 + 1984 + 3373 + 2 + 300 + 1024);
    assert_eq!(VERIFY_MAX, 6684);
    assert_eq!(ALGORITHM_MAX, 1 + 64 + 1024);
    assert_eq!(AEAD_MAX, 1 + 12 + 1 + 255 + 16_640 + 1024);
    assert_eq!(AEAD_MAX, 17_933);
    assert_eq!(DIFFERENTIAL_MAX, 1 + 1952 + 3309 + 2 + 300 + 1024);
    assert_eq!(DIFFERENTIAL_MAX, 6588);
    // crypto-decode takes the entry's octet and the largest entry input.
    let largest = [
        PUBLIC_KEY_MAX,
        CIPHERTEXT_MAX,
        KEY_SHARE_MAX,
        SIGNATURE_MAX,
        VERIFY_MAX,
        ALGORITHM_MAX,
    ]
    .into_iter()
    .max()
    .unwrap();
    assert_eq!(DECODE_MAX, 1 + largest);
    assert_eq!(fuzz_gate::CRYPTO_DECODE.max_len, 6685);
    assert_eq!(CRYPTO_AEAD.max_len, AEAD_MAX);
    assert_eq!(CRYPTO_DIFFERENTIAL.max_len, DIFFERENTIAL_MAX);
}
