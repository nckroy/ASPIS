// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The differential oracle of `crypto-differential`: libcrux (ADR 0069,
//! rule 8; docs/design/call-language.md, "Differential tests").
//!
//! [`Libcrux`] implements `aspis_crypto::fuzz::Oracle` with libcrux's
//! crates, which live in the fuzz workspace only, so they never enter the
//! product lock, the images or the SBOM (ADR 0068, rule 3). It answers
//! every method of the trait. A `None` from the trait means only "the
//! oracle lacks this primitive", and `aspis_crypto::fuzz::differential`
//! then skips the comparison, so no method here turns a libcrux error into
//! `None`: an error the entry's own bounds rule out is an `expect` with the
//! reason, and a skipped comparison can never pass silently.
//!
//! [`Recording`] wraps an oracle and notes each method that answered, and
//! [`COMPARED`] says, for each of the entry's selectors, which methods must
//! answer for the primitive to count as compared. `tests/crypto.rs` holds
//! [`Libcrux`] to them: every answer is checked (an oracle that corrupts
//! any one output makes the entry panic), every method is forwarded, and
//! the known answers of the standards come back through each method.

use std::cell::RefCell;

/// Whether a build-time variable is `1`.
const fn is_one(v: Option<&str>) -> bool {
    match v {
        Some(s) => matches!(s.as_bytes(), b"1"),
        None => false,
    }
}

// libcrux's build scripts turn on its SIMD backends unless these are set,
// and the repository's `.cargo/config.toml` sets them for every cargo run
// (docs/design/call-language.md, "Engine and tools"). A build that missed
// them, such as one from outside the repository, would compare against
// NEON or AVX2 code that differs by machine, so it fails here.
const _: () = assert!(
    is_one(option_env!("LIBCRUX_DISABLE_SIMD128"))
        && is_one(option_env!("LIBCRUX_DISABLE_SIMD256")),
    "build the fuzz workspace from the repository, whose .cargo/config.toml keeps libcrux portable"
);

use aspis_crypto::fuzz::{DIFFERENTIAL_PRIMITIVES, Oracle};
use libcrux_ml_dsa::ml_dsa_65;
use libcrux_ml_kem::mlkem768;

/// The methods `aspis_crypto::fuzz::Oracle` has that [`Libcrux`] can't
/// answer: none. With libcrux-aes's `acvp` feature, which `fuzz/gate`
/// turns on, libcrux answers all 25 (docs/design/call-language.md,
/// "Engine and tools", for why `acvp` is accepted in fuzz/ only).
///
/// One comparison has no method at all: QUIC's ChaCha20 header-protection
/// mask. libcrux keeps its raw ChaCha20 private (libcrux-chacha20poly1305's
/// `hacl` module is `pub(crate)`, and no feature exposes it), so the trait
/// has no ChaCha20 method, and `crates/crypto/tests/quic.rs` checks the
/// mask against RFC 8439's block function instead. A libcrux without
/// `acvp` would break this module's build, and move `aes128_ecb` and
/// `aes256_ecb` here. `tests/crypto.rs` asserts that this list is empty,
/// so it fails until the list, that assertion, [`COMPARED`] and the docs
/// are changed together.
pub const NOT_COMPARED: &[&str] = &[];

/// For each selector of `aspis_crypto::fuzz::differential`, in order: its
/// name, which is its kind in `crypto-differential`, and the oracle
/// methods that must all answer for the primitive to be compared. The
/// composite (20) is compared through its halves, over M′ built by the
/// entry: SHA-512 of the message, each half's key and signature, and each
/// half's verification of the signature with one bit flipped, which the
/// composite's verifier must accept exactly when both halves do.
pub const COMPARED: &[(u8, &str, &[&str])] = &[
    (0, "sha-256", &["sha256"]),
    (1, "sha-384", &["sha384"]),
    (2, "sha-512", &["sha512"]),
    (3, "sha3-256", &["sha3_256"]),
    (4, "shake256", &["shake256"]),
    (5, "hmac-sha-256", &["hmac_sha256"]),
    (6, "hmac-sha-384", &["hmac_sha384"]),
    (7, "hmac-sha-512", &["hmac_sha512"]),
    (8, "hkdf-sha-256", &["hkdf_sha256"]),
    (9, "hkdf-sha-384", &["hkdf_sha384"]),
    (10, "chacha20-poly1305", &["chacha20poly1305_seal"]),
    (11, "aes-256-gcm", &["aes256gcm_seal"]),
    (12, "x25519", &["x25519"]),
    (13, "ed25519-sign", &["ed25519_public", "ed25519_sign"]),
    (14, "ed25519-verify", &["ed25519_verify"]),
    (
        15,
        "ml-kem-768",
        &[
            "ml_kem_768_public",
            "ml_kem_768_encapsulate",
            "ml_kem_768_decapsulate",
        ],
    ),
    (16, "ml-kem-768-encapsulate", &["ml_kem_768_encapsulate"]),
    (17, "ml-kem-768-decapsulate", &["ml_kem_768_decapsulate"]),
    (
        18,
        "ml-dsa-65-sign",
        &["ml_dsa_65_public", "ml_dsa_65_sign"],
    ),
    (19, "ml-dsa-65-verify", &["ml_dsa_65_verify"]),
    (
        20,
        "composite",
        &[
            "ml_dsa_65_public",
            "ed25519_public",
            "sha512",
            "ml_dsa_65_sign",
            "ed25519_sign",
            "ml_dsa_65_verify",
            "ed25519_verify",
        ],
    ),
    (21, "aes-128-gcm", &["aes128gcm_seal"]),
    (22, "aes-128-mask", &["aes128_ecb"]),
    (23, "aes-256-mask", &["aes256_ecb"]),
];

// One row per selector: a selector C08 adds fails the build until it has
// one.
const _: () = assert!(COMPARED.len() == DIFFERENTIAL_PRIMITIVES as usize);

/// The oracle methods a primitive needs, by selector.
pub fn compared(selector: u8) -> &'static [&'static str] {
    COMPARED[usize::from(selector % DIFFERENTIAL_PRIMITIVES)].2
}

/// libcrux, as `aspis_crypto::fuzz::differential`'s oracle. Each method's
/// inputs come from the entry, within its bounds: HKDF output up to 255 ×
/// HashLen, SHAKE256 output up to 1 KiB, AEAD plaintext up to 2^14 octets
/// with aad up to 255, and ML-DSA contexts up to 255 when signing.
pub struct Libcrux;

impl Oracle for Libcrux {
    fn sha256(&self, m: &[u8]) -> Option<[u8; 32]> {
        Some(libcrux_sha2::sha256(m))
    }

    fn sha384(&self, m: &[u8]) -> Option<[u8; 48]> {
        Some(libcrux_sha2::sha384(m))
    }

    fn sha512(&self, m: &[u8]) -> Option<[u8; 64]> {
        Some(libcrux_sha2::sha512(m))
    }

    fn sha3_256(&self, m: &[u8]) -> Option<[u8; 32]> {
        Some(libcrux_sha3::sha256(m))
    }

    /// libcrux writes `out.len()` octets; an empty `out` is fine
    /// (`tests/crypto.rs`, `libcrux_known_answers`).
    fn shake256(&self, m: &[u8], out: &mut [u8]) -> Option<()> {
        libcrux_sha3::shake256_ema(out, m);
        Some(())
    }

    // The typed HMAC functions, which write a full tag; libcrux-hmac's
    // `hmac(Algorithm, ...)` would truncate to a shorter buffer silently.
    fn hmac_sha256(&self, key: &[u8], m: &[u8]) -> Option<[u8; 32]> {
        let mut tag = [0; 32];
        libcrux_hmac::hmac_sha2_256(&mut tag, key, m);
        Some(tag)
    }

    fn hmac_sha384(&self, key: &[u8], m: &[u8]) -> Option<[u8; 48]> {
        let mut tag = [0; 48];
        libcrux_hmac::hmac_sha2_384(&mut tag, key, m);
        Some(tag)
    }

    fn hmac_sha512(&self, key: &[u8], m: &[u8]) -> Option<[u8; 64]> {
        let mut tag = [0; 64];
        libcrux_hmac::hmac_sha2_512(&mut tag, key, m);
        Some(tag)
    }

    /// libcrux takes outputs of 0 to 255 × 32 octets, the entry's range
    /// (`tests/crypto.rs`, `libcrux_known_answers`).
    fn hkdf_sha256(&self, salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Option<()> {
        libcrux_hkdf::hkdf(libcrux_hkdf::Algorithm::Sha256, out, salt, ikm, info)
            .expect("HKDF-SHA-256 output within 255 × HashLen");
        Some(())
    }

    fn hkdf_sha384(&self, salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Option<()> {
        libcrux_hkdf::hkdf(libcrux_hkdf::Algorithm::Sha384, out, salt, ikm, info)
            .expect("HKDF-SHA-384 output within 255 × HashLen");
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
        let mut tag = [0; 16];
        libcrux_chacha20poly1305::encrypt_detached(key, pt, ct, &mut tag, aad, nonce)
            .expect("ChaCha20-Poly1305 seals a plaintext of at most 2^14 octets");
        Some(tag)
    }

    fn aes256gcm_seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
    ) -> Option<[u8; 16]> {
        let key = libcrux_aes::AesGcm256Key::from(*key);
        let nonce = libcrux_aes::AesGcm256Nonce::from(*nonce);
        let mut tag = libcrux_aes::AesGcm256Tag::from([0; 16]);
        key.encrypt(ct, &mut tag, &nonce, aad, pt)
            .expect("AES-256-GCM seals a plaintext of at most 2^14 octets");
        Some(*tag.as_ref())
    }

    fn aes128gcm_seal(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 12],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
    ) -> Option<[u8; 16]> {
        let key = libcrux_aes::AesGcm128Key::from(*key);
        let nonce = libcrux_aes::AesGcm128Nonce::from(*nonce);
        let mut tag = libcrux_aes::AesGcm128Tag::from([0; 16]);
        key.encrypt(ct, &mut tag, &nonce, aad, pt)
            .expect("AES-128-GCM seals a plaintext of at most 2^14 octets");
        Some(*tag.as_ref())
    }

    /// The portable block function, named, so the masks are checked
    /// against the same AES on every machine (libcrux-aes's `acvp`
    /// module, behind the feature `fuzz/gate` turns on).
    fn aes128_ecb(&self, key: &[u8; 16], block: &[u8; 16]) -> Option<[u8; 16]> {
        let mut b = *block;
        libcrux_aes::acvp::portable_aes128_encrypt_block(key, &mut b);
        Some(b)
    }

    fn aes256_ecb(&self, key: &[u8; 32], block: &[u8; 16]) -> Option<[u8; 16]> {
        let mut b = *block;
        libcrux_aes::acvp::portable_aes256_encrypt_block(key, &mut b);
        Some(b)
    }

    /// The raw function of RFC 7748, section 5, with an all-zero output
    /// kept. Not `ecdh`, which takes the public key first and refuses a
    /// zero output.
    fn x25519(&self, k: &[u8; 32], u: &[u8; 32]) -> Option<[u8; 32]> {
        let mut out = [0; 32];
        libcrux_curve25519::hacl::scalarmult(&mut out, k, u);
        Some(out)
    }

    fn ed25519_public(&self, seed: &[u8; 32]) -> Option<[u8; 32]> {
        let mut pk = [0; 32];
        libcrux_ed25519::secret_to_public(&mut pk, seed);
        Some(pk)
    }

    fn ed25519_sign(&self, seed: &[u8; 32], m: &[u8]) -> Option<[u8; 64]> {
        Some(
            libcrux_ed25519::sign(m, seed)
                .expect("Ed25519 signs a message of at most a few KiB under any seed"),
        )
    }

    /// A key or signature libcrux can't decode is `Some(false)`, as the
    /// trait asks. HACL's Ed25519 doesn't refuse small-order keys, so it
    /// is as lax as `aspis-crypto` or laxer (ADR 0069, rule 5), which is
    /// the direction the entry's property allows.
    fn ed25519_verify(&self, pk: &[u8; 32], m: &[u8], sig: &[u8; 64]) -> Option<bool> {
        Some(libcrux_ed25519::verify(m, pk, sig).is_ok())
    }

    /// The seed is d ‖ z, as FIPS 203's ML-KEM.KeyGen_internal takes it
    /// and as `aspis-crypto` lays it out.
    fn ml_kem_768_public(&self, seed: &[u8; 64]) -> Option<[u8; 1184]> {
        let kp = mlkem768::generate_key_pair(*seed);
        Some(*kp.pk())
    }

    /// libcrux's `encapsulate` doesn't check the key's modulus: FIPS 203,
    /// section 7.2's check is `validate_public_key`, so it runs first, and
    /// a key that fails it is `Some(false)`.
    fn ml_kem_768_encapsulate(
        &self,
        ek: &[u8; 1184],
        m: &[u8; 32],
        ct: &mut [u8; 1088],
        ss: &mut [u8; 32],
    ) -> Option<bool> {
        let pk = mlkem768::MlKem768PublicKey::from(ek);
        if !mlkem768::validate_public_key(&pk) {
            return Some(false);
        }
        let (c, s) = mlkem768::encapsulate(&pk, *m);
        ct.copy_from_slice(c.as_ref());
        *ss = s;
        Some(true)
    }

    fn ml_kem_768_decapsulate(&self, seed: &[u8; 64], ct: &[u8; 1088]) -> Option<[u8; 32]> {
        let kp = mlkem768::generate_key_pair(*seed);
        let ct = mlkem768::MlKem768Ciphertext::from(ct);
        Some(mlkem768::decapsulate(kp.private_key(), &ct))
    }

    fn ml_dsa_65_public(&self, xi: &[u8; 32]) -> Option<[u8; 1952]> {
        let kp = ml_dsa_65::generate_key_pair(*xi);
        Some(*kp.verification_key.as_ref())
    }

    /// FIPS 204, Algorithm 2 (ML-DSA.Sign), the pure form, through
    /// libcrux's context API with the caller's `rnd` as the hedge. A
    /// context over 255 octets can't happen (the entry passes at most
    /// 255), and rejection sampling that runs out is bounded at 2^-256
    /// (814 attempts, FIPS 204, Appendix C).
    fn ml_dsa_65_sign(
        &self,
        xi: &[u8; 32],
        m: &[u8],
        ctx: &[u8],
        rnd: &[u8; 32],
    ) -> Option<[u8; 3309]> {
        let kp = ml_dsa_65::generate_key_pair(*xi);
        let sig = ml_dsa_65::sign(&kp.signing_key, m, ctx, *rnd)
            .expect("a context of at most 255 octets, and rejection sampling within its bound");
        Some(*sig.as_ref())
    }

    /// A context over 255 octets, or a signature libcrux can't decode,
    /// such as one with a malformed hint, is `Some(false)`.
    fn ml_dsa_65_verify(
        &self,
        pk: &[u8; 1952],
        m: &[u8],
        ctx: &[u8],
        sig: &[u8; 3309],
    ) -> Option<bool> {
        let vk = ml_dsa_65::MLDSA65VerificationKey::new(*pk);
        let sig = ml_dsa_65::MLDSA65Signature::new(*sig);
        Some(ml_dsa_65::verify(&vk, m, ctx, &sig).is_ok())
    }
}

/// An oracle that forwards every method to another and notes the name of
/// each one that answered (returned `Some`), in call order.
/// `crypto-differential`'s kinds use it with [`Libcrux`]: an input is its
/// primitive's kind only if every method of [`COMPARED`] answered.
pub struct Recording<'a> {
    oracle: &'a dyn Oracle,
    answered: RefCell<Vec<&'static str>>,
}

impl<'a> Recording<'a> {
    pub fn new(oracle: &'a dyn Oracle) -> Self {
        Self {
            oracle,
            answered: RefCell::new(Vec::new()),
        }
    }

    /// The methods that answered, in call order.
    pub fn answered(&self) -> Vec<&'static str> {
        self.answered.borrow().clone()
    }

    /// Whether every method of `selector`'s [`COMPARED`] row answered.
    pub fn compared(&self, selector: u8) -> bool {
        let answered = self.answered.borrow();
        compared(selector).iter().all(|m| answered.contains(m))
    }

    fn note<T>(&self, name: &'static str, answer: Option<T>) -> Option<T> {
        if answer.is_some() {
            self.answered.borrow_mut().push(name);
        }
        answer
    }
}

/// [`Recording`]'s methods, from one list, so [`RECORDED`] is exactly the
/// methods it forwards. A method the trait gains would default to `None`
/// here, as in [`Libcrux`]; `tests/crypto.rs` compares this list with the
/// trait's source and fails by the method's name.
macro_rules! forward {
    ($(fn $name:ident(&self $(, $arg:ident: $ty:ty)*) -> $ret:ty;)+) => {
        /// The methods [`Recording`] forwards and notes: every method of
        /// `aspis_crypto::fuzz::Oracle`, in the trait's order.
        pub const RECORDED: &[&str] = &[$(stringify!($name)),+];

        impl Oracle for Recording<'_> {
            $(
                fn $name(&self $(, $arg: $ty)*) -> $ret {
                    self.note(stringify!($name), self.oracle.$name($($arg),*))
                }
            )+
        }
    };
}

forward! {
    fn sha256(&self, m: &[u8]) -> Option<[u8; 32]>;
    fn sha384(&self, m: &[u8]) -> Option<[u8; 48]>;
    fn sha512(&self, m: &[u8]) -> Option<[u8; 64]>;
    fn sha3_256(&self, m: &[u8]) -> Option<[u8; 32]>;
    fn shake256(&self, m: &[u8], out: &mut [u8]) -> Option<()>;
    fn hmac_sha256(&self, key: &[u8], m: &[u8]) -> Option<[u8; 32]>;
    fn hmac_sha384(&self, key: &[u8], m: &[u8]) -> Option<[u8; 48]>;
    fn hmac_sha512(&self, key: &[u8], m: &[u8]) -> Option<[u8; 64]>;
    fn hkdf_sha256(&self, salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Option<()>;
    fn hkdf_sha384(&self, salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Option<()>;
    fn chacha20poly1305_seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8]
    ) -> Option<[u8; 16]>;
    fn aes256gcm_seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8]
    ) -> Option<[u8; 16]>;
    fn aes128gcm_seal(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 12],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8]
    ) -> Option<[u8; 16]>;
    fn aes128_ecb(&self, key: &[u8; 16], block: &[u8; 16]) -> Option<[u8; 16]>;
    fn aes256_ecb(&self, key: &[u8; 32], block: &[u8; 16]) -> Option<[u8; 16]>;
    fn x25519(&self, k: &[u8; 32], u: &[u8; 32]) -> Option<[u8; 32]>;
    fn ed25519_public(&self, seed: &[u8; 32]) -> Option<[u8; 32]>;
    fn ed25519_sign(&self, seed: &[u8; 32], m: &[u8]) -> Option<[u8; 64]>;
    fn ed25519_verify(&self, pk: &[u8; 32], m: &[u8], sig: &[u8; 64]) -> Option<bool>;
    fn ml_kem_768_public(&self, seed: &[u8; 64]) -> Option<[u8; 1184]>;
    fn ml_kem_768_encapsulate(
        &self,
        ek: &[u8; 1184],
        m: &[u8; 32],
        ct: &mut [u8; 1088],
        ss: &mut [u8; 32]
    ) -> Option<bool>;
    fn ml_kem_768_decapsulate(&self, seed: &[u8; 64], ct: &[u8; 1088]) -> Option<[u8; 32]>;
    fn ml_dsa_65_public(&self, xi: &[u8; 32]) -> Option<[u8; 1952]>;
    fn ml_dsa_65_sign(
        &self,
        xi: &[u8; 32],
        m: &[u8],
        ctx: &[u8],
        rnd: &[u8; 32]
    ) -> Option<[u8; 3309]>;
    fn ml_dsa_65_verify(
        &self,
        pk: &[u8; 1952],
        m: &[u8],
        ctx: &[u8],
        sig: &[u8; 3309]
    ) -> Option<bool>;
}
