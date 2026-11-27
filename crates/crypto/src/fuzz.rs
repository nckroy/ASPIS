// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Fuzz support (ADR 0068, rules 3 to 5; ADR 0069, rules 5 and 8;
//! docs/design/call-language.md, "Fuzz entry points", "Differential
//! tests").
//!
//! C71's harness wraps these in libFuzzer targets inside `fuzz/`, its own
//! workspace. Nothing here depends on `arbitrary`, libcrux or any fuzz
//! crate, even behind `cfg(fuzzing)`: a target dependency would still
//! enter the product's `Cargo.lock`, which rule 3 of ADR 0068 keeps free of
//! them. The functions are plain and public, so the crate's replay tests
//! run them under `cargo test` over every vector and over mutations.
//!
//! The entries are the trust-boundary decoders of rule 5, and each checks
//! its properties with `assert!`, so a broken property is a panic:
//!
//! - [`public_key`], [`ciphertext`] and [`signature`] decode keys,
//!   ciphertexts and signatures of any length. An accepted input
//!   re-encodes to itself, and every refusal is one the decoder documents.
//! - [`key_share`] decodes X25519MLKEM768's client and server shares (RFC
//!   10024), of any length, and uses each in the exchange.
//! - [`verify`] decodes a key and a signature and verifies them, with a
//!   context up to 300 octets, so the 255-octet limit is crossed.
//! - [`aead_open`] opens a ciphertext under a fixed key, with
//!   ChaCha20-Poly1305 or AES-256-GCM, and with the `quic` feature also
//!   AES-128-GCM.
//! - [`algorithm`] decodes an OID, a TLS codepoint or a JOSE name.
//! - [`differential`] compares `aspis-crypto` with an [`Oracle`], which C71
//!   implements with libcrux (rule 8).
//!
//! Each decoding entry returns the refusal its input met, or `Ok` if the
//! input was accepted or held nothing to decode. Fuzz targets ignore it;
//! the replay tests use it to show that the corpus reaches every refusal.
//!
//! Selectors keep their numbers whatever the features, so a corpus means
//! the same in every build. A selector whose family isn't built does
//! nothing: [`aead_open`] returns `Ok` for AES-128-GCM without `quic`, as
//! for input with nothing to decode, and [`differential`] skips the
//! primitive.
//! [`Error::OutputLength`] and [`Error::SigningFailed`] are never
//! returned: the entries size their own buffers, and signing fails only if
//! a library breaks its contract.
//!
//! Each target's `max_len` is its format's limit plus 1 KiB (call-language
//! "The gate for each target", item 1): for [`public_key`], 1 + 1,984 + 1
//! KiB; for [`ciphertext`], 1,088 + 1 KiB; for [`signature`], 1 + 3,373 + 1
//! KiB; for [`key_share`], 1 + 1,216 + 1 KiB; for [`verify`], 1 + 1,984 +
//! 3,373 + 2 + 300 + 1 KiB of message;
//! for [`aead_open`], 1 + 12 + 1 + 255 + [`MAX_CIPHERTEXT`] + 1 KiB; for
//! [`algorithm`], 1 + 64 + 1 KiB; for [`differential`], 1 + 1,952 + 3,309
//! + 2 + 300 + 1 KiB.

use crate::Error;

/// The seed of the fixed X25519 key [`public_key`] exchanges with.
pub const X25519_SEED: [u8; 32] = [0x58; 32];
/// The seed d ‖ z of the fixed ML-KEM-768 key [`ciphertext`] decapsulates
/// with.
pub const ML_KEM_SEED: [u8; 64] = [0x4b; 64];
/// The random octets m with which [`key_share`] encapsulates to a client
/// share. The server's ephemeral X25519 key there is [`X25519_SEED`]'s,
/// and the fixed client key is that of [`ML_KEM_SEED`] and
/// [`X25519_SEED`].
pub const KEY_SHARE_M: [u8; 32] = [0x6d; 32];
/// The fixed key [`aead_open`] opens with, for ChaCha20-Poly1305 and
/// AES-256-GCM. AES-128-GCM, with the `quic` feature, takes its first 16
/// octets, `AEAD_128_KEY`. The replay tests seal their seeds with them.
pub const AEAD_KEY: [u8; 32] = [0xae; 32];
/// The fixed AES-128-GCM key of [`aead_open`]: [`AEAD_KEY`]'s first 16
/// octets (feature `quic`).
#[cfg(feature = "quic")]
pub const AEAD_128_KEY: [u8; 16] = [0xae; 16];
/// The longest AEAD plaintext the entries take: TLS 1.3's record limit,
/// 2^14 octets (RFC 9846, section 5.1). Longer input is cut to it.
pub const MAX_PLAINTEXT: usize = 1 << 14;
/// The longest ciphertext and tag [`aead_open`] takes: TLS 1.3's limit
/// for a protected record, 2^14 + 256 octets (RFC 9846, section 5.2).
/// Longer input is cut to it.
pub const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 256;
/// The longest context [`verify`] and [`differential`] read: past the
/// limit of 255, so [`Error::ContextTooLong`] is reached.
pub const MAX_FUZZ_CONTEXT: usize = 300;
/// The longest SHAKE256 output [`differential`] compares.
pub const MAX_XOF: usize = 1024;
/// How many primitives [`differential`] selects among, by octet 0.
pub const DIFFERENTIAL_PRIMITIVES: u8 = 24;

/// A broken property: `e` isn't one of the refusals `kinds` the decoder
/// documents.
fn refused(e: Error, kinds: &[Error]) -> Error {
    assert!(kinds.contains(&e), "undocumented refusal {e:?}");
    e
}

/// A cursor over fuzz input that takes fields in order. A field the input
/// runs out before is zero-padded ([`Input::array`]) or short
/// ([`Input::take`]).
struct Input<'a>(&'a [u8]);

#[allow(
    dead_code,
    reason = "which fields an entry takes depends on the families built"
)]
impl<'a> Input<'a> {
    /// Up to `n` octets: fewer if the input runs out.
    fn take(&mut self, n: usize) -> &'a [u8] {
        let (head, tail) = self.0.split_at(n.min(self.0.len()));
        self.0 = tail;
        head
    }

    /// `N` octets, zero-padded if the input runs out.
    fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0; N];
        let got = self.take(N);
        out[..got.len()].copy_from_slice(got);
        out
    }

    fn byte(&mut self) -> u8 {
        self.array::<1>()[0]
    }

    /// A big-endian `u16`.
    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.array())
    }

    /// A context's length (a big-endian `u16` modulo
    /// [`MAX_FUZZ_CONTEXT`] + 1), then the context.
    fn context(&mut self) -> &'a [u8] {
        let n = usize::from(self.u16()) % (MAX_FUZZ_CONTEXT + 1);
        self.take(n)
    }

    /// A one-octet length, then that many octets.
    fn short(&mut self) -> &'a [u8] {
        let n = usize::from(self.byte());
        self.take(n)
    }

    fn rest(self) -> &'a [u8] {
        self.0
    }
}

/// Public-key decoding (ADR 0069, rule 5). Octet 0 picks the key type, mod
/// 5: X25519, Ed25519, an ML-KEM-768 encapsulation key, an ML-DSA-65
/// verifying key, or a composite key. The rest is the key, of any length.
///
/// Properties: an accepted key's `to_bytes` is the input. Every refusal
/// is `Length`, `Encoding` (Ed25519 and the composite), `WeakKey` (the
/// same) or `Modulus` (ML-KEM). An X25519 key is also used in an exchange
/// with [`X25519_SEED`]'s key, which gives a secret that isn't all zeros,
/// or `NonContributory` (RFC 7748, section 6.1).
#[cfg(all(feature = "x25519", feature = "ml-kem", feature = "composite"))]
pub fn public_key(data: &[u8]) -> Result<(), Error> {
    use crate::composite::CompositeVerifyingKey;
    use crate::ed25519::Ed25519VerifyingKey;
    use crate::ml_dsa::MlDsa65VerifyingKey;
    use crate::ml_kem::MlKem768EncapsulationKey;
    use crate::x25519::{X25519PublicKey, X25519SecretKey};
    use Error::{Encoding, Length, Modulus, NonContributory, WeakKey};

    let Some((&which, key)) = data.split_first() else {
        return Ok(());
    };
    match which % 5 {
        0 => {
            let pk = X25519PublicKey::from_bytes(key).map_err(|e| refused(e, &[Length]))?;
            assert!(pk.to_bytes() == key, "X25519 key doesn't re-encode");
            match X25519SecretKey::from_seed(&X25519_SEED).diffie_hellman(&pk) {
                Ok(s) => assert!(s.as_bytes() != &[0; 32], "all-zero X25519 secret"),
                Err(e) => return Err(refused(e, &[NonContributory])),
            }
        }
        1 => {
            let pk = Ed25519VerifyingKey::from_bytes(key)
                .map_err(|e| refused(e, &[Length, Encoding, WeakKey]))?;
            assert!(pk.to_bytes() == key, "Ed25519 key doesn't re-encode");
        }
        2 => {
            let ek = MlKem768EncapsulationKey::from_bytes(key)
                .map_err(|e| refused(e, &[Length, Modulus]))?;
            assert!(ek.to_bytes() == key, "ML-KEM key doesn't re-encode");
        }
        3 => {
            let vk = MlDsa65VerifyingKey::from_bytes(key).map_err(|e| refused(e, &[Length]))?;
            assert!(vk.to_bytes() == key, "ML-DSA key doesn't re-encode");
        }
        _ => {
            let vk = CompositeVerifyingKey::from_bytes(key)
                .map_err(|e| refused(e, &[Length, Encoding, WeakKey]))?;
            assert!(vk.to_bytes() == key, "composite key doesn't re-encode");
        }
    }
    Ok(())
}

/// ML-KEM-768 ciphertext decoding. The input is the ciphertext, of any
/// length.
///
/// Properties: the only refusal is `Length`; an accepted ciphertext
/// re-encodes to itself, and decapsulating it under [`ML_KEM_SEED`]'s key
/// gives the same secret twice (FIPS 203, Algorithm 18, is deterministic).
#[cfg(feature = "ml-kem")]
pub fn ciphertext(data: &[u8]) -> Result<(), Error> {
    use crate::ml_kem::{MlKem768Ciphertext, MlKem768DecapsulationKey};

    let ct = MlKem768Ciphertext::from_bytes(data).map_err(|e| refused(e, &[Error::Length]))?;
    assert!(ct.to_bytes() == data, "ciphertext doesn't re-encode");
    let dk = MlKem768DecapsulationKey::from_seed(&ML_KEM_SEED);
    assert!(
        dk.decapsulate(&ct) == dk.decapsulate(&ct),
        "decapsulation isn't deterministic"
    );
    Ok(())
}

/// X25519MLKEM768 key-share decoding (RFC 10024, sections 4.1 and 4.2).
/// Octet 0 picks the share, mod 2: a client share (0) or a server share
/// (1). The rest is the share, of any length.
///
/// Properties: an accepted share re-encodes to itself.
///
/// - A client share's refusals are `Length` and `Modulus`. An accepted one
///   is encapsulated to with [`KEY_SHARE_M`] and [`X25519_SEED`]'s key,
///   twice: both give the same server share, which decodes back to
///   itself, and the same secret, or both give `NonContributory`.
/// - A server share's only refusal at decoding is `Length`. An accepted
///   one is decapsulated twice with the fixed client key, of
///   [`ML_KEM_SEED`] and [`X25519_SEED`]: both give the same secret, or
///   both `NonContributory`.
///
/// Neither half of a secret is all zeros, so neither was left unfilled.
#[cfg(feature = "hybrid")]
pub fn key_share(data: &[u8]) -> Result<(), Error> {
    use crate::hybrid::{
        X25519MlKem768ClientShare, X25519MlKem768DecapsulationKey, X25519MlKem768ServerShare,
        X25519MlKem768SharedSecret,
    };
    use Error::{Length, Modulus, NonContributory};

    /// Both halves of a secret are other than all zeros.
    fn contributory(s: &X25519MlKem768SharedSecret) -> bool {
        let (ml_kem, x25519) = s.as_bytes().split_at(32);
        ml_kem != [0; 32] && x25519 != [0; 32]
    }

    let Some((&which, share)) = data.split_first() else {
        return Ok(());
    };
    if which % 2 == 0 {
        let client = X25519MlKem768ClientShare::from_bytes(share)
            .map_err(|e| refused(e, &[Length, Modulus]))?;
        assert!(client.to_bytes() == share, "client share doesn't re-encode");
        let first = client.encapsulate(&KEY_SHARE_M, &X25519_SEED);
        let again = client.encapsulate(&KEY_SHARE_M, &X25519_SEED);
        match (first, again) {
            (Ok((server, s)), Ok((server2, s2))) => {
                assert!(
                    server == server2 && s == s2,
                    "encapsulation isn't deterministic"
                );
                let bytes = server.to_bytes();
                assert!(
                    X25519MlKem768ServerShare::from_bytes(&bytes) == Ok(server),
                    "server share doesn't decode back"
                );
                assert!(contributory(&s), "an all-zero half in the secret");
            }
            (Err(e), Err(e2)) => {
                assert!(e == e2, "encapsulation isn't deterministic");
                return Err(refused(e, &[NonContributory]));
            }
            _ => panic!("encapsulation isn't deterministic"),
        }
    } else {
        let server =
            X25519MlKem768ServerShare::from_bytes(share).map_err(|e| refused(e, &[Length]))?;
        assert!(server.to_bytes() == share, "server share doesn't re-encode");
        let client = X25519MlKem768DecapsulationKey::from_seed(&ML_KEM_SEED, &X25519_SEED);
        let first = client.decapsulate(&server);
        assert!(
            first == client.decapsulate(&server),
            "decapsulation isn't deterministic"
        );
        let s = first.map_err(|e| refused(e, &[NonContributory]))?;
        assert!(contributory(&s), "an all-zero half in the secret");
    }
    Ok(())
}

/// Signature decoding. Octet 0 picks the scheme, mod 3: Ed25519,
/// ML-DSA-65 or the composite. The rest is the signature, of any length.
///
/// Properties: every refusal is `Length` or `Encoding`, and an accepted
/// signature's `to_bytes` is the input.
#[cfg(feature = "composite")]
pub fn signature(data: &[u8]) -> Result<(), Error> {
    use crate::composite::CompositeSignature;
    use crate::ed25519::Ed25519Signature;
    use crate::ml_dsa::MlDsa65Signature;
    use Error::{Encoding, Length};

    let Some((&which, sig)) = data.split_first() else {
        return Ok(());
    };
    let kinds = &[Length, Encoding];
    let same = match which % 3 {
        0 => {
            Ed25519Signature::from_bytes(sig)
                .map_err(|e| refused(e, kinds))?
                .to_bytes()
                == sig
        }
        1 => {
            MlDsa65Signature::from_bytes(sig)
                .map_err(|e| refused(e, kinds))?
                .to_bytes()
                == sig
        }
        _ => {
            CompositeSignature::from_bytes(sig)
                .map_err(|e| refused(e, kinds))?
                .to_bytes()
                == sig
        }
    };
    assert!(same, "signature doesn't re-encode");
    Ok(())
}

/// Decoding and verification together. Octet 0 picks the scheme, mod 3:
/// Ed25519, ML-DSA-65 or the composite. Then come the public key and the
/// signature, each at its scheme's length (shorter if the input runs out,
/// which decoding refuses); for ML-DSA-65 and the composite, a big-endian
/// `u16` context length, taken modulo [`MAX_FUZZ_CONTEXT`] + 1, and the
/// context; and the rest is the message.
///
/// Properties: a bad key or signature is refused at decoding, with
/// `Length`, `Encoding` or `WeakKey`. A context over 255 octets gives
/// `ContextTooLong`. A message that starts with the composite's prefix
/// never verifies under a standalone scheme (RFC 10073, section 9.4).
/// Verifying again gives the same result.
#[cfg(feature = "composite")]
pub fn verify(data: &[u8]) -> Result<(), Error> {
    use crate::composite::{self, CompositeSignature, CompositeVerifyingKey};
    use crate::ed25519::{Ed25519Signature, Ed25519VerifyingKey};
    use crate::ml_dsa::{self, MlDsa65Signature, MlDsa65VerifyingKey};
    use crate::{COMPOSITE_PREFIX, ed25519};
    use Error::{ContextTooLong, Encoding, Length, Verification, WeakKey};

    let mut input = Input(data);
    let Some(&which) = data.first() else {
        return Ok(());
    };
    input.byte();
    let decoding = &[Length, Encoding, WeakKey];
    let (result, ctx_len, standalone) = match which % 3 {
        0 => {
            let pk = Ed25519VerifyingKey::from_bytes(input.take(ed25519::PUBLIC_KEY_LEN))
                .map_err(|e| refused(e, decoding))?;
            let sig = Ed25519Signature::from_bytes(input.take(ed25519::SIGNATURE_LEN))
                .map_err(|e| refused(e, decoding))?;
            let msg = input.rest();
            let r = pk.verify(msg, &sig);
            assert!(r == pk.verify(msg, &sig), "Ed25519 isn't deterministic");
            (r, 0, msg.starts_with(COMPOSITE_PREFIX))
        }
        1 => {
            let pk = MlDsa65VerifyingKey::from_bytes(input.take(ml_dsa::VERIFYING_KEY_LEN))
                .map_err(|e| refused(e, decoding))?;
            let sig = MlDsa65Signature::from_bytes(input.take(ml_dsa::SIGNATURE_LEN))
                .map_err(|e| refused(e, decoding))?;
            let ctx = input.context();
            let msg = input.rest();
            let r = pk.verify(msg, ctx, &sig);
            assert!(r == pk.verify(msg, ctx, &sig), "ML-DSA isn't deterministic");
            (r, ctx.len(), msg.starts_with(COMPOSITE_PREFIX))
        }
        _ => {
            let pk = CompositeVerifyingKey::from_bytes(input.take(composite::PUBLIC_KEY_LEN))
                .map_err(|e| refused(e, decoding))?;
            let sig = CompositeSignature::from_bytes(input.take(composite::SIGNATURE_LEN))
                .map_err(|e| refused(e, decoding))?;
            let ctx = input.context();
            let msg = input.rest();
            let r = pk.verify(msg, ctx, &sig);
            assert!(
                r == pk.verify(msg, ctx, &sig),
                "composite isn't deterministic"
            );
            (r, ctx.len(), false)
        }
    };
    if ctx_len > ml_dsa::MAX_CONTEXT {
        assert!(result == Err(ContextTooLong), "a long context was taken");
    } else if standalone {
        assert!(
            result == Err(Verification),
            "a composite half verified alone"
        );
    }
    result.map_err(|e| refused(e, &[ContextTooLong, Verification]))
}

/// AEAD opening. Octet 0 picks the AEAD, mod 3: ChaCha20-Poly1305 (0)
/// or AES-256-GCM (1) under [`AEAD_KEY`], or AES-128-GCM (2) under
/// `AEAD_128_KEY`, the last with the `quic` feature only. Then come the
/// 12-octet nonce, a one-octet aad length and the aad, and the rest is
/// ciphertext ‖ tag, cut to [`MAX_CIPHERTEXT`]. QUIC's packets and Retry
/// tags (RFC 9001) reach the same decoder as TLS records.
///
/// Properties: input shorter than a tag gives `Length`, and one that
/// doesn't open gives `Verification` with the output zeroed. Input that
/// opens seals back to itself. Without `quic`, selector 2 returns `Ok`
/// and opens nothing, so the selectors keep their numbers.
#[cfg(feature = "aead")]
pub fn aead_open(data: &[u8]) -> Result<(), Error> {
    #[cfg(feature = "quic")]
    use crate::aead::Aes128GcmKey;
    use crate::aead::{Aes256GcmKey, ChaCha20Poly1305Key, NONCE_LEN, TAG_LEN};

    /// Opens into a buffer that starts non-zero, then checks the result.
    macro_rules! check {
        ($key:expr, $nonce:expr, $aad:expr, $input:expr) => {{
            let (key, nonce, aad, input) = ($key, $nonce, $aad, $input);
            let n = input.len().saturating_sub(TAG_LEN);
            let mut out = [0xa5; MAX_CIPHERTEXT];
            match key.open(nonce, aad, input, &mut out[..n]) {
                Ok(len) => {
                    assert!(len == n, "AEAD plaintext length");
                    let mut again = [0; MAX_CIPHERTEXT];
                    let sealed = key
                        .seal(nonce, aad, &out[..n], &mut again)
                        .expect("a buffer of MAX_CIPHERTEXT holds it");
                    assert!(&again[..sealed] == input, "AEAD doesn't seal back");
                    Ok(())
                }
                Err(e) => {
                    if e == Error::Verification {
                        assert!(out[..n].iter().all(|&b| b == 0), "AEAD output not zeroed");
                    }
                    Err(refused(e, &[Error::Length, Error::Verification]))
                }
            }
        }};
    }

    let Some(&which) = data.first() else {
        return Ok(());
    };
    let mut input = Input(data);
    input.byte();
    let nonce: [u8; NONCE_LEN] = input.array();
    let aad = input.short();
    let rest = input.rest();
    let rest = &rest[..rest.len().min(MAX_CIPHERTEXT)];
    match which % 3 {
        0 => check!(
            ChaCha20Poly1305Key::from_bytes(&AEAD_KEY),
            &nonce,
            aad,
            rest
        ),
        1 => check!(Aes256GcmKey::from_bytes(&AEAD_KEY), &nonce, aad, rest),
        #[cfg(feature = "quic")]
        _ => check!(Aes128GcmKey::from_bytes(&AEAD_128_KEY), &nonce, aad, rest),
        #[cfg(not(feature = "quic"))]
        _ => Ok(()),
    }
}

/// Algorithm identifiers (ADR 0069, rule 6). Octet 0 picks the form, mod
/// 3: an OID's DER content octets (the rest); a TLS codepoint (octet 1 the
/// registry, mod 3: group, signature scheme or cipher suite; then a
/// big-endian `u16`); or a JOSE name (octet 1 the registry, mod 2: `alg`
/// or `enc`; then the rest, as UTF-8).
///
/// Properties: the only refusal is `UnknownAlgorithm`, and an accepted
/// identifier maps back to the same one.
pub fn algorithm(data: &[u8]) -> Result<(), Error> {
    use crate::algorithm::{Algorithm, JoseName, TlsCodepoint};

    let Some((&which, rest)) = data.split_first() else {
        return Ok(());
    };
    let unknown = |e| refused(e, &[Error::UnknownAlgorithm]);
    match which % 3 {
        0 => {
            let alg = Algorithm::from_oid_der(rest).map_err(unknown)?;
            assert!(alg.oid_der() == Some(rest), "OID doesn't map back");
            assert!(alg.oid().is_some(), "an OID without its dotted form");
        }
        1 => {
            let mut input = Input(rest);
            let registry = input.byte();
            let value = input.u16();
            let cp = match registry % 3 {
                0 => TlsCodepoint::NamedGroup(value),
                1 => TlsCodepoint::SignatureScheme(value),
                _ => TlsCodepoint::CipherSuite(value),
            };
            let alg = Algorithm::from_tls(cp).map_err(unknown)?;
            assert!(alg.tls() == Some(cp), "TLS codepoint doesn't map back");
        }
        _ => {
            let Some((&registry, rest)) = rest.split_first() else {
                return Err(Error::UnknownAlgorithm);
            };
            let name = core::str::from_utf8(rest).map_err(|_| Error::UnknownAlgorithm)?;
            let name = if registry % 2 == 0 {
                JoseName::Alg(name)
            } else {
                JoseName::Enc(name)
            };
            let alg = Algorithm::from_jose(name).map_err(unknown)?;
            assert!(alg.jose() == Some(name), "JOSE name doesn't map back");
        }
    }
    Ok(())
}

/// An independent implementation that [`differential`] compares
/// `aspis-crypto` with (ADR 0069, rule 8). C71's `fuzz/` workspace
/// implements it with libcrux, which never enters the product's lock file.
///
/// Every method has a default that returns `None`, meaning the oracle
/// lacks the primitive; the comparison is then skipped. Inputs and outputs
/// are fixed-size or borrowed, so nothing allocates. There is no composite
/// method: no oracle implements RFC 10073, so [`differential`] checks the
/// composite through its two components. It builds M′ itself and compares
/// each half with the oracle's ML-DSA-65 and Ed25519 over M′.
///
/// QUIC's header protection is compared through its AES block function,
/// which libcrux-aes gives only behind its `acvp` feature. There is no
/// ChaCha20 method: libcrux-chacha20poly1305 keeps its raw ChaCha20
/// private, so the ChaCha20 mask is checked by the crate's tests against
/// RFC 8439's block function instead.
///
/// [`differential`] calls [`Self::aes128gcm_seal`], [`Self::aes128_ecb`]
/// and [`Self::aes256_ecb`] only when `aspis-crypto` is built with its
/// `quic` feature. The trait has them in every build, so an oracle is
/// written once, whatever features it is built against. They are the
/// oracle's AES, not this crate's, so they reach no AES-128 here.
#[allow(unused_variables, reason = "the defaults ignore their inputs")]
pub trait Oracle {
    /// SHA-256 of `m`.
    fn sha256(&self, m: &[u8]) -> Option<[u8; 32]> {
        None
    }
    /// SHA-384 of `m`.
    fn sha384(&self, m: &[u8]) -> Option<[u8; 48]> {
        None
    }
    /// SHA-512 of `m`.
    fn sha512(&self, m: &[u8]) -> Option<[u8; 64]> {
        None
    }
    /// SHA3-256 of `m`.
    fn sha3_256(&self, m: &[u8]) -> Option<[u8; 32]> {
        None
    }
    /// Fills `out` with SHAKE256 of `m`.
    fn shake256(&self, m: &[u8], out: &mut [u8]) -> Option<()> {
        None
    }
    /// HMAC-SHA-256 of `m` under `key`.
    fn hmac_sha256(&self, key: &[u8], m: &[u8]) -> Option<[u8; 32]> {
        None
    }
    /// HMAC-SHA-384 of `m` under `key`.
    fn hmac_sha384(&self, key: &[u8], m: &[u8]) -> Option<[u8; 48]> {
        None
    }
    /// HMAC-SHA-512 of `m` under `key`.
    fn hmac_sha512(&self, key: &[u8], m: &[u8]) -> Option<[u8; 64]> {
        None
    }
    /// Fills `out` with HKDF-SHA-256 (extract with `salt`, then expand
    /// with `info`). `out` is at most 255 × 32 octets.
    fn hkdf_sha256(&self, salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Option<()> {
        None
    }
    /// Fills `out` with HKDF-SHA-384. `out` is at most 255 × 48 octets.
    fn hkdf_sha384(&self, salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Option<()> {
        None
    }
    /// Encrypts `pt` into `ct` (of the same length) and returns the tag.
    fn chacha20poly1305_seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
    ) -> Option<[u8; 16]> {
        None
    }
    /// As [`Self::chacha20poly1305_seal`], with AES-256-GCM.
    fn aes256gcm_seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
    ) -> Option<[u8; 16]> {
        None
    }
    /// As [`Self::chacha20poly1305_seal`], with AES-128-GCM.
    fn aes128gcm_seal(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 12],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
    ) -> Option<[u8; 16]> {
        None
    }
    /// One AES-128 block encryption (AES-ECB of one block), from which
    /// QUIC's AES-128 header-protection mask is taken (RFC 9001, section
    /// 5.4.3).
    fn aes128_ecb(&self, key: &[u8; 16], block: &[u8; 16]) -> Option<[u8; 16]> {
        None
    }
    /// As [`Self::aes128_ecb`], with AES-256.
    fn aes256_ecb(&self, key: &[u8; 32], block: &[u8; 16]) -> Option<[u8; 16]> {
        None
    }
    /// The raw X25519 function of RFC 7748, section 5, all-zero output
    /// included.
    fn x25519(&self, k: &[u8; 32], u: &[u8; 32]) -> Option<[u8; 32]> {
        None
    }
    /// The Ed25519 public key of `seed`.
    fn ed25519_public(&self, seed: &[u8; 32]) -> Option<[u8; 32]> {
        None
    }
    /// The Ed25519 signature of `m` under `seed`'s key.
    fn ed25519_sign(&self, seed: &[u8; 32], m: &[u8]) -> Option<[u8; 64]> {
        None
    }
    /// Whether `sig` verifies over `m` under `pk`; a key or signature the
    /// oracle can't decode is `Some(false)`.
    fn ed25519_verify(&self, pk: &[u8; 32], m: &[u8], sig: &[u8; 64]) -> Option<bool> {
        None
    }
    /// The ML-KEM-768 encapsulation key of the seed d ‖ z.
    fn ml_kem_768_public(&self, seed: &[u8; 64]) -> Option<[u8; 1184]> {
        None
    }
    /// Encapsulates to `ek` with the random octets `m`, writing the
    /// ciphertext and secret: `Some(true)`. `Some(false)` means the oracle
    /// refused `ek`, which must agree with [`Error::Modulus`].
    fn ml_kem_768_encapsulate(
        &self,
        ek: &[u8; 1184],
        m: &[u8; 32],
        ct: &mut [u8; 1088],
        ss: &mut [u8; 32],
    ) -> Option<bool> {
        None
    }
    /// Decapsulates `ct` with the key of the seed d ‖ z.
    fn ml_kem_768_decapsulate(&self, seed: &[u8; 64], ct: &[u8; 1088]) -> Option<[u8; 32]> {
        None
    }
    /// The ML-DSA-65 verifying key of the seed ξ.
    fn ml_dsa_65_public(&self, xi: &[u8; 32]) -> Option<[u8; 1952]> {
        None
    }
    /// The ML-DSA-65 signature of `m` under `ctx` (at most 255 octets),
    /// with `xi`'s key, hedged with `rnd` (FIPS 204, Algorithm 2).
    fn ml_dsa_65_sign(
        &self,
        xi: &[u8; 32],
        m: &[u8],
        ctx: &[u8],
        rnd: &[u8; 32],
    ) -> Option<[u8; 3309]> {
        None
    }
    /// Whether `sig` verifies over `m` under `ctx` and `pk`; a signature
    /// the oracle can't decode, or a context over 255 octets, is
    /// `Some(false)`.
    fn ml_dsa_65_verify(
        &self,
        pk: &[u8; 1952],
        m: &[u8],
        ctx: &[u8],
        sig: &[u8; 3309],
    ) -> Option<bool> {
        None
    }
}

/// The differential target (ADR 0069, rule 8). Octet 0 picks a primitive,
/// mod [`DIFFERENTIAL_PRIMITIVES`]; fixed-size seeds and inputs follow,
/// zero-padded when the input runs out, and the rest is the message.
///
/// | Octet 0 | Primitive | Input after it |
/// |---|---|---|
/// | 0, 1, 2 | SHA-256, SHA-384, SHA-512 | the message |
/// | 3 | SHA3-256 | the message |
/// | 4 | SHAKE256 | a `u16` output length mod [`MAX_XOF`] + 1, the message |
/// | 5, 6, 7 | HMAC-SHA-256, -384, -512 | a one-octet key length, the key, the message |
/// | 8, 9 | HKDF-SHA-256, -384 | salt, ikm and info, each after a one-octet length; a `u16` output length mod 255 × HashLen + 1 |
/// | 10, 11 | ChaCha20-Poly1305, AES-256-GCM sealing | key, nonce, a one-octet aad length, the aad, the plaintext (cut to [`MAX_PLAINTEXT`]) |
/// | 12 | X25519 | k, u |
/// | 13 | Ed25519 key and signing | seed, the message |
/// | 14 | Ed25519 verification | public key, signature, the message |
/// | 15 | ML-KEM-768 key, encapsulation, decapsulation | seed d ‖ z, m |
/// | 16 | ML-KEM-768 encapsulation to any key | encapsulation key, m |
/// | 17 | ML-KEM-768 decapsulation of any ciphertext | seed d ‖ z, ciphertext |
/// | 18 | ML-DSA-65 key and signing | ξ, rnd, a one-octet context length, the context, the message |
/// | 19 | ML-DSA-65 verification | verifying key, signature, a `u16` context length mod 301, the context, the message |
/// | 20 | The composite's key and signing | the 64-octet private key, rnd, a one-octet context length, the context, the message |
/// | 21 | AES-128-GCM sealing (feature `quic`) | a 16-octet key, nonce, a one-octet aad length, the aad, the plaintext (cut to [`MAX_PLAINTEXT`]) |
/// | 22, 23 | QUIC's AES-128 and AES-256 header-protection masks (feature `quic`) | a 16- or 32-octet key, the 16-octet sample |
///
/// Properties, wherever the oracle returns `Some`:
///
/// - every output is the oracle's: digests, MACs, HKDF output, ciphertext
///   and tags, public keys, signatures (Ed25519 is deterministic, and
///   ML-DSA-65 is with its hedge given), ciphertexts and shared secrets;
/// - a header-protection mask is the first five octets of the oracle's
///   AES block encryption of the sample;
/// - a composite's public key is the oracle's ML-DSA-65 key then its
///   Ed25519 key, and its signature the oracle's ML-DSA-65 signature of M′
///   under the label, then its Ed25519 signature of M′, with M′ built
///   here, apart from the composite's code (RFC 10073, sections 2.2 and
///   3.2); an all-zero rnd is refused (rule 3);
/// - X25519 gives [`Error::NonContributory`] exactly when the oracle's raw
///   output is 32 zero octets, and the same octets otherwise;
/// - an ML-KEM-768 encapsulation key is refused with [`Error::Modulus`]
///   exactly when the oracle refuses it;
/// - `aspis-crypto`'s verifiers are never laxer: when one accepts, the
///   oracle accepts. `aspis-crypto` also refuses what the oracle may take:
///   non-canonical and small-order Ed25519 encodings (rule 5), and
///   messages that start with the composite's prefix (RFC 10073, section
///   9.4);
/// - `aspis-crypto`'s own signatures verify under its own verifiers,
///   except over a message that starts with the composite's prefix, and
///   its AEADs open what they sealed.
///
/// A primitive whose family isn't built is skipped: the entry returns
/// without comparing anything. Primitives 21 to 23 are built only with the
/// `quic` feature, and the selectors keep their numbers without it, so
/// [`DIFFERENTIAL_PRIMITIVES`] is 24 in every build. Nothing secret is
/// printed when a property breaks.
pub fn differential(oracle: &dyn Oracle, data: &[u8]) {
    let Some(&which) = data.first() else {
        return;
    };
    let mut input = Input(data);
    input.byte();
    let primitive = which % DIFFERENTIAL_PRIMITIVES;
    let _ = (oracle, &input);
    match primitive {
        #[cfg(feature = "sha2")]
        0..=2 => diff::sha2(oracle, primitive, input.rest()),
        #[cfg(feature = "sha3")]
        3 | 4 => diff::sha3(oracle, primitive, input),
        #[cfg(feature = "sha2")]
        5..=7 => diff::hmac(oracle, primitive, input),
        #[cfg(feature = "sha2")]
        8 | 9 => diff::hkdf(oracle, primitive == 8, input),
        #[cfg(feature = "aead")]
        10 | 11 => diff::aead(oracle, primitive, input),
        #[cfg(feature = "quic")]
        21 => diff::aead(oracle, primitive, input),
        #[cfg(feature = "x25519")]
        12 => diff::x25519(oracle, input),
        #[cfg(feature = "ed25519")]
        13 => diff::ed25519_sign(oracle, input),
        #[cfg(feature = "ed25519")]
        14 => diff::ed25519_verify(oracle, input),
        #[cfg(feature = "ml-kem")]
        15 => diff::ml_kem(oracle, input),
        #[cfg(feature = "ml-kem")]
        16 => diff::ml_kem_encapsulate(oracle, input),
        #[cfg(feature = "ml-kem")]
        17 => diff::ml_kem_decapsulate(oracle, input),
        #[cfg(feature = "ml-dsa")]
        18 => diff::ml_dsa_sign(oracle, input),
        #[cfg(feature = "ml-dsa")]
        19 => diff::ml_dsa_verify(oracle, input),
        #[cfg(feature = "composite")]
        20 => diff::composite(oracle, input),
        #[cfg(feature = "quic")]
        22 | 23 => diff::header_protection(oracle, primitive == 22, input),
        _ => {}
    }
}

/// [`differential`]'s comparisons, one per primitive.
mod diff {
    #[allow(unused_imports, reason = "used by the families built")]
    use super::{Input, MAX_PLAINTEXT, MAX_XOF, Oracle};
    #[cfg(any(feature = "ed25519", feature = "ml-dsa"))]
    use crate::COMPOSITE_PREFIX;
    #[allow(unused_imports, reason = "used by the families built")]
    use crate::Error;

    /// `ours` equals the oracle's output, where it has one.
    #[allow(dead_code, reason = "used by the families built")]
    fn same<T: PartialEq>(theirs: Option<T>, ours: &T, what: &str) {
        if let Some(theirs) = theirs {
            assert!(theirs == *ours, "{what} differs from the oracle");
        }
    }

    #[cfg(feature = "sha2")]
    pub(super) fn sha2(oracle: &dyn Oracle, which: u8, m: &[u8]) {
        use crate::hash::{sha256, sha384, sha512};
        match which {
            0 => same(oracle.sha256(m), &sha256(m), "SHA-256"),
            1 => same(oracle.sha384(m), &sha384(m), "SHA-384"),
            _ => same(oracle.sha512(m), &sha512(m), "SHA-512"),
        }
    }

    #[cfg(feature = "sha3")]
    pub(super) fn sha3(oracle: &dyn Oracle, which: u8, mut input: Input<'_>) {
        use crate::hash::{sha3_256, shake256};
        if which == 3 {
            let m = input.rest();
            return same(oracle.sha3_256(m), &sha3_256(m), "SHA3-256");
        }
        let n = usize::from(input.u16()) % (MAX_XOF + 1);
        let m = input.rest();
        let (mut ours, mut theirs) = ([0; MAX_XOF], [0; MAX_XOF]);
        shake256(m, &mut ours[..n]);
        if oracle.shake256(m, &mut theirs[..n]).is_some() {
            assert!(ours[..n] == theirs[..n], "SHAKE256 differs from the oracle");
        }
    }

    #[cfg(feature = "sha2")]
    pub(super) fn hmac(oracle: &dyn Oracle, which: u8, mut input: Input<'_>) {
        use crate::mac::{hmac_sha256, hmac_sha384, hmac_sha512};
        let key = input.short();
        let m = input.rest();
        match which {
            5 => same(
                oracle.hmac_sha256(key, m),
                &hmac_sha256(key, m),
                "HMAC-SHA-256",
            ),
            6 => same(
                oracle.hmac_sha384(key, m),
                &hmac_sha384(key, m),
                "HMAC-SHA-384",
            ),
            _ => same(
                oracle.hmac_sha512(key, m),
                &hmac_sha512(key, m),
                "HMAC-SHA-512",
            ),
        }
    }

    #[cfg(feature = "sha2")]
    pub(super) fn hkdf(oracle: &dyn Oracle, sha256: bool, mut input: Input<'_>) {
        use crate::mac::{Prk256, Prk384, hkdf_sha256_extract, hkdf_sha384_extract};
        let (salt, ikm, info) = (input.short(), input.short(), input.short());
        let max = if sha256 {
            Prk256::MAX_OUTPUT
        } else {
            Prk384::MAX_OUTPUT
        };
        let n = usize::from(input.u16()) % (max + 1);
        let mut ours = [0; Prk384::MAX_OUTPUT];
        let mut theirs = [0; Prk384::MAX_OUTPUT];
        let (ours, theirs) = (&mut ours[..n], &mut theirs[..n]);
        let supported = if sha256 {
            hkdf_sha256_extract(Some(salt), ikm)
                .expand(info, ours)
                .expect("within 255 × HashLen");
            oracle.hkdf_sha256(salt, ikm, info, theirs)
        } else {
            hkdf_sha384_extract(Some(salt), ikm)
                .expand(info, ours)
                .expect("within 255 × HashLen");
            oracle.hkdf_sha384(salt, ikm, info, theirs)
        };
        if supported.is_some() {
            assert!(ours == theirs, "HKDF differs from the oracle");
        }
    }

    /// Sealing with ChaCha20-Poly1305 (10), AES-256-GCM (11) or, with the
    /// `quic` feature, AES-128-GCM (21).
    #[cfg(feature = "aead")]
    pub(super) fn aead(oracle: &dyn Oracle, which: u8, mut input: Input<'_>) {
        #[cfg(feature = "quic")]
        use crate::aead::Aes128GcmKey;
        use crate::aead::{Aes256GcmKey, ChaCha20Poly1305Key};
        /// Seals `pt` in `ours` under `$key`, opens it again into `back`,
        /// and returns the tag.
        macro_rules! seal_and_open {
            ($key:expr, $nonce:expr, $aad:expr, $ours:expr, $back:expr) => {{
                let (k, nonce, aad, ours, back) = ($key, $nonce, $aad, $ours, $back);
                let tag = k.seal_in_place(nonce, aad, ours).expect("sealable");
                back.copy_from_slice(ours);
                k.open_in_place(nonce, aad, back, &tag)
                    .expect("opens what it sealed");
                tag
            }};
        }
        let key: [u8; 32] = if which == 21 {
            let mut k = [0; 32];
            k[..16].copy_from_slice(&input.array::<16>());
            k
        } else {
            input.array()
        };
        #[cfg(feature = "quic")]
        let key_128: &[u8; 16] = key[..16].try_into().expect("16 of 32 octets");
        let nonce: [u8; 12] = input.array();
        let aad = input.short();
        let pt = input.rest();
        let pt = &pt[..pt.len().min(MAX_PLAINTEXT)];
        let mut ours = [0; MAX_PLAINTEXT];
        let mut their_ct = [0; MAX_PLAINTEXT];
        let mut back = [0; MAX_PLAINTEXT];
        let n = pt.len();
        ours[..n].copy_from_slice(pt);
        let (o, b, t) = (&mut ours[..n], &mut back[..n], &mut their_ct[..n]);
        let (tag, their_tag) = match which {
            10 => (
                seal_and_open!(ChaCha20Poly1305Key::from_bytes(&key), &nonce, aad, o, b),
                oracle.chacha20poly1305_seal(&key, &nonce, aad, pt, t),
            ),
            #[cfg(feature = "quic")]
            21 => (
                seal_and_open!(Aes128GcmKey::from_bytes(key_128), &nonce, aad, o, b),
                oracle.aes128gcm_seal(key_128, &nonce, aad, pt, t),
            ),
            _ => (
                seal_and_open!(Aes256GcmKey::from_bytes(&key), &nonce, aad, o, b),
                oracle.aes256gcm_seal(&key, &nonce, aad, pt, t),
            ),
        };
        assert!(back[..n] == *pt, "AEAD doesn't open what it sealed");
        if let Some(their_tag) = their_tag {
            assert!(
                their_tag == tag && their_ct[..n] == ours[..n],
                "AEAD differs from the oracle"
            );
        }
    }

    /// QUIC's AES-128 (`aes128`) or AES-256 header-protection mask.
    #[cfg(feature = "quic")]
    pub(super) fn header_protection(oracle: &dyn Oracle, aes128: bool, mut input: Input<'_>) {
        use crate::quic::{Aes128HeaderProtectionKey, Aes256HeaderProtectionKey, MASK_LEN};
        let (ours, theirs) = if aes128 {
            let key: [u8; 16] = input.array();
            let sample: [u8; 16] = input.array();
            (
                Aes128HeaderProtectionKey::from_bytes(&key).mask(&sample),
                oracle.aes128_ecb(&key, &sample),
            )
        } else {
            let key: [u8; 32] = input.array();
            let sample: [u8; 16] = input.array();
            (
                Aes256HeaderProtectionKey::from_bytes(&key).mask(&sample),
                oracle.aes256_ecb(&key, &sample),
            )
        };
        if let Some(block) = theirs {
            assert!(
                block[..MASK_LEN] == ours,
                "header-protection mask differs from the oracle"
            );
        }
    }

    #[cfg(feature = "x25519")]
    pub(super) fn x25519(oracle: &dyn Oracle, mut input: Input<'_>) {
        use crate::x25519::{X25519PublicKey, X25519SecretKey};
        let (k, u): ([u8; 32], [u8; 32]) = (input.array(), input.array());
        let sk = X25519SecretKey::from_seed(&k);
        let pk = X25519PublicKey::from_bytes(&u).expect("every 32 octets are a key");
        let ours = sk.diffie_hellman(&pk);
        if let Some(theirs) = oracle.x25519(&k, &u) {
            match ours {
                Ok(s) => assert!(s.as_bytes() == &theirs, "X25519 differs from the oracle"),
                Err(e) => assert!(
                    e == Error::NonContributory && theirs == [0; 32],
                    "X25519 refused a contributory exchange"
                ),
            }
        }
    }

    #[cfg(feature = "ed25519")]
    pub(super) fn ed25519_sign(oracle: &dyn Oracle, mut input: Input<'_>) {
        use crate::ed25519::Ed25519SigningKey;
        let seed: [u8; 32] = input.array();
        let m = input.rest();
        let key = Ed25519SigningKey::from_seed(&seed);
        let vk = key.verifying_key();
        let sig = key.sign(m);
        same(oracle.ed25519_public(&seed), &vk.to_bytes(), "Ed25519 key");
        same(
            oracle.ed25519_sign(&seed, m),
            &sig.to_bytes(),
            "Ed25519 signature",
        );
        let r = vk.verify(m, &sig);
        if m.starts_with(COMPOSITE_PREFIX) {
            assert!(r == Err(Error::Verification), "a prefixed message verified");
        } else {
            assert!(r == Ok(()), "an Ed25519 signature doesn't verify");
        }
    }

    #[cfg(feature = "ed25519")]
    pub(super) fn ed25519_verify(oracle: &dyn Oracle, mut input: Input<'_>) {
        use crate::ed25519::{Ed25519Signature, Ed25519VerifyingKey};
        let (pk, sig): ([u8; 32], [u8; 64]) = (input.array(), input.array());
        let m = input.rest();
        let ours = match (
            Ed25519VerifyingKey::from_bytes(&pk),
            Ed25519Signature::from_bytes(&sig),
        ) {
            (Ok(k), Ok(s)) => k.verify(m, &s).is_ok(),
            _ => false,
        };
        if ours {
            assert!(
                oracle.ed25519_verify(&pk, m, &sig) != Some(false),
                "Ed25519 verification laxer than the oracle"
            );
        }
    }

    #[cfg(feature = "ml-kem")]
    pub(super) fn ml_kem(oracle: &dyn Oracle, mut input: Input<'_>) {
        use crate::ml_kem::MlKem768DecapsulationKey;
        let (seed, m): ([u8; 64], [u8; 32]) = (input.array(), input.array());
        let dk = MlKem768DecapsulationKey::from_seed(&seed);
        let ek = dk.encapsulation_key().to_bytes();
        same(oracle.ml_kem_768_public(&seed), &ek, "ML-KEM key");
        let (ct, ss) = dk.encapsulation_key().encapsulate(&m);
        assert!(dk.decapsulate(&ct) == ss, "ML-KEM round trip");
        let (mut their_ct, mut their_ss) = ([0; 1088], [0; 32]);
        if let Some(ok) = oracle.ml_kem_768_encapsulate(&ek, &m, &mut their_ct, &mut their_ss) {
            assert!(
                ok && their_ct == ct.to_bytes() && &their_ss == ss.as_bytes(),
                "ML-KEM encapsulation differs from the oracle"
            );
        }
        if let Some(theirs) = oracle.ml_kem_768_decapsulate(&seed, &ct.to_bytes()) {
            assert!(&theirs == ss.as_bytes(), "ML-KEM decapsulation differs");
        }
    }

    #[cfg(feature = "ml-kem")]
    pub(super) fn ml_kem_encapsulate(oracle: &dyn Oracle, mut input: Input<'_>) {
        use crate::ml_kem::MlKem768EncapsulationKey;
        let (ek, m): ([u8; 1184], [u8; 32]) = (input.array(), input.array());
        let ours = MlKem768EncapsulationKey::from_bytes(&ek);
        let (mut their_ct, mut their_ss) = ([0; 1088], [0; 32]);
        let Some(ok) = oracle.ml_kem_768_encapsulate(&ek, &m, &mut their_ct, &mut their_ss) else {
            return;
        };
        match ours {
            Ok(key) => {
                assert!(ok, "the oracle refused a key that passed the modulus check");
                let (ct, ss) = key.encapsulate(&m);
                assert!(
                    their_ct == ct.to_bytes() && &their_ss == ss.as_bytes(),
                    "ML-KEM encapsulation differs from the oracle"
                );
            }
            Err(e) => assert!(
                !ok && e == Error::Modulus,
                "a key failed the modulus check that the oracle took"
            ),
        }
    }

    #[cfg(feature = "ml-kem")]
    pub(super) fn ml_kem_decapsulate(oracle: &dyn Oracle, mut input: Input<'_>) {
        use crate::ml_kem::{MlKem768Ciphertext, MlKem768DecapsulationKey};
        let (seed, ct): ([u8; 64], [u8; 1088]) = (input.array(), input.array());
        let ours = MlKem768DecapsulationKey::from_seed(&seed)
            .decapsulate(&MlKem768Ciphertext::from_bytes(&ct).expect("every 1,088 octets"));
        if let Some(theirs) = oracle.ml_kem_768_decapsulate(&seed, &ct) {
            assert!(&theirs == ours.as_bytes(), "ML-KEM decapsulation differs");
        }
    }

    #[cfg(feature = "ml-dsa")]
    pub(super) fn ml_dsa_sign(oracle: &dyn Oracle, mut input: Input<'_>) {
        use crate::ml_dsa::MlDsa65SigningKey;
        let (xi, rnd): ([u8; 32], [u8; 32]) = (input.array(), input.array());
        let ctx = input.short();
        let m = input.rest();
        let key = MlDsa65SigningKey::from_seed(&xi);
        let vk = key.verifying_key();
        same(oracle.ml_dsa_65_public(&xi), &vk.to_bytes(), "ML-DSA key");
        let Ok(sig) = key.sign(m, ctx, &rnd) else {
            // Rejection sampling ran out, which FIPS 204 bounds away.
            return;
        };
        same(
            oracle.ml_dsa_65_sign(&xi, m, ctx, &rnd),
            &sig.to_bytes(),
            "ML-DSA signature",
        );
        let r = vk.verify(m, ctx, &sig);
        if m.starts_with(COMPOSITE_PREFIX) {
            assert!(r == Err(Error::Verification), "a prefixed message verified");
        } else {
            assert!(r == Ok(()), "an ML-DSA signature doesn't verify");
        }
    }

    #[cfg(feature = "ml-dsa")]
    pub(super) fn ml_dsa_verify(oracle: &dyn Oracle, mut input: Input<'_>) {
        use crate::ml_dsa::{MlDsa65Signature, MlDsa65VerifyingKey};
        let (pk, sig): ([u8; 1952], [u8; 3309]) = (input.array(), input.array());
        let ctx = input.context();
        let m = input.rest();
        let ours = match (
            MlDsa65VerifyingKey::from_bytes(&pk),
            MlDsa65Signature::from_bytes(&sig),
        ) {
            (Ok(k), Ok(s)) => k.verify(m, ctx, &s).is_ok(),
            _ => false,
        };
        if ours {
            assert!(
                oracle.ml_dsa_65_verify(&pk, m, ctx, &sig) != Some(false),
                "ML-DSA verification laxer than the oracle"
            );
        }
    }

    #[cfg(feature = "composite")]
    pub(super) fn composite(oracle: &dyn Oracle, mut input: Input<'_>) {
        use crate::composite::{CompositeSigningKey, LABEL, MAX_CONTEXT, PREFIX};
        use crate::hash::sha512;
        use crate::ml_dsa::{SIGNATURE_LEN, VERIFYING_KEY_LEN};
        let (seed, rnd): ([u8; 64], [u8; 32]) = (input.array(), input.array());
        let ctx = input.short();
        let m = input.rest();
        let key = CompositeSigningKey::from_bytes(&seed);
        let vk = key.verifying_key().to_bytes();
        let (ml_seed, ed_seed) = seed.split_at(32);
        let ml_seed: &[u8; 32] = ml_seed.try_into().expect("32 octets");
        let ed_seed: &[u8; 32] = ed_seed.try_into().expect("32 octets");
        same(
            oracle.ml_dsa_65_public(ml_seed),
            &vk[..VERIFYING_KEY_LEN].try_into().expect("1,952 octets"),
            "composite ML-DSA key",
        );
        same(
            oracle.ed25519_public(ed_seed),
            &vk[VERIFYING_KEY_LEN..].try_into().expect("32 octets"),
            "composite Ed25519 key",
        );
        let sig = match key.sign(m, ctx, &rnd) {
            Ok(sig) => sig.to_bytes(),
            // An all-zero hedge (rule 3), or rejection sampling that ran
            // out, which FIPS 204 bounds away.
            Err(e) => {
                assert!(e == Error::SigningFailed, "composite signing refused: {e}");
                return;
            }
        };
        assert!(rnd != [0; 32], "an all-zero hedge signed");
        // M′ = Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ SHA-512(M), built here
        // (RFC 10073, section 2.2). ctx is at most 255 octets.
        let ph = oracle.sha512(m).unwrap_or_else(|| sha512(m));
        let mut buf = [0u8; 32 + 30 + 1 + MAX_CONTEXT + 64];
        let mut n = 0;
        for part in [
            &PREFIX[..],
            &LABEL[..],
            &[u8::try_from(ctx.len()).expect("a short context")][..],
            ctx,
            &ph[..],
        ] {
            buf[n..n + part.len()].copy_from_slice(part);
            n += part.len();
        }
        let mp = &buf[..n];
        same(
            oracle.ml_dsa_65_sign(ml_seed, mp, LABEL, &rnd),
            &sig[..SIGNATURE_LEN].try_into().expect("3,309 octets"),
            "composite ML-DSA half",
        );
        same(
            oracle.ed25519_sign(ed_seed, mp),
            &sig[SIGNATURE_LEN..].try_into().expect("64 octets"),
            "composite Ed25519 half",
        );
    }
}
