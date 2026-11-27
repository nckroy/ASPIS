// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Replays the fuzz entry points of `aspis_crypto::fuzz` (ADR 0068, rule
//! 5; ADR 0069, rule 8) over every public key, ciphertext, signature,
//! QUIC packet and identifier in `tests/data/`, X25519MLKEM768 key shares
//! built from them, and mutations of each, so they run under `cargo test`
//! with no fuzz engine. C71's harness seeds its corpora from the same
//! files.
//!
//! The differential seam runs here against no oracle, and against one
//! built on the libraries' raw APIs and aspis-crypto's public API, which
//! must agree. C71's oracle is libcrux, inside `fuzz/`.
//!
//! AES-128-GCM and QUIC's header protection exist only with the crate's
//! `quic` feature. Without it, their seeds go through the entries too, and
//! the tests check that those selectors do nothing.

mod common;

use aspis_crypto::Error;
#[cfg(feature = "quic")]
use aspis_crypto::aead::Aes128GcmKey;
use aspis_crypto::aead::{Aes256GcmKey, ChaCha20Poly1305Key};
use aspis_crypto::algorithm::{Algorithm, JoseName, TlsCodepoint};
#[cfg(feature = "quic")]
use aspis_crypto::fuzz::AEAD_128_KEY;
use aspis_crypto::fuzz::{
    self, AEAD_KEY, DIFFERENTIAL_PRIMITIVES, KEY_SHARE_M, ML_KEM_SEED, Oracle, X25519_SEED,
};
use aspis_crypto::hybrid::X25519MlKem768DecapsulationKey;
use common::{Value, base64, field, hex, vectors};

const RFC7748: &str = include_str!("data/rfc7748.json");
const RFC8032: &str = include_str!("data/rfc8032.json");
const RFC10073: &str = include_str!("data/rfc10073.json");
const RFC9001: &str = include_str!("data/rfc9001.json");
const KEM_KEYGEN: &str = include_str!("data/acvp/ml-kem-768-keygen.json");
const KEM_ENCAP_DECAP: &str = include_str!("data/acvp/ml-kem-768-encapdecap.json");
const DSA_KEYGEN: &str = include_str!("data/acvp/ml-dsa-65-keygen.json");
const DSA_SIGGEN: &str = include_str!("data/acvp/ml-dsa-65-siggen.json");
const DSA_SIGVER: &str = include_str!("data/acvp/ml-dsa-65-sigver.json");

/// Every test of every group of an ACVP file.
fn acvp(text: &str) -> Vec<Value> {
    vectors(text)
        .get("testGroups")
        .as_array()
        .iter()
        .flat_map(|g| g.get("tests").as_array().to_vec())
        .collect()
}

/// The tests of an RFC file.
fn rfc(text: &str) -> Vec<Value> {
    vectors(text).get("tests").as_array().to_vec()
}

/// The RFC 10073 test object, and Appendix E's message and context.
fn rfc10073() -> (Value, Vec<u8>, Vec<u8>) {
    let v = vectors(RFC10073);
    let e = v.get("appendixE");
    let t = e.get("tests").as_array()[0].clone();
    (
        t,
        base64(e.get("m").as_str()),
        base64(e.get("ctx").as_str()),
    )
}

/// Mutations of `b`: every single-bit flip in its first and last 8
/// octets, truncation by one, extension by one, and all zeros and all
/// 0xFF of its length.
fn mutations(b: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let n = b.len();
    let mut positions: Vec<usize> = (0..n.min(8)).collect();
    positions.extend(n.saturating_sub(8).max(8)..n);
    for &i in &positions {
        for bit in 0..8 {
            let mut m = b.to_vec();
            m[i] ^= 1 << bit;
            out.push(m);
        }
    }
    if n > 0 {
        out.push(b[..n - 1].to_vec());
    }
    let mut longer = b.to_vec();
    longer.push(0);
    out.push(longer);
    out.push(vec![0; n]);
    out.push(vec![0xff; n]);
    out
}

/// `selector` ‖ the parts.
fn with(selector: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![selector];
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

/// The public keys, each with its selector for `fuzz::public_key`.
fn public_keys() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for t in rfc(RFC7748) {
        for k in ["inputUCoordinate", "alicePublicKey", "bobPublicKey"] {
            if t.try_get(k).is_some() {
                out.push(with(0, &[&field(&t, k)]));
            }
        }
    }
    for t in rfc(RFC8032) {
        out.push(with(1, &[&field(&t, "publicKey")]));
    }
    for t in acvp(KEM_KEYGEN).iter().chain(&acvp(KEM_ENCAP_DECAP)) {
        out.push(with(2, &[&field(t, "ek")]));
    }
    for text in [DSA_KEYGEN, DSA_SIGGEN, DSA_SIGVER] {
        for t in acvp(text).iter().take(5) {
            out.push(with(3, &[&field(t, "pk")]));
        }
    }
    let (t, _, _) = rfc10073();
    out.push(with(4, &[&base64(t.get("pk").as_str())]));
    // Weak and malformed forms the mutations might miss: the Ed25519
    // identity, and its non-canonical encoding y = 1 + p.
    out.push(with(
        1,
        &[&hex(
            "0100000000000000000000000000000000000000000000000000000000000000",
        )],
    ));
    out.push(with(
        1,
        &[&hex(
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        )],
    ));
    out
}

/// `fuzz::key_share` inputs: client shares (selector 0) of each ACVP
/// encapsulation key, five of which fail the modulus check, with RFC
/// 7748's public keys; server shares (selector 1) of each ACVP ciphertext
/// with the same keys; the fixed client key's share, and a server share
/// made for it, which decapsulates; and shares whose X25519 key is all
/// zeros, which give `NonContributory`.
fn key_shares() -> Vec<Vec<u8>> {
    let x = rfc(RFC7748)
        .into_iter()
        .find(|t| t.get("tcId").as_str() == "Section 6.1")
        .unwrap();
    let keys = [field(&x, "alicePublicKey"), field(&x, "bobPublicKey")];
    let mut out = Vec::new();
    for (i, t) in acvp(KEM_KEYGEN)
        .iter()
        .chain(&acvp(KEM_ENCAP_DECAP))
        .enumerate()
    {
        let pk = &keys[i % 2];
        out.push(with(0, &[&field(t, "ek"), pk]));
        if t.try_get("c").is_some() {
            out.push(with(1, &[&field(t, "c"), pk]));
        }
    }
    let client = X25519MlKem768DecapsulationKey::from_seed(&ML_KEM_SEED, &X25519_SEED);
    let share = client.client_share();
    let (server, _) = share.encapsulate(&KEY_SHARE_M, &[0x77; 32]).unwrap();
    let (share, server) = (share.to_bytes(), server.to_bytes());
    out.push(with(0, &[&share]));
    out.push(with(1, &[&server]));
    out.push(with(0, &[&share[..1184], &[0; 32]]));
    out.push(with(1, &[&server[..1088], &[0; 32]]));
    out
}

fn ciphertexts() -> Vec<Vec<u8>> {
    acvp(KEM_ENCAP_DECAP)
        .iter()
        .filter(|t| t.try_get("c").is_some())
        .map(|t| field(t, "c"))
        .collect()
}

fn signatures() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for t in rfc(RFC8032) {
        out.push(with(0, &[&field(&t, "signature")]));
    }
    for t in acvp(DSA_SIGGEN).iter().chain(&acvp(DSA_SIGVER)) {
        out.push(with(1, &[&field(t, "signature")]));
    }
    let (t, _, _) = rfc10073();
    for k in ["s", "sWithContext"] {
        out.push(with(2, &[&base64(t.get(k).as_str())]));
    }
    out
}

/// A big-endian `u16` context length and the context, as `fuzz::verify`
/// reads them.
fn ctx_field(ctx: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(ctx.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(ctx);
    out
}

/// What `fuzz::verify` must return for an input.
#[derive(Clone, Copy, Debug)]
enum Expect {
    /// `Ok(())`: the signature verifies.
    Accept,
    /// A refusal at decoding or verification: an ACVP sigVer vector that
    /// should fail, with a malformed signature or a wrong one.
    Refuse,
    /// Exactly this refusal.
    Is(Error),
}

impl Expect {
    fn check(self, r: Result<(), Error>, i: usize) {
        match self {
            Self::Accept => assert_eq!(r, Ok(()), "verify input {i}"),
            Self::Refuse => assert!(
                matches!(r, Err(Error::Encoding | Error::Verification)),
                "verify input {i}: {r:?}"
            ),
            Self::Is(e) => assert_eq!(r, Err(e), "verify input {i}"),
        }
    }
}

/// Inputs for `fuzz::verify`, each with what it must return: each
/// vector's key, signature, context and message, and contexts past the
/// limit.
fn verify_inputs() -> Vec<(Vec<u8>, Expect)> {
    let mut out = Vec::new();
    for t in rfc(RFC8032) {
        let (pk, sig, m) = (
            field(&t, "publicKey"),
            field(&t, "signature"),
            field(&t, "message"),
        );
        out.push((with(0, &[&pk, &sig, &m]), Expect::Accept));
    }
    let siggen = acvp(DSA_SIGGEN);
    let sigver = acvp(DSA_SIGVER);
    for (t, expect) in siggen
        .iter()
        .map(|t| (t, Expect::Accept))
        .chain(sigver.iter().map(|t| {
            if t.get("testPassed").as_bool() {
                (t, Expect::Accept)
            } else {
                (t, Expect::Refuse)
            }
        }))
    {
        let ctx = ctx_field(&field(t, "context"));
        out.push((
            with(
                1,
                &[
                    &field(t, "pk"),
                    &field(t, "signature"),
                    &ctx,
                    &field(t, "message"),
                ],
            ),
            expect,
        ));
    }
    let (t, m, ctx) = rfc10073();
    let pk = base64(t.get("pk").as_str());
    let s = base64(t.get("s").as_str());
    let s_ctx = base64(t.get("sWithContext").as_str());
    out.push((with(2, &[&pk, &s, &ctx_field(b""), &m]), Expect::Accept));
    out.push((
        with(2, &[&pk, &s_ctx, &ctx_field(&ctx), &m]),
        Expect::Accept,
    ));
    // Contexts of 256 and 300 octets (ContextTooLong), with a well-formed
    // composite signature and a well-formed ML-DSA-65 one.
    out.push((
        with(2, &[&pk, &s, &ctx_field(&[7; 256]), &m]),
        Expect::Is(Error::ContextTooLong),
    ));
    let dsa = &siggen[0];
    out.push((
        with(
            1,
            &[
                &field(dsa, "pk"),
                &field(dsa, "signature"),
                &ctx_field(&[7; 300]),
            ],
        ),
        Expect::Is(Error::ContextTooLong),
    ));
    out
}

/// `fuzz::aead_open` inputs that open: messages sealed under the fixed
/// keys, with the nonce and aad the entry reads. AES-128-GCM's need the
/// `quic` feature.
fn aead_inputs() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let messages: [&[u8]; 3] = [b"", b"a record", &[0x5a; 300]];
    for (i, pt) in messages.iter().enumerate() {
        let nonce = [i as u8; 12];
        let aad = b"aad";
        let mut ct = vec![0; pt.len() + 16];
        ChaCha20Poly1305Key::from_bytes(&AEAD_KEY)
            .seal(&nonce, aad, pt, &mut ct)
            .unwrap();
        out.push(with(0, &[&nonce, &[3], aad, &ct]));
        Aes256GcmKey::from_bytes(&AEAD_KEY)
            .seal(&nonce, aad, pt, &mut ct)
            .unwrap();
        out.push(with(1, &[&nonce, &[3], aad, &ct]));
        #[cfg(feature = "quic")]
        {
            Aes128GcmKey::from_bytes(&AEAD_128_KEY)
                .seal(&nonce, aad, pt, &mut ct)
                .unwrap();
            out.push(with(2, &[&nonce, &[3], aad, &ct]));
        }
    }
    out
}

/// The tests of RFC 9001's vector file.
fn rfc9001() -> Vec<Value> {
    rfc(RFC9001)
}

/// RFC 9001, Appendix A's protected packets as `fuzz::aead_open` reads
/// them: the AEAD's selector, the packet's nonce, its unprotected header
/// as the aad, and the protected payload. They are under the RFC's keys,
/// not the entry's fixed ones, so each is refused with `Verification`.
/// The Retry tag goes in as a ciphertext with no plaintext. Without the
/// `quic` feature, the AES-128-GCM ones (selector 2) open nothing.
fn quic_inputs() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for t in rfc9001() {
        let id = t.get("tcId").as_str().to_string();
        let packet = field(&t, "packet");
        if id.starts_with("A.4") {
            let odcid = field(&t, "odcid");
            let mut aad = vec![u8::try_from(odcid.len()).unwrap()];
            aad.extend_from_slice(&odcid);
            aad.extend_from_slice(&packet[..packet.len() - 16]);
            let len = [u8::try_from(aad.len()).unwrap()];
            out.push(with(
                2,
                &[
                    &field(&t, "nonce"),
                    &len,
                    &aad,
                    &packet[packet.len() - 16..],
                ],
            ));
            continue;
        }
        let header = field(&t, "header");
        let pn = t.get("packetNumber").as_u64().to_be_bytes();
        let mut nonce = field(&t, "iv");
        for (a, b) in nonce[4..].iter_mut().zip(pn) {
            *a ^= b;
        }
        let selector = if id.starts_with("A.5") { 0 } else { 2 };
        let len = [u8::try_from(header.len()).unwrap()];
        out.push(with(
            selector,
            &[&nonce, &len, &header, &packet[header.len()..]],
        ));
    }
    out
}

/// `fuzz::algorithm` inputs: every identifier, and some unknown ones.
fn identifiers() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for &alg in Algorithm::ALL {
        if let Some(d) = alg.oid_der() {
            out.push(with(0, &[d]));
        }
        if let Some(cp) = alg.tls() {
            let (reg, v) = match cp {
                TlsCodepoint::NamedGroup(v) => (0, v),
                TlsCodepoint::SignatureScheme(v) => (1, v),
                TlsCodepoint::CipherSuite(v) => (2, v),
            };
            out.push(with(1, &[&[reg], &v.to_be_bytes()]));
        }
        match alg.jose() {
            Some(JoseName::Alg(name)) => out.push(with(2, &[&[0], name.as_bytes()])),
            Some(JoseName::Enc(name)) => out.push(with(2, &[&[1], name.as_bytes()])),
            None => {}
        }
    }
    out.push(with(2, &[&[0], b"EdDSA"]));
    out.push(with(2, &[&[0], &[0xff, 0xfe]]));
    out
}

/// Runs `entry` over every input and its mutations, and collects the
/// refusals it met.
fn replay(entry: fn(&[u8]) -> Result<(), Error>, inputs: &[Vec<u8>], kinds: &mut Vec<Error>) {
    let mut note = |r: Result<(), Error>| {
        if let Err(e) = r
            && !kinds.contains(&e)
        {
            kinds.push(e);
        }
    };
    for input in inputs {
        note(entry(input));
        for m in mutations(input) {
            note(entry(&m));
        }
    }
    note(entry(&[]));
}

/// Every vector, and its mutations, goes through its entry, and the
/// corpus reaches every refusal an entry can return (ADR 0068, the gate's
/// item 4). `OutputLength` and `SigningFailed` aren't returned by any
/// entry (see `aspis_crypto::fuzz`).
#[test]
fn replay_vectors_and_error_kinds() {
    let mut kinds = Vec::new();
    replay(fuzz::public_key, &public_keys(), &mut kinds);
    replay(fuzz::ciphertext, &ciphertexts(), &mut kinds);
    replay(fuzz::key_share, &key_shares(), &mut kinds);
    replay(fuzz::signature, &signatures(), &mut kinds);
    let verify: Vec<Vec<u8>> = verify_inputs().into_iter().map(|(v, _)| v).collect();
    replay(fuzz::verify, &verify, &mut kinds);
    replay(fuzz::aead_open, &aead_inputs(), &mut kinds);
    replay(fuzz::aead_open, &quic_inputs(), &mut kinds);
    replay(fuzz::algorithm, &identifiers(), &mut kinds);
    for kind in [
        Error::Length,
        Error::Encoding,
        Error::WeakKey,
        Error::Modulus,
        Error::NonContributory,
        Error::ContextTooLong,
        Error::Verification,
        Error::UnknownAlgorithm,
    ] {
        assert!(kinds.contains(&kind), "the corpus never reaches {kind:?}");
    }
    assert!(!kinds.contains(&Error::OutputLength));
    assert!(!kinds.contains(&Error::SigningFailed));
}

/// The seeds that should be accepted are: each vector key, ciphertext and
/// signature, the passing verifications, and the sealed AEAD inputs.
#[test]
fn vectors_accepted() {
    // All but the last two, the weak and malformed seeds. ML-KEM's
    // key-check vectors include five keys that fail the modulus check.
    let keys = public_keys();
    for k in &keys[..keys.len() - 2] {
        let r = fuzz::public_key(k);
        assert!(r.is_ok() || r == Err(Error::Modulus), "{r:?}");
    }
    for c in ciphertexts() {
        assert_eq!(fuzz::ciphertext(&c), Ok(()));
    }
    // All but the last two, whose X25519 keys are all zeros. ML-KEM's
    // key-check vectors include five keys that fail the modulus check.
    let shares = key_shares();
    let mut modulus = 0;
    for s in &shares[..shares.len() - 2] {
        match fuzz::key_share(s) {
            Ok(()) => {}
            Err(Error::Modulus) if s[0] == 0 => modulus += 1,
            r => panic!("{r:?}"),
        }
    }
    assert_eq!(modulus, 5);
    for s in &shares[shares.len() - 2..] {
        assert_eq!(fuzz::key_share(s), Err(Error::NonContributory));
    }
    for s in signatures() {
        let r = fuzz::signature(&s);
        // Some of the sigVer vectors have malformed hints or z.
        assert!(
            r.is_ok() || (s[0] == 1 && r == Err(Error::Encoding)),
            "{r:?}"
        );
    }
    for a in aead_inputs() {
        assert_eq!(fuzz::aead_open(&a), Ok(()));
    }
    // RFC 9001's four packets, under keys other than the entry's. Without
    // `quic`, AES-128-GCM's selector returns `Ok` and opens nothing.
    let quic = quic_inputs();
    assert_eq!(quic.len(), 4);
    for q in quic {
        let expect = if cfg!(feature = "quic") || q[0] != 2 {
            Err(Error::Verification)
        } else {
            Ok(())
        };
        assert_eq!(fuzz::aead_open(&q), expect);
    }
    let verify = verify_inputs();
    // RFC 8032's five, ACVP's sigGen and sigVer, RFC 10073's two, and two
    // long contexts.
    assert_eq!(verify.len(), 5 + 25 + 2 + 2);
    for (i, (v, expect)) in verify.iter().enumerate() {
        expect.check(fuzz::verify(v), i);
    }
    let ids = identifiers();
    for id in &ids[..ids.len() - 2] {
        assert_eq!(fuzz::algorithm(id), Ok(()));
    }
}

/// Inputs for `fuzz::differential`: each primitive's vectors laid out as
/// the entry reads them, and filler of several lengths for every
/// primitive.
fn differential_inputs() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut filler = |n: usize| -> Vec<u8> {
        (0..n)
            .map(|_| {
                // xorshift64: arbitrary octets, the same every run.
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    };
    for sel in 0..DIFFERENTIAL_PRIMITIVES {
        for n in [0, 40, 300, 2000, 7000] {
            out.push(with(sel, &[&filler(n)]));
        }
    }
    for t in rfc(RFC7748)
        .iter()
        .filter(|t| t.try_get("inputScalar").is_some())
    {
        out.push(with(
            12,
            &[&field(t, "inputScalar"), &field(t, "inputUCoordinate")],
        ));
    }
    // An all-zero u (NonContributory) for an RFC scalar.
    out.push(with(
        12,
        &[&field(&rfc(RFC7748)[0], "inputScalar"), &[0; 32]],
    ));
    for t in rfc(RFC8032) {
        out.push(with(13, &[&field(&t, "secretKey"), &field(&t, "message")]));
        out.push(with(
            14,
            &[
                &field(&t, "publicKey"),
                &field(&t, "signature"),
                &field(&t, "message"),
            ],
        ));
    }
    for t in acvp(KEM_KEYGEN) {
        out.push(with(15, &[&field(&t, "d"), &field(&t, "z"), &[0x33; 32]]));
    }
    for t in acvp(KEM_ENCAP_DECAP) {
        let m = t
            .try_get("m")
            .map(|_| field(&t, "m"))
            .unwrap_or_else(|| vec![1; 32]);
        out.push(with(16, &[&field(&t, "ek"), &m]));
        if t.try_get("c").is_some() {
            out.push(with(17, &[&[0x44; 64], &field(&t, "c")]));
        }
    }
    for t in acvp(DSA_KEYGEN) {
        out.push(with(
            18,
            &[&field(&t, "seed"), &[0x55; 32], &[3], b"ctx", b"message"],
        ));
    }
    for t in acvp(DSA_SIGGEN).iter().chain(&acvp(DSA_SIGVER)) {
        let ctx = ctx_field(&field(t, "context"));
        out.push(with(
            19,
            &[
                &field(t, "pk"),
                &field(t, "signature"),
                &ctx,
                &field(t, "message"),
            ],
        ));
    }
    // The composite: RFC 10073's key, with Appendix E's message and
    // context, under a hedge and under the refused all-zero one.
    let (t, m, ctx) = rfc10073();
    let sk = base64(t.get("sk").as_str());
    let len = [u8::try_from(ctx.len()).unwrap()];
    for rnd in [[0x66; 32], [0; 32]] {
        out.push(with(20, &[&sk, &rnd, &len, &ctx, &m]));
        out.push(with(20, &[&sk, &rnd, &[0], &m]));
    }
    // RFC 9001's AES-128-GCM payloads and AES-128 header protection,
    // which are skipped without `quic`.
    for t in rfc9001() {
        let id = t.get("tcId").as_str().to_string();
        if id.starts_with("A.4") {
            out.push(with(21, &[&field(&t, "key"), &field(&t, "nonce"), &[0]]));
        } else if !id.starts_with("A.5") {
            let header = field(&t, "header");
            let len = [u8::try_from(header.len()).unwrap()];
            let payload = t
                .try_get("payload")
                .map(|_| field(&t, "payload"))
                .unwrap_or_else(|| field(&t, "cryptoFrame"));
            out.push(with(
                21,
                &[&field(&t, "key"), &field(&t, "iv"), &len, &header, &payload],
            ));
            out.push(with(22, &[&field(&t, "hp"), &field(&t, "sample")]));
        }
    }
    out
}

/// No oracle: aspis-crypto's side runs over every input without panicking.
#[test]
fn differential_no_oracle() {
    struct Nothing;
    impl Oracle for Nothing {}
    for d in differential_inputs() {
        fuzz::differential(&Nothing, &d);
    }
    fuzz::differential(&Nothing, &[]);
}

/// An oracle on the libraries' raw APIs, and on aspis-crypto's public API
/// where the libraries' would only repeat it.
struct Raw;

/// Hands ML-DSA the caller's hedge, once.
struct Hedge([u8; 32], bool);

impl ml_dsa::signature::rand_core::TryRng for Hedge {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unreachable!("ML-DSA draws 32 octets")
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unreachable!("ML-DSA draws 32 octets")
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        assert!(!self.1 && dst.len() == 32);
        dst.copy_from_slice(&self.0);
        self.1 = true;
        Ok(())
    }
}

impl ml_dsa::signature::rand_core::TryCryptoRng for Hedge {}

impl Oracle for Raw {
    fn sha256(&self, m: &[u8]) -> Option<[u8; 32]> {
        Some(aspis_crypto::hash::sha256(m))
    }
    fn sha3_256(&self, m: &[u8]) -> Option<[u8; 32]> {
        Some(aspis_crypto::hash::sha3_256(m))
    }
    fn shake256(&self, m: &[u8], out: &mut [u8]) -> Option<()> {
        aspis_crypto::hash::shake256(m, out);
        Some(())
    }
    fn hmac_sha512(&self, key: &[u8], m: &[u8]) -> Option<[u8; 64]> {
        Some(aspis_crypto::mac::hmac_sha512(key, m))
    }
    fn hkdf_sha384(&self, salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Option<()> {
        aspis_crypto::mac::hkdf_sha384_extract(Some(salt), ikm)
            .expand(info, out)
            .ok()
    }
    fn chacha20poly1305_seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
    ) -> Option<[u8; 16]> {
        ct.copy_from_slice(pt);
        ChaCha20Poly1305Key::from_bytes(key)
            .seal_in_place(nonce, aad, ct)
            .ok()
    }
    #[cfg(feature = "quic")]
    fn aes128gcm_seal(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 12],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
    ) -> Option<[u8; 16]> {
        use aes_gcm::aead::{AeadInOut, KeyInit};
        ct.copy_from_slice(pt);
        let tag = aes_gcm::Aes128Gcm::new(key.into())
            .encrypt_inout_detached(nonce.into(), aad, ct.into())
            .ok()?;
        Some(tag.into())
    }
    #[cfg(feature = "quic")]
    fn aes128_ecb(&self, key: &[u8; 16], block: &[u8; 16]) -> Option<[u8; 16]> {
        use aes::cipher::{BlockCipherEncrypt, KeyInit};
        let mut b = aes::Block::from(*block);
        aes::Aes128::new(key.into()).encrypt_block(&mut b);
        Some(b.into())
    }
    #[cfg(feature = "quic")]
    fn aes256_ecb(&self, key: &[u8; 32], block: &[u8; 16]) -> Option<[u8; 16]> {
        use aes::cipher::{BlockCipherEncrypt, KeyInit};
        let mut b = aes::Block::from(*block);
        aes::Aes256::new(key.into()).encrypt_block(&mut b);
        Some(b.into())
    }
    fn x25519(&self, k: &[u8; 32], u: &[u8; 32]) -> Option<[u8; 32]> {
        Some(x25519_dalek::x25519(*k, *u))
    }
    fn ed25519_public(&self, seed: &[u8; 32]) -> Option<[u8; 32]> {
        Some(
            ed25519_dalek::SigningKey::from_bytes(seed)
                .verifying_key()
                .to_bytes(),
        )
    }
    fn ed25519_sign(&self, seed: &[u8; 32], m: &[u8]) -> Option<[u8; 64]> {
        use ed25519_dalek::Signer;
        Some(
            ed25519_dalek::SigningKey::from_bytes(seed)
                .sign(m)
                .to_bytes(),
        )
    }
    fn ed25519_verify(&self, pk: &[u8; 32], m: &[u8], sig: &[u8; 64]) -> Option<bool> {
        let Ok(pk) = ed25519_dalek::VerifyingKey::from_bytes(pk) else {
            return Some(false);
        };
        let sig = ed25519_dalek::Signature::from_bytes(sig);
        Some(pk.verify_strict(m, &sig).is_ok())
    }
    fn ml_kem_768_public(&self, seed: &[u8; 64]) -> Option<[u8; 1184]> {
        use aspis_crypto::ml_kem::MlKem768DecapsulationKey;
        Some(
            MlKem768DecapsulationKey::from_seed(seed)
                .encapsulation_key()
                .to_bytes(),
        )
    }
    fn ml_kem_768_encapsulate(
        &self,
        ek: &[u8; 1184],
        m: &[u8; 32],
        ct: &mut [u8; 1088],
        ss: &mut [u8; 32],
    ) -> Option<bool> {
        let Ok(ek) = aspis_crypto::ml_kem::MlKem768EncapsulationKey::from_bytes(ek) else {
            return Some(false);
        };
        let (c, s) = ek.encapsulate(m);
        *ct = c.to_bytes();
        *ss = *s.as_bytes();
        Some(true)
    }
    fn ml_dsa_65_public(&self, xi: &[u8; 32]) -> Option<[u8; 1952]> {
        let esk = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa65>::from_seed(xi.into());
        Some(esk.verifying_key().encode().as_slice().try_into().unwrap())
    }
    fn ml_dsa_65_sign(
        &self,
        xi: &[u8; 32],
        m: &[u8],
        ctx: &[u8],
        rnd: &[u8; 32],
    ) -> Option<[u8; 3309]> {
        let esk = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa65>::from_seed(xi.into());
        let sig = esk.sign_randomized(m, ctx, &mut Hedge(*rnd, false)).ok()?;
        Some(sig.encode().as_slice().try_into().unwrap())
    }
    fn ml_dsa_65_verify(
        &self,
        pk: &[u8; 1952],
        m: &[u8],
        ctx: &[u8],
        sig: &[u8; 3309],
    ) -> Option<bool> {
        let pk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(pk[..].try_into().unwrap());
        let Some(sig) = ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(sig[..].try_into().unwrap())
        else {
            return Some(false);
        };
        Some(pk.verify_with_context(m, ctx, &sig))
    }
}

/// The raw oracle agrees with aspis-crypto over every input.
#[test]
fn differential_self() {
    for d in differential_inputs() {
        fuzz::differential(&Raw, &d);
    }
}

/// An oracle that disagrees on one primitive makes the target panic.
#[test]
#[should_panic(expected = "SHA3-256 differs from the oracle")]
fn differential_detects_disagreement() {
    struct Flip;
    impl Oracle for Flip {
        fn sha3_256(&self, m: &[u8]) -> Option<[u8; 32]> {
            let mut d = aspis_crypto::hash::sha3_256(m);
            d[0] ^= 1;
            Some(d)
        }
    }
    fuzz::differential(&Flip, &with(3, &[b"abc"]));
}

/// A wrong AES block makes the header-protection comparison panic.
#[cfg(feature = "quic")]
#[test]
#[should_panic(expected = "header-protection mask differs from the oracle")]
fn differential_detects_a_wrong_mask() {
    struct Flip;
    impl Oracle for Flip {
        fn aes256_ecb(&self, key: &[u8; 32], block: &[u8; 16]) -> Option<[u8; 16]> {
            let mut b = Raw.aes256_ecb(key, block)?;
            b[4] ^= 1;
            Some(b)
        }
    }
    fuzz::differential(&Flip, &with(23, &[&[1; 32], &[2; 16]]));
}

/// Without `quic`, the differential's AES-128-GCM and header-protection
/// selectors (21 to 23) are skipped: an oracle that panics on their
/// methods is never called, and the numbering is unchanged.
#[cfg(not(feature = "quic"))]
#[test]
fn quic_selectors_skipped() {
    struct Loud;
    impl Oracle for Loud {
        fn aes128gcm_seal(
            &self,
            _key: &[u8; 16],
            _nonce: &[u8; 12],
            _aad: &[u8],
            _pt: &[u8],
            _ct: &mut [u8],
        ) -> Option<[u8; 16]> {
            panic!("AES-128-GCM reached without quic")
        }
        fn aes128_ecb(&self, _key: &[u8; 16], _block: &[u8; 16]) -> Option<[u8; 16]> {
            panic!("AES-128 reached without quic")
        }
        fn aes256_ecb(&self, _key: &[u8; 32], _block: &[u8; 16]) -> Option<[u8; 16]> {
            panic!("AES-256 header protection reached without quic")
        }
    }
    assert_eq!(DIFFERENTIAL_PRIMITIVES, 24);
    for sel in 21..24 {
        fuzz::differential(&Loud, &with(sel, &[&[7; 64]]));
    }
    for d in differential_inputs() {
        fuzz::differential(&Loud, &d);
    }
}
