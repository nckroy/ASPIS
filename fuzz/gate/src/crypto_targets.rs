// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! C08's targets (ADR 0068, rule 4; ADR 0069, rules 5 and 8;
//! docs/design/call-language.md, "Trust-boundary parsers" and "Fuzz entry
//! points"), wrapping C08's own entry functions in `aspis_crypto::fuzz`:
//!
//! - `crypto-decode`: the six decoding entries, `public_key`,
//!   `ciphertext`, `key_share`, `signature`, `verify` and `algorithm`.
//!   Octet 0 modulo 6 picks the entry, in that order, and the rest is the
//!   entry's own input, unchanged. Each entry checks its properties with
//!   `assert!` (re-encoding, documented refusals, determinism inside), and
//!   the target calls it twice, which must give the same result.
//! - `crypto-aead`: `aead_open`, twice, with the same result.
//! - `crypto-differential`: `differential`, with libcrux as the oracle
//!   ([`crate::crypto_oracle::Libcrux`]).
//!
//! Why eight entries are three targets is recorded in call-language.md,
//! "The harness" ("C08's eight entries are three targets"): the six
//! decoding entries share a shape and a cost, `aead_open`'s input runs to
//! 17 KiB, and the differential's oracle and cost differ.
//!
//! Kinds ("The gate for each target", item 4). `aspis_crypto::Error` is
//! `#[non_exhaustive]`, so a `match` here needs a wildcard and the
//! `kinds!` macro's guarantee can't hold. So, as
//! [`crate::idl_targets::DECODE_KINDS`] does, each table is a plain
//! `const`, and [`outcome`] names each of today's ten variants, with
//! `undocumented` for any other. `OutputLength` and `SigningFailed` get
//! names that no table holds, since no entry returns them (C08's module
//! doc): a seed that reached one, or a new variant, fails `tests/kinds.rs`
//! as a kind not in the table, and the entries already panic on a refusal
//! they don't document. `crypto-decode`'s kinds are named by entry and
//! scheme, for exactly the outcomes each scheme's decoder documents, so
//! the gate can't be met by one scheme while another goes unreached.
//!
//! Seeds come from `crates/crypto/tests/data`, embedded
//! ([`crate::crypto_repo`]), and are generated at build time, as the C07
//! and ABNF targets' are; none is committed.

use aspis_crypto::{
    Error, aead, composite, ed25519,
    fuzz::{
        self, AEAD_128_KEY, AEAD_KEY, KEY_SHARE_M, MAX_CIPHERTEXT, MAX_FUZZ_CONTEXT, ML_KEM_SEED,
        Oracle, X25519_SEED,
    },
    hybrid::{self, X25519MlKem768DecapsulationKey},
    ml_dsa, ml_kem,
};

use crate::crypto_oracle::{COMPARED, Libcrux, Recording};
use crate::crypto_repo::{
    acvp, ctx_field, differential_inputs, rfc, rfc10073, tc_name,
    vectors::{base64, field},
    with,
};

const KIB: usize = 1 << 10;

// ---- max_len, from aspis_crypto::fuzz's module doc ----------------------
//
// Each entry's format limit plus 1 KiB ("The gate for each target",
// item 1). `tests/crypto.rs` pins the numbers.

/// `public_key`: a selector, the longest key (the composite's) and 1 KiB.
pub const PUBLIC_KEY_MAX: usize = 1 + composite::PUBLIC_KEY_LEN + KIB;
/// `ciphertext`: an ML-KEM-768 ciphertext and 1 KiB.
pub const CIPHERTEXT_MAX: usize = ml_kem::CIPHERTEXT_LEN + KIB;
/// `key_share`: a selector, the longer share (the client's) and 1 KiB.
pub const KEY_SHARE_MAX: usize = 1 + hybrid::CLIENT_SHARE_LEN + KIB;
/// `signature`: a selector, the longest signature (the composite's) and
/// 1 KiB.
pub const SIGNATURE_MAX: usize = 1 + composite::SIGNATURE_LEN + KIB;
/// `verify`: a selector, the composite's key and signature, a context
/// length and up to [`MAX_FUZZ_CONTEXT`] octets of context, and 1 KiB of
/// message.
pub const VERIFY_MAX: usize =
    1 + composite::PUBLIC_KEY_LEN + composite::SIGNATURE_LEN + 2 + MAX_FUZZ_CONTEXT + KIB;
/// The module doc's figure for an OID's DER content octets.
pub const OID_MAX: usize = 64;
/// `algorithm`: a selector, an OID's content octets and 1 KiB.
pub const ALGORITHM_MAX: usize = 1 + OID_MAX + KIB;
/// `aead_open`: a selector, the nonce, an aad length and up to 255
/// octets of aad, [`MAX_CIPHERTEXT`] and 1 KiB.
pub const AEAD_MAX: usize = 1 + aead::NONCE_LEN + 1 + 255 + MAX_CIPHERTEXT + KIB;
/// `differential`: a selector, an ML-DSA-65 key and signature (selector
/// 19, the longest fixed fields), a context length and up to
/// [`MAX_FUZZ_CONTEXT`] octets of context, and 1 KiB of message.
pub const DIFFERENTIAL_MAX: usize =
    1 + ml_dsa::VERIFYING_KEY_LEN + ml_dsa::SIGNATURE_LEN + 2 + MAX_FUZZ_CONTEXT + KIB;
/// `crypto-decode`: the entry's octet and the largest entry's input,
/// `verify`'s.
pub const DECODE_MAX: usize = 1 + VERIFY_MAX;

// ---- crypto-decode ------------------------------------------------------

/// A decoding entry: its kind prefix, its function, and the schemes its
/// own octet 0 picks among (none for `ciphertext`).
pub struct Entry {
    pub name: &'static str,
    pub run: fn(&[u8]) -> Result<(), Error>,
    pub schemes: &'static [&'static str],
}

/// The schemes `signature` and `verify` pick among, mod 3.
const SIGNATURE_SCHEMES: &[&str] = &["ed25519", "ml-dsa", "composite"];

/// `crypto-decode`'s entries, in the order octet 0 modulo 6 picks them.
pub const ENTRIES: [Entry; 6] = [
    Entry {
        name: "public-key",
        run: fuzz::public_key,
        schemes: &["x25519", "ed25519", "ml-kem", "ml-dsa", "composite"],
    },
    Entry {
        name: "ciphertext",
        run: fuzz::ciphertext,
        schemes: &[],
    },
    Entry {
        name: "key-share",
        run: fuzz::key_share,
        schemes: &["client", "server"],
    },
    Entry {
        name: "signature",
        run: fuzz::signature,
        schemes: SIGNATURE_SCHEMES,
    },
    Entry {
        name: "verify",
        run: fuzz::verify,
        schemes: SIGNATURE_SCHEMES,
    },
    Entry {
        name: "algorithm",
        run: fuzz::algorithm,
        schemes: &["oid", "tls", "jose"],
    },
];

/// The entry octet 0 picks, and the entry's input.
pub fn split_entry(data: &[u8]) -> Option<(&'static Entry, &[u8])> {
    let (&which, rest) = data.split_first()?;
    Some((&ENTRIES[usize::from(which) % ENTRIES.len()], rest))
}

/// An entry's result, the same twice.
fn twice(run: fn(&[u8]) -> Result<(), Error>, input: &[u8]) -> Result<(), Error> {
    let r = run(input);
    assert!(r == run(input), "the entry isn't deterministic: {r:?}");
    r
}

/// `crypto-decode`: the entry octet 0 picks, on the rest, twice.
pub fn decode(data: &[u8]) {
    if let Some((e, rest)) = split_entry(data) {
        let _ = twice(e.run, rest);
    }
}

/// The name of an entry's result. Each of today's variants has one;
/// `output-length` and `signing-failed` are in no table, since no entry
/// returns them, and a variant added later is `undocumented`.
pub fn outcome(r: Result<(), Error>) -> &'static str {
    match r {
        Ok(()) => "ok",
        Err(Error::Length) => "length",
        Err(Error::Encoding) => "encoding",
        Err(Error::WeakKey) => "weak-key",
        Err(Error::Modulus) => "modulus",
        Err(Error::NonContributory) => "non-contributory",
        Err(Error::ContextTooLong) => "context-too-long",
        Err(Error::Verification) => "verification",
        Err(Error::OutputLength) => "output-length",
        Err(Error::UnknownAlgorithm) => "unknown-algorithm",
        Err(Error::SigningFailed) => "signing-failed",
        Err(_) => "undocumented",
    }
}

/// `name` as a kind: the table's entry, or, for a name the table doesn't
/// hold, the name itself, kept for the process. Only a seed or corpus
/// input that breaks the table reaches the second case, which
/// `tests/kinds.rs` and `fuzz kinds` then report by its name.
fn kind_in(table: &'static [&'static str], name: String) -> &'static str {
    table
        .iter()
        .copied()
        .find(|k| *k == name)
        .unwrap_or_else(|| Box::leak(name.into_boxed_str()))
}

/// The kinds `crypto-decode` reaches: `empty` (the input, or the entry's
/// input, is empty and the entry returned `Ok`), then for each entry and
/// scheme the outcomes that scheme's decoder documents.
pub const DECODE_KINDS: &[&str] = &[
    "empty",
    // public_key: X25519 refuses only the length, and its exchange an
    // all-zero secret; Ed25519 and the composite a length, a
    // non-canonical point or a small-order one; ML-KEM a length or the
    // modulus check; every 1,952 octets are an ML-DSA-65 key.
    "public-key-x25519-ok",
    "public-key-x25519-length",
    "public-key-x25519-non-contributory",
    "public-key-ed25519-ok",
    "public-key-ed25519-length",
    "public-key-ed25519-encoding",
    "public-key-ed25519-weak-key",
    "public-key-ml-kem-ok",
    "public-key-ml-kem-length",
    "public-key-ml-kem-modulus",
    "public-key-ml-dsa-ok",
    "public-key-ml-dsa-length",
    "public-key-composite-ok",
    "public-key-composite-length",
    "public-key-composite-encoding",
    "public-key-composite-weak-key",
    // ciphertext: one scheme, whose only refusal is the length.
    "ciphertext-ok",
    "ciphertext-length",
    // key_share: a client share's key fails the modulus check, and either
    // share's exchange may give an all-zero X25519 half.
    "key-share-client-ok",
    "key-share-client-length",
    "key-share-client-modulus",
    "key-share-client-non-contributory",
    "key-share-server-ok",
    "key-share-server-length",
    "key-share-server-non-contributory",
    // signature: a length, or a malformed encoding.
    "signature-ed25519-ok",
    "signature-ed25519-length",
    "signature-ed25519-encoding",
    "signature-ml-dsa-ok",
    "signature-ml-dsa-length",
    "signature-ml-dsa-encoding",
    "signature-composite-ok",
    "signature-composite-length",
    "signature-composite-encoding",
    // verify: Ed25519 takes no context; ML-DSA-65's key decoder refuses
    // only the length, so it has no `weak-key`.
    "verify-ed25519-ok",
    "verify-ed25519-length",
    "verify-ed25519-encoding",
    "verify-ed25519-weak-key",
    "verify-ed25519-verification",
    "verify-ml-dsa-ok",
    "verify-ml-dsa-length",
    "verify-ml-dsa-encoding",
    "verify-ml-dsa-context-too-long",
    "verify-ml-dsa-verification",
    "verify-composite-ok",
    "verify-composite-length",
    "verify-composite-encoding",
    "verify-composite-weak-key",
    "verify-composite-context-too-long",
    "verify-composite-verification",
    // algorithm: each form maps back, or is unknown.
    "algorithm-oid-ok",
    "algorithm-oid-unknown-algorithm",
    "algorithm-tls-ok",
    "algorithm-tls-unknown-algorithm",
    "algorithm-jose-ok",
    "algorithm-jose-unknown-algorithm",
];

/// The kind of an entry's input and result: `empty`, or
/// `<entry>-<scheme>-<outcome>`, the scheme read from the entry's input
/// as the entry reads it.
pub fn entry_kind(e: &Entry, input: &[u8], r: Result<(), Error>) -> &'static str {
    let Some(&first) = input.first() else {
        return if r.is_ok() {
            "empty"
        } else {
            kind_in(DECODE_KINDS, format!("{}-{}", e.name, outcome(r)))
        };
    };
    let name = if e.schemes.is_empty() {
        format!("{}-{}", e.name, outcome(r))
    } else {
        let scheme = e.schemes[usize::from(first) % e.schemes.len()];
        format!("{}-{scheme}-{}", e.name, outcome(r))
    };
    kind_in(DECODE_KINDS, name)
}

/// The kinds an input reaches in `crypto-decode`.
pub fn decode_kinds(data: &[u8]) -> Vec<&'static str> {
    let Some((e, rest)) = split_entry(data) else {
        return vec!["empty"];
    };
    vec![entry_kind(e, rest, (e.run)(rest))]
}

// ---- crypto-aead --------------------------------------------------------

/// `crypto-aead`: `aead_open`, twice.
pub fn aead(data: &[u8]) {
    let _ = twice(fuzz::aead_open, data);
}

/// The AEADs `aead_open` picks among, mod 3.
const AEADS: [&str; 3] = ["chacha20-poly1305", "aes-256-gcm", "aes-128-gcm"];

/// The kinds `crypto-aead` reaches: `empty`, then each AEAD's opening,
/// refusal of a short input, and refusal of a tag that doesn't verify.
/// Without `quic`, `aead_open` returns `Ok` for AES-128-GCM and opens
/// nothing, so `aes-128-gcm-ok` alone proves nothing: its `-length` and
/// `-verification` are the kinds that need `quic`. The feature is also
/// proved at compile time: [`aead_seeds`] seals under
/// `aspis_crypto::fuzz::AEAD_128_KEY`, which exists only with it.
pub const AEAD_KINDS: &[&str] = &[
    "empty",
    "chacha20-poly1305-ok",
    "chacha20-poly1305-length",
    "chacha20-poly1305-verification",
    "aes-256-gcm-ok",
    "aes-256-gcm-length",
    "aes-256-gcm-verification",
    "aes-128-gcm-ok",
    "aes-128-gcm-length",
    "aes-128-gcm-verification",
];

/// The kinds an input reaches in `crypto-aead`.
pub fn aead_kinds(data: &[u8]) -> Vec<&'static str> {
    let Some(&which) = data.first() else {
        return vec!["empty"];
    };
    let name = format!(
        "{}-{}",
        AEADS[usize::from(which) % AEADS.len()],
        outcome(fuzz::aead_open(data))
    );
    vec![kind_in(AEAD_KINDS, name)]
}

// ---- crypto-differential -----------------------------------------------

/// `crypto-differential`: C08's differential with libcrux as the oracle.
pub fn differential(data: &[u8]) {
    fuzz::differential(&Libcrux, data);
}

/// The kinds `crypto-differential` reaches: `empty`; each primitive's
/// name, from [`COMPARED`], when every oracle method its row lists
/// answered; `composite-context-too-long`, the composite with a context
/// over 255 octets, which the entry refuses to sign, whatever rnd, after
/// comparing only the public keys; `composite-zero-hedge`, the composite
/// under an all-zero rnd and a context of at most 255, which the entry
/// refuses to sign (ADR 0069, rule 3), likewise; and `not-compared` for
/// any other input where an oracle method its row lists wasn't asked: an
/// Ed25519 or ML-DSA-65 verification `aspis-crypto` refuses (the oracle
/// is asked only when it accepts), or, in a build without `quic`, 21 to
/// 23. Signing never skips: ML-DSA-65's, and the composite's under a
/// nonzero rnd and a short context, must succeed, or the entry panics.
/// So the kinds test asks for a seed that runs every comparison of each
/// primitive.
pub const DIFFERENTIAL_KINDS: &[&str] = &[
    "empty",
    "not-compared",
    "composite-context-too-long",
    "composite-zero-hedge",
    "sha-256",
    "sha-384",
    "sha-512",
    "sha3-256",
    "shake256",
    "hmac-sha-256",
    "hmac-sha-384",
    "hmac-sha-512",
    "hkdf-sha-256",
    "hkdf-sha-384",
    "chacha20-poly1305",
    "aes-256-gcm",
    "x25519",
    "ed25519-sign",
    "ed25519-verify",
    "ml-kem-768",
    "ml-kem-768-encapsulate",
    "ml-kem-768-decapsulate",
    "ml-dsa-65-sign",
    "ml-dsa-65-verify",
    "composite",
    "aes-128-gcm",
    "aes-128-mask",
    "aes-256-mask",
];

/// The composite's selector in the differential.
pub const COMPOSITE: u8 = 20;

/// Whether a composite input's rnd, the 32 octets after the selector and
/// the 64-octet private key, zero-padded as the entry reads them, is all
/// zeros.
pub fn zero_hedge(data: &[u8]) -> bool {
    data.get(1 + composite::PRIVATE_KEY_LEN..)
        .unwrap_or(&[])
        .iter()
        .take(composite::RANDOMNESS_LEN)
        .all(|&b| b == 0)
}

/// The length of a composite input's context, as the entry reads it:
/// after the selector, the private key and rnd, a big-endian `u16`,
/// zero-padded, modulo [`MAX_FUZZ_CONTEXT`] + 1, and then that many
/// octets, or fewer if the input runs out.
pub fn composite_context_len(data: &[u8]) -> usize {
    let rest = data
        .get(1 + composite::PRIVATE_KEY_LEN + composite::RANDOMNESS_LEN..)
        .unwrap_or(&[]);
    let mut len = [0; 2];
    for (d, s) in len.iter_mut().zip(rest) {
        *d = *s;
    }
    let n = usize::from(u16::from_be_bytes(len)) % (MAX_FUZZ_CONTEXT + 1);
    n.min(rest.len().saturating_sub(2))
}

/// The kinds an input reaches in `crypto-differential`, and the oracle
/// methods that answered.
pub fn differential_compared(data: &[u8]) -> (&'static str, Vec<&'static str>) {
    let Some(&which) = data.first() else {
        return ("empty", Vec::new());
    };
    let rec = Recording::new(&Libcrux);
    fuzz::differential(&rec, data);
    let sel = which % aspis_crypto::fuzz::DIFFERENTIAL_PRIMITIVES;
    let kind = if rec.compared(sel) {
        COMPARED[usize::from(sel)].1
    } else if sel == COMPOSITE && composite_context_len(data) > composite::MAX_CONTEXT {
        "composite-context-too-long"
    } else if sel == COMPOSITE && zero_hedge(data) {
        "composite-zero-hedge"
    } else {
        "not-compared"
    };
    (kind, rec.answered())
}

/// The kinds an input reaches in `crypto-differential`.
pub fn differential_kinds(data: &[u8]) -> Vec<&'static str> {
    vec![differential_compared(data).0]
}

// ---- seeds ---------------------------------------------------------------

/// The Ed25519 identity, a small-order point.
pub const ED25519_IDENTITY: [u8; 32] = {
    let mut b = [0; 32];
    b[0] = 1;
    b
};

/// y = 1 + p: the identity's non-canonical encoding.
pub const ED25519_NON_CANONICAL: [u8; 32] = {
    let mut b = [0xff; 32];
    b[0] = 0xee;
    b[31] = 0x7f;
    b
};

/// ℓ, the order of Ed25519's base point, little-endian: an s that isn't
/// below it is refused (RFC 8032, section 5.1.7).
pub const ED25519_L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// The entries' octets in `crypto-decode`.
const PUBLIC_KEY: u8 = 0;
const CIPHERTEXT: u8 = 1;
const KEY_SHARE: u8 = 2;
const SIGNATURE: u8 = 3;
const VERIFY: u8 = 4;
const ALGORITHM: u8 = 5;

/// `input`, cut to `max`, with `-cut` added to its name if it was longer.
pub fn cut(name: String, mut input: Vec<u8>, max: usize) -> (String, Vec<u8>) {
    if input.len() > max {
        input.truncate(max);
        (format!("{name}-cut"), input)
    } else {
        (name, input)
    }
}

/// `a` with its first octet's lowest bit flipped, or a zero octet if it
/// is empty: a changed message.
fn changed(a: &[u8]) -> Vec<u8> {
    let mut b = a.to_vec();
    match b.first_mut() {
        Some(x) => *x ^= 1,
        None => b.push(0),
    }
    b
}

/// The ML-DSA-65 and composite vectors' parts: RFC 10073's key and
/// signatures, and its Appendix E message and context.
struct Composite {
    pk: Vec<u8>,
    s: Vec<u8>,
    s_ctx: Vec<u8>,
    m: Vec<u8>,
    ctx: Vec<u8>,
}

fn composite_vector() -> Composite {
    let (t, m, ctx) = rfc10073();
    Composite {
        pk: base64(t.get("pk").as_str()),
        s: base64(t.get("s").as_str()),
        s_ctx: base64(t.get("sWithContext").as_str()),
        m,
        ctx,
    }
}

/// `pk` with its Ed25519 half replaced.
fn with_ed25519_key(pk: &[u8], ed: &[u8; 32]) -> Vec<u8> {
    [&pk[..ml_dsa::VERIFYING_KEY_LEN], &ed[..]].concat()
}

/// `sig` with its last 32 octets, an Ed25519 s, replaced by ℓ.
fn with_s_of_l(sig: &[u8]) -> Vec<u8> {
    [&sig[..sig.len() - 32], &ED25519_L[..]].concat()
}

/// `crypto-decode`'s seeds, each framed with its entry's octet and named
/// `<entry>-<scheme>-<source>`, so `tests/crypto.rs` can check each
/// reaches its entry and scheme: every key, share, ciphertext, signature
/// and identifier of the vectors; the weak and malformed forms the
/// decoders document; and lengths one short and one long.
pub fn decode_seeds() -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = vec![("empty".into(), Vec::new())];
    let mut push = |name: String, entry: u8, input: &[&[u8]]| {
        let mut d = vec![entry];
        for p in input {
            d.extend_from_slice(p);
        }
        out.push(cut(name, d, DECODE_MAX));
    };
    for (i, e) in ENTRIES.iter().enumerate() {
        push(format!("{}-alone", e.name), i as u8, &[]);
    }

    let x25519 = rfc("rfc7748.json");
    let rfc8032 = rfc("rfc8032.json");
    let c = composite_vector();
    let kem: Vec<_> = acvp("ml-kem-768-keygen")
        .into_iter()
        .chain(acvp("ml-kem-768-encapdecap"))
        .map(|(_, t)| t)
        .collect();
    let siggen = acvp("ml-dsa-65-siggen");
    let sigver = acvp("ml-dsa-65-sigver");

    // public_key (0): every vector key; the weak and malformed Ed25519
    // keys, alone and as the composite's half; X25519's u = 0 and u = 1,
    // whose exchange is all zeros; each type's length one short and one
    // long; and the longest input.
    for t in &x25519 {
        for k in ["inputUCoordinate", "alicePublicKey", "bobPublicKey"] {
            if t.try_get(k).is_some() {
                push(
                    format!("public-key-x25519-{}-{}", tc_name(t), k.to_lowercase()),
                    PUBLIC_KEY,
                    &[&[0], &field(t, k)],
                );
            }
        }
    }
    for t in &rfc8032 {
        push(
            format!("public-key-ed25519-rfc8032-{}", tc_name(t)),
            PUBLIC_KEY,
            &[&[1], &field(t, "publicKey")],
        );
    }
    for (i, t) in kem.iter().enumerate() {
        push(
            format!("public-key-ml-kem-acvp-{i}-{}", tc_name(t)),
            PUBLIC_KEY,
            &[&[2], &field(t, "ek")],
        );
    }
    for file in ["ml-dsa-65-keygen", "ml-dsa-65-siggen", "ml-dsa-65-sigver"] {
        for (_, t) in acvp(file).iter().take(5) {
            push(
                format!("public-key-ml-dsa-{file}-{}", tc_name(t)),
                PUBLIC_KEY,
                &[&[3], &field(t, "pk")],
            );
        }
    }
    push(
        "public-key-composite-rfc10073".into(),
        PUBLIC_KEY,
        &[&[4], &c.pk],
    );
    for (name, ed) in [
        ("identity", ED25519_IDENTITY),
        ("non-canonical", ED25519_NON_CANONICAL),
    ] {
        push(
            format!("public-key-ed25519-{name}"),
            PUBLIC_KEY,
            &[&[1], &ed],
        );
        push(
            format!("public-key-composite-{name}"),
            PUBLIC_KEY,
            &[&[4], &with_ed25519_key(&c.pk, &ed)],
        );
    }
    let mut one = [0; 32];
    one[0] = 1;
    push(
        "public-key-x25519-zero".into(),
        PUBLIC_KEY,
        &[&[0], &[0; 32]],
    );
    push("public-key-x25519-one".into(), PUBLIC_KEY, &[&[0], &one]);
    for (scheme, sel, len) in [
        ("x25519", 0u8, 32),
        ("ed25519", 1, ed25519::PUBLIC_KEY_LEN),
        ("ml-kem", 2, ml_kem::ENCAPSULATION_KEY_LEN),
        ("ml-dsa", 3, ml_dsa::VERIFYING_KEY_LEN),
        ("composite", 4, composite::PUBLIC_KEY_LEN),
    ] {
        for (what, n) in [("short", len - 1), ("long", len + 1)] {
            push(
                format!("public-key-{scheme}-{what}"),
                PUBLIC_KEY,
                &[&[sel], &vec![0x5a; n]],
            );
        }
    }
    push(
        "public-key-composite-max-len".into(),
        PUBLIC_KEY,
        &[&[4], &vec![0x5a; DECODE_MAX - 2]],
    );

    // ciphertext (1): every ACVP ciphertext; one short and one long; the
    // longest input.
    for (i, t) in kem.iter().enumerate() {
        if t.try_get("c").is_some() {
            push(
                format!("ciphertext-acvp-{i}-{}", tc_name(t)),
                CIPHERTEXT,
                &[&field(t, "c")],
            );
        }
    }
    for (what, n) in [
        ("short", ml_kem::CIPHERTEXT_LEN - 1),
        ("long", ml_kem::CIPHERTEXT_LEN + 1),
        ("max-len", DECODE_MAX - 1),
    ] {
        push(format!("ciphertext-{what}"), CIPHERTEXT, &[&vec![0x5a; n]]);
    }

    // key_share (2): client shares of each ACVP key, five of which fail
    // the modulus check, and server shares of each ACVP ciphertext, with
    // RFC 7748's public keys; the fixed client key's share and a server
    // share made for it, which both go through; each with an all-zero
    // X25519 half; and lengths one short and one long.
    let exchange = x25519
        .iter()
        .find(|t| t.try_get("alicePublicKey").is_some())
        .expect("RFC 7748, section 6.1");
    let keys = [
        field(exchange, "alicePublicKey"),
        field(exchange, "bobPublicKey"),
    ];
    for (i, t) in kem.iter().enumerate() {
        let pk = &keys[i % 2];
        push(
            format!("key-share-client-acvp-{i}-{}", tc_name(t)),
            KEY_SHARE,
            &[&[0], &field(t, "ek"), pk],
        );
        if t.try_get("c").is_some() {
            push(
                format!("key-share-server-acvp-{i}-{}", tc_name(t)),
                KEY_SHARE,
                &[&[1], &field(t, "c"), pk],
            );
        }
    }
    let client = X25519MlKem768DecapsulationKey::from_seed(&ML_KEM_SEED, &X25519_SEED);
    let share = client.client_share();
    let (server, _) = share
        .encapsulate(&KEY_SHARE_M, &[0x77; 32])
        .expect("a contributory exchange");
    let (share, server) = (share.to_bytes(), server.to_bytes());
    push("key-share-client-fixed".into(), KEY_SHARE, &[&[0], &share]);
    push("key-share-server-fixed".into(), KEY_SHARE, &[&[1], &server]);
    push(
        "key-share-client-zero-x25519".into(),
        KEY_SHARE,
        &[&[0], &share[..ml_kem::ENCAPSULATION_KEY_LEN], &[0; 32]],
    );
    push(
        "key-share-server-zero-x25519".into(),
        KEY_SHARE,
        &[&[1], &server[..ml_kem::CIPHERTEXT_LEN], &[0; 32]],
    );
    for (scheme, sel, b) in [("client", 0u8, &share[..]), ("server", 1, &server[..])] {
        push(
            format!("key-share-{scheme}-short"),
            KEY_SHARE,
            &[&[sel], &b[..b.len() - 1]],
        );
        push(
            format!("key-share-{scheme}-long"),
            KEY_SHARE,
            &[&[sel], b, &[0]],
        );
    }

    // signature (3): every vector signature (sigVer's malformed hints and
    // z are refused); an Ed25519 s of ℓ, alone and as the composite's
    // half; and lengths one short and one long.
    for t in &rfc8032 {
        push(
            format!("signature-ed25519-rfc8032-{}", tc_name(t)),
            SIGNATURE,
            &[&[0], &field(t, "signature")],
        );
    }
    for (file, vs) in [("siggen", &siggen), ("sigver", &sigver)] {
        for (_, t) in vs {
            push(
                format!("signature-ml-dsa-{file}-{}", tc_name(t)),
                SIGNATURE,
                &[&[1], &field(t, "signature")],
            );
        }
    }
    push(
        "signature-composite-rfc10073".into(),
        SIGNATURE,
        &[&[2], &c.s],
    );
    push(
        "signature-composite-rfc10073-ctx".into(),
        SIGNATURE,
        &[&[2], &c.s_ctx],
    );
    let ed_sig = field(&rfc8032[0], "signature");
    push(
        "signature-ed25519-s-of-l".into(),
        SIGNATURE,
        &[&[0], &with_s_of_l(&ed_sig)],
    );
    push(
        "signature-composite-s-of-l".into(),
        SIGNATURE,
        &[&[2], &with_s_of_l(&c.s)],
    );
    for (scheme, sel, len) in [
        ("ed25519", 0u8, ed25519::SIGNATURE_LEN),
        ("ml-dsa", 1, ml_dsa::SIGNATURE_LEN),
        ("composite", 2, composite::SIGNATURE_LEN),
    ] {
        for (what, n) in [("short", len - 1), ("long", len + 1)] {
            push(
                format!("signature-{scheme}-{what}"),
                SIGNATURE,
                &[&[sel], &vec![0x5a; n]],
            );
        }
    }

    // verify (4): each vector's key, signature, context and message, and
    // the message changed; the ACVP vectors cut to max_len when longer
    // (a cut vector's message changed, so it doesn't verify); the weak
    // and malformed Ed25519 keys; contexts of 255, 256 and 300 octets;
    // a short input for each scheme; and signatures over a message that
    // starts with the composite's prefix, which no standalone scheme
    // verifies (RFC 10073, section 9.4).
    for t in &rfc8032 {
        let (pk, sig, m) = (
            field(t, "publicKey"),
            field(t, "signature"),
            field(t, "message"),
        );
        let id = tc_name(t);
        push(
            format!("verify-ed25519-rfc8032-{id}"),
            VERIFY,
            &[&[0], &pk, &sig, &m],
        );
        push(
            format!("verify-ed25519-rfc8032-{id}-changed"),
            VERIFY,
            &[&[0], &pk, &sig, &changed(&m)],
        );
    }
    for (file, vs) in [("siggen", &siggen), ("sigver", &sigver)] {
        for (_, t) in vs {
            let outcome = match t.try_get("testPassed") {
                None => "",
                Some(p) if p.as_bool() => "-pass",
                Some(_) => "-fail",
            };
            push(
                format!("verify-ml-dsa-{file}-{}{outcome}", tc_name(t)),
                VERIFY,
                &[
                    &[1],
                    &field(t, "pk"),
                    &field(t, "signature"),
                    &ctx_field(&field(t, "context")),
                    &field(t, "message"),
                ],
            );
        }
    }
    let none = ctx_field(b"");
    push(
        "verify-composite-rfc10073".into(),
        VERIFY,
        &[&[2], &c.pk, &c.s, &none, &c.m],
    );
    push(
        "verify-composite-rfc10073-ctx".into(),
        VERIFY,
        &[&[2], &c.pk, &c.s_ctx, &ctx_field(&c.ctx), &c.m],
    );
    push(
        "verify-composite-rfc10073-changed".into(),
        VERIFY,
        &[&[2], &c.pk, &c.s, &none, &changed(&c.m)],
    );
    push(
        "verify-composite-rfc10073-ctx-changed".into(),
        VERIFY,
        &[&[2], &c.pk, &c.s_ctx, &ctx_field(&c.ctx), &changed(&c.m)],
    );
    let (ed_pk, ed_m) = (
        field(&rfc8032[0], "publicKey"),
        field(&rfc8032[0], "message"),
    );
    for (name, ed) in [
        ("identity", ED25519_IDENTITY),
        ("non-canonical", ED25519_NON_CANONICAL),
    ] {
        push(
            format!("verify-ed25519-{name}"),
            VERIFY,
            &[&[0], &ed, &ed_sig, &ed_m],
        );
        push(
            format!("verify-composite-{name}"),
            VERIFY,
            &[&[2], &with_ed25519_key(&c.pk, &ed), &c.s, &none, &c.m],
        );
    }
    push(
        "verify-ed25519-s-of-l".into(),
        VERIFY,
        &[&[0], &ed_pk, &with_s_of_l(&ed_sig), &ed_m],
    );
    let dsa = &siggen[0].1;
    let (dsa_pk, dsa_sig) = (field(dsa, "pk"), field(dsa, "signature"));
    for n in [255, 256, MAX_FUZZ_CONTEXT] {
        let ctx = ctx_field(&vec![7; n]);
        push(
            format!("verify-ml-dsa-ctx-{n}"),
            VERIFY,
            &[&[1], &dsa_pk, &dsa_sig, &ctx],
        );
        push(
            format!("verify-composite-ctx-{n}"),
            VERIFY,
            &[&[2], &c.pk, &c.s, &ctx, &c.m],
        );
    }
    for (scheme, sel) in [("ed25519", 0u8), ("ml-dsa", 1), ("composite", 2)] {
        push(
            format!("verify-{scheme}-short"),
            VERIFY,
            &[&[sel], &[0x5a; 10]],
        );
    }
    // The prefix rule: signatures that verify over the message, made with
    // libcrux (which the differential holds equal to aspis-crypto's) from
    // fixed seeds, and refused because of what the message starts with.
    let prefixed = [&composite::PREFIX[..], b"a prefixed message"].concat();
    let seed = [0x21; 32];
    let pk = answer(Libcrux.ed25519_public(&seed));
    let sig = answer(Libcrux.ed25519_sign(&seed, &prefixed));
    push(
        "verify-ed25519-prefixed".into(),
        VERIFY,
        &[&[0], &pk, &sig, &prefixed],
    );
    let xi = [0x12; 32];
    let pk = answer(Libcrux.ml_dsa_65_public(&xi));
    let sig = answer(Libcrux.ml_dsa_65_sign(&xi, &prefixed, b"", &[0x55; 32]));
    push(
        "verify-ml-dsa-prefixed".into(),
        VERIFY,
        &[&[1], &pk, &sig, &none, &prefixed],
    );

    // algorithm (5): every OID, TLS codepoint and JOSE name; the
    // deprecated `EdDSA`, an `alg` name under `enc`, and a name that isn't
    // UTF-8; unknown OIDs, one of 64 octets and one of 65; and an unknown
    // codepoint in each TLS registry.
    for &alg in aspis_crypto::algorithm::Algorithm::ALL {
        let name = alg.name().to_lowercase().replace([' ', '_'], "-");
        if let Some(d) = alg.oid_der() {
            push(format!("algorithm-oid-{name}"), ALGORITHM, &[&[0], d]);
        }
        if let Some(cp) = alg.tls() {
            let (reg, v) = tls_parts(cp);
            push(
                format!("algorithm-tls-{name}"),
                ALGORITHM,
                &[&[1, reg], &v.to_be_bytes()],
            );
        }
        if let Some(j) = alg.jose() {
            let (reg, n) = jose_parts(j);
            push(
                format!("algorithm-jose-{name}"),
                ALGORITHM,
                &[&[2, reg], n.as_bytes()],
            );
            if reg == 0 {
                push(
                    format!("algorithm-jose-{name}-as-enc"),
                    ALGORITHM,
                    &[&[2, 1], n.as_bytes()],
                );
            }
        }
    }
    push(
        "algorithm-jose-eddsa".into(),
        ALGORITHM,
        &[&[2, 0], b"EdDSA"],
    );
    push(
        "algorithm-jose-not-utf-8".into(),
        ALGORITHM,
        &[&[2, 0], &[0xff, 0xfe]],
    );
    push(
        "algorithm-oid-unknown".into(),
        ALGORITHM,
        &[&[0], &[0x2a, 0x03]],
    );
    push(
        "algorithm-oid-64".into(),
        ALGORITHM,
        &[&[0], &[0x2b; OID_MAX]],
    );
    push(
        "algorithm-oid-65".into(),
        ALGORITHM,
        &[&[0], &[0x2b; OID_MAX + 1]],
    );
    for reg in 0..3u8 {
        push(
            format!("algorithm-tls-unknown-{reg}"),
            ALGORITHM,
            &[&[1, reg], &[0xfe, 0xfe]],
        );
    }
    out
}

/// A TLS codepoint as `algorithm` reads it: the registry's octet and the
/// value.
pub fn tls_parts(cp: aspis_crypto::algorithm::TlsCodepoint) -> (u8, u16) {
    use aspis_crypto::algorithm::TlsCodepoint;
    match cp {
        TlsCodepoint::NamedGroup(v) => (0, v),
        TlsCodepoint::SignatureScheme(v) => (1, v),
        TlsCodepoint::CipherSuite(v) => (2, v),
    }
}

/// A JOSE name as `algorithm` reads it: the registry's octet and the name.
pub fn jose_parts(j: aspis_crypto::algorithm::JoseName<'static>) -> (u8, &'static str) {
    use aspis_crypto::algorithm::JoseName;
    match j {
        JoseName::Alg(n) => (0, n),
        JoseName::Enc(n) => (1, n),
    }
}

/// The plaintext lengths [`aead_seeds`] seals: empty, short, a few
/// hundred octets, TLS 1.3's record limit (`MAX_PLAINTEXT`), and the
/// longest `aead_open` opens, [`MAX_CIPHERTEXT`] less the tag.
pub const AEAD_LENGTHS: [usize; 5] = [
    0,
    8,
    300,
    aspis_crypto::fuzz::MAX_PLAINTEXT,
    MAX_CIPHERTEXT - aead::TAG_LEN,
];

/// Seals `pt` with AEAD `which` (0, 1 or 2, as `aead_open` picks) under
/// the entry's fixed key.
fn seal(which: u8, nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let mut ct = vec![0; pt.len() + aead::TAG_LEN];
    let n = match which {
        0 => aead::ChaCha20Poly1305Key::from_bytes(&AEAD_KEY).seal(nonce, aad, pt, &mut ct),
        1 => aead::Aes256GcmKey::from_bytes(&AEAD_KEY).seal(nonce, aad, pt, &mut ct),
        _ => aead::Aes128GcmKey::from_bytes(&AEAD_128_KEY).seal(nonce, aad, pt, &mut ct),
    }
    .expect("the buffer holds the plaintext and the tag");
    assert_eq!(n, ct.len());
    ct
}

/// An `aead_open` input: the AEAD, the nonce, the aad's length and the
/// aad, then ciphertext ‖ tag.
fn aead_input(which: u8, nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> Vec<u8> {
    let len = u8::try_from(aad.len()).expect("an aad of at most 255 octets");
    with(which, &[nonce, &[len], aad, ct])
}

/// `crypto-aead`'s seeds: for each AEAD, messages of each length in
/// [`AEAD_LENGTHS`] sealed under the fixed key with a 3-octet aad, and one
/// with a 255-octet aad, which open; the longest with one more octet,
/// which the entry cuts off, so it still opens; one octet longer still,
/// sealed, so the cut drops the tag's last octet and it doesn't open;
/// ciphertexts of 0 and 15 octets, under a tag's length; RFC 9001's
/// protected packets and Retry tag, under the RFC's keys, which don't
/// open under the fixed ones; and the empty input.
pub fn aead_seeds() -> Vec<(String, Vec<u8>)> {
    let mut out = vec![("empty".to_string(), Vec::new())];
    for (which, name) in AEADS.iter().enumerate() {
        let which = which as u8;
        for (i, &n) in AEAD_LENGTHS.iter().enumerate() {
            let nonce = [i as u8; 12];
            let pt = vec![0x5a; n];
            let ct = seal(which, &nonce, b"aad", &pt);
            out.push((
                format!("{name}-sealed-{n}"),
                aead_input(which, &nonce, b"aad", &ct),
            ));
            if n == MAX_CIPHERTEXT - aead::TAG_LEN {
                let mut longer = aead_input(which, &nonce, b"aad", &ct);
                longer.push(0);
                out.push((format!("{name}-sealed-{n}-and-1"), longer));
                let pt = vec![0x5a; n + 1];
                let ct = seal(which, &nonce, b"aad", &pt);
                out.push((
                    format!("{name}-sealed-{}-cut", n + 1),
                    aead_input(which, &nonce, b"aad", &ct),
                ));
            }
        }
        let aad = [0xaa; 255];
        let ct = seal(which, &[9; 12], &aad, b"a record");
        out.push((
            format!("{name}-sealed-aad-255"),
            aead_input(which, &[9; 12], &aad, &ct),
        ));
        for n in [0, aead::TAG_LEN - 1] {
            out.push((
                format!("{name}-short-{n}"),
                aead_input(which, &[0; 12], b"", &vec![0x5a; n]),
            ));
        }
    }
    out.extend(quic_inputs());
    out
}

/// RFC 9001, Appendix A's protected packets as `aead_open` reads them, as
/// `crates/crypto/tests/fuzz.rs` builds them: the AEAD, the packet's
/// nonce, its unprotected header as the aad, and the protected payload;
/// and the Retry integrity tag, a ciphertext with no plaintext. They are
/// under the RFC's keys, not the entry's, so each gives `Verification`.
pub fn quic_inputs() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for t in rfc("rfc9001.json") {
        let id = t.get("tcId").as_str().to_string();
        let name = format!("rfc9001-{}", tc_name(&t));
        let packet = field(&t, "packet");
        if id.starts_with("A.4") {
            let odcid = field(&t, "odcid");
            let mut aad = vec![u8::try_from(odcid.len()).expect("a short odcid")];
            aad.extend_from_slice(&odcid);
            aad.extend_from_slice(&packet[..packet.len() - aead::TAG_LEN]);
            let nonce: [u8; 12] = field(&t, "nonce").try_into().expect("a 12-octet nonce");
            out.push((
                format!("aes-128-gcm-{name}"),
                aead_input(2, &nonce, &aad, &packet[packet.len() - aead::TAG_LEN..]),
            ));
            continue;
        }
        let header = field(&t, "header");
        let pn = t.get("packetNumber").as_u64().to_be_bytes();
        let mut nonce: [u8; 12] = field(&t, "iv").try_into().expect("a 12-octet iv");
        for (a, b) in nonce[4..].iter_mut().zip(pn) {
            *a ^= b;
        }
        let (which, aead) = if id.starts_with("A.5") {
            (0, "chacha20-poly1305")
        } else {
            (2, "aes-128-gcm")
        };
        out.push((
            format!("{aead}-{name}"),
            aead_input(which, &nonce, &header, &packet[header.len()..]),
        ));
    }
    out
}

/// `crypto-differential`'s seeds: [`differential_inputs`],
/// each cut to `max_len` (a cut ML-DSA-65 vector's message changes, so it
/// doesn't verify and isn't compared), then the empty input.
pub fn differential_seeds() -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = differential_inputs()
        .into_iter()
        .map(|(n, d)| cut(n, d, DIFFERENTIAL_MAX))
        .collect();
    out.push(("empty".into(), Vec::new()));
    out
}

/// libcrux's answer, which it always gives ([`Libcrux`] answers every
/// method), for keys and signatures that `aspis-crypto` makes only inside
/// the crate.
fn answer<T>(x: Option<T>) -> T {
    x.expect("libcrux answers every method")
}
