// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! aspis-crypto's known-answer vectors, embedded, for the `crypto-`
//! targets' seeds and the libcrux oracle's tests
//! (docs/design/call-language.md, "The harness"; ADR 0068, rules 3 and 4;
//! ADR 0069, rule 7).
//!
//! The vector files of `crates/crypto/tests/data/` (the RFCs' JSON
//! vectors and the ACVP ML-KEM-768 and ML-DSA-65 subsets) are embedded
//! with `include_str!`, as [`crate::idl_repo`] embeds the interfaces, so
//! the seeds made from them can't drift and nothing reads files while
//! fuzzing. `tests/targets.rs` checks that [`VECTOR_FILES`] is every
//! tracked JSON file there, byte for byte. They are read with
//! aspis-crypto's own test reader ([`vectors`], included by path, as
//! aspis-crypto's `src/kat.rs` includes it), so there is one reader.
//! Each file keeps its own license (`REUSE.toml`): the inputs built here
//! are written only to `build/fuzz/seeds/`, never committed or shipped.
//!
//! The builders mirror those of `crates/crypto/tests/fuzz.rs`, which C08
//! keeps in its tests; sharing them would change aspis-crypto's tests,
//! which C71 doesn't. The files are parsed lazily, in seed generators and
//! tests only, never in a target's run.

use std::sync::LazyLock;

use aspis_crypto::composite;

/// aspis-crypto's test reader: hex, base64 and the JSON vector files.
#[path = "../../../crates/crypto/tests/common/mod.rs"]
pub mod vectors;

use vectors::{Value, base64, field};

/// One vector file, with its path in the repository.
pub struct VectorFile {
    pub path: &'static str,
    pub text: &'static str,
}

macro_rules! vector_file {
    ($name:literal) => {
        VectorFile {
            path: concat!("crates/crypto/tests/data/", $name),
            text: include_str!(concat!("../../../crates/crypto/tests/data/", $name)),
        }
    };
}

/// Every vector file of `crates/crypto/tests/data/`.
pub const VECTOR_FILES: &[VectorFile] = &[
    vector_file!("rfc4231.json"),
    vector_file!("rfc5869.json"),
    vector_file!("rfc7748.json"),
    vector_file!("rfc8032.json"),
    vector_file!("rfc8439.json"),
    vector_file!("rfc9001.json"),
    vector_file!("rfc10073.json"),
    vector_file!("acvp/ml-kem-768-keygen.json"),
    vector_file!("acvp/ml-kem-768-encapdecap.json"),
    vector_file!("acvp/ml-dsa-65-keygen.json"),
    vector_file!("acvp/ml-dsa-65-siggen.json"),
    vector_file!("acvp/ml-dsa-65-sigver.json"),
];

/// Every file of [`VECTOR_FILES`], parsed, in order.
static PARSED: LazyLock<Vec<Value>> = LazyLock::new(|| {
    VECTOR_FILES
        .iter()
        .map(|f| vectors::vectors(f.text))
        .collect()
});

/// A vector file, parsed, by its name under `crates/crypto/tests/data/`,
/// such as `rfc8032.json` or `acvp/ml-dsa-65-sigver.json`.
pub fn parsed(name: &str) -> &'static Value {
    let i = VECTOR_FILES
        .iter()
        .position(|f| f.path.strip_prefix("crates/crypto/tests/data/") == Some(name))
        .unwrap_or_else(|| panic!("no vector file {name}"));
    &PARSED[i]
}

/// The tests of an RFC file.
pub fn rfc(name: &str) -> Vec<Value> {
    parsed(name).get("tests").as_array().to_vec()
}

/// Every test of every group of an ACVP file, each with its group's
/// `tgId` and `deterministic` (if the group has one), as
/// `(group, test)`.
pub fn acvp(name: &str) -> Vec<(Value, Value)> {
    parsed(&format!("acvp/{name}.json"))
        .get("testGroups")
        .as_array()
        .iter()
        .flat_map(|g| {
            g.get("tests")
                .as_array()
                .iter()
                .map(|t| (g.clone(), t.clone()))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// RFC 10073's Appendix E: its test object (the key, the signatures),
/// and its message and context.
pub fn rfc10073() -> (Value, Vec<u8>, Vec<u8>) {
    let e = parsed("rfc10073.json").get("appendixE");
    (
        e.get("tests").as_array()[0].clone(),
        base64(e.get("m").as_str()),
        base64(e.get("ctx").as_str()),
    )
}

/// `selector` ‖ the parts.
pub fn with(selector: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![selector];
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

/// A big-endian `u16` context length and the context, as
/// `aspis_crypto::fuzz::verify` and the differential's selectors 19 and
/// 20 read them.
pub fn ctx_field(ctx: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(ctx.len())
        .expect("a context of at most 300 octets")
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(ctx);
    out
}

/// A one-octet length and the octets, as the entries' `short` fields.
fn short(b: &[u8]) -> Vec<u8> {
    let mut out = vec![u8::try_from(b.len()).expect("a short field of at most 255 octets")];
    out.extend_from_slice(b);
    out
}

/// A test's `tcId`, as a seed name's part: lowercase, with every run of
/// other characters a hyphen (`"Section 5.2, X25519 test vector 1"` is
/// `section-5-2-x25519-test-vector-1`).
pub fn tc_name(t: &Value) -> String {
    let id = t.get("tcId");
    let raw = match id {
        Value::Number(_) => id.as_u64().to_string(),
        _ => id.as_str().to_string(),
    };
    let mut out = String::new();
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_end_matches('-').to_string()
}

/// FIPS 197's AES-128 example (Appendix C.1): key, plaintext and
/// ciphertext. FIPS 197 is a work of the US government, with no notice,
/// as `crates/crypto/tests/quic.rs` notes for the same constants.
pub const FIPS197_C1: ([u8; 16], [u8; 16], [u8; 16]) = (
    [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ],
    [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ],
    [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a,
    ],
);

/// FIPS 197's AES-256 example (Appendix C.3): key, plaintext and
/// ciphertext.
pub const FIPS197_C3: ([u8; 32], [u8; 16], [u8; 16]) = (
    [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ],
    [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ],
    [
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60,
        0x89,
    ],
);

/// The lengths of the filler each selector gets: arbitrary octets after
/// the selector, so every primitive runs on inputs the vectors don't
/// shape. 6,000 keeps the longest under `crypto-differential`'s
/// `max_len`.
pub const FILLER_LENGTHS: [usize; 5] = [0, 40, 300, 2000, 6000];

/// Inputs for `aspis_crypto::fuzz::differential`, each named: filler of
/// each length in [`FILLER_LENGTHS`] for every selector, then each
/// primitive's vectors laid out as the entry reads them, and the limits
/// of its length fields. Vectors longer than a target's `max_len` are
/// left whole here; the target cuts them.
pub fn differential_inputs() -> Vec<(String, Vec<u8>)> {
    use crate::crypto_oracle::COMPARED;
    use aspis_crypto::fuzz::DIFFERENTIAL_PRIMITIVES;

    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    let mut push = |name: String, bytes: Vec<u8>| out.push((name, bytes));

    // Filler, from the xorshift64 of crates/crypto/tests/fuzz.rs.
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for sel in 0..DIFFERENTIAL_PRIMITIVES {
        let name = COMPARED[usize::from(sel)].1;
        for n in FILLER_LENGTHS {
            let filler: Vec<u8> = (0..n)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect();
            push(format!("{name}-filler-{n}"), with(sel, &[&filler]));
        }
    }

    // SHAKE256's output lengths at the ends of its range (4).
    for n in [0u16, aspis_crypto::fuzz::MAX_XOF as u16] {
        push(
            format!("shake256-out-{n}"),
            with(4, &[&n.to_be_bytes(), b"abc"]),
        );
    }

    // RFC 4231's HMAC cases (5 to 7): a one-octet key length, the key,
    // the message.
    for t in rfc("rfc4231.json") {
        for (sel, name) in [
            (5, "hmac-sha-256"),
            (6, "hmac-sha-384"),
            (7, "hmac-sha-512"),
        ] {
            push(
                format!("{name}-rfc4231-{}", tc_name(&t)),
                with(sel, &[&short(&field(&t, "key")), &field(&t, "data")]),
            );
        }
    }

    // RFC 5869's A.1 to A.3 (8; and as HKDF-SHA-384, 9): salt, ikm and
    // info after one-octet lengths, then the output length as a `u16`;
    // and the output lengths at the ends of each range, 0 and 255 ×
    // HashLen.
    use aspis_crypto::mac::{Prk256, Prk384};
    for t in rfc("rfc5869.json") {
        let fields = [
            short(&field(&t, "salt")),
            short(&field(&t, "ikm")),
            short(&field(&t, "info")),
        ];
        let l = u16::try_from(t.get("l").as_u64()).expect("a short output");
        for (sel, name, max) in [
            (8, "hkdf-sha-256", Prk256::MAX_OUTPUT),
            (9, "hkdf-sha-384", Prk384::MAX_OUTPUT),
        ] {
            let max = u16::try_from(max).expect("255 × HashLen fits a u16");
            for (n, what) in [
                (l, "rfc5869".to_string()),
                (0, "out-0".into()),
                (max, format!("out-{max}")),
            ] {
                push(
                    format!("{name}-{what}-{}", tc_name(&t)),
                    with(sel, &[&fields[0], &fields[1], &fields[2], &n.to_be_bytes()]),
                );
            }
        }
    }

    // RFC 8439's AEAD vectors (10; and as AES-256-GCM, 11): key, nonce, a
    // one-octet aad length, the aad, the plaintext.
    for t in rfc("rfc8439.json") {
        for (sel, name) in [(10, "chacha20-poly1305"), (11, "aes-256-gcm")] {
            push(
                format!("{name}-rfc8439-{}", tc_name(&t)),
                with(
                    sel,
                    &[
                        &field(&t, "key"),
                        &field(&t, "nonce"),
                        &short(&field(&t, "aad")),
                        &field(&t, "plaintext"),
                    ],
                ),
            );
        }
    }
    // Empty plaintext and aad, under each AEAD's all-zero key.
    for (sel, name) in [
        (10, "chacha20-poly1305"),
        (11, "aes-256-gcm"),
        (21, "aes-128-gcm"),
    ] {
        push(format!("{name}-empty"), with(sel, &[&[0; 44], &[0]]));
    }

    // RFC 7748's scalars and u-coordinates (12), its exchange's keys, and
    // an all-zero u, whose output is all zeros (NonContributory). The
    // iterated vectors all start from k = u = 9, so one of them is kept.
    let x25519 = rfc("rfc7748.json");
    for t in &x25519 {
        let pairs: &[(&str, &str)] = &[
            ("inputScalar", "inputUCoordinate"),
            ("initialK", "initialU"),
            ("alicePrivateKey", "bobPublicKey"),
            ("bobPrivateKey", "alicePublicKey"),
        ];
        let iterated = t.try_get("iterations").is_some_and(|n| n.as_u64() > 1);
        for (i, (k, u)) in pairs.iter().enumerate() {
            if t.try_get(k).is_some() && !iterated {
                push(
                    format!("x25519-rfc7748-{}-{i}", tc_name(t)),
                    with(12, &[&field(t, k), &field(t, u)]),
                );
            }
        }
    }
    push(
        "x25519-zero-u".into(),
        with(12, &[&field(&x25519[0], "inputScalar"), &[0; 32]]),
    );

    // RFC 8032's seeds and messages (13), and its keys, signatures and
    // messages (14), which verify, so the oracle is asked.
    for t in rfc("rfc8032.json") {
        push(
            format!("ed25519-sign-rfc8032-{}", tc_name(&t)),
            with(13, &[&field(&t, "secretKey"), &field(&t, "message")]),
        );
        push(
            format!("ed25519-verify-rfc8032-{}", tc_name(&t)),
            with(
                14,
                &[
                    &field(&t, "publicKey"),
                    &field(&t, "signature"),
                    &field(&t, "message"),
                ],
            ),
        );
    }
    // A message that starts with the composite's prefix, which
    // aspis-crypto's standalone verifier refuses (RFC 10073, section 9.4).
    let first = &rfc("rfc8032.json")[0];
    push(
        "ed25519-sign-prefixed".into(),
        with(13, &[&field(first, "secretKey"), composite::PREFIX, b"m"]),
    );

    // ACVP ML-KEM-768: keyGen's d ‖ z with an m (15), every
    // encapsulation key with its m (16; five fail the modulus check), and
    // every ciphertext (17).
    for (_, t) in acvp("ml-kem-768-keygen") {
        push(
            format!("ml-kem-768-keygen-{}", tc_name(&t)),
            with(15, &[&field(&t, "d"), &field(&t, "z"), &[0x33; 32]]),
        );
    }
    for (_, t) in acvp("ml-kem-768-encapdecap") {
        let m = t
            .try_get("m")
            .map(|_| field(&t, "m"))
            .unwrap_or_else(|| vec![1; 32]);
        push(
            format!("ml-kem-768-encapsulate-{}", tc_name(&t)),
            with(16, &[&field(&t, "ek"), &m]),
        );
        if t.try_get("c").is_some() {
            push(
                format!("ml-kem-768-decapsulate-{}", tc_name(&t)),
                with(17, &[&[0x44; 64], &field(&t, "c")]),
            );
        }
    }

    // ACVP ML-DSA-65: keyGen's ξ with a hedge, a context and a message
    // (18), and one over a prefixed message; every sigGen and sigVer
    // vector's key, signature, context and message (19).
    for (_, t) in acvp("ml-dsa-65-keygen") {
        push(
            format!("ml-dsa-65-sign-keygen-{}", tc_name(&t)),
            with(
                18,
                &[&field(&t, "seed"), &[0x55; 32], &short(b"ctx"), b"message"],
            ),
        );
    }
    push(
        "ml-dsa-65-sign-prefixed".into(),
        with(
            18,
            &[&[0x12; 32], &[0x55; 32], &[0], composite::PREFIX, b"m"],
        ),
    );
    for file in ["ml-dsa-65-siggen", "ml-dsa-65-sigver"] {
        for (_, t) in acvp(file) {
            let outcome = match t.try_get("testPassed") {
                None => "",
                Some(p) if p.as_bool() => "-pass",
                Some(_) => "-fail",
            };
            let kind = file.trim_start_matches("ml-dsa-65-");
            push(
                format!("ml-dsa-65-verify-{kind}-{}{outcome}", tc_name(&t)),
                with(
                    19,
                    &[
                        &field(&t, "pk"),
                        &field(&t, "signature"),
                        &ctx_field(&field(&t, "context")),
                        &field(&t, "message"),
                    ],
                ),
            );
        }
    }

    // The composite (20): RFC 10073's private key, with Appendix E's
    // message, with and without its context, under two hedges, whose
    // first four octets flip a bit of the ML-DSA-65 half (even) or of the
    // Ed25519 half (odd) for the laxness check; and under the all-zero
    // hedge that aspis-crypto refuses (ADR 0069, rule 3). Then contexts
    // of 255 octets, which signs, and of 256 and 300, which give
    // ContextTooLong whatever the hedge.
    let (t, m, ctx) = rfc10073();
    let sk = base64(t.get("sk").as_str());
    let hedges = [
        ([0x66; 32], "hedged-flip-ml-dsa"),
        ([0x67; 32], "hedged-flip-ed25519"),
        ([0; 32], "zero-hedge"),
    ];
    for (rnd, hedge) in hedges {
        push(
            format!("composite-rfc10073-ctx-{hedge}"),
            with(20, &[&sk, &rnd, &ctx_field(&ctx), &m]),
        );
        push(
            format!("composite-rfc10073-{hedge}"),
            with(20, &[&sk, &rnd, &ctx_field(b""), &m]),
        );
    }
    for n in [255, 256, aspis_crypto::fuzz::MAX_FUZZ_CONTEXT] {
        for (rnd, hedge) in &hedges[1..] {
            push(
                format!("composite-ctx-{n}-{hedge}"),
                with(20, &[&sk, rnd, &ctx_field(&vec![7; n]), &m]),
            );
        }
    }

    // RFC 9001's AES-128-GCM payloads (21) and AES-128 header-protection
    // samples (22), and its ChaCha20-Poly1305 packet (10). The Retry
    // integrity tag is AES-128-GCM over an empty plaintext.
    for t in rfc("rfc9001.json") {
        let id = t.get("tcId").as_str();
        let name = tc_name(&t);
        if id.starts_with("A.4") {
            push(
                format!("aes-128-gcm-rfc9001-{name}"),
                with(21, &[&field(&t, "key"), &field(&t, "nonce"), &[0]]),
            );
        } else if id.starts_with("A.5") {
            push(
                format!("chacha20-poly1305-rfc9001-{name}"),
                with(
                    10,
                    &[
                        &field(&t, "key"),
                        &field(&t, "nonce"),
                        &short(&field(&t, "header")),
                        &field(&t, "plaintext"),
                    ],
                ),
            );
        } else {
            let payload = t
                .try_get("payload")
                .map(|_| field(&t, "payload"))
                .unwrap_or_else(|| field(&t, "cryptoFrame"));
            push(
                format!("aes-128-gcm-rfc9001-{name}"),
                with(
                    21,
                    &[
                        &field(&t, "key"),
                        &field(&t, "iv"),
                        &short(&field(&t, "header")),
                        &payload,
                    ],
                ),
            );
            push(
                format!("aes-128-mask-rfc9001-{name}"),
                with(22, &[&field(&t, "hp"), &field(&t, "sample")]),
            );
        }
    }

    // FIPS 197's examples, as a key and a sample (22, 23).
    push(
        "aes-128-mask-fips197-c1".into(),
        with(22, &[&FIPS197_C1.0, &FIPS197_C1.1]),
    );
    push(
        "aes-256-mask-fips197-c3".into(),
        with(23, &[&FIPS197_C3.0, &FIPS197_C3.1]),
    );
    out
}
