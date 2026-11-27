// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The algorithms' identifiers (ADR 0069, rule 6): every one maps back,
//! the DER forms match the dotted OIDs, and unknown identifiers are
//! refused, never defaulted.

use std::collections::HashSet;

use aspis_crypto::Error;
use aspis_crypto::algorithm::{Algorithm, JoseName, TlsCodepoint};

/// An OID's DER content octets (ITU-T X.690, section 8.19), written here
/// independently of the crate's table.
fn der(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted.split('.').map(|a| a.parse().unwrap()).collect();
    let mut out = vec![u8::try_from(arcs[0] * 40 + arcs[1]).unwrap()];
    for &arc in &arcs[2..] {
        let mut groups = vec![(arc & 0x7f) as u8];
        let mut rest = arc >> 7;
        while rest > 0 {
            groups.push((rest & 0x7f) as u8 | 0x80);
            rest >>= 7;
        }
        out.extend(groups.iter().rev());
    }
    out
}

#[test]
fn every_variant_round_trips() {
    for &alg in Algorithm::ALL {
        assert!(!alg.name().is_empty());
        if let Some(d) = alg.oid_der() {
            assert_eq!(Algorithm::from_oid_der(d), Ok(alg), "{alg:?}");
        }
        if let Some(cp) = alg.tls() {
            assert_eq!(Algorithm::from_tls(cp), Ok(alg), "{alg:?}");
        }
        if let Some(name) = alg.jose() {
            assert_eq!(Algorithm::from_jose(name), Ok(alg), "{alg:?}");
        }
        assert_eq!(alg.oid().is_some(), alg.oid_der().is_some(), "{alg:?}");
    }
    // ALL is complete and has no duplicates, and the identifiers are
    // unique across variants.
    assert_eq!(Algorithm::ALL.len(), 18);
    let set: HashSet<_> = Algorithm::ALL.iter().collect();
    assert_eq!(set.len(), Algorithm::ALL.len());
    let oids: HashSet<_> = Algorithm::ALL.iter().filter_map(|a| a.oid()).collect();
    let tls: HashSet<_> = Algorithm::ALL.iter().filter_map(|a| a.tls()).collect();
    let jose: HashSet<_> = Algorithm::ALL.iter().filter_map(|a| a.jose()).collect();
    assert_eq!(oids.len(), 17);
    assert_eq!(tls.len(), 7);
    assert_eq!(jose.len(), 6);
}

#[test]
fn der_matches_dotted() {
    for &alg in Algorithm::ALL {
        if let Some(dotted) = alg.oid() {
            assert_eq!(alg.oid_der(), Some(der(dotted).as_slice()), "{alg:?}");
        }
    }
    // Spot checks against the standards.
    assert_eq!(Algorithm::Ed25519.oid(), Some("1.3.101.112"));
    assert_eq!(Algorithm::X25519.oid(), Some("1.3.101.110"));
    assert_eq!(Algorithm::MlDsa65.oid(), Some("2.16.840.1.101.3.4.3.18"));
    assert_eq!(Algorithm::MlKem768.oid(), Some("2.16.840.1.101.3.4.4.2"));
    assert_eq!(Algorithm::Sha3_256.oid(), Some("2.16.840.1.101.3.4.2.8"));
    assert_eq!(
        Algorithm::MlDsa65Ed25519Sha512.oid(),
        Some("1.3.6.1.5.5.7.6.48")
    );
}

#[test]
fn unknowns_refused() {
    let unknown = Err(Error::UnknownAlgorithm);
    // SHA-224, Ed448, ML-DSA-44, the composite with a trailing octet, a
    // truncated OID, and nothing.
    for dotted in [
        "2.16.840.1.101.3.4.2.4",
        "1.3.101.113",
        "2.16.840.1.101.3.4.3.17",
    ] {
        assert_eq!(Algorithm::from_oid_der(&der(dotted)), unknown, "{dotted}");
    }
    let mut long = der("1.3.6.1.5.5.7.6.48");
    long.push(0x01);
    assert_eq!(Algorithm::from_oid_der(&long), unknown);
    let short = der("1.3.6.1.5.5.7.6.48");
    assert_eq!(Algorithm::from_oid_der(&short[..short.len() - 1]), unknown);
    assert_eq!(Algorithm::from_oid_der(&[]), unknown);
    // mldsa44, ecdsa_secp256r1_sha256 (0x0403), ed448 (0x0808),
    // TLS_AES_128_GCM_SHA256 (0x1301), secp256r1 (23), and a group value
    // under another registry.
    for cp in [
        TlsCodepoint::SignatureScheme(0x0904),
        TlsCodepoint::SignatureScheme(0x0403),
        TlsCodepoint::SignatureScheme(0x0808),
        TlsCodepoint::CipherSuite(0x1301),
        TlsCodepoint::NamedGroup(23),
        TlsCodepoint::SignatureScheme(0x11ec),
        TlsCodepoint::CipherSuite(0x001d),
    ] {
        assert_eq!(Algorithm::from_tls(cp), unknown, "{cp:?}");
    }
    // The deprecated "EdDSA" (RFC 9864), "none", the empty name, and a
    // name in the wrong case.
    for name in [
        "EdDSA",
        "none",
        "",
        "ed25519",
        "hs256",
        "ML-DSA-44",
        "ML-DSA-65 ",
    ] {
        assert_eq!(
            Algorithm::from_jose(JoseName::Alg(name)),
            unknown,
            "{name:?}"
        );
        assert_eq!(
            Algorithm::from_jose(JoseName::Enc(name)),
            unknown,
            "{name:?}"
        );
    }
    // A name from the other registry: no `alg` is "A256GCM", and no `enc`
    // is "HS256" or "Ed25519".
    assert_eq!(Algorithm::from_jose(JoseName::Alg("A256GCM")), unknown);
    for name in ["HS256", "HS384", "HS512", "Ed25519", "ML-DSA-65"] {
        assert_eq!(Algorithm::from_jose(JoseName::Enc(name)), unknown, "{name}");
    }
}

/// The composite's TLS codepoint is D65's and its JOSE name C37's (rule
/// 6), so it has neither yet.
#[test]
fn composite_has_no_tls_or_jose() {
    assert_eq!(Algorithm::MlDsa65Ed25519Sha512.tls(), None);
    assert_eq!(Algorithm::MlDsa65Ed25519Sha512.jose(), None);
    assert_eq!(
        Algorithm::MlDsa65Ed25519Sha512.name(),
        "id-MLDSA65-Ed25519-SHA512"
    );
}

/// The TLS values ASPIS negotiates (ADR 0003, rule 1; ADR 0020, rule 3).
#[test]
fn tls_values() {
    assert_eq!(
        Algorithm::X25519MlKem768.tls(),
        Some(TlsCodepoint::NamedGroup(0x11ec))
    );
    assert_eq!(Algorithm::X25519MlKem768.oid(), None);
    assert_eq!(
        Algorithm::from_tls(TlsCodepoint::CipherSuite(0x1303)),
        Ok(Algorithm::ChaCha20Poly1305)
    );
    assert_eq!(
        Algorithm::from_tls(TlsCodepoint::CipherSuite(0x1302)),
        Ok(Algorithm::Aes256Gcm)
    );
    assert_eq!(
        Algorithm::Ed25519.tls(),
        Some(TlsCodepoint::SignatureScheme(0x0807))
    );
    assert_eq!(Algorithm::Ed25519.jose(), Some(JoseName::Alg("Ed25519")));
    assert_eq!(Algorithm::MlDsa65.jose(), Some(JoseName::Alg("ML-DSA-65")));
    assert_eq!(Algorithm::Aes256Gcm.jose(), Some(JoseName::Enc("A256GCM")));
}
