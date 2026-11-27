// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The algorithms' identifiers (ADR 0069, rule 6). Built whatever the
//! families, since naming an algorithm needs none of them.
//!
//! [`Algorithm`] names every algorithm ASPIS uses, and maps each to the
//! identifiers that outside formats carry: its OID (C28's X.509), its TLS
//! codepoint (C29) and its JOSE name (C37), where each exists. Decoding an
//! identifier that names no variant gives [`Error::UnknownAlgorithm`],
//! never a default (rule 6).
//!
//! This module identifies; it doesn't set policy. Which algorithms a
//! protocol offers or accepts is the protocol's chunk's decision. In
//! particular:
//!
//! - **TLS cipher suites.** A TLS 1.3 suite names an AEAD and a hash. ADR
//!   0020, rule 3 pairs each of ASPIS's AEADs with one hash, so
//!   [`Algorithm::Aes256Gcm`] maps to `TLS_AES_256_GCM_SHA384` and
//!   [`Algorithm::ChaCha20Poly1305`] to `TLS_CHACHA20_POLY1305_SHA256`,
//!   and [`Algorithm::from_tls`] gives only the AEAD. The suite's hash is
//!   C29's to apply.
//! - **JOSE.** A [`JoseName`] says which registry a name is from: the
//!   `alg` values of JWS and JWE, or JWE's `enc` values (RFC 7518,
//!   sections 3.1, 4.1 and 5.1). A name from the other registry is
//!   refused, so a header's `"alg": "A256GCM"` names nothing.
//!   [`Algorithm::from_jose`] accepts only fully specified names
//!   (RFC 9864). The deprecated "EdDSA" is refused; whether C37 accepts it
//!   from outside providers, with `crv` "Ed25519", is decided above this
//!   layer.
//! - **The composite** has an OID (RFC 10073), but no TLS codepoint until
//!   D65 picks a private-use one, and no JOSE name until C37 and D86 pick
//!   one (rule 6).
//! - **ASPIS's own records** carry identifiers as the chunks that define
//!   them decide (rule 6, last bullet), so there is no numeric ASPIS code
//!   here.
//!
//! The OIDs are from NIST's Computer Security Objects Register and the
//! RFCs named on each variant. The TLS and JOSE values were checked
//! against IANA's "TLS Parameters" and "JSON Object Signing and
//! Encryption" registries on 2026-11-26.

use crate::Error;

/// An algorithm ASPIS uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Algorithm {
    /// SHA-256 (FIPS 180-4).
    Sha256,
    /// SHA-384 (FIPS 180-4).
    Sha384,
    /// SHA-512 (FIPS 180-4).
    Sha512,
    /// SHA3-256 (FIPS 202).
    Sha3_256,
    /// SHAKE256 (FIPS 202).
    Shake256,
    /// HMAC-SHA-256 (RFC 2104; OID from RFC 4231, section 3.1).
    HmacSha256,
    /// HMAC-SHA-384 (RFC 4231, section 3.1).
    HmacSha384,
    /// HMAC-SHA-512 (RFC 4231, section 3.1).
    HmacSha512,
    /// HKDF-SHA-256 (RFC 5869; OID from RFC 8619).
    HkdfSha256,
    /// HKDF-SHA-384 (RFC 5869; OID from RFC 8619).
    HkdfSha384,
    /// ChaCha20-Poly1305 (RFC 8439; OID from RFC 8103).
    ChaCha20Poly1305,
    /// AES-256-GCM (NIST SP 800-38D).
    Aes256Gcm,
    /// X25519 (RFC 7748; OID from RFC 8410).
    X25519,
    /// Ed25519 (RFC 8032; OID from RFC 8410).
    Ed25519,
    /// ML-KEM-768 (FIPS 203).
    MlKem768,
    /// The hybrid key exchange X25519MLKEM768 (RFC 10024), ASPIS's TLS
    /// group (ADR 0003, rule 1). It has no OID.
    ///
    /// This crate gives its two halves, the `ml_kem` and `x25519`
    /// modules, not the hybrid. The ML-KEM part comes first,
    /// the reverse of the name: the client's share is the encapsulation
    /// key (1,184 octets) followed by the X25519 public key (32), the
    /// server's share is the ciphertext (1,088) followed by the X25519
    /// public key (32), and the shared secret is ML-KEM's (32) followed by
    /// X25519's (32). The caller assembles the 64-octet secret and keeps it
    /// in a clearing buffer such as [`crate::Zeroizing`].
    X25519MlKem768,
    /// ML-DSA-65 (FIPS 204).
    MlDsa65,
    /// The composite signature `id-MLDSA65-Ed25519-SHA512` (RFC 10073),
    /// ASPIS's own (ADR 0020, rule 2).
    MlDsa65Ed25519Sha512,
}

/// A TLS codepoint: a value in one of IANA's TLS registries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TlsCodepoint {
    /// A "TLS Supported Groups" value (key exchange).
    NamedGroup(u16),
    /// A "TLS SignatureScheme" value.
    SignatureScheme(u16),
    /// A "TLS Cipher Suites" value. It implies a hash as well as the AEAD.
    CipherSuite(u16),
}

/// A JOSE name: a value in one of IANA's "JSON Web Signature and
/// Encryption Algorithms" registry's two usages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum JoseName<'a> {
    /// An `alg` value: a JWS signature or MAC, or a JWE key management
    /// algorithm (RFC 7518, sections 3.1 and 4.1).
    Alg(&'a str),
    /// A JWE `enc` value: content encryption (RFC 7518, section 5.1).
    Enc(&'a str),
}

/// The identifiers of one algorithm.
struct Ids {
    alg: Algorithm,
    name: &'static str,
    /// The OID in dotted form.
    oid: Option<&'static str>,
    /// The OID's DER content octets: the encoding without its tag and
    /// length (ITU-T X.690, section 8.19).
    der: Option<&'static [u8]>,
    tls: Option<TlsCodepoint>,
    jose: Option<JoseName<'static>>,
}

/// NIST's arc for algorithms, 2.16.840.1.101.3.4, as DER content octets.
macro_rules! nist {
    ($($tail:literal),*) => {
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, $($tail),*]
    };
}

/// RSADSI's arc, 1.2.840.113549, as DER content octets.
macro_rules! rsadsi {
    ($($tail:literal),*) => {
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, $($tail),*]
    };
}

/// Every algorithm and its identifiers, in the order of [`Algorithm`].
const TABLE: &[Ids] = &[
    Ids {
        alg: Algorithm::Sha256,
        name: "SHA-256",
        oid: Some("2.16.840.1.101.3.4.2.1"),
        der: Some(nist!(0x02, 0x01)),
        tls: None,
        jose: None,
    },
    Ids {
        alg: Algorithm::Sha384,
        name: "SHA-384",
        oid: Some("2.16.840.1.101.3.4.2.2"),
        der: Some(nist!(0x02, 0x02)),
        tls: None,
        jose: None,
    },
    Ids {
        alg: Algorithm::Sha512,
        name: "SHA-512",
        oid: Some("2.16.840.1.101.3.4.2.3"),
        der: Some(nist!(0x02, 0x03)),
        tls: None,
        jose: None,
    },
    Ids {
        alg: Algorithm::Sha3_256,
        name: "SHA3-256",
        oid: Some("2.16.840.1.101.3.4.2.8"),
        der: Some(nist!(0x02, 0x08)),
        tls: None,
        jose: None,
    },
    Ids {
        alg: Algorithm::Shake256,
        name: "SHAKE256",
        oid: Some("2.16.840.1.101.3.4.2.12"),
        der: Some(nist!(0x02, 0x0c)),
        tls: None,
        jose: None,
    },
    // JOSE: RFC 7518, section 3.2.
    Ids {
        alg: Algorithm::HmacSha256,
        name: "HMAC-SHA-256",
        oid: Some("1.2.840.113549.2.9"),
        der: Some(rsadsi!(0x02, 0x09)),
        tls: None,
        jose: Some(JoseName::Alg("HS256")),
    },
    Ids {
        alg: Algorithm::HmacSha384,
        name: "HMAC-SHA-384",
        oid: Some("1.2.840.113549.2.10"),
        der: Some(rsadsi!(0x02, 0x0a)),
        tls: None,
        jose: Some(JoseName::Alg("HS384")),
    },
    Ids {
        alg: Algorithm::HmacSha512,
        name: "HMAC-SHA-512",
        oid: Some("1.2.840.113549.2.11"),
        der: Some(rsadsi!(0x02, 0x0b)),
        tls: None,
        jose: Some(JoseName::Alg("HS512")),
    },
    Ids {
        alg: Algorithm::HkdfSha256,
        name: "HKDF-SHA-256",
        oid: Some("1.2.840.113549.1.9.16.3.28"),
        der: Some(rsadsi!(0x01, 0x09, 0x10, 0x03, 0x1c)),
        tls: None,
        jose: None,
    },
    Ids {
        alg: Algorithm::HkdfSha384,
        name: "HKDF-SHA-384",
        oid: Some("1.2.840.113549.1.9.16.3.29"),
        der: Some(rsadsi!(0x01, 0x09, 0x10, 0x03, 0x1d)),
        tls: None,
        jose: None,
    },
    // TLS_CHACHA20_POLY1305_SHA256 (RFC 9846). JOSE registers no name for
    // it.
    Ids {
        alg: Algorithm::ChaCha20Poly1305,
        name: "ChaCha20-Poly1305",
        oid: Some("1.2.840.113549.1.9.16.3.18"),
        der: Some(rsadsi!(0x01, 0x09, 0x10, 0x03, 0x12)),
        tls: Some(TlsCodepoint::CipherSuite(0x1303)),
        jose: None,
    },
    // TLS_AES_256_GCM_SHA384 (RFC 9846); JOSE's `enc` "A256GCM" (RFC 7518,
    // section 5.3).
    Ids {
        alg: Algorithm::Aes256Gcm,
        name: "AES-256-GCM",
        oid: Some("2.16.840.1.101.3.4.1.46"),
        der: Some(nist!(0x01, 0x2e)),
        tls: Some(TlsCodepoint::CipherSuite(0x1302)),
        jose: Some(JoseName::Enc("A256GCM")),
    },
    // The group x25519 (RFC 9846; RFC 8422).
    Ids {
        alg: Algorithm::X25519,
        name: "X25519",
        oid: Some("1.3.101.110"),
        der: Some(&[0x2b, 0x65, 0x6e]),
        tls: Some(TlsCodepoint::NamedGroup(0x001d)),
        jose: None,
    },
    // The scheme ed25519 (RFC 9846); JOSE's fully specified "Ed25519"
    // (RFC 9864, section 2.2).
    Ids {
        alg: Algorithm::Ed25519,
        name: "Ed25519",
        oid: Some("1.3.101.112"),
        der: Some(&[0x2b, 0x65, 0x70]),
        tls: Some(TlsCodepoint::SignatureScheme(0x0807)),
        jose: Some(JoseName::Alg("Ed25519")),
    },
    // The group MLKEM768 (draft-ietf-tls-mlkem-11). ASPIS negotiates only
    // the hybrid (ADR 0020, rule 2), but can name it.
    Ids {
        alg: Algorithm::MlKem768,
        name: "ML-KEM-768",
        oid: Some("2.16.840.1.101.3.4.4.2"),
        der: Some(nist!(0x04, 0x02)),
        tls: Some(TlsCodepoint::NamedGroup(0x0201)),
        jose: None,
    },
    // The group X25519MLKEM768 (RFC 10024).
    Ids {
        alg: Algorithm::X25519MlKem768,
        name: "X25519MLKEM768",
        oid: None,
        der: None,
        tls: Some(TlsCodepoint::NamedGroup(0x11ec)),
        jose: None,
    },
    // The scheme mldsa65 (draft-ietf-tls-mldsa-06); JOSE's "ML-DSA-65"
    // (RFC 9964).
    Ids {
        alg: Algorithm::MlDsa65,
        name: "ML-DSA-65",
        oid: Some("2.16.840.1.101.3.4.3.18"),
        der: Some(nist!(0x03, 0x12)),
        tls: Some(TlsCodepoint::SignatureScheme(0x0905)),
        jose: Some(JoseName::Alg("ML-DSA-65")),
    },
    // RFC 10073, section 6. No TLS codepoint or JOSE name yet (rule 6).
    Ids {
        alg: Algorithm::MlDsa65Ed25519Sha512,
        name: "id-MLDSA65-Ed25519-SHA512",
        oid: Some("1.3.6.1.5.5.7.6.48"),
        der: Some(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x30]),
        tls: None,
        jose: None,
    },
];

impl Algorithm {
    /// Every algorithm, in declaration order.
    pub const ALL: &'static [Algorithm] = &[
        Self::Sha256,
        Self::Sha384,
        Self::Sha512,
        Self::Sha3_256,
        Self::Shake256,
        Self::HmacSha256,
        Self::HmacSha384,
        Self::HmacSha512,
        Self::HkdfSha256,
        Self::HkdfSha384,
        Self::ChaCha20Poly1305,
        Self::Aes256Gcm,
        Self::X25519,
        Self::Ed25519,
        Self::MlKem768,
        Self::X25519MlKem768,
        Self::MlDsa65,
        Self::MlDsa65Ed25519Sha512,
    ];

    fn ids(self) -> &'static Ids {
        // TABLE lists the variants in declaration order; the tests check it.
        &TABLE[self as usize]
    }

    /// The algorithm's name as its standard writes it, such as
    /// "ML-DSA-65" or "id-MLDSA65-Ed25519-SHA512". For people, not for
    /// matching.
    pub fn name(self) -> &'static str {
        self.ids().name
    }

    /// The algorithm's OID in dotted form, where it has one.
    pub fn oid(self) -> Option<&'static str> {
        self.ids().oid
    }

    /// The OID's DER content octets, without the tag and length, where it
    /// has one: what C28's decoder finds inside an `OBJECT IDENTIFIER`.
    pub fn oid_der(self) -> Option<&'static [u8]> {
        self.ids().der
    }

    /// The algorithm whose OID has the DER content octets `der`. Any
    /// other octets give [`Error::UnknownAlgorithm`].
    pub fn from_oid_der(der: &[u8]) -> Result<Self, Error> {
        TABLE
            .iter()
            .find(|i| i.der == Some(der))
            .map(|i| i.alg)
            .ok_or(Error::UnknownAlgorithm)
    }

    /// The algorithm's TLS codepoint, where it has one. For an AEAD it is
    /// the TLS 1.3 cipher suite that ADR 0020, rule 3 pairs it with, which
    /// fixes a hash too.
    pub fn tls(self) -> Option<TlsCodepoint> {
        self.ids().tls
    }

    /// The algorithm a TLS codepoint names. A codepoint of no variant
    /// gives [`Error::UnknownAlgorithm`]. A cipher suite gives its AEAD
    /// only; the suite's hash is C29's to apply.
    pub fn from_tls(cp: TlsCodepoint) -> Result<Self, Error> {
        TABLE
            .iter()
            .find(|i| i.tls == Some(cp))
            .map(|i| i.alg)
            .ok_or(Error::UnknownAlgorithm)
    }

    /// The algorithm's JOSE name, where it has one: an `alg`, or the `enc`
    /// "A256GCM" for AES-256-GCM.
    pub fn jose(self) -> Option<JoseName<'static>> {
        self.ids().jose
    }

    /// The algorithm a JOSE name names in its own registry, compared
    /// exactly, as JOSE names are case-sensitive (RFC 7515, section
    /// 4.1.1). A name from the other registry, such as `alg` "A256GCM",
    /// gives [`Error::UnknownAlgorithm`]. Only fully specified names are
    /// known (RFC 9864): "EdDSA", like any other unknown name, is refused
    /// too.
    pub fn from_jose(name: JoseName<'_>) -> Result<Self, Error> {
        TABLE
            .iter()
            .find(|i| i.jose.is_some_and(|j| j == name))
            .map(|i| i.alg)
            .ok_or(Error::UnknownAlgorithm)
    }
}
