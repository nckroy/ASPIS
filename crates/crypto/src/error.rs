// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The crate's one error type.

use core::fmt;

/// Why an operation failed.
///
/// The variants carry no data, so no secret, and no position in a secret,
/// can leak through an error (ADR 0069, rule 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// An encoded input isn't its exact length (rule 5), or an AEAD input
    /// is shorter than a tag or longer than the cipher takes.
    Length,
    /// An encoded input is malformed: an ML-DSA signature's hint or z, or
    /// a non-canonical Ed25519 point or scalar.
    Encoding,
    /// A small-order Ed25519 public key or R (rule 5).
    WeakKey,
    /// An ML-KEM encapsulation key fails FIPS 203's modulus check (rule 5).
    Modulus,
    /// An all-zero X25519 shared secret (RFC 7748, section 6.1; rule 5).
    NonContributory,
    /// A signature context over 255 octets (FIPS 204; RFC 10073).
    ContextTooLong,
    /// A signature, MAC or AEAD tag that doesn't verify.
    Verification,
    /// An output that can't be produced: HKDF output over 255 times the
    /// hash's length, or an AEAD buffer too small or too long.
    OutputLength,
    /// An OID, TLS codepoint or JOSE name that names no algorithm here
    /// (rule 6).
    UnknownAlgorithm,
    /// ML-DSA signing failed: the library's rejection sampling ran out, or
    /// the caller's hedge was refused (a composite's all-zero hedge, rule
    /// 3).
    SigningFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Length => "wrong length",
            Self::Encoding => "malformed encoding",
            Self::WeakKey => "small-order key",
            Self::Modulus => "encapsulation key fails the modulus check",
            Self::NonContributory => "all-zero shared secret",
            Self::ContextTooLong => "context over 255 octets",
            Self::Verification => "verification failed",
            Self::OutputLength => "output length out of range",
            Self::UnknownAlgorithm => "unknown algorithm",
            Self::SigningFailed => "signing failed",
        })
    }
}

impl core::error::Error for Error {}
