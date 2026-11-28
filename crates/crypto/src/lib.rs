// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! ASPIS's cryptographic primitives (ADR 0069).
//!
//! RustCrypto's and dalek's crates supply every primitive (rule 1). This
//! crate wraps them, and it is the only ASPIS crate that uses them, apart
//! from SHA-512 in the boot stub and initfs and SHA-256 in xtask (rule 2).
//! It is `no_std`, forbids `unsafe`, and allocates only with its `alloc`
//! feature.
//!
//! Each family is a cargo feature, so a user builds only what it takes:
//!
//! - `sha3`: [`hash::sha3_256`] and [`hash::shake256`] (FIPS 202), for
//!   ASPIS's own hashes (ADR 0003, rule 3) and the IDL lock;
//! - `sha2`: [`hash::sha256`], [`hash::sha384`] and [`hash::sha512`]
//!   (FIPS 180-4), HMAC and HKDF ([`mac`]), for TLS 1.3's key schedule
//!   (ADR 0020, rule 3) and the entropy service's DRBG;
//! - `aead`: ChaCha20-Poly1305 and AES-256-GCM ([`aead`]), the bulk
//!   ciphers of ADR 0003, rule 4;
//! - `quic`, which needs `aead`: QUIC v1's fixed ciphers, AES-128-GCM
//!   (`aead::Aes128GcmKey`) and the header-protection masks (`quic`, RFC
//!   9001, section 5.4). ADR 0003, rule 4 admits AES-128 only for QUIC
//!   v1's Initial packets and Retry tags, whose keys come from public
//!   values;
//! - `x25519` and `ml-kem`: X25519 ([`x25519`], RFC 7748) and ML-KEM-768
//!   ([`ml_kem`], FIPS 203), the halves of the hybrid key exchange (ADR
//!   0003, rule 1);
//! - `hybrid`, which needs `x25519` and `ml-kem`: the hybrid itself, TLS
//!   1.3's group X25519MLKEM768 ([`hybrid`], RFC 10024), with its shares,
//!   their checks and the 64-octet shared secret;
//! - `ed25519` and `ml-dsa`: verification of standalone Ed25519
//!   ([`ed25519`], RFC 8032) and ML-DSA-65 ([`ml_dsa`], FIPS 204)
//!   signatures, the components of ASPIS's composite signature (ADR 0003,
//!   rule 2). Their signing keys are crate-private: only the composite
//!   signs with them (ADR 0020, rule 2);
//! - `composite`: ASPIS's signature, `id-MLDSA65-Ed25519-SHA512`
//!   ([`composite`], RFC 10073; ADR 0020, rule 2), which needs the two
//!   signature families and `sha2`.
//!
//! Every family is a default feature but `quic`, and AES-128 is reachable
//! only through `quic`. A crate that doesn't name it can't reach AES-128
//! when built on its own; cargo unifies features across a build, so
//! `cargo xtask lint` keeps `quic` to the manifests it lists: the fuzz
//! harness, and later C29's QUIC, where ADR 0003, rule 4 admits AES-128
//! (rule 2).
//!
//! Two modules are built whatever the families: [`algorithm`], the
//! algorithms' identifiers (rule 6), and [`fuzz`], the entry points C71's
//! fuzz targets wrap, with the seam for the differential oracle (rule 8).
//!
//! The rules every module keeps:
//!
//! - **Randomness is an input** (rule 3). Nothing here draws randomness.
//!   Every key, nonce and hedge comes from the caller as bytes, and the
//!   caller takes it from the entropy service (ADR 0021, rule 1).
//! - **Outside input is checked where it is decoded** (rule 5). Every
//!   decoder takes octets and checks their exact length first.
//! - **Secrets are cleared and compared in constant time** (rule 5).
//!   Secret types are neither `Clone` nor `Copy`, clear themselves on drop,
//!   and print `..` in place of their bytes. Those that can be compared
//!   implement [`subtle::ConstantTimeEq`], and their `==` goes through it.
//!   The clearing covers this crate's types and its own copies, not the
//!   libraries' internal stack temporaries (such as ML-DSA's per-signature
//!   randomness or HMAC's padded key): a server that holds long-term keys
//!   relies on its process isolation for those.
//! - **Errors carry no data** ([`Error`]), so nothing secret leaks through
//!   one.
//!
//! The design is in docs/decisions/0069-cryptography-libraries.md.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;
// The unit tests run on the host, with std.
#[cfg(test)]
extern crate std;

mod error;
mod secret;

#[cfg(feature = "aead")]
pub mod aead;
pub mod algorithm;
#[cfg(feature = "composite")]
pub mod composite;
#[cfg(feature = "ed25519")]
pub mod ed25519;
pub mod fuzz;
#[cfg(any(feature = "sha3", feature = "sha2"))]
pub mod hash;
#[cfg(feature = "hybrid")]
pub mod hybrid;
#[cfg(feature = "sha2")]
pub mod mac;
#[cfg(feature = "ml-dsa")]
pub mod ml_dsa;
#[cfg(feature = "ml-kem")]
pub mod ml_kem;
#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "ml-dsa")]
mod rng;
#[cfg(feature = "x25519")]
pub mod x25519;

// Known-answer tests that need the crate-private signing keys, or the
// libraries' expanded key forms, which the public API never takes.
#[cfg(all(test, any(feature = "ed25519", feature = "ml-dsa", feature = "ml-kem")))]
mod kat;

/// The prefix of every composite message representative, the ASCII string
/// "CompositeAlgorithmSignatures2025" (RFC 10073, section 2.2). The
/// standalone Ed25519 and ML-DSA-65 verifiers refuse messages that start
/// with it, so neither half of a composite signature can be split off and
/// verified alone (RFC 10073, section 9.4; ADR 0020, rule 2).
#[cfg(any(feature = "ed25519", feature = "ml-dsa"))]
pub(crate) const COMPOSITE_PREFIX: &[u8; 32] = b"CompositeAlgorithmSignatures2025";

pub use error::Error;
pub use secret::SharedSecret;
/// A buffer cleared on drop, for key octets handed to the caller.
pub use zeroize::Zeroizing;
