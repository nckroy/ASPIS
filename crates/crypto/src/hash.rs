// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The hash functions.
//!
//! - **SHA-3** (feature `sha3`, FIPS 202): SHA3-256 is ASPIS's own hash
//!   (ADR 0003, rule 3): the IDL lock's (ADR 0067, rule 7) and the
//!   authorization tree's (ADR 0016). SHAKE256 is the extendable-output
//!   function, for conditioning and derivation.
//! - **SHA-2** (feature `sha2`, FIPS 180-4): SHA-256 and SHA-384 for TLS
//!   1.3's transcripts and key schedule (ADR 0020, rule 3), and SHA-512
//!   for Ed25519, the composite's pre-hash (RFC 10073) and the initial
//!   image's digests.
//!
//! Each hash has a one-shot function and an incremental state. The states
//! are `Clone`, so a TLS transcript can be forked, and they clear their
//! internal state on drop, since they may hash secrets.

use core::fmt;

// sha2 and sha3 re-export the same `digest` 0.11 trait. Calls name it in
// full, since `Digest` and `Update` both apply to the SHA-3 states.
#[cfg(feature = "sha2")]
use sha2::Digest;
#[cfg(all(feature = "sha3", not(feature = "sha2")))]
use sha3::Digest;

/// Defines an incremental fixed-output hash over a RustCrypto `Digest`.
macro_rules! fixed_hash {
    ($(#[$doc:meta])* $name:ident, $inner:ty, $len:literal) => {
        $(#[$doc])*
        #[derive(Clone, Default)]
        pub struct $name($inner);

        impl $name {
            /// The digest's length in octets.
            pub const LEN: usize = $len;

            /// A fresh state.
            pub fn new() -> Self {
                Self::default()
            }

            /// Absorbs `data`.
            pub fn update(&mut self, data: &[u8]) {
                Digest::update(&mut self.0, data);
            }

            /// The digest of everything absorbed.
            pub fn finalize(self) -> [u8; $len] {
                Digest::finalize(self.0).into()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { .. }"))
            }
        }
    };
}

#[cfg(feature = "sha3")]
fixed_hash!(
    /// SHA3-256 (FIPS 202, section 6.1), incrementally.
    Sha3_256,
    sha3::Sha3_256,
    32
);

#[cfg(feature = "sha2")]
fixed_hash!(
    /// SHA-256 (FIPS 180-4, section 6.2), incrementally.
    Sha256,
    sha2::Sha256,
    32
);

#[cfg(feature = "sha2")]
fixed_hash!(
    /// SHA-384 (FIPS 180-4, section 6.5), incrementally.
    Sha384,
    sha2::Sha384,
    48
);

#[cfg(feature = "sha2")]
fixed_hash!(
    /// SHA-512 (FIPS 180-4, section 6.4), incrementally.
    Sha512,
    sha2::Sha512,
    64
);

/// SHA3-256 of `data` (FIPS 202, section 6.1).
#[cfg(feature = "sha3")]
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(data);
    h.finalize()
}

/// SHA-256 of `data` (FIPS 180-4, section 6.2).
#[cfg(feature = "sha2")]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    <sha2::Sha256 as Digest>::digest(data).into()
}

/// SHA-384 of `data` (FIPS 180-4, section 6.5).
#[cfg(feature = "sha2")]
pub fn sha384(data: &[u8]) -> [u8; 48] {
    <sha2::Sha384 as Digest>::digest(data).into()
}

/// SHA-512 of `data` (FIPS 180-4, section 6.4).
#[cfg(feature = "sha2")]
pub fn sha512(data: &[u8]) -> [u8; 64] {
    <sha2::Sha512 as Digest>::digest(data).into()
}

/// SHAKE256 of `data` (FIPS 202, section 6.2), filling all of `out`.
#[cfg(feature = "sha3")]
pub fn shake256(data: &[u8], out: &mut [u8]) {
    let mut h = Shake256::new();
    h.update(data);
    h.finalize_xof().read(out);
}

/// SHAKE256 (FIPS 202, section 6.2), incrementally: absorb, then read any
/// amount of output from a [`Shake256Reader`].
#[cfg(feature = "sha3")]
#[derive(Clone, Default)]
pub struct Shake256(shake::Shake256);

#[cfg(feature = "sha3")]
impl Shake256 {
    /// A fresh state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Absorbs `data`.
    pub fn update(&mut self, data: &[u8]) {
        shake::Update::update(&mut self.0, data);
    }

    /// Ends absorbing, and returns the reader that squeezes the output.
    pub fn finalize_xof(self) -> Shake256Reader {
        Shake256Reader(shake::ExtendableOutput::finalize_xof(self.0))
    }
}

#[cfg(feature = "sha3")]
impl fmt::Debug for Shake256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Shake256 { .. }")
    }
}

/// SHAKE256's output, read in pieces of any size. Reading `a` octets then
/// `b` gives the same octets as reading `a + b` at once.
#[cfg(feature = "sha3")]
#[derive(Clone)]
pub struct Shake256Reader(shake::Shake256Reader);

#[cfg(feature = "sha3")]
impl Shake256Reader {
    /// Fills `out` with the next octets of output.
    pub fn read(&mut self, out: &mut [u8]) {
        shake::XofReader::read(&mut self.0, out);
    }
}

#[cfg(feature = "sha3")]
impl fmt::Debug for Shake256Reader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Shake256Reader { .. }")
    }
}
