// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! HMAC (RFC 2104) and HKDF (RFC 5869) over SHA-2 (feature `sha2`).
//!
//! - HMAC-SHA-256 and HMAC-SHA-384 serve TLS 1.3's key schedule (ADR 0020,
//!   rule 3), and HMAC-SHA-512 the entropy service's HMAC_DRBG (C21). A
//!   tag is checked with [`HmacSha256::verify`] and its siblings, which
//!   compare in constant time.
//! - HKDF-SHA-256 and HKDF-SHA-384 give extract and expand separately, so
//!   TLS 1.3's HKDF-Expand-Label (C29) can be built on [`Prk256::expand`].
//!   [`Prk256::expand_array`] and [`Prk256::expand_prk`] keep the output
//!   in a clearing type, so a derived secret never sits in a plain array.
//!
//! Keyed states and pseudorandom keys are secrets: they clear themselves
//! on drop, and aren't `Clone` (ADR 0069, rule 5).

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha384, Sha512};
use zeroize::{Zeroize, Zeroizing};

use crate::Error;
use crate::secret::{Secret, secret_newtype};

/// Defines a keyed HMAC state and its one-shot function.
macro_rules! hmac_type {
    ($(#[$doc:meta])* $name:ident, $one_shot:ident, $hash:ty, $len:literal, $rfc:literal) => {
        $(#[$doc])*
        ///
        /// It is a secret: it clears its keyed state on drop, isn't
        /// `Clone`, and has no equality.
        pub struct $name(Hmac<$hash>);

        impl $name {
            /// The tag's length in octets.
            pub const LEN: usize = $len;

            /// A state keyed with `key`, of any length (RFC 2104, section
            /// 3: a key longer than the hash's block is hashed first).
            pub fn new(key: &[u8]) -> Self {
                // HMAC takes a key of any length, so this can't fail.
                Self(<Hmac<$hash> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length"))
            }

            /// Absorbs `data`.
            pub fn update(&mut self, data: &[u8]) {
                Mac::update(&mut self.0, data);
            }

            /// The tag of everything absorbed.
            pub fn finalize(self) -> [u8; $len] {
                Mac::finalize(self.0).into_bytes().into()
            }

            /// Checks `tag` against the tag of everything absorbed, in
            /// constant time. A tag of the wrong length doesn't verify.
            pub fn verify(self, tag: &[u8]) -> Result<(), Error> {
                Mac::verify_slice(self.0, tag).map_err(|_| Error::Verification)
            }
        }

        // The state's fields clear themselves on drop: the hash cores
        // through sha2's `zeroize` feature, and the block buffer through
        // digest's (both enabled in Cargo.toml). `Hmac` itself doesn't
        // implement `ZeroizeOnDrop`, but it holds the same core and buffer
        // as the hash, which does only while those features are on. This
        // fails to compile if a change turns them off.
        const _: () = {
            fn clears<T: zeroize::ZeroizeOnDrop>() {}
            let _ = clears::<$hash>;
        };

        impl zeroize::ZeroizeOnDrop for $name {}

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), " { .. }"))
            }
        }

        #[doc = concat!("HMAC-", $rfc, " of `data` under `key`.")]
        pub fn $one_shot(key: &[u8], data: &[u8]) -> [u8; $len] {
            let mut h = $name::new(key);
            h.update(data);
            h.finalize()
        }
    };
}

hmac_type!(
    /// HMAC-SHA-256 (RFC 2104; RFC 4231), incrementally.
    HmacSha256,
    hmac_sha256,
    Sha256,
    32,
    "SHA-256"
);

hmac_type!(
    /// HMAC-SHA-384 (RFC 2104; RFC 4231), incrementally.
    HmacSha384,
    hmac_sha384,
    Sha384,
    48,
    "SHA-384"
);

hmac_type!(
    /// HMAC-SHA-512 (RFC 2104; RFC 4231), incrementally. C21's HMAC_DRBG
    /// is built on it.
    HmacSha512,
    hmac_sha512,
    Sha512,
    64,
    "SHA-512"
);

/// Defines an HKDF pseudorandom key and its extract function.
macro_rules! hkdf_type {
    ($(#[$doc:meta])* $name:ident, $extract:ident, $hash:ty, $len:literal, $hname:literal) => {
        $(#[$doc])*
        ///
        /// It is a secret: it clears itself on drop, isn't `Clone`, and is
        /// compared in constant time.
        pub struct $name(Secret<$len>);

        impl $name {
            /// The key's length in octets, the hash's output length.
            pub const LEN: usize = $len;

            /// The most octets [`Self::expand`] gives: 255 times the
            /// hash's length (RFC 5869, section 2.3).
            pub const MAX_OUTPUT: usize = 255 * $len;

            /// A pseudorandom key the caller already holds, such as a TLS
            /// 1.3 secret (RFC 5869, section 3.3: extract may be skipped).
            pub fn from_bytes(prk: &[u8; $len]) -> Self {
                Self(Secret::new(prk))
            }

            /// The key's octets.
            pub fn as_bytes(&self) -> &[u8; $len] {
                self.0.as_bytes()
            }

            /// HKDF-Expand (RFC 5869, section 2.3): fills `okm` from this
            /// key and `info`. More than [`Self::MAX_OUTPUT`] octets give
            /// [`Error::OutputLength`], and `okm` is left untouched.
            pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), Error> {
                // A PRK of the hash's length is always accepted.
                let hk = Hkdf::<$hash>::from_prk(self.0.as_bytes()).expect("a PRK of HashLen octets");
                hk.expand(info, okm).map_err(|_| Error::OutputLength)
            }

            /// HKDF-Expand into `N` octets held in a buffer that clears
            /// itself on drop, for a derived secret such as a key or an
            /// IV. More than [`Self::MAX_OUTPUT`] octets give
            /// [`Error::OutputLength`].
            pub fn expand_array<const N: usize>(
                &self,
                info: &[u8],
            ) -> Result<Zeroizing<[u8; N]>, Error> {
                let mut okm = Zeroizing::new([0u8; N]);
                self.expand(info, &mut okm[..])?;
                Ok(okm)
            }

            /// HKDF-Expand into the next pseudorandom key of the same
            /// hash, as TLS 1.3's Derive-Secret does (RFC 8446, section
            /// 7.1). The octets never leave a clearing type.
            pub fn expand_prk(&self, info: &[u8]) -> Self {
                // HashLen octets are always within the limit.
                let okm = self.expand_array::<$len>(info).expect("HashLen octets");
                Self::from_bytes(&okm)
            }
        }

        secret_newtype!($name);

        #[doc = concat!("HKDF-Extract with ", $hname, " (RFC 5869, section 2.2).")]
        ///
        /// `None` and an empty salt both mean a salt of HashLen zero
        /// octets, as the RFC says.
        pub fn $extract(salt: Option<&[u8]>, ikm: &[u8]) -> $name {
            let (mut prk, _) = Hkdf::<$hash>::extract(salt, ikm);
            let key = $name(Secret::from_slice(&prk));
            prk.as_mut_slice().zeroize();
            key
        }
    };
}

hkdf_type!(
    /// An HKDF-SHA-256 pseudorandom key (RFC 5869).
    Prk256,
    hkdf_sha256_extract,
    Sha256,
    32,
    "SHA-256"
);

hkdf_type!(
    /// An HKDF-SHA-384 pseudorandom key (RFC 5869).
    Prk384,
    hkdf_sha384_extract,
    Sha384,
    48,
    "SHA-384"
);
