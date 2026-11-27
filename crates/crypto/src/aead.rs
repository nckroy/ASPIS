// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The AEADs of ADR 0003, rule 4 (feature `aead`): ChaCha20-Poly1305 (RFC
//! 8439, section 2.8) and AES-256-GCM (NIST SP 800-38D), and, with the
//! `quic` feature alone, AES-128-GCM for QUIC's Initial packets and Retry
//! tags.
//!
//! ChaCha20-Poly1305 and AES-256-GCM take a 256-bit key, and they protect
//! secrets. AES-128-GCM takes a 128-bit key, and rule 4 admits it only for
//! keys a standard derives from public values: QUIC v1 protects its
//! Initial packets with a key derived from the client's Destination
//! Connection ID, and its Retry integrity tag with a key the RFC fixes
//! (RFC 9001, sections 5.2 and 5.8). Those keys guard against corruption,
//! not eavesdropping. Every key that protects secrets is 256 bits. So
//! `Aes128GcmKey` and `AES_128_KEY_LEN` exist only with the `quic`
//! feature, which isn't a default one. A crate that doesn't name it can't
//! reach AES-128 when built on its own, and `cargo xtask lint` keeps
//! `quic` to the QUIC code it lists (ADR 0069, rule 2).
//!
//! Each takes a 96-bit nonce and gives a 128-bit tag. Nonces are the
//! caller's to manage: a nonce must never repeat under one key, which TLS
//! 1.3's and QUIC's record layers (C29) ensure with their sequence
//! numbers.
//!
//! Each key type seals and opens either in place, with the tag apart, or
//! from one buffer into another, with the tag after the ciphertext. When
//! a tag doesn't verify, the output is zeroed before the error returns, so
//! no unauthenticated octets reach the caller.

#[cfg(feature = "quic")]
use aes_gcm::Aes128Gcm;
use aes_gcm::{Aes256Gcm, AesGcm};
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{
    AeadInOut, KeyInit,
    consts::{U12, U16},
    inout::InOutBuf,
};
use zeroize::Zeroize;

use crate::Error;

/// The key length in octets of ChaCha20-Poly1305 and AES-256-GCM.
pub const KEY_LEN: usize = 32;
/// The key length in octets of AES-128-GCM (feature `quic`).
#[cfg(feature = "quic")]
pub const AES_128_KEY_LEN: usize = 16;
/// The nonce length in octets.
pub const NONCE_LEN: usize = 12;
/// The tag length in octets.
pub const TAG_LEN: usize = 16;

/// The longest input each cipher takes, as its library checks it before
/// anything else. Opening checks it first, so input that is too long
/// gives `Length`, not a forged tag's `Verification`.
trait Limits {
    /// Whether a plaintext or ciphertext of `len` octets, with `aad_len`
    /// octets of associated data, is within the cipher's limits.
    fn fits(len: usize, aad_len: usize) -> bool;
}

impl Limits for ChaCha20Poly1305 {
    /// Fewer than 64 × (2^32 − 1) octets of text: chacha20poly1305 0.11's
    /// check, one octet under RFC 8439's limit of 274,877,906,880 (section
    /// 2.8).
    fn fits(len: usize, _aad_len: usize) -> bool {
        len / 64 < u32::MAX as usize
    }
}

impl<Aes> Limits for AesGcm<Aes, U12> {
    /// At most 2^36 − 32 octets of text and 2^61 − 1 octets of associated
    /// data, for either key size (NIST SP 800-38D, section 5.2.1.1, in
    /// octets; aes-gcm 0.11's P_MAX and A_MAX).
    fn fits(len: usize, aad_len: usize) -> bool {
        (len as u64) <= (1 << 36) - 32 && (aad_len as u64) < (1 << 61)
    }
}

/// Encrypts `buf` in place and returns the tag. Input too long for the
/// cipher gives `OutputLength`.
fn seal_in_place<A: AeadInOut<NonceSize = U12, TagSize = U16> + Limits>(
    cipher: &A,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; TAG_LEN], Error> {
    cipher
        .encrypt_inout_detached(nonce.into(), aad, buf.into())
        .map(Into::into)
        .map_err(|_| Error::OutputLength)
}

/// Decrypts `buf` in place if `tag` verifies. Otherwise zeroes `buf` and
/// gives `Verification`. Input too long for the cipher gives `Length`,
/// with `buf` untouched.
fn open_in_place<A: AeadInOut<NonceSize = U12, TagSize = U16> + Limits>(
    cipher: &A,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), Error> {
    if !A::fits(buf.len(), aad.len()) {
        return Err(Error::Length);
    }
    cipher
        .decrypt_inout_detached(nonce.into(), aad, buf.into(), tag.into())
        .map_err(|_| {
            buf.zeroize();
            Error::Verification
        })
}

/// Encrypts `plaintext` into `out` as ciphertext ‖ tag, and returns the
/// length written.
fn seal<A: AeadInOut<NonceSize = U12, TagSize = U16> + Limits>(
    cipher: &A,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let n = plaintext.len();
    let total = n.checked_add(TAG_LEN).ok_or(Error::OutputLength)?;
    let out = out.get_mut(..total).ok_or(Error::OutputLength)?;
    let (ct, tag_out) = out.split_at_mut(n);
    let buf = InOutBuf::new(plaintext, ct).map_err(|_| Error::OutputLength)?;
    let tag = cipher
        .encrypt_inout_detached(nonce.into(), aad, buf)
        .map_err(|_| Error::OutputLength)?;
    tag_out.copy_from_slice(&tag);
    Ok(total)
}

/// Decrypts ciphertext ‖ tag into `out`, and returns the plaintext's
/// length. Input shorter than a tag, or too long for the cipher, gives
/// `Length`, and a short `out` gives `OutputLength`. If the tag doesn't
/// verify, `out` is zeroed.
fn open<A: AeadInOut<NonceSize = U12, TagSize = U16> + Limits>(
    cipher: &A,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let n = ciphertext_and_tag
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(Error::Length)?;
    if !A::fits(n, aad.len()) {
        return Err(Error::Length);
    }
    let (ct, tag) = ciphertext_and_tag.split_at(n);
    let out = out.get_mut(..n).ok_or(Error::OutputLength)?;
    let buf = InOutBuf::new(ct, out).map_err(|_| Error::OutputLength)?;
    let tag: &[u8; TAG_LEN] = tag.try_into().map_err(|_| Error::Length)?;
    cipher
        .decrypt_inout_detached(nonce.into(), aad, buf, tag.into())
        .map_err(|_| Error::Verification)
        .inspect_err(|_| out.zeroize())?;
    Ok(n)
}

/// Defines a key type over one of the library's AEADs.
macro_rules! aead_key {
    ($(#[$doc:meta])* $name:ident, $inner:ty, $key_len:expr) => {
        $(#[$doc])*
        ///
        /// It is a secret: the library clears the key schedule on drop
        /// (its `zeroize` feature), and the type isn't `Clone` and has no
        /// equality.
        pub struct $name($inner);

        impl $name {
            /// The key from its octets, which the caller takes from a
            /// key schedule or the entropy service (ADR 0069, rule 3).
            pub fn from_bytes(key: &[u8; $key_len]) -> Self {
                Self(<$inner as KeyInit>::new(key.into()))
            }

            /// Encrypts `buf` in place, and returns the tag.
            /// [`Error::OutputLength`] if `buf` is longer than the
            /// cipher allows.
            pub fn seal_in_place(
                &self,
                nonce: &[u8; NONCE_LEN],
                aad: &[u8],
                buf: &mut [u8],
            ) -> Result<[u8; TAG_LEN], Error> {
                seal_in_place(&self.0, nonce, aad, buf)
            }

            /// Decrypts `buf` in place if `tag` verifies, and otherwise
            /// zeroes it and gives [`Error::Verification`]. Input longer
            /// than the cipher takes gives [`Error::Length`].
            pub fn open_in_place(
                &self,
                nonce: &[u8; NONCE_LEN],
                aad: &[u8],
                buf: &mut [u8],
                tag: &[u8; TAG_LEN],
            ) -> Result<(), Error> {
                open_in_place(&self.0, nonce, aad, buf, tag)
            }

            /// Writes `plaintext`'s ciphertext and then the tag into
            /// `out`, and returns the length written: the plaintext's
            /// plus [`TAG_LEN`]. A shorter `out` gives
            /// [`Error::OutputLength`].
            pub fn seal(
                &self,
                nonce: &[u8; NONCE_LEN],
                aad: &[u8],
                plaintext: &[u8],
                out: &mut [u8],
            ) -> Result<usize, Error> {
                seal(&self.0, nonce, aad, plaintext, out)
            }

            /// Opens ciphertext ‖ tag into `out`, and returns the
            /// plaintext's length. Input shorter than [`TAG_LEN`], or
            /// longer than the cipher takes, gives [`Error::Length`], a
            /// short `out` gives
            /// [`Error::OutputLength`], and a tag that doesn't verify
            /// gives [`Error::Verification`] with `out` zeroed.
            pub fn open(
                &self,
                nonce: &[u8; NONCE_LEN],
                aad: &[u8],
                ciphertext_and_tag: &[u8],
                out: &mut [u8],
            ) -> Result<usize, Error> {
                open(&self.0, nonce, aad, ciphertext_and_tag, out)
            }
        }

        // The library type clears itself on drop; this checks that it
        // says so.
        const _: () = {
            fn clears<T: zeroize::ZeroizeOnDrop>() {}
            let _ = clears::<$inner>;
        };

        impl zeroize::ZeroizeOnDrop for $name {}

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

aead_key!(
    /// A ChaCha20-Poly1305 key (RFC 8439, section 2.8).
    ChaCha20Poly1305Key,
    ChaCha20Poly1305,
    KEY_LEN
);

aead_key!(
    /// An AES-256-GCM key (NIST SP 800-38D), for boards with hardware AES
    /// (ADR 0003, rule 4).
    Aes256GcmKey,
    Aes256Gcm,
    KEY_LEN
);

#[cfg(feature = "quic")]
aead_key!(
    /// An AES-128-GCM key (NIST SP 800-38D), for QUIC v1's Initial
    /// packets and Retry integrity tags only (RFC 9001, sections 5.2 and
    /// 5.8). It exists only with the `quic` feature.
    ///
    /// ADR 0003, rule 4 admits it only for keys a standard derives from
    /// public values. An Initial key comes from the client's Destination
    /// Connection ID, which any observer sees, and the Retry key is
    /// printed in the RFC, so neither keeps anything secret. Never use it
    /// for a key that protects secrets: those are 256 bits, with
    /// [`ChaCha20Poly1305Key`] or [`Aes256GcmKey`].
    Aes128GcmKey,
    Aes128Gcm,
    AES_128_KEY_LEN
);

#[cfg(test)]
mod tests {
    #[cfg(feature = "quic")]
    use super::Aes128Gcm;
    use super::{Aes256Gcm, ChaCha20Poly1305, Limits};

    /// The limits are the libraries' own, at their edges. Inputs this
    /// long can't be allocated in a test, so only the checks are run.
    #[test]
    fn limits() {
        let chacha_max = 64 * (u32::MAX as usize - 1) + 63;
        assert!(ChaCha20Poly1305::fits(chacha_max, usize::MAX));
        assert!(!ChaCha20Poly1305::fits(chacha_max + 1, 0));
        let p_max = (1usize << 36) - 32;
        assert!(Aes256Gcm::fits(p_max, (1 << 61) - 1));
        assert!(!Aes256Gcm::fits(p_max + 1, 0));
        assert!(!Aes256Gcm::fits(0, 1 << 61));
        #[cfg(feature = "quic")]
        {
            assert!(Aes128Gcm::fits(p_max, (1 << 61) - 1));
            assert!(!Aes128Gcm::fits(p_max + 1, 0));
            assert!(!Aes128Gcm::fits(0, 1 << 61));
        }
    }
}
