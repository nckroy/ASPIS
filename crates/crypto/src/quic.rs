// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! QUIC's header protection (RFC 9001, section 5.4; feature `quic`).
//!
//! The module exists only with the `quic` feature, which isn't a default
//! one, as does AES-128-GCM in [`crate::aead`]. All three keys serve QUIC
//! alone, and the AES-128 key is one ADR 0003, rule 4 admits only for
//! QUIC v1's Initial packets. A crate that doesn't name the feature can't
//! reach them when built on its own, and `cargo xtask lint` keeps `quic`
//! to the QUIC code it lists (ADR 0069, rule 2).
//!
//! QUIC hides each packet's number, and some bits of its first octet,
//! under a 5-octet mask. The mask comes from a 16-octet sample of the
//! protected payload, under a header-protection key that the record layer
//! derives with the label "quic hp" (RFC 9001, section 5.1). The function
//! follows the packet's AEAD:
//!
//! - **AES** (section 5.4.3): the first 5 octets of AES-ECB of the sample.
//!   [`Aes256HeaderProtectionKey`] goes with AES-256-GCM.
//!   [`Aes128HeaderProtectionKey`] goes with AES-128-GCM, which ASPIS
//!   uses only for QUIC v1's Initial packets. Their header-protection key
//!   is derived from the client's Destination Connection ID, a public
//!   value (section 5.2; ADR 0003, rule 4).
//! - **ChaCha20** (section 5.4.4): the raw ChaCha20 function of RFC 8439,
//!   section 2.4, applied to 5 zero octets. The sample's first 4 octets
//!   are the block counter, read little-endian, and its other 12 octets
//!   are the nonce. [`ChaCha20HeaderProtectionKey`] goes with
//!   ChaCha20-Poly1305.
//!
//! Where the sample is taken, which bits of the header the mask covers,
//! and how the keys are derived are the record layer's (C29). The keys are
//! secrets: each clears itself on drop, isn't `Clone`, has no equality,
//! and prints `..` in place of its octets.

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::{Aes128Enc, Aes256Enc};
use chacha20::cipher::{KeyIvInit, StreamCipherCore};
use chacha20::variants::Ietf;
use chacha20::{ChaChaCore, R20};
use zeroize::{Zeroize, Zeroizing};

/// The sample's length in octets (RFC 9001, section 5.4.2).
pub const SAMPLE_LEN: usize = 16;
/// The mask's length in octets (RFC 9001, section 5.4.1).
pub const MASK_LEN: usize = 5;
/// The AES-128 header-protection key's length in octets.
pub const AES_128_KEY_LEN: usize = 16;
/// The AES-256 and ChaCha20 header-protection keys' length in octets.
pub const KEY_LEN: usize = 32;

/// Defines an AES header-protection key over one of the library's
/// encrypt-only block ciphers.
macro_rules! aes_key {
    ($(#[$doc:meta])* $name:ident, $inner:ty, $key_len:expr) => {
        $(#[$doc])*
        ///
        /// The library clears the key schedule on drop (its `zeroize`
        /// feature).
        pub struct $name($inner);

        impl $name {
            /// The key from its octets, which the record layer derives
            /// with the label "quic hp" (RFC 9001, section 5.1).
            pub fn from_bytes(key: &[u8; $key_len]) -> Self {
                Self(<$inner as KeyInit>::new(key.into()))
            }

            /// The mask for `sample`: the first [`MASK_LEN`] octets of
            /// AES-ECB of the sample (RFC 9001, section 5.4.3).
            pub fn mask(&self, sample: &[u8; SAMPLE_LEN]) -> [u8; MASK_LEN] {
                let mut block = aes::Block::from(*sample);
                self.0.encrypt_block(&mut block);
                let mut mask = [0; MASK_LEN];
                mask.copy_from_slice(&block[..MASK_LEN]);
                block.as_mut_slice().zeroize();
                mask
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

aes_key!(
    /// An AES-128 header-protection key, for QUIC v1's Initial packets
    /// only (RFC 9001, sections 5.2 and 5.4.3).
    ///
    /// ADR 0003, rule 4 admits AES-128 only for keys a standard derives
    /// from public values. Never use it for a key that protects secrets.
    Aes128HeaderProtectionKey,
    Aes128Enc,
    AES_128_KEY_LEN
);

aes_key!(
    /// An AES-256 header-protection key, for packets protected with
    /// AES-256-GCM (RFC 9001, section 5.4.3).
    Aes256HeaderProtectionKey,
    Aes256Enc,
    KEY_LEN
);

/// A ChaCha20 header-protection key, for packets protected with
/// ChaCha20-Poly1305 (RFC 9001, section 5.4.4).
///
/// It keeps the key's octets, cleared on drop, and builds a ChaCha20
/// state for each mask, since each sample brings its own nonce. The
/// library clears that state on drop (its `zeroize` feature).
pub struct ChaCha20HeaderProtectionKey(Zeroizing<[u8; KEY_LEN]>);

impl ChaCha20HeaderProtectionKey {
    /// The key from its 32 octets, which the record layer derives with
    /// the label "quic hp" (RFC 9001, section 5.1).
    pub fn from_bytes(key: &[u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(*key))
    }

    /// The mask for `sample`: ChaCha20 of 5 zero octets, with the
    /// sample's first 4 octets as the little-endian block counter and the
    /// other 12 as the nonce (RFC 9001, section 5.4.4).
    ///
    /// Every counter is taken, 0xFFFFFFFF included. The library's
    /// `ChaCha20` stream refuses to use that last block, so the mask is
    /// read from the core's block function, which takes any position.
    pub fn mask(&self, sample: &[u8; SAMPLE_LEN]) -> [u8; MASK_LEN] {
        let (counter, nonce) = sample.split_at(4);
        let counter = u32::from_le_bytes([counter[0], counter[1], counter[2], counter[3]]);
        let nonce: &[u8; 12] = nonce.try_into().expect("16 − 4 octets");
        let mut core = ChaChaCore::<R20, Ietf>::new((&*self.0).into(), nonce.into());
        core.set_block_pos(counter);
        let mut block = Default::default();
        core.write_keystream_block(&mut block);
        // The keystream XOR 5 zero octets is the keystream.
        let mut mask = [0; MASK_LEN];
        mask.copy_from_slice(&block[..MASK_LEN]);
        block.as_mut_slice().zeroize();
        mask
    }
}

// The library's core clears itself on drop; this checks that it says so.
const _: () = {
    fn clears<T: zeroize::ZeroizeOnDrop>() {}
    let _ = clears::<ChaChaCore<R20, Ietf>>;
};

impl zeroize::ZeroizeOnDrop for ChaCha20HeaderProtectionKey {}

impl core::fmt::Debug for ChaCha20HeaderProtectionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ChaCha20HeaderProtectionKey(..)")
    }
}
