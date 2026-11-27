// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The hybrid key exchange X25519MLKEM768 (RFC 10024), ASPIS's TLS 1.3
//! group (ADR 0003, rule 1; ADR 0020, rule 2; feature `hybrid`).
//!
//! It is built from this crate's [`ml_kem`] and [`x25519`] wrappers, and
//! adds only the concatenations and their checks. In each, the ML-KEM part
//! comes first, the reverse of the name (RFC 10024, section 4.1):
//!
//! - **The client share** is the client's ML-KEM-768 encapsulation key
//!   (1,184 octets) followed by its X25519 public key (32): 1,216 octets
//!   (section 4.1).
//! - **The server share** is the ML-KEM-768 ciphertext encapsulated to
//!   that key (1,088 octets) followed by the server's X25519 public key
//!   (32): 1,120 octets (section 4.2).
//! - **The shared secret** is ML-KEM's (32 octets) followed by X25519's
//!   (32): 64 octets (section 4.3). TLS 1.3's key schedule takes it whole.
//!
//! The 64-octet secret is safe only as the (EC)DHE input to TLS 1.3's key
//! schedule, which binds it to the handshake transcript. The RFC's
//! analysis relies on that binding, and the plain concatenation can't be
//! assumed secure in any other protocol (RFC 10024, section 6). Another
//! protocol needs its own combiner, and the secret is never a key itself.
//!
//! The checks RFC 10024 requires, each where the input is decoded or used
//! (ADR 0069, rule 5):
//!
//! - **Exact lengths.** A share of any other length gives
//!   [`Error::Length`] (sections 4.1 and 4.2).
//! - **The modulus check.** The server checks the client's encapsulation
//!   key as FIPS 203, section 7.2 says, when the client share is decoded.
//!   A key that fails gives [`Error::Modulus`] (section 4.2).
//! - **An all-zero X25519 secret** gives [`Error::NonContributory`], on
//!   either side (section 4.3, through RFC 9846, section 7.4.2).
//! - **ML-KEM decapsulation can't fail.** A ciphertext not made for the
//!   key gives a pseudorandom secret (FIPS 203, Algorithm 18, implicit
//!   rejection), which matches nothing.
//!
//! RFC 10024 has the connection aborted with an `illegal_parameter` alert
//! for each refusal. Sending the alert is the TLS stack's job.
//!
//! Randomness is an input (ADR 0069, rule 3). The client's key takes
//! ML-KEM-768's seed d ‖ z and an X25519 secret key. The server's
//! encapsulation takes ML-KEM's m and an X25519 ephemeral secret key. The
//! caller takes each fresh from the entropy service for every exchange.
//! The client recovers m when it decapsulates, so m discloses that
//! output of the generator to the peer (RFC 10024, section 6).
//!
//! The module gives out no component secret on its own: it returns only
//! the 64-octet secret, and its keys hold their component keys privately.

use core::fmt;

use crate::ml_kem::{self, MlKem768Ciphertext, MlKem768DecapsulationKey, MlKem768EncapsulationKey};
use crate::secret::{Secret, secret_newtype};
use crate::x25519::{self, X25519PublicKey, X25519SecretKey};
use crate::{Error, SharedSecret, Zeroizing};

/// A client share's length in octets: the encapsulation key, then the
/// X25519 public key.
pub const CLIENT_SHARE_LEN: usize = ml_kem::ENCAPSULATION_KEY_LEN + x25519::KEY_LEN;
/// A server share's length in octets: the ciphertext, then the X25519
/// public key.
pub const SERVER_SHARE_LEN: usize = ml_kem::CIPHERTEXT_LEN + x25519::KEY_LEN;
/// The shared secret's length in octets: ML-KEM's, then X25519's.
pub const SHARED_SECRET_LEN: usize = 64;

// The sizes RFC 10024 states (sections 4.1 to 4.3).
const _: () = assert!(CLIENT_SHARE_LEN == 1216 && SERVER_SHARE_LEN == 1120);

/// Joins the two component secrets, ML-KEM's first (RFC 10024, section
/// 4.3). The buffer on the way clears itself, and so do the components
/// when the caller drops them.
fn combine(ml_kem: &SharedSecret, x25519: &SharedSecret) -> X25519MlKem768SharedSecret {
    let mut octets = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
    let (first, second) = octets.split_at_mut(32);
    first.copy_from_slice(ml_kem.as_bytes());
    second.copy_from_slice(x25519.as_bytes());
    X25519MlKem768SharedSecret(Secret::new(&octets))
}

/// The client's key for one X25519MLKEM768 exchange: an ML-KEM-768
/// decapsulation key and an X25519 secret key.
///
/// It is a secret: both keys clear themselves on drop, and the type isn't
/// `Clone` and has no equality. Nothing needs to compare these keys, which
/// live for one handshake.
pub struct X25519MlKem768DecapsulationKey {
    ml_kem: MlKem768DecapsulationKey,
    x25519: X25519SecretKey,
}

impl X25519MlKem768DecapsulationKey {
    /// The key from ML-KEM-768's 64-octet seed d ‖ z (FIPS 203, Algorithm
    /// 16) and X25519's 32-octet secret key (RFC 7748, section 5), which
    /// the caller takes from the entropy service (ADR 0069, rule 3).
    pub fn from_seed(
        ml_kem_seed: &[u8; ml_kem::SEED_LEN],
        x25519_seed: &[u8; x25519::KEY_LEN],
    ) -> Self {
        Self {
            ml_kem: MlKem768DecapsulationKey::from_seed(ml_kem_seed),
            x25519: X25519SecretKey::from_seed(x25519_seed),
        }
    }

    /// The client share to send (RFC 10024, section 4.1).
    pub fn client_share(&self) -> X25519MlKem768ClientShare {
        X25519MlKem768ClientShare {
            ml_kem: self.ml_kem.encapsulation_key(),
            x25519: self.x25519.public_key(),
        }
    }

    /// The shared secret from the server's share (RFC 10024, section 4.3).
    ///
    /// A server share whose X25519 key gives an all-zero secret gives
    /// [`Error::NonContributory`]. The ML-KEM half can't fail: a ciphertext
    /// not made for this key gives a pseudorandom secret that matches
    /// nothing (implicit rejection).
    pub fn decapsulate(
        &self,
        share: &X25519MlKem768ServerShare,
    ) -> Result<X25519MlKem768SharedSecret, Error> {
        let x25519 = self.x25519.diffie_hellman(&share.x25519)?;
        let ml_kem = self.ml_kem.decapsulate(&share.ml_kem);
        Ok(combine(&ml_kem, &x25519))
    }
}

impl zeroize::ZeroizeOnDrop for X25519MlKem768DecapsulationKey {}

impl fmt::Debug for X25519MlKem768DecapsulationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("X25519MlKem768DecapsulationKey(..)")
    }
}

/// A client share: an ML-KEM-768 encapsulation key that passed FIPS 203's
/// modulus check, then an X25519 public key (RFC 10024, section 4.1).
#[derive(Clone, PartialEq, Eq)]
pub struct X25519MlKem768ClientShare {
    ml_kem: MlKem768EncapsulationKey,
    x25519: X25519PublicKey,
}

impl X25519MlKem768ClientShare {
    /// Decodes a client share, as the server does (ADR 0069, rule 5):
    ///
    /// - a length other than 1,216 gives [`Error::Length`];
    /// - an encapsulation key that fails FIPS 203's modulus check gives
    ///   [`Error::Modulus`] (RFC 10024, section 4.2).
    ///
    /// Every 32 octets are an X25519 key (RFC 7748, section 5). So an
    /// accepted share's [`Self::to_bytes`] returns the input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != CLIENT_SHARE_LEN {
            return Err(Error::Length);
        }
        let (ek, pk) = bytes.split_at(ml_kem::ENCAPSULATION_KEY_LEN);
        Ok(Self {
            ml_kem: MlKem768EncapsulationKey::from_bytes(ek)?,
            x25519: X25519PublicKey::from_bytes(pk)?,
        })
    }

    /// The share's octets.
    pub fn to_bytes(&self) -> [u8; CLIENT_SHARE_LEN] {
        let mut out = [0; CLIENT_SHARE_LEN];
        let (ek, pk) = out.split_at_mut(ml_kem::ENCAPSULATION_KEY_LEN);
        ek.copy_from_slice(&self.ml_kem.to_bytes());
        pk.copy_from_slice(self.x25519.as_bytes());
        out
    }

    /// The server's side of the exchange: the server share to send, and the
    /// shared secret (RFC 10024, sections 4.2 and 4.3).
    ///
    /// `m` is ML-KEM's 32 random octets (FIPS 203, Algorithm 17), and
    /// `x25519_seed` the server's ephemeral X25519 secret key. Both must be
    /// fresh from the entropy service for every call (ADR 0069, rule 3).
    ///
    /// A client share whose X25519 key gives an all-zero secret gives
    /// [`Error::NonContributory`] (RFC 10024, section 4.3).
    pub fn encapsulate(
        &self,
        m: &[u8; ml_kem::RANDOMNESS_LEN],
        x25519_seed: &[u8; x25519::KEY_LEN],
    ) -> Result<(X25519MlKem768ServerShare, X25519MlKem768SharedSecret), Error> {
        let ephemeral = X25519SecretKey::from_seed(x25519_seed);
        let x25519 = ephemeral.diffie_hellman(&self.x25519)?;
        let (ct, ml_kem) = self.ml_kem.encapsulate(m);
        let share = X25519MlKem768ServerShare {
            ml_kem: ct,
            x25519: ephemeral.public_key(),
        };
        Ok((share, combine(&ml_kem, &x25519)))
    }
}

impl fmt::Debug for X25519MlKem768ClientShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("X25519MlKem768ClientShare(1216 octets)")
    }
}

/// A server share: an ML-KEM-768 ciphertext, then an X25519 public key
/// (RFC 10024, section 4.2).
#[derive(Clone, PartialEq, Eq)]
pub struct X25519MlKem768ServerShare {
    ml_kem: MlKem768Ciphertext,
    x25519: X25519PublicKey,
}

impl X25519MlKem768ServerShare {
    /// Decodes a server share, as the client does. A length other than
    /// 1,120 gives [`Error::Length`] (RFC 10024, section 4.2). Every 1,088
    /// octets are a ciphertext (FIPS 203, section 7.3) and every 32 an
    /// X25519 key, so an accepted share's [`Self::to_bytes`] returns the
    /// input. A bad X25519 key is caught at
    /// [`X25519MlKem768DecapsulationKey::decapsulate`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SERVER_SHARE_LEN {
            return Err(Error::Length);
        }
        let (ct, pk) = bytes.split_at(ml_kem::CIPHERTEXT_LEN);
        Ok(Self {
            ml_kem: MlKem768Ciphertext::from_bytes(ct)?,
            x25519: X25519PublicKey::from_bytes(pk)?,
        })
    }

    /// The share's octets.
    pub fn to_bytes(&self) -> [u8; SERVER_SHARE_LEN] {
        let mut out = [0; SERVER_SHARE_LEN];
        let (ct, pk) = out.split_at_mut(ml_kem::CIPHERTEXT_LEN);
        ct.copy_from_slice(&self.ml_kem.to_bytes());
        pk.copy_from_slice(self.x25519.as_bytes());
        out
    }
}

impl fmt::Debug for X25519MlKem768ServerShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("X25519MlKem768ServerShare(1120 octets)")
    }
}

/// The 64-octet shared secret of X25519MLKEM768: ML-KEM-768's secret, then
/// X25519's (RFC 10024, section 4.3).
///
/// It has [`SharedSecret`]'s guarantees: it clears itself on drop, is
/// compared in constant time, and its `Debug` prints `..` in place of its
/// octets. It is neither `Clone` nor `Copy`.
pub struct X25519MlKem768SharedSecret(Secret<SHARED_SECRET_LEN>);

impl X25519MlKem768SharedSecret {
    /// The secret's octets, for TLS 1.3's key schedule.
    ///
    /// They are safe only as that schedule's (EC)DHE input, which binds
    /// them to the transcript (RFC 10024, section 6). Another protocol
    /// needs its own combiner.
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_LEN] {
        self.0.as_bytes()
    }
}

secret_newtype!(X25519MlKem768SharedSecret);
