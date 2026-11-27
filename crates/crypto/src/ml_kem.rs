// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! ML-KEM-768 (FIPS 203), the post-quantum half of ASPIS's key exchange
//! (ADR 0003, rule 1; feature `ml-kem`).
//!
//! - **Key generation** takes the 64-octet seed d ‖ z (FIPS 203, Algorithm
//!   16, ML-KEM.KeyGen_internal), which the caller takes from the entropy
//!   service (ADR 0069, rule 3).
//! - **Encapsulation** takes its 32 random octets m from the caller too
//!   (Algorithm 17, ML-KEM.Encaps_internal). FIPS 203's ML-KEM.Encaps
//!   draws m itself; here the caller draws it.
//! - **Decapsulation** never fails. A ciphertext that wasn't made for the
//!   key gives a pseudorandom secret instead, J(z ‖ c) (implicit
//!   rejection, Algorithm 18).
//! - **An encapsulation key from outside** gets FIPS 203's modulus check
//!   (section 7.2) when it is decoded (ADR 0069, rule 5).

use ml_kem::array::Array;
use ml_kem::{Decapsulate, KeyExport, MlKem768};
use zeroize::Zeroize;

use crate::secret::Secret;
use crate::{Error, SharedSecret, Zeroizing};

/// A decapsulation key's seed length in octets: d ‖ z.
pub const SEED_LEN: usize = 64;
/// An encapsulation key's length in octets.
pub const ENCAPSULATION_KEY_LEN: usize = 1184;
/// A ciphertext's length in octets.
pub const CIPHERTEXT_LEN: usize = 1088;
/// The length in octets of encapsulation's random input m.
pub const RANDOMNESS_LEN: usize = 32;

/// Copies a library array of `N` octets into a plain array.
fn to_array<const N: usize>(octets: &[u8]) -> [u8; N] {
    let mut out = [0; N];
    out.copy_from_slice(octets);
    out
}

/// Moves a library shared key into a [`SharedSecret`], and clears the
/// library's copy and the copy made on the way.
fn shared_secret(mut key: ml_kem::SharedKey) -> SharedSecret {
    let mut octets = Zeroizing::new([0u8; 32]);
    octets.copy_from_slice(key.as_slice());
    key.as_mut_slice().zeroize();
    SharedSecret::from_bytes(&octets)
}

/// Decapsulates `ct` with `dk`. It is the one path from a library key to a
/// shared secret, for [`MlKem768DecapsulationKey::decapsulate`] and for
/// the known-answer tests of expanded keys.
pub(crate) fn decapsulate_with(
    dk: &ml_kem::DecapsulationKey<MlKem768>,
    ct: &MlKem768Ciphertext,
) -> SharedSecret {
    shared_secret(dk.decapsulate(&ct.0))
}

/// An ML-KEM-768 decapsulation key.
///
/// It is a secret: the library clears its key on drop, and the seed kept
/// here clears itself too. The type isn't `Clone`. Its equality compares
/// the seeds in constant time.
pub struct MlKem768DecapsulationKey {
    dk: ml_kem::DecapsulationKey<MlKem768>,
    /// The seed, kept so that [`Self::to_seed`] needn't ask the library,
    /// whose copy comes back by value and can't be cleared.
    seed: Secret<SEED_LEN>,
}

impl MlKem768DecapsulationKey {
    /// The key from its seed d ‖ z (FIPS 203, Algorithm 16), which the
    /// caller takes from the entropy service (ADR 0069, rule 3).
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let mut library_seed = ml_kem::Seed::from(*seed);
        let dk = ml_kem::DecapsulationKey::<MlKem768>::from_seed(library_seed);
        library_seed.as_mut_slice().zeroize();
        Self {
            dk,
            seed: Secret::new(seed),
        }
    }

    /// The seed d ‖ z, for storage. The buffer clears itself on drop.
    pub fn to_seed(&self) -> Zeroizing<[u8; SEED_LEN]> {
        Zeroizing::new(*self.seed.as_bytes())
    }

    /// The matching encapsulation key.
    pub fn encapsulation_key(&self) -> MlKem768EncapsulationKey {
        MlKem768EncapsulationKey(self.dk.encapsulation_key().clone())
    }

    /// Decapsulates `ct` (FIPS 203, Algorithm 18). It can't fail: a
    /// ciphertext not made for this key gives a pseudorandom secret that
    /// matches nothing (implicit rejection).
    pub fn decapsulate(&self, ct: &MlKem768Ciphertext) -> SharedSecret {
        decapsulate_with(&self.dk, ct)
    }
}

// The library's key clears itself on drop; this checks that it says so.
const _: () = {
    fn clears<T: zeroize::ZeroizeOnDrop>() {}
    let _ = clears::<ml_kem::DecapsulationKey<MlKem768>>;
};

impl zeroize::ZeroizeOnDrop for MlKem768DecapsulationKey {}

/// The key is determined by its seed, so comparing seeds compares keys.
impl subtle::ConstantTimeEq for MlKem768DecapsulationKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.seed.ct_eq(&other.seed)
    }
}

impl PartialEq for MlKem768DecapsulationKey {
    fn eq(&self, other: &Self) -> bool {
        subtle::ConstantTimeEq::ct_eq(self, other).into()
    }
}

impl Eq for MlKem768DecapsulationKey {}

impl core::fmt::Debug for MlKem768DecapsulationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MlKem768DecapsulationKey(..)")
    }
}

/// An ML-KEM-768 encapsulation key that passed FIPS 203's modulus check.
#[derive(Clone, PartialEq, Eq)]
pub struct MlKem768EncapsulationKey(ml_kem::EncapsulationKey<MlKem768>);

impl MlKem768EncapsulationKey {
    /// Decodes an encapsulation key (ADR 0069, rule 5):
    ///
    /// - a length other than 1,184 gives [`Error::Length`];
    /// - a key whose coefficients don't all lie below q gives
    ///   [`Error::Modulus`] (FIPS 203, section 7.2: ByteEncode12 of
    ///   ByteDecode12 must give the input back).
    ///
    /// So an accepted key's [`Self::to_bytes`] returns the input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let key = Array::try_from(bytes).map_err(|_| Error::Length)?;
        // The library makes the modulus check, and it is the only way
        // decoding can fail once the length is right.
        ml_kem::EncapsulationKey::new(&key)
            .map(Self)
            .map_err(|_| Error::Modulus)
    }

    /// The key's octets.
    pub fn to_bytes(&self) -> [u8; ENCAPSULATION_KEY_LEN] {
        to_array(self.0.to_bytes().as_slice())
    }

    /// Encapsulates a shared secret for this key, with the caller's 32
    /// random octets `m` (FIPS 203, Algorithm 17). `m` must be fresh from
    /// the entropy service for every call (ADR 0069, rule 3): the secret
    /// is derived from it.
    pub fn encapsulate(&self, m: &[u8; RANDOMNESS_LEN]) -> (MlKem768Ciphertext, SharedSecret) {
        let mut library_m = ml_kem::B32::from(*m);
        let (ct, key) = self.0.encapsulate_deterministic(&library_m);
        library_m.as_mut_slice().zeroize();
        (MlKem768Ciphertext(ct), shared_secret(key))
    }
}

impl core::fmt::Debug for MlKem768EncapsulationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MlKem768EncapsulationKey(1184 octets)")
    }
}

/// An ML-KEM-768 ciphertext.
#[derive(Clone, PartialEq, Eq)]
pub struct MlKem768Ciphertext(ml_kem::Ciphertext<MlKem768>);

impl MlKem768Ciphertext {
    /// Decodes a ciphertext. A length other than 1,088 gives
    /// [`Error::Length`]. Every 1,088 octets are a ciphertext: FIPS 203
    /// checks nothing more (section 7.3), and a ciphertext not made for
    /// the key is caught by implicit rejection.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Array::try_from(bytes).map(Self).map_err(|_| Error::Length)
    }

    /// The ciphertext's octets.
    pub fn to_bytes(&self) -> [u8; CIPHERTEXT_LEN] {
        to_array(self.0.as_slice())
    }
}

impl core::fmt::Debug for MlKem768Ciphertext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MlKem768Ciphertext(1088 octets)")
    }
}
