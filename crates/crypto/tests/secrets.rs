// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The secret types' guarantees that can be checked from outside (ADR 0069,
//! rule 5): each clears itself on drop, those with equality compare in
//! constant time, and none prints its octets. That none is `Clone` or
//! `Copy` is checked by review of their definitions. The crate-private
//! signing keys are checked in `src/kat.rs`.

use aspis_crypto::SharedSecret;
use aspis_crypto::aead::{Aes128GcmKey, Aes256GcmKey, ChaCha20Poly1305Key};
use aspis_crypto::composite::CompositeSigningKey;
use aspis_crypto::mac::{HmacSha256, HmacSha384, HmacSha512, Prk256, Prk384};
use aspis_crypto::ml_kem::MlKem768DecapsulationKey;
use aspis_crypto::quic::{
    Aes128HeaderProtectionKey, Aes256HeaderProtectionKey, ChaCha20HeaderProtectionKey,
};
use aspis_crypto::x25519::X25519SecretKey;
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

/// Compiles only for types that clear themselves on drop.
fn zod<T: ZeroizeOnDrop>() {}
/// Compiles only for types with constant-time equality.
fn ct<T: ConstantTimeEq + Eq>() {}

/// Every secret type clears itself on drop. The shared secret, the
/// pseudorandom keys, and the ML-KEM-768 decapsulation key and composite
/// signing key (through their seeds) have constant-time equality, and
/// `==` goes through it. The AEAD keys, the header-protection keys, the
/// HMAC states and the X25519 secret key have no equality at all: nothing
/// needs to compare them.
#[test]
fn secret_types() {
    zod::<SharedSecret>();
    zod::<Prk256>();
    zod::<Prk384>();
    zod::<ChaCha20Poly1305Key>();
    zod::<Aes256GcmKey>();
    zod::<Aes128GcmKey>();
    zod::<Aes128HeaderProtectionKey>();
    zod::<Aes256HeaderProtectionKey>();
    zod::<ChaCha20HeaderProtectionKey>();
    zod::<HmacSha256>();
    zod::<HmacSha384>();
    zod::<HmacSha512>();
    zod::<X25519SecretKey>();
    zod::<MlKem768DecapsulationKey>();
    zod::<CompositeSigningKey>();

    ct::<SharedSecret>();
    ct::<Prk256>();
    ct::<Prk384>();
    ct::<MlKem768DecapsulationKey>();
    ct::<CompositeSigningKey>();
}

#[test]
fn debug_redacts() {
    let bytes = [0x5Au8; 48];
    let hex: String = bytes[..8].iter().map(|b| format!("{b:02x}")).collect();
    let printed = [
        format!("{:?}", SharedSecret::from_bytes(&[0x5A; 32])),
        format!("{:?}", Prk256::from_bytes(&[0x5A; 32])),
        format!("{:?}", Prk384::from_bytes(&bytes)),
        format!("{:?}", ChaCha20Poly1305Key::from_bytes(&[0x5A; 32])),
        format!("{:?}", Aes256GcmKey::from_bytes(&[0x5A; 32])),
        format!("{:?}", Aes128GcmKey::from_bytes(&[0x5A; 16])),
        format!("{:?}", Aes128HeaderProtectionKey::from_bytes(&[0x5A; 16])),
        format!("{:?}", Aes256HeaderProtectionKey::from_bytes(&[0x5A; 32])),
        format!("{:?}", ChaCha20HeaderProtectionKey::from_bytes(&[0x5A; 32])),
        format!("{:?}", HmacSha256::new(&bytes)),
        format!("{:?}", HmacSha384::new(&bytes)),
        format!("{:?}", HmacSha512::new(&bytes)),
        format!("{:?}", X25519SecretKey::from_seed(&[0x5A; 32])),
        format!("{:?}", MlKem768DecapsulationKey::from_seed(&[0x5A; 64])),
        format!("{:?}", CompositeSigningKey::from_bytes(&[0x5A; 64])),
    ];
    for p in &printed {
        assert!(!p.contains(&hex), "{p}");
        assert!(!p.contains("90, 90"), "{p}");
        assert!(!p.contains("0x5a") && !p.contains("0x5A"), "{p}");
        assert!(p.contains(".."), "{p}");
    }
}

#[test]
fn shared_secret_eq() {
    let a = SharedSecret::from_bytes(&[1; 32]);
    let b = SharedSecret::from_bytes(&[1; 32]);
    let mut other = [1; 32];
    other[31] = 2;
    let c = SharedSecret::from_bytes(&other);
    assert!(bool::from(a.ct_eq(&b)));
    assert!(!bool::from(a.ct_eq(&c)));
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_eq!(a.as_bytes(), &[1; 32]);

    let p = Prk384::from_bytes(&[3; 48]);
    let mut q = [3; 48];
    q[0] = 4;
    assert_eq!(p, Prk384::from_bytes(&[3; 48]));
    assert_ne!(p, Prk384::from_bytes(&q));
}

#[test]
fn decapsulation_key_eq() {
    let a = MlKem768DecapsulationKey::from_seed(&[1; 64]);
    let mut other = [1; 64];
    other[63] = 2;
    assert_eq!(a, MlKem768DecapsulationKey::from_seed(&[1; 64]));
    assert_ne!(a, MlKem768DecapsulationKey::from_seed(&other));
    assert!(bool::from(
        a.ct_eq(&MlKem768DecapsulationKey::from_seed(&[1; 64]))
    ));
}
