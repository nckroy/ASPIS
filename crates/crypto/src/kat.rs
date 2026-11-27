// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Known answers that need what the public API doesn't give (ADR 0069,
//! rule 7):
//!
//! - the standalone Ed25519 and ML-DSA-65 signing keys, which are
//!   crate-private, because only the composite signs (ADR 0020, rule 2);
//! - the libraries' expanded key forms, which NIST's ACVP vectors use for
//!   signing and decapsulation. ASPIS keys come only from seeds, so the
//!   public API never takes them. Both crates deprecate those forms, so
//!   the tests that use them allow it.
//!
//! The vector files and their reader are the integration tests' own, in
//! `tests/`.

#[path = "../tests/common/mod.rs"]
mod common;

/// Compiles only for types that clear themselves on drop.
#[cfg(any(feature = "ed25519", feature = "ml-dsa"))]
fn zod<T: zeroize::ZeroizeOnDrop>() {}

#[cfg(feature = "ed25519")]
mod ed25519 {
    use std::format;

    use super::common::{array, field, vectors};
    use super::zod;
    use crate::COMPOSITE_PREFIX;
    use crate::Error;
    use crate::ed25519::Ed25519SigningKey;

    const RFC8032: &str = include_str!("../tests/data/rfc8032.json");

    /// RFC 8032, section 7.1: the seed gives the public key, and signing
    /// gives the published signature, since Ed25519 is deterministic.
    #[test]
    fn rfc8032_sign() {
        let v = vectors(RFC8032);
        for t in v.get("tests").as_array() {
            let id = t.get("tcId").as_str();
            let key = Ed25519SigningKey::from_seed(&array(t, "secretKey"));
            let vk = key.verifying_key();
            assert_eq!(vk.to_bytes(), array::<32>(t, "publicKey"), "{id}");
            let msg = field(t, "message");
            let sig = key.sign(&msg);
            assert_eq!(sig.to_bytes(), array::<64>(t, "signature"), "{id}");
            assert_eq!(vk.verify(&msg, &sig), Ok(()), "{id}");
        }
    }

    /// A standalone verifier refuses a message that starts with the
    /// composite's prefix, even under a good signature (RFC 10073, section
    /// 9.4; ADR 0020, rule 2). The composite's own check still accepts it.
    /// A message that starts with less than the whole prefix is ordinary.
    #[test]
    fn composite_prefix_refused() {
        let key = Ed25519SigningKey::from_seed(&[3; 32]);
        let vk = key.verifying_key();
        let mut msg = COMPOSITE_PREFIX.to_vec();
        msg.extend_from_slice(b"COMPSIG-MLDSA65-Ed25519-SHA512");
        let sig = key.sign(&msg);
        assert_eq!(vk.verify(&msg, &sig), Err(Error::Verification));
        assert_eq!(vk.verify_any(&msg, &sig), Ok(()));

        let short = &COMPOSITE_PREFIX[..31];
        let sig = key.sign(short);
        assert_eq!(vk.verify(short, &sig), Ok(()));
    }

    #[test]
    fn signing_key_is_secret() {
        zod::<Ed25519SigningKey>();
        let printed = format!("{:?}", Ed25519SigningKey::from_seed(&[0x5A; 32]));
        assert_eq!(printed, "Ed25519SigningKey(..)");
    }
}

#[cfg(feature = "ml-dsa")]
mod ml_dsa {
    use std::{format, vec::Vec};

    use ml_dsa::{ExpandedSigningKey, KeyExport, MlDsa65};

    use super::common::{Value, array, field, vectors};
    use super::zod;
    use crate::Error;
    use crate::ml_dsa::{MAX_CONTEXT, MlDsa65SigningKey, sign_with};
    use crate::rng::OneShot;

    const KEYGEN: &str = include_str!("../tests/data/acvp/ml-dsa-65-keygen.json");
    const SIGGEN: &str = include_str!("../tests/data/acvp/ml-dsa-65-siggen.json");

    /// Every group, with its tests.
    fn groups(v: &Value) -> Vec<(Value, Vec<Value>)> {
        v.get("testGroups")
            .as_array()
            .iter()
            .map(|g| (g.clone(), g.get("tests").as_array().to_vec()))
            .collect()
    }

    /// FIPS 204, Algorithm 6 (ML-DSA.KeyGen_internal): ξ gives the
    /// verifying key, and the expanded signing key.
    #[test]
    #[allow(deprecated)]
    fn acvp_keygen() {
        let v = vectors(KEYGEN);
        let (_, tests) = &groups(&v)[0];
        assert_eq!(tests.len(), 5);
        for t in tests {
            let seed = array::<32>(t, "seed");
            let id = t.get("tcId").as_u64();
            let key = MlDsa65SigningKey::from_seed(&seed);
            assert_eq!(
                key.verifying_key().to_bytes().as_slice(),
                field(t, "pk").as_slice(),
                "tcId {id}"
            );
            let esk = ExpandedSigningKey::<MlDsa65>::from_seed((&seed).into());
            assert_eq!(
                esk.to_expanded().as_slice(),
                field(t, "sk").as_slice(),
                "tcId {id}"
            );
            assert_eq!(esk.verifying_key().to_bytes().as_slice(), field(t, "pk"));
        }
    }

    /// FIPS 204, Algorithm 2 (ML-DSA.Sign), from the vectors' expanded keys:
    /// group 3 is the deterministic variant, which is rnd = 32 zero octets,
    /// and group 15 is hedged with the vector's rnd. Both reproduce the
    /// published signatures through the one signing path.
    #[test]
    #[allow(deprecated)]
    fn acvp_siggen() {
        let v = vectors(SIGGEN);
        let mut n = 0;
        for (g, tests) in groups(&v) {
            let deterministic = g.get("deterministic").as_bool();
            for t in &tests {
                let sk = field(t, "sk");
                let esk =
                    ExpandedSigningKey::<MlDsa65>::from_expanded(sk.as_slice().try_into().unwrap());
                let rnd = if deterministic {
                    [0; 32]
                } else {
                    array(t, "rnd")
                };
                let sig =
                    sign_with(&esk, &field(t, "message"), &field(t, "context"), &rnd).unwrap();
                assert_eq!(
                    sig.to_bytes().as_slice(),
                    field(t, "signature").as_slice(),
                    "tcId {}",
                    t.get("tcId").as_u64()
                );
                n += 1;
            }
        }
        assert_eq!(n, 10);
    }

    /// Different hedges give different signatures, and both verify.
    #[test]
    fn hedged_round_trip() {
        let key = MlDsa65SigningKey::from_seed(&[1; 32]);
        let (msg, ctx) = (b"a message", b"a context");
        let a = key.sign(msg, ctx, &[2; 32]).unwrap();
        let b = key.sign(msg, ctx, &[3; 32]).unwrap();
        assert_ne!(a, b);
        let vk = key.verifying_key();
        assert_eq!(vk.verify(msg, ctx, &a), Ok(()));
        assert_eq!(vk.verify(msg, ctx, &b), Ok(()));
        // The same hedge gives the same signature.
        assert_eq!(key.sign(msg, ctx, &[2; 32]).unwrap(), a);
    }

    #[test]
    fn context_limit() {
        let key = MlDsa65SigningKey::from_seed(&[1; 32]);
        let long = [7; MAX_CONTEXT + 1];
        let sig = key.sign(b"m", &long[..MAX_CONTEXT], &[0; 32]).unwrap();
        assert_eq!(
            key.verifying_key().verify(b"m", &long[..MAX_CONTEXT], &sig),
            Ok(())
        );
        assert_eq!(key.sign(b"m", &long, &[0; 32]), Err(Error::ContextTooLong));
    }

    /// The hedge adapter gives the caller's 32 octets once, and refuses any
    /// other request.
    #[test]
    fn one_shot() {
        use ml_dsa::signature::rand_core::TryRng;
        let mut r = OneShot::new(&[9; 32]);
        assert!(r.try_next_u32().is_err());
        assert!(r.try_next_u64().is_err());
        assert!(r.try_fill_bytes(&mut [0; 16]).is_err());
        let mut out = [0; 32];
        assert!(r.try_fill_bytes(&mut out).is_ok());
        assert_eq!(out, [9; 32]);
        assert!(r.try_fill_bytes(&mut out).is_err());
    }

    #[test]
    fn signing_key_is_secret() {
        zod::<MlDsa65SigningKey>();
        let printed = format!("{:?}", MlDsa65SigningKey::from_seed(&[0x5A; 32]));
        assert_eq!(printed, "MlDsa65SigningKey(..)");
    }
}

#[cfg(feature = "ml-kem")]
mod ml_kem {
    use std::vec::Vec;

    #[allow(deprecated)]
    use ml_kem::{DecapsulationKey, ExpandedKeyEncoding, MlKem768};

    use super::common::{Value, array, field, vectors};
    use crate::ml_kem::{MlKem768Ciphertext, decapsulate_with};

    const KEYGEN: &str = include_str!("../tests/data/acvp/ml-kem-768-keygen.json");
    const ENCAP_DECAP: &str = include_str!("../tests/data/acvp/ml-kem-768-encapdecap.json");

    /// The tests of the groups whose `function` is `function`, or of every
    /// group if it is `None`.
    fn tests(v: &Value, function: Option<&str>) -> Vec<Value> {
        v.get("testGroups")
            .as_array()
            .iter()
            .filter(|g| function.is_none_or(|f| g.get("function").as_str() == f))
            .flat_map(|g| g.get("tests").as_array().to_vec())
            .collect()
    }

    /// FIPS 203, Algorithm 16 (ML-KEM.KeyGen_internal): d ‖ z gives the
    /// vector's expanded decapsulation key.
    #[test]
    #[allow(deprecated)]
    fn acvp_keygen_expanded() {
        let v = vectors(KEYGEN);
        for t in tests(&v, None) {
            let mut seed = field(&t, "d");
            seed.extend(field(&t, "z"));
            let dk = DecapsulationKey::<MlKem768>::from_seed(seed.as_slice().try_into().unwrap());
            assert_eq!(
                dk.to_expanded_bytes().as_slice(),
                field(&t, "dk").as_slice(),
                "tcId {}",
                t.get("tcId").as_u64()
            );
        }
    }

    /// FIPS 203, Algorithm 18 (ML-KEM.Decaps_internal), from the vectors'
    /// expanded keys, including the modified ciphertexts that implicit
    /// rejection answers with J(z ‖ c).
    #[test]
    #[allow(deprecated)]
    fn acvp_decapsulation() {
        let v = vectors(ENCAP_DECAP);
        let tests = tests(&v, Some("decapsulation"));
        assert_eq!(tests.len(), 10);
        let mut modified = 0;
        for t in &tests {
            let dk = DecapsulationKey::<MlKem768>::from_expanded_bytes(
                field(t, "dk").as_slice().try_into().unwrap(),
            )
            .unwrap();
            let ct = MlKem768Ciphertext::from_bytes(&field(t, "c")).unwrap();
            assert_eq!(
                decapsulate_with(&dk, &ct).as_bytes(),
                &array::<32>(t, "k"),
                "tcId {}",
                t.get("tcId").as_u64()
            );
            modified += usize::from(t.get("reason").as_str() == "modified ciphertext");
        }
        assert_eq!(modified, 5);
    }
}

#[cfg(feature = "composite")]
mod composite {
    use super::common::{field, vectors};
    use crate::composite::{LABEL, MAX_CONTEXT, PREFIX, prehash, representative};
    use crate::{COMPOSITE_PREFIX, Error};

    const RFC10073: &str = include_str!("../tests/data/rfc10073.json");

    /// RFC 10073, Appendix D: M′ = Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖
    /// PH(M). The appendix's examples are for another composite, so its M′
    /// with that label taken out is ours with our label taken out.
    #[test]
    fn rfc10073_appendix_d_representative() {
        let v = vectors(RFC10073);
        for t in v.get("appendixD").get("tests").as_array() {
            let m = field(t, "message");
            let ctx = field(t, "context");
            let their = field(t, "messageRepresentative");
            let their_label = t.get("label").as_str().as_bytes();
            let ours = representative(&prehash(&m), &ctx).unwrap();
            let ours = ours.as_bytes();
            assert_eq!(&ours[..32], &their[..32]);
            assert_eq!(&ours[32..32 + LABEL.len()], LABEL);
            assert_eq!(&ours[32 + LABEL.len()..], &their[32 + their_label.len()..]);
        }
        assert_eq!(PREFIX, COMPOSITE_PREFIX);
    }

    /// The longest context fills the buffer exactly; a longer one is
    /// refused.
    #[test]
    fn representative_bounds() {
        let ph = [0x11; 64];
        let ctx = [0x22; MAX_CONTEXT + 1];
        let m = representative(&ph, &ctx[..MAX_CONTEXT]).unwrap();
        assert_eq!(m.as_bytes().len(), 32 + 30 + 1 + 255 + 64);
        assert_eq!(m.as_bytes()[62], 255);
        assert!(representative(&ph, &ctx).is_err_and(|e| e == Error::ContextTooLong));
        assert_eq!(
            representative(&ph, b"").unwrap().as_bytes().len(),
            32 + 30 + 1 + 64
        );
    }
}
