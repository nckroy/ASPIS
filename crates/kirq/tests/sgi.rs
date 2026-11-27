// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The kernel's SGIs and their encodings (K26).

use kirq::affinity::Affinity;
use kirq::intid::Intid;
use kirq::sgi::{Sgi, SgiError, V2Target, V3Target, gicd_sgir, icc_sgi1r, v2_cpu_mask};

#[test]
fn the_kernels_sgis_are_0_1_and_2() {
    assert_eq!(Sgi::RemoteCall as u8, 0);
    assert_eq!(Sgi::Reschedule as u8, 1);
    assert_eq!(Sgi::Stop as u8, 2);
    for s in Sgi::ALL {
        // Arm recommends 0 to 7 for the non-secure world.
        assert!((s as u8) < 8);
        assert_eq!(Sgi::from_intid(s.intid()), Some(s));
        assert_ne!(Sgi::ENABLED_MASK & 1 << s as u32, 0);
    }
    assert_eq!(Sgi::ENABLED_MASK.count_ones() as usize, Sgi::ALL.len());
    for n in 3..16 {
        assert_eq!(Sgi::from_intid(Intid(n)), None);
    }
}

#[test]
fn gicd_sgir_encodes_each_filter() {
    for s in Sgi::ALL {
        let n = s as u32;
        assert_eq!(gicd_sgir(s, V2Target::List(0b0100)), Ok(0x0004_0000 | n));
        assert_eq!(gicd_sgir(s, V2Target::List(0x81)), Ok(0x0081_0000 | n));
        assert_eq!(gicd_sgir(s, V2Target::AllButSelf), Ok(0x0100_0000 | n));
        assert_eq!(gicd_sgir(s, V2Target::SelfOnly), Ok(0x0200_0000 | n));
    }
    assert_eq!(
        gicd_sgir(Sgi::Stop, V2Target::List(0)),
        Err(SgiError::EmptyList)
    );
}

fn aff(aff3: u8, aff2: u8, aff1: u8, aff0: u8) -> Affinity {
    Affinity {
        aff3,
        aff2,
        aff1,
        aff0,
    }
}

#[test]
fn icc_sgi1r_places_each_field() {
    let core = |a| V3Target::Core(a);
    assert_eq!(
        icc_sgi1r(Sgi::RemoteCall, core(aff(0, 0, 0, 0)), false),
        Ok(1)
    );
    assert_eq!(
        icc_sgi1r(Sgi::Reschedule, core(aff(0, 0, 0, 15)), false),
        Ok(1 << 24 | 1 << 15)
    );
    // Aff0 16 is range 1, bit 0, and needs RSS.
    assert_eq!(
        icc_sgi1r(Sgi::Stop, core(aff(0, 0, 0, 16)), true),
        Ok(1 << 44 | 2 << 24 | 1)
    );
    assert_eq!(
        icc_sgi1r(Sgi::Stop, core(aff(0, 0, 0, 16)), false),
        Err(SgiError::NeedsRss)
    );
    assert_eq!(
        icc_sgi1r(Sgi::Stop, core(aff(0, 0, 0, 255)), true),
        Ok(15 << 44 | 2 << 24 | 1 << 15)
    );
    assert_eq!(
        icc_sgi1r(Sgi::Reschedule, core(aff(0xaa, 0xbb, 0xcc, 3)), false),
        Ok(0xaa << 48 | 0xbb << 32 | 1 << 24 | 0xcc << 16 | 1 << 3)
    );
    assert_eq!(
        icc_sgi1r(Sgi::Stop, V3Target::AllButSelf, false),
        Ok(1 << 40 | 2 << 24)
    );
}

#[test]
fn v2_cpu_masks() {
    assert_eq!(v2_cpu_mask(0), Ok(None));
    assert_eq!(v2_cpu_mask(0x0101_0101), Ok(Some(1)));
    assert_eq!(v2_cpu_mask(0x8080_8080), Ok(Some(0x80)));
    // Only SGI 0's byte counts.
    assert_eq!(v2_cpu_mask(0xff00_0004), Ok(Some(4)));
    assert_eq!(v2_cpu_mask(0x0000_0003), Err(SgiError::BadMask));
}
