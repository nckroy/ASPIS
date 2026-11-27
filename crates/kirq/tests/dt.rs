// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Decoding GIC specifiers, cpu `reg` and `status`.

use kirq::affinity::{Affinity, MPIDR_AFFINITY_MASK};
use kirq::dt::{
    DtError, Specifier, be_u32, be_u32_or_u64, cpu_affinity, gic_specifier, is_enabled,
};
use kirq::intid::Intid;

fn cells(v: &[u32]) -> Vec<u8> {
    v.iter().flat_map(|c| c.to_be_bytes()).collect()
}

#[test]
fn qemu_timer_entry_2_is_intid_27() {
    // QEMU virt's timer node: secure, non-secure, virtual and hypervisor
    // physical timers, with the GICv2 form of the flags and the GICv3 one.
    for flags in [0xf04, 0x04] {
        let prop = cells(&[1, 13, flags, 1, 14, flags, 1, 11, flags, 1, 10, flags]);
        assert_eq!(
            gic_specifier(&prop, 3, 2),
            Ok(Specifier {
                intid: Intid(27),
                flags
            })
        );
        assert_eq!(gic_specifier(&prop, 3, 0).unwrap().intid, Intid(29));
        assert_eq!(gic_specifier(&prop, 3, 4), Err(DtError::Short));
    }
}

#[test]
fn spis_and_bad_specifiers() {
    assert_eq!(
        gic_specifier(&cells(&[0, 1, 4]), 3, 0).unwrap().intid,
        Intid(33)
    );
    assert_eq!(
        gic_specifier(&cells(&[0, 987, 4]), 3, 0).unwrap().intid,
        Intid(1019)
    );
    assert_eq!(
        gic_specifier(&cells(&[0, 988, 4]), 3, 0),
        Err(DtError::Number(988))
    );
    assert_eq!(
        gic_specifier(&cells(&[1, 16, 4]), 3, 0),
        Err(DtError::Number(16))
    );
    assert_eq!(
        gic_specifier(&cells(&[2, 1, 4]), 3, 0),
        Err(DtError::Type(2))
    );
    assert_eq!(gic_specifier(&cells(&[1, 11]), 3, 0), Err(DtError::Short));
    assert_eq!(
        gic_specifier(&cells(&[1, 11, 4]), 2, 0),
        Err(DtError::Cells)
    );
    assert_eq!(gic_specifier(&[0, 0, 0, 1, 0], 3, 0), Err(DtError::Short));
}

#[test]
fn cpu_reg_with_one_and_two_cells() {
    assert_eq!(
        cpu_affinity(&cells(&[0x0003]), 1),
        Some(Affinity {
            aff0: 3,
            ..Affinity::default()
        })
    );
    assert_eq!(
        cpu_affinity(&cells(&[0x0001_0203]), 1),
        Some(Affinity {
            aff3: 0,
            aff2: 1,
            aff1: 2,
            aff0: 3
        })
    );
    assert_eq!(
        cpu_affinity(&cells(&[0x7f, 0x0001_0203]), 2),
        Some(Affinity {
            aff3: 0x7f,
            aff2: 1,
            aff1: 2,
            aff0: 3
        })
    );
    // Bits that aren't affinity, a short property, or three cells.
    assert_eq!(cpu_affinity(&cells(&[0x0100_0000]), 1), None);
    assert_eq!(cpu_affinity(&cells(&[0x100, 0]), 2), None);
    assert_eq!(cpu_affinity(&cells(&[0]), 2), None);
    assert_eq!(cpu_affinity(&cells(&[0, 0, 0]), 3), None);
}

#[test]
fn the_mpidr_mask_drops_mt_u_and_res1() {
    let mpidr = 0x8000_0000 | 1 << 30 | 1 << 24 | 0x12_0003_0405;
    assert_eq!(mpidr & MPIDR_AFFINITY_MASK, 0x12_0003_0405);
    let a = Affinity::from_mpidr(mpidr);
    assert_eq!(
        a,
        Affinity {
            aff3: 0x12,
            aff2: 3,
            aff1: 4,
            aff0: 5
        }
    );
    assert_eq!(a.mpidr(), 0x12_0003_0405);
    assert_eq!(a.irouter(), 0x12_0003_0405);
    assert_eq!(Affinity::from_packed(a.packed()), a);
    assert_eq!(a.packed(), 0x1203_0405);
}

#[test]
fn status_and_cells() {
    assert!(is_enabled(None));
    assert!(is_enabled(Some(b"okay\0")));
    assert!(is_enabled(Some(b"ok")));
    assert!(!is_enabled(Some(b"disabled\0")));
    assert!(!is_enabled(Some(b"fail\0")));
    assert_eq!(be_u32(&[0, 0, 1, 0]), Some(256));
    assert_eq!(be_u32(&[0, 1]), None);
    assert_eq!(be_u32_or_u64(&[0, 0, 0, 0, 0, 2, 0, 0]), Some(0x2_0000));
    assert_eq!(be_u32_or_u64(&[0, 2, 0, 0]), Some(0x2_0000));
    assert_eq!(be_u32_or_u64(&[0; 6]), None);
}
