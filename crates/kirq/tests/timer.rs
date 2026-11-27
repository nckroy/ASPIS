// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The virtual timer's interrupt from the device tree, its control bits,
//! and the compare value that arms nothing.

use kirq::dt::DtError;
use kirq::intid::Intid;
use kirq::regs::cntv_ctl::{ENABLE, IMASK, ISTATUS};
use kirq::timer::{CVAL_DISARMED, TimerError, VIRTUAL_INDEX, asserts, virtual_intid};

fn cells(v: &[u32]) -> Vec<u8> {
    v.iter().flat_map(|c| c.to_be_bytes()).collect()
}

/// A timer node's four entries, each with `flags`.
fn timer_node(ppis: [u32; 4], flags: u32) -> Vec<u8> {
    cells(&ppis.iter().flat_map(|&n| [1, n, flags]).collect::<Vec<_>>())
}

#[test]
fn the_virtual_timer_is_entry_2() {
    assert_eq!(VIRTUAL_INDEX, 2);
    // QEMU virt's GICv2 and GICv3 forms, and the Pi 4's level-low form.
    for flags in [0xf04, 0x04, 0xf08] {
        let prop = timer_node([13, 14, 11, 10], flags);
        assert_eq!(virtual_intid(&prop, 3), Ok(Intid(27)));
    }
    // Another PPI, if a board wires it so.
    assert_eq!(
        virtual_intid(&timer_node([13, 14, 12, 10], 4), 3),
        Ok(Intid(28))
    );
}

#[test]
fn a_timer_node_the_kernel_cant_use() {
    // Only the secure and non-secure physical timers.
    assert_eq!(
        virtual_intid(&cells(&[1, 13, 4, 1, 14, 4]), 3),
        Err(TimerError::Dt(DtError::Short))
    );
    // An SPI where the virtual timer should be.
    assert_eq!(
        virtual_intid(&cells(&[1, 13, 4, 1, 14, 4, 0, 5, 4, 1, 10, 4]), 3),
        Err(TimerError::NotPpi(Intid(37)))
    );
    // A parent that isn't a three-cell GIC.
    assert_eq!(
        virtual_intid(&timer_node([13, 14, 11, 10], 4), 2),
        Err(TimerError::Dt(DtError::Cells))
    );
    // A bad type cell.
    assert_eq!(
        virtual_intid(&cells(&[1, 13, 4, 1, 14, 4, 2, 11, 4]), 3),
        Err(TimerError::Dt(DtError::Type(2)))
    );
    // A PPI number beyond 15.
    assert_eq!(
        virtual_intid(&cells(&[1, 13, 4, 1, 14, 4, 1, 16, 4]), 3),
        Err(TimerError::Dt(DtError::Number(16)))
    );
}

#[test]
fn the_timer_asserts_only_when_enabled_unmasked_and_met() {
    assert!(asserts(ENABLE | ISTATUS));
    assert!(!asserts(ENABLE));
    assert!(!asserts(ISTATUS));
    assert!(!asserts(ENABLE | IMASK | ISTATUS));
    assert!(!asserts(0));
    // Bits above the three are ignored.
    assert!(asserts(ENABLE | ISTATUS | 1 << 8));
}

#[test]
fn the_disarmed_compare_value_is_never_reached() {
    assert_eq!(CVAL_DISARMED, u64::MAX);
    // At 1 GHz, QEMU max's frequency, the count reaches it after more than
    // 500 years; the Pi 4's 54 MHz takes far longer.
    let years = CVAL_DISARMED / 1_000_000_000 / (365 * 24 * 3600);
    assert!(years > 500);
}
