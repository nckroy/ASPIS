// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The classification of an acknowledged interrupt, and the register
//! helpers the drivers index by INTID.

use kirq::dispatch::{Action, classify};
use kirq::intid::Intid;
use kirq::regs::{self, gicd, icc};

/// QEMU virt's distributor: 256 SPIs.
const LINES: u32 = 288;

#[test]
fn special_intids_are_spurious() {
    for n in 1020..1024 {
        assert_eq!(classify(Intid(n), Some(Intid(27)), LINES), Action::Spurious);
        assert!(Intid(n).is_special());
    }
}

#[test]
fn the_kernels_interrupts() {
    let timer = Some(Intid(27));
    assert_eq!(classify(Intid(0), timer, LINES), Action::RemoteCall);
    assert_eq!(classify(Intid(1), timer, LINES), Action::Reschedule);
    assert_eq!(classify(Intid(2), timer, LINES), Action::Stop);
    assert_eq!(classify(Intid(27), timer, LINES), Action::Timer);
    // Without an armed timer, its PPI is anyone's.
    assert_eq!(
        classify(Intid(27), None, LINES),
        Action::Unclaimed(Intid(27))
    );
}

#[test]
fn everything_else_is_unclaimed() {
    let timer = Some(Intid(27));
    for n in (3..16).chain(16..27).chain(28..32).chain([32, 100, 287]) {
        assert_eq!(
            classify(Intid(n), timer, LINES),
            Action::Unclaimed(Intid(n))
        );
    }
    // The largest distributor reaches SPI 1019.
    assert_eq!(
        classify(Intid(1019), timer, 1020),
        Action::Unclaimed(Intid(1019))
    );
}

#[test]
fn intids_beyond_the_lines_are_extended() {
    // SPIs the distributor doesn't have, an extended PPI, extended SPIs and
    // LPIs: no enable register is indexed for them.
    let timer = Some(Intid(27));
    for n in [288, 1019, 1056, 1119, 4096, 4200, 5119, 8192, 0xff_ffff] {
        assert_eq!(classify(Intid(n), timer, LINES), Action::Extended(Intid(n)));
    }
    // Special INTIDs stay spurious, whatever the lines.
    assert_eq!(classify(Intid(1023), timer, 32), Action::Spurious);
}

#[test]
fn line_bits_stop_at_the_lines() {
    assert_eq!(
        regs::line_bit(gicd::ICENABLER, Intid(287), LINES),
        Some((0x180 + 4 * 8, 1 << 31))
    );
    assert_eq!(
        regs::line_bit(gicd::ICENABLER, Intid(0), 32),
        Some((0x180, 1))
    );
    // An LPI would write 0x580, inside IPRIORITYR; an extended SPI 0x38c,
    // inside ICACTIVER.
    for n in [288, 1019, 1056, 4200, 8192] {
        assert_eq!(regs::line_bit(gicd::ICENABLER, Intid(n), LINES), None);
    }
}

#[test]
fn extended_ranges() {
    assert_eq!(regs::espi_lines(0), 0);
    // ESPI_range is ignored without the ESPI bit.
    assert_eq!(regs::espi_lines(31 << 27), 0);
    assert_eq!(regs::espi_lines(gicd::TYPER_ESPI), 32);
    assert_eq!(regs::espi_lines(gicd::TYPER_ESPI | 31 << 27), 1024);
    assert_eq!(regs::eppi_words(0), 0);
    assert_eq!(regs::eppi_words(1 << 27), 1);
    assert_eq!(regs::eppi_words(2 << 27), 2);
    // Other values are reserved: no extended PPIs.
    assert_eq!(regs::eppi_words(3 << 27), 0);
    // The other GICR_TYPER fields don't count.
    assert_eq!(regs::eppi_words(0xffff_ffff_0000_0000 | 0x7ff_ffff), 0);
}

#[test]
fn intid_ranges() {
    assert!(Intid(15).is_sgi() && Intid(15).is_private() && !Intid(15).is_ppi());
    assert!(Intid(16).is_ppi() && Intid(31).is_ppi() && Intid(31).is_private());
    assert!(Intid(32).is_spi() && Intid(1019).is_spi() && !Intid(1020).is_spi());
    assert!(Intid(8192).is_lpi() && !Intid(8191).is_lpi());
    assert_eq!(Intid::ppi(11), Some(Intid(27)));
    assert_eq!(Intid::ppi(16), None);
    assert_eq!(Intid::spi(0), Some(Intid(32)));
    assert_eq!(Intid::spi(988), None);
}

#[test]
fn register_indexing() {
    assert_eq!(regs::bit(gicd::ISENABLER, Intid(0)), (0x100, 1));
    assert_eq!(regs::bit(gicd::ISENABLER, Intid(33)), (0x104, 2));
    assert_eq!(
        regs::bit(gicd::ICPENDR, Intid(287)),
        (0x280 + 4 * 8, 1 << 31)
    );
    assert_eq!(regs::byte(gicd::IPRIORITYR, Intid(27)), (0x418, 24));
    assert_eq!(regs::byte(gicd::ITARGETSR, Intid(32)), (0x820, 0));
    assert_eq!(regs::icfgr(Intid(33)), (0xc08, 2));
    assert_eq!(regs::irouter(Intid(32)), 0x6100);
    assert_eq!(regs::repeat_byte(0xa0), 0xa0a0_a0a0);
}

#[test]
fn typer_lines_and_revisions() {
    // QEMU virt: 256 SPIs, ITLinesNumber 8.
    assert_eq!(regs::lines(8), 288);
    assert_eq!(regs::lines(0), 32);
    // The largest ITLinesNumber would reach the special INTIDs.
    assert_eq!(regs::lines(31), 1020);
    assert_eq!(regs::lines(0xffff_ffe8), 288);
    assert_eq!(regs::arch_rev(0x2b), 2);
    assert_eq!(regs::arch_rev(0x3b), 3);
    assert_eq!(regs::arch_rev(0x4b), 4);
    assert!(regs::cpu_has_gic_sysregs(1 << 24));
    assert!(!regs::cpu_has_gic_sysregs(0xf0ff_ffff));
}

#[test]
fn active_priority_register_counts() {
    // ICC_CTLR_EL1.PRIbits is the priority bits less one.
    let ctlr = |bits: u64| (bits - 1) << icc::CTLR_PRIBITS_SHIFT;
    assert_eq!(icc::ap1r_count(ctlr(4)), 1);
    assert_eq!(icc::ap1r_count(ctlr(5)), 1);
    assert_eq!(icc::ap1r_count(ctlr(6)), 2);
    assert_eq!(icc::ap1r_count(ctlr(7)), 4);
    assert_eq!(icc::ap1r_count(ctlr(8)), 4);
}
