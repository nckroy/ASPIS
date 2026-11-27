// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Register offsets and bits of the GICv2 (Arm IHI 0048B) and the GICv3
//! (Arm IHI 0069), and of the generic timer, as the kernel uses them.
//! Offsets are in bytes from the start of their frame.

use crate::intid::{Intid, SPECIAL_FIRST};

/// The distributor (`GICD_*`), on both versions unless marked.
pub mod gicd {
    pub const CTLR: usize = 0x0000;
    pub const TYPER: usize = 0x0004;
    pub const IGROUPR: usize = 0x0080;
    pub const ISENABLER: usize = 0x0100;
    pub const ICENABLER: usize = 0x0180;
    pub const ISPENDR: usize = 0x0200;
    pub const ICPENDR: usize = 0x0280;
    pub const ISACTIVER: usize = 0x0300;
    pub const ICACTIVER: usize = 0x0380;
    pub const IPRIORITYR: usize = 0x0400;
    /// GICv2 only (on a GICv3 with affinity routing, `IROUTER` instead).
    pub const ITARGETSR: usize = 0x0800;
    pub const ICFGR: usize = 0x0c00;
    /// GICv2 only: sends an SGI.
    pub const SGIR: usize = 0x0f00;
    /// GICv2 only: clears SGIs pending from each source core, a byte per
    /// SGI, four registers.
    pub const CPENDSGIR: usize = 0x0f10;
    /// GICv3: routes SPI `n`, a 64-bit register at `IROUTER + 8 n`.
    pub const IROUTER: usize = 0x6000;
    /// GICv3.1: the extended SPIs' `ICENABLER<n>E`, `ICPENDR<n>E` and
    /// `ICACTIVER<n>E`, one bit per extended SPI from INTID 4096.
    pub const ICENABLER_E: usize = 0x1400;
    pub const ICPENDR_E: usize = 0x1800;
    pub const ICACTIVER_E: usize = 0x1c00;
    /// `GICD_PIDR2` on a GICv2. Its layout is implementation defined there,
    /// but Arm's GICs, and QEMU's, put the architecture revision in 7:4.
    pub const PIDR2_V2: usize = 0x0fe8;
    /// `GICD_PIDR2` on a GICv3.
    pub const PIDR2_V3: usize = 0xffe8;

    /// `GICD_CTLR` bit 0: on a GICv2, enables forwarding, of Group 0 where
    /// the view has groups or of Group 1 in the non-secure view. On a
    /// GICv3, `EnableGrp0` where `DS` is 1; in the non-secure view with two
    /// security states, `EnableGrp1` only without affinity routing, and RES0
    /// with it. Linux writes it on a GICv3 too, and never reads it back.
    pub const CTLR_ENABLE: u32 = 1 << 0;
    /// `GICD_CTLR` bit 1 on a GICv3: `EnableGrp1A` in the non-secure view,
    /// `EnableGrp1` where `DS` is 1.
    pub const CTLR_ENABLE_G1A: u32 = 1 << 1;
    /// `GICD_CTLR` bit 4 on a GICv3: `ARE_NS` in the non-secure view, `ARE`
    /// where `DS` is 1. Affinity routing.
    pub const CTLR_ARE_NS: u32 = 1 << 4;
    /// `GICD_CTLR` bit 31 on a GICv3: a write to `CTLR` or `ICENABLER` is
    /// still in progress.
    pub const CTLR_RWP: u32 = 1 << 31;
    /// `GICD_TYPER` bits 4:0: `ITLinesNumber`.
    pub const TYPER_IT_LINES: u32 = 0x1f;
    /// `GICD_TYPER` bits 7:5 on a GICv2: `CPUNumber`, the cores less one.
    pub const TYPER_CPU_NUMBER_SHIFT: u32 = 5;
    /// `GICD_TYPER` bit 10 on a GICv2: the Security Extensions.
    pub const TYPER_SECURITY_EXTN: u32 = 1 << 10;
    /// `GICD_TYPER` bit 8 on a GICv3.1: the extended SPI range exists.
    pub const TYPER_ESPI: u32 = 1 << 8;
    /// `GICD_TYPER` bits 31:27 on a GICv3.1: `ESPI_range`, the extended
    /// SPIs in 32s, less one.
    pub const TYPER_ESPI_RANGE_SHIFT: u32 = 27;
    /// `GICD_CTLR` bit 6 on a GICv3: `DS`, one security state. It reads 1
    /// on QEMU with `secure=off`.
    pub const CTLR_DS: u32 = 1 << 6;
    /// `GICD_SGIR` bits 25:24: `TargetListFilter`.
    pub const SGIR_FILTER_SHIFT: u32 = 24;
    /// `GICD_SGIR` bits 23:16: `CPUTargetList`.
    pub const SGIR_TARGETS_SHIFT: u32 = 16;
}

/// The GICv2 CPU interface (`GICC_*`).
pub mod gicc {
    pub const CTLR: usize = 0x0000;
    pub const PMR: usize = 0x0004;
    pub const BPR: usize = 0x0008;
    pub const IAR: usize = 0x000c;
    pub const EOIR: usize = 0x0010;
    pub const RPR: usize = 0x0014;
    pub const HPPIR: usize = 0x0018;
    /// `GICC_APR0` to `APR3`, the active priorities.
    pub const APR: usize = 0x00d0;
    /// `GICC_NSAPR0` to `NSAPR3`, the non-secure active priorities.
    pub const NSAPR: usize = 0x00e0;
    /// `GICC_CTLR` bit 0: enables signaling, of Group 0 where the view has
    /// groups, or of Group 1 in the non-secure view.
    pub const CTLR_ENABLE: u32 = 1 << 0;
    /// `GICC_IAR` bits 9:0: the interrupt ID.
    pub const IAR_INTID: u32 = 0x3ff;
    /// `GICC_IAR` bits 12:10: for an SGI, the core that sent it.
    pub const IAR_CPUID_SHIFT: u32 = 10;
}

/// The GICv3 redistributor (`GICR_*`). Each core's has two 64 KiB frames:
/// `RD_base`, then `SGI_base` at [`gicr::SGI_FRAME`]. A redistributor with
/// direct virtual LPIs (GICv4's `VLPIS`) has two more.
pub mod gicr {
    pub const CTLR: usize = 0x0000;
    /// 64 bits.
    pub const TYPER: usize = 0x0008;
    pub const WAKER: usize = 0x0014;
    pub const PIDR2: usize = 0xffe8;
    /// The second frame, `SGI_base`, from `RD_base`.
    pub const SGI_FRAME: usize = 0x1_0000;
    /// In `SGI_base`.
    pub const IGROUPR0: usize = 0x0080;
    pub const ISENABLER0: usize = 0x0100;
    pub const ICENABLER0: usize = 0x0180;
    pub const ISPENDR0: usize = 0x0200;
    pub const ICPENDR0: usize = 0x0280;
    pub const ISACTIVER0: usize = 0x0300;
    pub const ICACTIVER0: usize = 0x0380;
    pub const IPRIORITYR: usize = 0x0400;

    /// The bytes of a redistributor without `VLPIS`: two 64 KiB frames.
    pub const SIZE: u64 = 0x2_0000;
    /// The bytes of a redistributor with `VLPIS`: four 64 KiB frames.
    pub const SIZE_VLPIS: u64 = 0x4_0000;

    /// `GICR_CTLR` bit 0: LPIs are enabled at this redistributor.
    pub const CTLR_ENABLE_LPIS: u32 = 1 << 0;
    /// `GICR_CTLR` bit 3: a write to `ICENABLER0` is still in progress.
    pub const CTLR_RWP: u32 = 1 << 3;
    /// `GICR_TYPER` bits 31:27 on a GICv3.1: `PPInum`. 1 or 2 means 32 or
    /// 64 extended PPIs, from INTID 1056, whose bits follow the PPIs' in
    /// `SGI_base`'s `ICENABLER`, `ICPENDR` and `ICACTIVER` arrays.
    pub const TYPER_PPINUM_SHIFT: u32 = 27;
    /// `GICR_TYPER` bit 1: direct virtual LPIs, two more frames.
    pub const TYPER_VLPIS: u64 = 1 << 1;
    /// `GICR_TYPER` bit 4: the last redistributor in its region.
    pub const TYPER_LAST: u64 = 1 << 4;
    /// `GICR_WAKER` bit 1: the core is asleep, to the redistributor.
    pub const WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
    /// `GICR_WAKER` bit 2: the redistributor's interface is quiescent.
    pub const WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;
}

/// The GICv3 CPU interface's system registers (`ICC_*_EL1`).
pub mod icc {
    /// `ICC_SRE_EL1` bit 0: the system-register interface is in use.
    pub const SRE_SRE: u64 = 1 << 0;
    /// `ICC_CTLR_EL1` bit 1: `EOImode`; 0 makes `EOIR` both drop the
    /// priority and deactivate.
    pub const CTLR_EOIMODE: u64 = 1 << 1;
    /// `ICC_CTLR_EL1` bits 10:8: `PRIbits`, the priority bits less one.
    pub const CTLR_PRIBITS_SHIFT: u32 = 8;
    /// `ICC_CTLR_EL1` bit 18: `RSS`, SGIs can target Aff0 16 to 255.
    pub const CTLR_RSS: u64 = 1 << 18;
    /// `ICC_IAR1_EL1` bits 23:0: the interrupt ID.
    pub const IAR_INTID: u64 = 0xff_ffff;
    /// `ICC_IGRPEN1_EL1` bit 0: Group 1 is enabled.
    pub const IGRPEN1_ENABLE: u64 = 1 << 0;

    /// How many `ICC_AP1R<n>_EL1` registers exist, for an `ICC_CTLR_EL1`
    /// value: 1 for 5 priority bits or fewer, 2 for 6, 4 for 7 or 8, as
    /// Linux's `gic_cpu_sys_reg_init` clears them.
    pub const fn ap1r_count(ctlr: u64) -> usize {
        match ((ctlr >> CTLR_PRIBITS_SHIFT) & 7) + 1 {
            0..=5 => 1,
            6 => 2,
            _ => 4,
        }
    }
}

/// `ID_AA64PFR0_EL1` bits 27:24: the GIC system-register interface. Not 0
/// means the CPU implements it (a GICv3 or GICv4 CPU interface).
pub const fn cpu_has_gic_sysregs(id_aa64pfr0: u64) -> bool {
    (id_aa64pfr0 >> 24) & 0xf != 0
}

/// `ISR_EL1` bit 7: an IRQ is pending at this core, whether or not
/// `PSTATE.I` masks it.
pub const ISR_I: u64 = 1 << 7;

/// The `DAIF` register's `I` bit: IRQs are masked.
pub const DAIF_I: u64 = 1 << 7;
/// The `DAIF` register's `F` bit: FIQs are masked.
pub const DAIF_F: u64 = 1 << 6;

/// The number of interrupt lines a `GICD_TYPER` value gives, SGIs and PPIs
/// included: 32 × (`ITLinesNumber` + 1), at most 1020, since INTIDs 1020
/// to 1023 are special.
pub const fn lines(typer: u32) -> u32 {
    let n = 32 * ((typer & gicd::TYPER_IT_LINES) + 1);
    if n > SPECIAL_FIRST { SPECIAL_FIRST } else { n }
}

/// The architecture revision in a `PIDR2` value, bits 7:4: 1 or 2 for a
/// GICv1 or GICv2, 3 for a GICv3, 4 for a GICv4.
pub const fn arch_rev(pidr2: u32) -> u8 {
    ((pidr2 >> 4) & 0xf) as u8
}

/// The word offset and bit for `intid` in a register array with one bit per
/// interrupt, from the array's first register at `base`: `IGROUPR`,
/// `ISENABLER`, `ICENABLER`, `ISPENDR`, `ICPENDR`, `ISACTIVER` and
/// `ICACTIVER`.
pub const fn bit(base: usize, intid: Intid) -> (usize, u32) {
    (base + 4 * (intid.0 as usize / 32), 1 << (intid.0 % 32))
}

/// As [`bit`], for an interrupt the distributor has: `None` unless
/// `intid` is below `lines` ([`lines`]). An INTID beyond them, such as an
/// LPI or an extended SPI, would index past the array, into other
/// registers.
pub const fn line_bit(base: usize, intid: Intid, lines: u32) -> Option<(usize, u32)> {
    if intid.0 < lines {
        Some(bit(base, intid))
    } else {
        None
    }
}

/// The extended SPIs a GICv3 `GICD_TYPER` value gives: 0 without the
/// extended range, else 32 × (`ESPI_range` + 1), from INTID 4096.
pub const fn espi_lines(typer: u32) -> u32 {
    if typer & gicd::TYPER_ESPI == 0 {
        0
    } else {
        32 * ((typer >> gicd::TYPER_ESPI_RANGE_SHIFT) + 1)
    }
}

/// The 32-bit registers of extended PPIs a `GICR_TYPER` value gives, after
/// register 0 of each array: 1 or 2 with `PPInum` 1 or 2, else 0, as Linux's
/// `GICR_TYPER_NR_PPIS` reads it.
pub const fn eppi_words(typer: u64) -> usize {
    match (typer >> gicr::TYPER_PPINUM_SHIFT) & 0x1f {
        n @ (1 | 2) => n as usize,
        _ => 0,
    }
}

/// The word offset and shift for `intid` in a register array with one byte
/// per interrupt: `IPRIORITYR` and `ITARGETSR`.
pub const fn byte(base: usize, intid: Intid) -> (usize, u32) {
    (base + (intid.0 as usize & !3), 8 * (intid.0 % 4))
}

/// The word offset and shift for `intid`'s two bits in `GICD_ICFGR`; the
/// upper bit set means edge-triggered.
pub const fn icfgr(intid: Intid) -> (usize, u32) {
    (
        gicd::ICFGR + 4 * (intid.0 as usize / 16),
        2 * (intid.0 % 16),
    )
}

/// The offset of `GICD_IROUTER<n>` for SPI `intid`.
pub const fn irouter(intid: Intid) -> usize {
    gicd::IROUTER + 8 * intid.0 as usize
}

/// A byte value repeated in each of a word's four bytes.
pub const fn repeat_byte(b: u8) -> u32 {
    u32::from_ne_bytes([b; 4])
}

/// The EL1 virtual timer's control register (`CNTV_CTL_EL0`).
pub mod cntv_ctl {
    /// Bit 0: the timer is enabled.
    pub const ENABLE: u64 = 1 << 0;
    /// Bit 1: the timer's interrupt is masked.
    pub const IMASK: u64 = 1 << 1;
    /// Bit 2: the timer's condition is met (read-only).
    pub const ISTATUS: u64 = 1 << 2;
}

/// The EL1 timer control register (`CNTKCTL_EL1`): what EL0 may reach.
pub mod cntkctl {
    /// Bit 0: EL0 may read the physical count.
    pub const EL0PCTEN: u64 = 1 << 0;
    /// Bit 1: EL0 may read the virtual count.
    pub const EL0VCTEN: u64 = 1 << 1;
    /// Bit 2: the event stream is enabled.
    pub const EVNTEN: u64 = 1 << 2;
    /// Bit 8: EL0 may use the virtual timer.
    pub const EL0VTEN: u64 = 1 << 8;
    /// Bit 9: EL0 may use the physical timer.
    pub const EL0PTEN: u64 = 1 << 9;
    /// Every bit that gives EL0 a timer, a count or events.
    pub const EL0_ANY: u64 = EL0PCTEN | EL0VCTEN | EVNTEN | EL0VTEN | EL0PTEN;
}
