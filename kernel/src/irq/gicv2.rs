// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The GICv2 back end: the Pi 4's GIC-400, and QEMU's `gic-version=2`
//! (ADR 0007, rule 1; kernel specification, "The kernel's interrupt
//! controller"). The register choices follow Linux's `irq-gic.c`.
//!
//! The kernel enables the distributor and the CPU interface through bit 0
//! of their `CTLR`, in whatever view it has. With the Security Extensions,
//! as on the Pi 4, the kernel has the non-secure view: `IGROUPR` is RAZ/WI,
//! the firmware must have made the kernel's interrupts Group 1, and bit 0
//! enables Group 1. Without them, as on QEMU with `secure=off`, the kernel
//! writes `IGROUPR` itself, making every interrupt Group 0, and bit 0
//! enables Group 0, which is signaled as IRQ because `FIQEn` stays clear.

use super::arch::Mmio;
use super::{Cores, SendError, Target};
use core::sync::atomic::{AtomicU8, Ordering};
use kirq::intid::{Intid, SPI_BASE};
use kirq::regs::{self, gicc, gicd};
use kirq::sgi::{Sgi, V2Target, gicd_sgir, v2_cpu_mask};
use kirq::{MAX_CORES, PRIORITY, PRIORITY_MASK};

pub struct GicV2 {
    dist: Mmio,
    cpu: Mmio,
    lines: u32,
    /// Whether the GIC lacks the Security Extensions, so the kernel sets
    /// the groups itself.
    own_groups: bool,
    /// Each core's CPU-interface mask, recorded by its `init_cpu`; 0 until
    /// then, and 0 on a uniprocessor GIC, which has no masks.
    masks: [AtomicU8; MAX_CORES],
}

impl GicV2 {
    pub fn new(dist: Mmio, cpu: Mmio) -> GicV2 {
        let typer = dist.read32(gicd::TYPER);
        GicV2 {
            dist,
            cpu,
            lines: regs::lines(typer),
            own_groups: typer & gicd::TYPER_SECURITY_EXTN == 0,
            masks: [const { AtomicU8::new(0) }; MAX_CORES],
        }
    }

    pub fn lines(&self) -> u32 {
        self.lines
    }

    pub fn dist(&self) -> Mmio {
        self.dist
    }

    #[cfg_attr(not(aspis_test_build), allow(dead_code))]
    pub fn cpu(&self) -> Mmio {
        self.cpu
    }

    /// The architecture revision in `GICD_PIDR2`, whose layout is
    /// implementation defined on a GICv2: 2 on Arm's GIC-400 and on QEMU's.
    pub fn arch_rev(&self) -> u8 {
        regs::arch_rev(self.dist.read32(gicd::PIDR2_V2))
    }

    /// This core's CPU-interface mask, from `GICD_ITARGETSR0`, which is
    /// banked: `None` on a uniprocessor GIC.
    fn own_mask(&self) -> Option<u8> {
        match v2_cpu_mask(self.dist.read32(gicd::ITARGETSR)) {
            Ok(m) => m,
            Err(_) => panic!("the GICv2's ITARGETSR0 names more than one CPU interface"),
        }
    }

    /// Sets up the distributor, from the boot core: every SPI disabled,
    /// not pending, not active, at the kernel's priority, level-triggered
    /// and routed to the boot core, and Group 0 if the kernel sets groups.
    pub fn init_dist(&self) {
        let d = self.dist;
        d.write32(gicd::CTLR, 0);
        let spis = || (SPI_BASE..self.lines).map(Intid);
        for i in spis().step_by(32) {
            if self.own_groups {
                d.write32(regs::bit(gicd::IGROUPR, i).0, 0);
            }
            d.write32(regs::bit(gicd::ICENABLER, i).0, !0);
            d.write32(regs::bit(gicd::ICPENDR, i).0, !0);
            d.write32(regs::bit(gicd::ICACTIVER, i).0, !0);
        }
        // On a uniprocessor GIC, ITARGETSR is RAZ/WI, and every SPI goes to
        // the one core.
        let targets = self.own_mask().map_or(0, regs::repeat_byte);
        for i in spis().step_by(4) {
            d.write32(
                regs::byte(gicd::IPRIORITYR, i).0,
                regs::repeat_byte(PRIORITY),
            );
            if targets != 0 {
                d.write32(regs::byte(gicd::ITARGETSR, i).0, targets);
            }
        }
        // Level-triggered; C13b sets edge for the handlers that need it.
        for i in spis().step_by(16) {
            d.write32(regs::icfgr(i).0, 0);
        }
        d.write32(gicd::CTLR, gicd::CTLR_ENABLE);
    }

    /// Sets up this core's banked distributor registers and its CPU
    /// interface. `core` is this core's index in the core table.
    pub fn init_cpu(&self, core: usize) {
        let (d, c) = (self.dist, self.cpu);
        self.masks[core].store(self.own_mask().unwrap_or(0), Ordering::Relaxed);
        if self.own_groups {
            // Every SGI and PPI Group 0, signaled as IRQ.
            d.write32(gicd::IGROUPR, 0);
        }
        // Every PPI disabled, and SGIs 3 to 15 too where the GIC lets them
        // be: the GIC-400's and QEMU's SGIs are always enabled.
        d.write32(gicd::ICENABLER, !Sgi::ENABLED_MASK);
        // SGIs' pending bits are cleared through CPENDSGIR, by source.
        d.write32(gicd::ICPENDR, 0xffff_0000);
        for r in 0..4 {
            d.write32(gicd::CPENDSGIR + 4 * r, !0);
        }
        d.write32(gicd::ICACTIVER, !0);
        for r in 0..8 {
            d.write32(gicd::IPRIORITYR + 4 * r, regs::repeat_byte(PRIORITY));
        }
        c.write32(gicc::PMR, PRIORITY_MASK as u32);
        c.write32(gicc::BPR, 0);
        // No priority that firmware left active may block the kernel's
        // interrupts; writing 0 is always allowed.
        for r in 0..4 {
            c.write32(gicc::APR + 4 * r, 0);
            c.write32(gicc::NSAPR + 4 * r, 0);
        }
        // Enable, with EOImode 0 and FIQEn clear.
        c.write32(gicc::CTLR, gicc::CTLR_ENABLE);
        d.write32(gicd::ISENABLER, Sgi::ENABLED_MASK);
    }

    /// Acknowledges the highest-priority pending interrupt: `GICC_IAR`'s
    /// whole value, which the end of interrupt must repeat. Then `DMB ISH`,
    /// as Linux's `gic_handle_irq` orders an SGI's acknowledge: a Device
    /// read doesn't order later Normal reads, and the handler must see what
    /// the SGI's sender wrote before its `DSB ISHST` ([`GicV2::send`]).
    pub fn ack(&self) -> u32 {
        let raw = self.cpu.read32(gicc::IAR);
        super::arch::dmb_ish();
        raw
    }

    pub fn intid(raw: u32) -> Intid {
        Intid(raw & gicc::IAR_INTID)
    }

    /// Drops the priority and deactivates the interrupt (EOI mode 0).
    pub fn eoi(&self, raw: u32) {
        self.cpu.write32(gicc::EOIR, raw);
    }

    /// The register and bit for line `i` in the array at `base`. An INTID
    /// beyond the lines would index other registers: a kernel bug.
    fn line_bit(&self, base: usize, i: Intid) -> (usize, u32) {
        match regs::line_bit(base, i, self.lines) {
            Some(b) => b,
            None => panic!("INTID {} is beyond the GICv2's {} lines", i.0, self.lines),
        }
    }

    fn set_bit(&self, base: usize, i: Intid) {
        let (off, bit) = self.line_bit(base, i);
        self.dist.write32(off, bit);
    }

    fn get_bit(&self, base: usize, i: Intid) -> bool {
        let (off, bit) = self.line_bit(base, i);
        self.dist.read32(off) & bit != 0
    }

    pub fn enable(&self, i: Intid) {
        self.set_bit(gicd::ISENABLER, i);
    }

    pub fn disable(&self, i: Intid) {
        self.set_bit(gicd::ICENABLER, i);
    }

    pub fn is_enabled(&self, i: Intid) -> bool {
        self.get_bit(gicd::ISENABLER, i)
    }

    pub fn is_pending(&self, i: Intid) -> bool {
        self.get_bit(gicd::ISPENDR, i)
    }

    #[cfg_attr(not(aspis_test_build), allow(dead_code))]
    pub fn set_pending(&self, i: Intid) {
        self.set_bit(gicd::ISPENDR, i);
    }

    /// Clears `i`'s pending state; for an SGI, from every source.
    #[cfg_attr(not(aspis_test_build), allow(dead_code))]
    pub fn clear_pending(&self, i: Intid) {
        if i.is_sgi() {
            let (off, shift) = regs::byte(gicd::CPENDSGIR, i);
            self.dist.write32(off, 0xff << shift);
        } else {
            self.set_bit(gicd::ICPENDR, i);
        }
    }

    pub fn pmr(&self) -> u8 {
        self.cpu.read32(gicc::PMR) as u8
    }

    #[cfg_attr(not(aspis_test_build), allow(dead_code))]
    pub fn set_pmr(&self, v: u8) {
        self.cpu.write32(gicc::PMR, v as u32);
    }

    /// The register value that sends `sgi` to `target`, from core `this`.
    pub fn sgir(
        &self,
        sgi: Sgi,
        target: Target,
        this: usize,
        cores: &Cores,
    ) -> Result<u32, SendError> {
        let t = match target {
            Target::AllButSelf => V2Target::AllButSelf,
            Target::Core(i) if i >= cores.len() => return Err(SendError::NoSuchCore),
            Target::Core(i) => match self.masks[i].load(Ordering::Relaxed) {
                // A uniprocessor GIC has no masks: send to self by filter.
                0 if i == this => V2Target::SelfOnly,
                0 => return Err(SendError::NotStarted),
                m => V2Target::List(m),
            },
        };
        gicd_sgir(sgi, t).map_err(SendError::Sgi)
    }

    /// Sends an SGI: `DSB ISHST`, so the target sees what this core wrote,
    /// then one write to `GICD_SGIR`.
    pub fn send(&self, sgir: u32) {
        super::arch::dsb_ishst();
        self.dist.write32(gicd::SGIR, sgir);
    }

    /// The core mask `init_cpu` recorded for `core`.
    #[cfg_attr(not(aspis_test_build), allow(dead_code))]
    pub fn mask(&self, core: usize) -> u8 {
        self.masks[core].load(Ordering::Relaxed)
    }
}
