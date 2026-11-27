// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The GICv3 back end, for QEMU's `gic-version=3` and servers (ADR 0007,
//! rule 2 and Consequences; kernel specification, "The kernel's interrupt
//! controller"). A GICv4 is driven as a GICv3. The register choices follow
//! Linux's `irq-gic-v3.c`.
//!
//! Every SGI, PPI and SPI is Group 1, with affinity routing. The CPU
//! interface is the system-register one (`ICC_*_EL1`), which the stub lets
//! EL1 use when it is entered at EL2. Extended PPIs and SPIs (GICv3.1) are
//! disabled, and LPIs too where the redistributor lets them be; the kernel
//! uses none until C13b.

use super::arch::{self, Mmio};
use super::{Cores, SendError, Target, wait_until};
use kirq::intid::{Intid, SPI_BASE};
use kirq::regs::{self, gicd, gicr, icc};
use kirq::sgi::{Sgi, V3Target, icc_sgi1r};
use kirq::{MAX_CORES, PRIORITY, PRIORITY_MASK};

pub struct GicV3 {
    dist: Mmio,
    /// Each core's redistributor, its `RD_base` frame and the `SGI_base`
    /// frame after it, by core index.
    rd: [Option<Mmio>; MAX_CORES],
    lines: u32,
}

impl GicV3 {
    /// The distributor, and each core's redistributor.
    pub fn new(dist: Mmio, rd: [Option<Mmio>; MAX_CORES]) -> GicV3 {
        GicV3 {
            dist,
            rd,
            lines: regs::lines(dist.read32(gicd::TYPER)),
        }
    }

    pub fn lines(&self) -> u32 {
        self.lines
    }

    pub fn dist(&self) -> Mmio {
        self.dist
    }

    /// Core `core`'s redistributor: `RD_base`, with `SGI_base` at
    /// [`gicr::SGI_FRAME`].
    pub fn rd(&self, core: usize) -> Mmio {
        match self.rd.get(core).copied().flatten() {
            Some(rd) => rd,
            None => panic!("core {core} has no redistributor"),
        }
    }

    fn sgi_frame(&self, core: usize) -> Mmio {
        self.rd(core).at(gicr::SGI_FRAME)
    }

    pub fn arch_rev(&self) -> u8 {
        regs::arch_rev(self.dist.read32(gicd::PIDR2_V3))
    }

    fn wait_dist(&self) {
        wait_until("GICD_CTLR.RWP", || {
            self.dist.read32(gicd::CTLR) & gicd::CTLR_RWP == 0
        });
    }

    /// Sets up the distributor, from the boot core, in the order Linux's
    /// `gic_dist_init` uses: `GICD_IROUTER` is RES0 until affinity routing
    /// is on, so every SPI is configured, then routing is enabled, then
    /// each SPI is routed to the boot core.
    pub fn init_dist(&self, boot: &Cores) {
        let d = self.dist;
        // 1. Off, and wait for it.
        d.write32(gicd::CTLR, 0);
        self.wait_dist();
        // 2. Every SPI Group 1, disabled, not pending, not active, at the
        // kernel's priority and level-triggered (C13b sets edge where a
        // handler needs it).
        let spis = || (SPI_BASE..self.lines).map(Intid);
        for i in spis().step_by(32) {
            d.write32(regs::bit(gicd::IGROUPR, i).0, !0);
            d.write32(regs::bit(gicd::ICENABLER, i).0, !0);
            d.write32(regs::bit(gicd::ICPENDR, i).0, !0);
            d.write32(regs::bit(gicd::ICACTIVER, i).0, !0);
        }
        for i in spis().step_by(4) {
            d.write32(
                regs::byte(gicd::IPRIORITYR, i).0,
                regs::repeat_byte(PRIORITY),
            );
        }
        for i in spis().step_by(16) {
            d.write32(regs::icfgr(i).0, 0);
        }
        // Extended SPIs, as Linux's `gic_dist_init` does: disabled, not
        // pending, not active. The kernel enables none.
        let espis = regs::espi_lines(d.read32(gicd::TYPER)) as usize;
        for w in 0..espis / 32 {
            d.write32(gicd::ICENABLER_E + 4 * w, !0);
            d.write32(gicd::ICPENDR_E + 4 * w, !0);
            d.write32(gicd::ICACTIVER_E + 4 * w, !0);
        }
        self.wait_dist();
        // 3. Affinity routing and Group 1, as Linux writes it for either
        // security view: bit 1 is EnableGrp1A in the non-secure view, or
        // EnableGrp1 where DS is 1. Bit 0 is EnableGrp0 where DS is 1, and
        // RES0 in the non-secure view with affinity routing.
        d.write32(
            gicd::CTLR,
            gicd::CTLR_ARE_NS | gicd::CTLR_ENABLE_G1A | gicd::CTLR_ENABLE,
        );
        self.wait_dist();
        if d.read32(gicd::CTLR) & gicd::CTLR_ARE_NS == 0 {
            panic!("the GICv3 won't enable affinity routing");
        }
        // 4. Route every SPI to the boot core alone.
        let to = boot.affinity(boot.boot()).irouter();
        for i in spis() {
            d.write64(regs::irouter(i), to);
        }
    }

    /// Sets up core `core`'s redistributor and this core's CPU interface.
    /// `core` must be this core's index in the core table.
    pub fn init_cpu(&self, core: usize) {
        let rd = self.rd(core);
        let sgi = self.sgi_frame(core);
        // Wake the redistributor: the core is awake, and its interface
        // must leave quiescence.
        let waker = rd.read32(gicr::WAKER);
        rd.write32(gicr::WAKER, waker & !gicr::WAKER_PROCESSOR_SLEEP);
        wait_until("GICR_WAKER.ChildrenAsleep", || {
            rd.read32(gicr::WAKER) & gicr::WAKER_CHILDREN_ASLEEP == 0
        });
        // Every SGI and PPI Group 1, disabled, not pending, not active, and
        // every extended PPI (GICv3.1) disabled, not pending, not active,
        // as Linux's `gic_cpu_config` covers them.
        sgi.write32(gicr::IGROUPR0, !0);
        sgi.write32(gicr::ICENABLER0, !0);
        sgi.write32(gicr::ICPENDR0, !0);
        sgi.write32(gicr::ICACTIVER0, !0);
        for w in 1..=regs::eppi_words(rd.read64(gicr::TYPER)) {
            sgi.write32(gicr::ICENABLER0 + 4 * w, !0);
            sgi.write32(gicr::ICPENDR0 + 4 * w, !0);
            sgi.write32(gicr::ICACTIVER0 + 4 * w, !0);
        }
        let rwp = || {
            wait_until("GICR_CTLR.RWP", || {
                rd.read32(gicr::CTLR) & gicr::CTLR_RWP == 0
            })
        };
        rwp();
        // LPIs that firmware or an earlier kernel left enabled, as Linux
        // disables them: whether EnableLPIs can be cleared is
        // implementation defined, so an LPI may still arrive, and is then
        // logged and ended (`irq::handle`).
        let ctlr = rd.read32(gicr::CTLR);
        if ctlr & gicr::CTLR_ENABLE_LPIS != 0 {
            rd.write32(gicr::CTLR, ctlr & !gicr::CTLR_ENABLE_LPIS);
            rwp();
            if rd.read32(gicr::CTLR) & gicr::CTLR_ENABLE_LPIS != 0 {
                crate::klog!(
                    Notice,
                    "interrupts",
                    "core {core}'s redistributor has LPIs enabled, and won't disable them"
                );
            }
        }
        for r in 0..8 {
            sgi.write32(gicr::IPRIORITYR + 4 * r, regs::repeat_byte(PRIORITY));
        }

        // The system-register interface. EL1 can set ICC_SRE_EL1.SRE only
        // once EL2, if there is one, has set ICC_SRE_EL2.Enable: the stub
        // does it when it is entered at EL2, else the firmware or the
        // hypervisor must have.
        // SAFETY: `ICC_SRE_EL1` exists, since the CPU has the GIC system
        // registers (checked at init); setting SRE leaves the
        // memory-mapped interface, which the kernel doesn't use.
        unsafe { arch::set_icc_sre(arch::icc_sre() | icc::SRE_SRE) };
        arch::isb();
        if arch::icc_sre() & icc::SRE_SRE == 0 {
            panic!("the GICv3's system-register interface can't be enabled");
        }
        // SAFETY: with SRE set, these registers exist. Every interrupt is
        // masked at the PE (PSTATE.I), and none is active at this core: the
        // kernel has acknowledged none, and the active priorities cleared
        // below drop any firmware left.
        unsafe {
            arch::set_icc_pmr(PRIORITY_MASK as u64);
            arch::set_icc_bpr1(0);
            // EOI mode 0: EOIR both drops the priority and deactivates.
            let ctlr = arch::icc_ctlr() & !icc::CTLR_EOIMODE;
            arch::set_icc_ctlr(ctlr);
            arch::isb();
            for n in 0..icc::ap1r_count(ctlr) {
                arch::clear_icc_ap1r(n);
            }
            arch::set_icc_igrpen1(icc::IGRPEN1_ENABLE);
        }
        arch::isb();
        sgi.write32(gicr::ISENABLER0, Sgi::ENABLED_MASK);
    }

    /// Acknowledges the highest-priority pending Group 1 interrupt.
    pub fn ack(&self) -> u32 {
        // SAFETY: the caller (`irq::handle`) ends every interrupt that
        // isn't special.
        (unsafe { arch::icc_iar1() } & icc::IAR_INTID) as u32
    }

    /// Drops the priority and deactivates the interrupt (EOI mode 0), then
    /// `ISB`.
    pub fn eoi(&self, intid: u32) {
        // SAFETY: `intid` came from `ack`, and is active.
        unsafe { arch::set_icc_eoir1(intid as u64) };
        arch::isb();
    }

    /// The frame and register for interrupt `i`'s bit in `base`: core
    /// `this`'s redistributor for an SGI or PPI, else the distributor. An
    /// INTID beyond the distributor's lines, such as an LPI or an extended
    /// SPI, would index other registers: a kernel bug.
    fn bit(&self, base_dist: usize, base_rd: usize, i: Intid, this: usize) -> (Mmio, usize, u32) {
        if i.is_private() {
            let (off, bit) = regs::bit(base_rd, i);
            (self.sgi_frame(this), off, bit)
        } else {
            match regs::line_bit(base_dist, i, self.lines) {
                Some((off, bit)) => (self.dist, off, bit),
                None => panic!("INTID {} is beyond the GICv3's {} lines", i.0, self.lines),
            }
        }
    }

    pub fn enable(&self, i: Intid, this: usize) {
        let (f, off, bit) = self.bit(gicd::ISENABLER, gicr::ISENABLER0, i, this);
        f.write32(off, bit);
    }

    pub fn disable(&self, i: Intid, this: usize) {
        let (f, off, bit) = self.bit(gicd::ICENABLER, gicr::ICENABLER0, i, this);
        f.write32(off, bit);
        if i.is_private() {
            let rd = self.rd(this);
            wait_until("GICR_CTLR.RWP", || {
                rd.read32(gicr::CTLR) & gicr::CTLR_RWP == 0
            });
        } else {
            self.wait_dist();
        }
    }

    pub fn is_enabled(&self, i: Intid, this: usize) -> bool {
        let (f, off, bit) = self.bit(gicd::ISENABLER, gicr::ISENABLER0, i, this);
        f.read32(off) & bit != 0
    }

    pub fn is_pending(&self, i: Intid, this: usize) -> bool {
        let (f, off, bit) = self.bit(gicd::ISPENDR, gicr::ISPENDR0, i, this);
        f.read32(off) & bit != 0
    }

    #[cfg_attr(not(aspis_test_build), allow(dead_code))]
    pub fn set_pending(&self, i: Intid, this: usize) {
        let (f, off, bit) = self.bit(gicd::ISPENDR, gicr::ISPENDR0, i, this);
        f.write32(off, bit);
    }

    #[cfg_attr(not(aspis_test_build), allow(dead_code))]
    pub fn clear_pending(&self, i: Intid, this: usize) {
        let (f, off, bit) = self.bit(gicd::ICPENDR, gicr::ICPENDR0, i, this);
        f.write32(off, bit);
    }

    pub fn pmr(&self) -> u8 {
        arch::icc_pmr() as u8
    }

    #[cfg_attr(not(aspis_test_build), allow(dead_code))]
    pub fn set_pmr(&self, v: u8) {
        // SAFETY: the system-register interface is enabled; the tests that
        // lower the mask restore it.
        unsafe { arch::set_icc_pmr(v as u64) };
        arch::isb();
    }

    /// The `ICC_SGI1R_EL1` value that sends `sgi` to `target`.
    pub fn sgi1r(&self, sgi: Sgi, target: Target, cores: &Cores) -> Result<u64, SendError> {
        let t = match target {
            Target::AllButSelf => V3Target::AllButSelf,
            Target::Core(i) if i >= cores.len() => return Err(SendError::NoSuchCore),
            Target::Core(i) => V3Target::Core(cores.affinity(i)),
        };
        let rss = arch::icc_ctlr() & icc::CTLR_RSS != 0;
        icc_sgi1r(sgi, t, rss).map_err(SendError::Sgi)
    }

    /// Sends an SGI: `DSB ISHST`, so the target sees what this core wrote,
    /// one write to `ICC_SGI1R_EL1`, then `ISB`.
    pub fn send(&self, sgi1r: u64) {
        arch::dsb_ishst();
        // SAFETY: the system-register interface is enabled, and the value
        // came from `sgi1r`: one of the kernel's SGIs, as Group 1.
        unsafe { arch::set_icc_sgi1r(sgi1r) };
        arch::isb();
    }
}
