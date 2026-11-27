// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! In-QEMU tests of the interrupt controller (ADR 0036, rule 5), on the GIC
//! the kernel really drives: a GICv2 on `a72-v2` and a GICv3 on `max-v3`.
//!
//! Each test leaves no interrupt pending or active. None waits with WFI
//! for an interrupt that might not come: they take interrupts in windows,
//! for a bounded count of the clock. Secondary cores are off until C12, so
//! the cross-core test reads the target's redistributor instead, and skips
//! with one core. Tests check only the interrupts they set: firmware may
//! leave a level line asserted, such as a physical timer's. A test that
//! sends an interrupt polls, with a bound, for it to become pending
//! ([`spin_until`]): only TCG makes it pending as the write completes.

use super::*;
use crate::timer;
use kcap::preempt::{Budget, Pending, Preempted};
use kirq::regs::{DAIF_F, DAIF_I, gicc, gicd, icc};

fn irq() -> &'static Irq {
    get().expect("irq::init didn't run")
}

/// `n` milliseconds of the clock.
fn ms(n: u64) -> u64 {
    timer::frequency() * n / 1000
}

/// Opens windows until `cond` holds, for at most `counts` of the clock.
fn take_interrupts_until(mut cond: impl FnMut() -> bool, counts: u64) -> bool {
    let start = timer::now();
    loop {
        window();
        if cond() {
            return true;
        }
        if timer::now() - start > counts {
            return false;
        }
    }
}

/// Sends `sgi` to this core, with IRQs masked.
fn send_to_self(sgi: Sgi) {
    let me = irq().this_core();
    send_sgi(sgi, Target::Core(me)).expect("can't send an SGI to this core");
}

/// Waits, masked and for at most 10 ms, until this core sees an IRQ
/// pending (`ISR_EL1.I`), and says whether it did.
fn signaled() -> bool {
    spin_until(pending, ms(10))
}

/// Waits, masked and for at most 10 ms, until `i` is pending at the GIC,
/// and says whether it is.
fn pending_at_gic(i: Intid) -> bool {
    spin_until(|| irq().is_pending(i), ms(10))
}

fn counter(s: &Stats, sgi: Sgi) -> u64 {
    match sgi {
        Sgi::RemoteCall => s.remote_call,
        Sgi::Reschedule => s.reschedule,
        Sgi::Stop => s.stop,
    }
}

/// Takes `sgi`, already sent, and checks that it was delivered once.
fn deliver(sgi: Sgi, before: &Stats) {
    assert!(
        take_interrupts_until(|| counter(&stats(), sgi) > counter(before, sgi), ms(500)),
        "{sgi:?} wasn't delivered"
    );
    assert_eq!(counter(&stats(), sgi), counter(before, sgi) + 1);
    assert!(!irq().is_pending(sgi.intid()));
    take_reschedule();
}

/// Test accessors.
impl Irq {
    fn set_pending(&self, i: Intid) {
        match &self.gic {
            Gic::V2(g) => g.set_pending(i),
            Gic::V3(g) => g.set_pending(i, self.this_core()),
        }
    }

    fn clear_pending(&self, i: Intid) {
        match &self.gic {
            Gic::V2(g) => g.clear_pending(i),
            Gic::V3(g) => g.clear_pending(i, self.this_core()),
        }
    }

    fn pmr(&self) -> u8 {
        match &self.gic {
            Gic::V2(g) => g.pmr(),
            Gic::V3(g) => g.pmr(),
        }
    }

    fn set_pmr(&self, v: u8) {
        match &self.gic {
            Gic::V2(g) => g.set_pmr(v),
            Gic::V3(g) => g.set_pmr(v),
        }
    }

    /// Whether this core's CPU interface has nothing active: its running
    /// priority is idle, so every interrupt taken was ended.
    fn idle(&self) -> bool {
        let rpr = match &self.gic {
            Gic::V2(g) => g.cpu().read32(gicc::RPR) as u64,
            Gic::V3(_) => arch::icc_rpr(),
        };
        rpr & 0xff == 0xff
    }
}

crate::kernel_test!(gic_version_matches_the_cpu, {
    let sysregs = regs::cpu_has_gic_sysregs(arch::id_aa64pfr0());
    match &irq().gic {
        Gic::V2(g) => assert!(matches!(g.arch_rev(), 1 | 2), "GICv2 PIDR2"),
        Gic::V3(g) => {
            assert!(matches!(g.arch_rev(), 3 | 4), "GICv3 PIDR2");
            assert!(sysregs, "a GICv3 with no GIC system registers");
        }
    }
    // A QEMU fact, not an architectural one: QEMU gives the CPU the GIC
    // system registers only with a GICv3. A CPU wired to a GIC-400 may
    // have them.
    assert_eq!(sysregs, irq().is_v3(), "QEMU's CPU and GIC disagree");
});

crate::kernel_test!(gic_is_enabled, {
    let irq = irq();
    assert_eq!(irq.pmr(), kirq::PRIORITY_MASK);
    match &irq.gic {
        Gic::V2(g) => {
            assert_ne!(g.dist().read32(gicd::CTLR) & gicd::CTLR_ENABLE, 0);
            let ctlr = g.cpu().read32(gicc::CTLR);
            assert_eq!(ctlr & 1, 1, "GICC_CTLR doesn't enable signaling");
            // FIQEn (bit 3) and EOImode (bits 9 and 10) stay clear.
            assert_eq!(ctlr & (1 << 3 | 3 << 9), 0, "GICC_CTLR {ctlr:#x}");
            for r in 0..4 {
                assert_eq!(g.cpu().read32(gicc::APR + 4 * r), 0, "GICC_APR{r}");
                assert_eq!(g.cpu().read32(gicc::NSAPR + 4 * r), 0, "GICC_NSAPR{r}");
            }
        }
        Gic::V3(g) => {
            // Bit 0 is EnableGrp0 where DS is 1, as on QEMU with
            // secure=off; with two security states, the non-secure view
            // reads it as 0 once affinity routing is on.
            let ctlr = g.dist().read32(gicd::CTLR);
            let mut want = gicd::CTLR_ARE_NS | gicd::CTLR_ENABLE_G1A;
            if ctlr & gicd::CTLR_DS != 0 {
                want |= gicd::CTLR_ENABLE;
            }
            assert_eq!(ctlr & want, want, "GICD_CTLR {ctlr:#x}");
            assert_ne!(arch::icc_sre() & icc::SRE_SRE, 0);
            assert_ne!(arch::icc_igrpen1() & icc::IGRPEN1_ENABLE, 0);
            let ctlr = arch::icc_ctlr();
            assert_eq!(ctlr & icc::CTLR_EOIMODE, 0, "ICC_CTLR_EL1 {ctlr:#x}");
            // BPR1 holds the minimum the interface allows (3 on QEMU's):
            // a write of 0 saturates there. With one priority it doesn't
            // matter.
            assert!(arch::icc_bpr1() & 7 <= 3);
            for n in 0..icc::ap1r_count(ctlr) {
                assert_eq!(arch::icc_ap1r(n), 0, "ICC_AP1R{n}_EL1");
            }
            // Nothing is active: the running priority is idle.
            assert_eq!(arch::icc_rpr() & 0xff, 0xff);
            let waker = g.rd(irq.this_core()).read32(gicr::WAKER);
            assert_eq!(
                waker & (gicr::WAKER_PROCESSOR_SLEEP | gicr::WAKER_CHILDREN_ASLEEP),
                0,
                "GICR_WAKER {waker:#x}"
            );
        }
    }
});

crate::kernel_test!(only_the_kernels_interrupts_are_enabled, {
    let irq = irq();
    for s in Sgi::ALL {
        assert!(irq.is_enabled(s.intid()), "{s:?} isn't enabled");
    }
    // On a GICv3 the other SGIs can be disabled; a GICv2's may be fixed on.
    if irq.is_v3() {
        for n in 3..16 {
            assert!(!irq.is_enabled(Intid(n)), "SGI {n} is enabled");
        }
    }
    // Of the PPIs, only the virtual timer's, which the timer enables.
    let t = timer::intid().expect("timer::init didn't run");
    assert!(irq.is_enabled(t), "the timer's PPI isn't enabled");
    for n in (16..32).filter(|&n| n != t.0) {
        assert!(!irq.is_enabled(Intid(n)), "PPI {} is enabled", n - 16);
    }
    for n in 32..irq.lines() {
        assert!(!irq.is_enabled(Intid(n)), "SPI {} is enabled", n - 32);
    }
});

/// The enabled cpu nodes in the device tree.
fn cpu_nodes() -> usize {
    let fdt = crate::mm::device_tree().expect("no device tree");
    let cpus = fdt.find_node("/cpus").expect("no /cpus");
    cpus.children()
        .filter(|n| n.property("device_type").and_then(|p| p.as_str()) == Some("cpu"))
        .filter(|n| dt::is_enabled(n.property("status").map(|p| p.value)))
        .count()
}

crate::kernel_test!(each_core_has_its_interface, {
    let irq = irq();
    let cores = irq.cores();
    assert_eq!(cores.len(), cpu_nodes());
    let me = Affinity::from_mpidr(arch::mpidr());
    assert_eq!(cores.affinity(cores.boot()), me);
    assert_eq!(irq.this_core(), cores.boot());
    match &irq.gic {
        Gic::V2(g) => {
            let mask = g.mask(cores.boot());
            let cpus = (g.dist().read32(gicd::TYPER) >> gicd::TYPER_CPU_NUMBER_SHIFT & 7) + 1;
            // A uniprocessor GIC has no masks.
            if cpus == 1 {
                assert_eq!(mask, 0);
            } else {
                assert_eq!(mask.count_ones(), 1, "the boot core's mask {mask:#x}");
            }
        }
        Gic::V3(g) => {
            for i in 0..cores.len() {
                let typer = g.rd(i).read64(gicr::TYPER);
                assert_eq!(Affinity::from_gicr_typer(typer), cores.affinity(i));
                for j in 0..i {
                    assert_ne!(
                        g.rd(i).va(0),
                        g.rd(j).va(0),
                        "two cores share a redistributor"
                    );
                }
            }
        }
    }
});

crate::kernel_test!(sgi_to_self_is_delivered, {
    for sgi in [Sgi::RemoteCall, Sgi::Reschedule] {
        let before = stats();
        send_to_self(sgi);
        // Masked: it waits, pending, and the core sees it pending.
        assert!(pending_at_gic(sgi.intid()), "{sgi:?} isn't pending");
        assert!(signaled(), "ISR_EL1.I is clear with {sgi:?} pending");
        assert_eq!(counter(&stats(), sgi), counter(&before, sgi));
        deliver(sgi, &before);
        assert_ne!(daif() & DAIF_I, 0, "IRQs stayed unmasked");
    }
    assert!(!pending());
});

crate::kernel_test!(every_self_addressed_form_is_delivered, {
    let irq = irq();
    let me = irq.this_core();
    let mut forms = 0;
    match &irq.gic {
        Gic::V2(g) => {
            let mask = g.mask(me);
            for t in [
                kirq::sgi::V2Target::SelfOnly,
                kirq::sgi::V2Target::List(mask),
            ] {
                if t == kirq::sgi::V2Target::List(0) {
                    continue; // uniprocessor: no masks
                }
                let before = stats();
                g.send(kirq::sgi::gicd_sgir(Sgi::Reschedule, t).unwrap());
                deliver(Sgi::Reschedule, &before);
                forms += 1;
            }
        }
        Gic::V3(g) => {
            let before = stats();
            g.send(
                g.sgi1r(Sgi::Reschedule, Target::Core(me), irq.cores())
                    .unwrap(),
            );
            deliver(Sgi::Reschedule, &before);
            forms += 1;
        }
    }
    assert!(forms > 0);
});

crate::kernel_test!(cross_core_sgi_reaches_only_its_target, {
    let irq = irq();
    let cores = irq.cores();
    if cores.len() == 1 {
        crate::uart::write("  (one core: nothing to cross to; skipped)\n");
        return;
    }
    let me = irq.this_core();
    let target = (me + 1) % cores.len();
    let sgi = Sgi::Reschedule;
    match &irq.gic {
        Gic::V2(g) => {
            // Until C12 starts the core and records its mask, it can't be
            // named.
            assert_eq!(g.mask(target), 0);
            assert_eq!(
                irq.send_sgi(sgi, Target::Core(target)),
                Err(SendError::NotStarted)
            );
        }
        Gic::V3(g) => {
            // The target's redistributor keeps its reset groups until its
            // core sets them (C12); a Group 1 SGI to a Group 0 INTID is
            // dropped. Make the kernel's SGIs Group 1 there for the test.
            let frame = g.rd(target).at(gicr::SGI_FRAME);
            let groups = frame.read32(gicr::IGROUPR0);
            frame.write32(gicr::IGROUPR0, groups | Sgi::ENABLED_MASK);
            irq.send_sgi(sgi, Target::Core(target)).unwrap();
            let reached = spin_until(
                || frame.read32(gicr::ISPENDR0) & 1 << sgi as u32 != 0,
                ms(10),
            );
            frame.write32(gicr::ICPENDR0, Sgi::ENABLED_MASK);
            frame.write32(gicr::IGROUPR0, groups);
            assert!(reached, "the SGI isn't pending at core {target}");
        }
    }
    // Nothing reached this core.
    assert!(!irq.is_pending(sgi.intid()));
    assert!(!pending());
    let before = stats();
    window();
    assert_eq!(stats(), before);
});

crate::kernel_test!(nothing_pending_acknowledges_as_spurious, {
    assert!(!pending());
    let before = stats();
    assert_eq!(handle(), Action::Spurious);
    assert_eq!(
        stats(),
        Stats {
            spurious: before.spurious + 1,
            ..before
        }
    );
    // The next interrupt is delivered as usual.
    let before = stats();
    send_to_self(Sgi::RemoteCall);
    deliver(Sgi::RemoteCall, &before);
});

crate::kernel_test!(an_interrupt_below_the_priority_mask_is_spurious, {
    let irq = irq();
    let sgi = Sgi::Reschedule;
    irq.set_pmr(0);
    send_to_self(sgi);
    assert!(pending_at_gic(sgi.intid()));
    // The GIC signals nothing below the mask.
    assert!(!pending(), "ISR_EL1.I is set below the priority mask");
    let before = stats();
    assert_eq!(handle(), Action::Spurious);
    assert_eq!(stats().spurious, before.spurious + 1);
    assert!(
        irq.is_pending(sgi.intid()),
        "a spurious acknowledge took it"
    );
    irq.set_pmr(kirq::PRIORITY_MASK);
    assert_eq!(irq.pmr(), kirq::PRIORITY_MASK);
    deliver(sgi, &before);
});

crate::kernel_test!(interrupts_stay_masked_in_critical_sections, {
    let entry = daif();
    assert_eq!(entry & (DAIF_I | DAIF_F), DAIF_I | DAIF_F);
    let sgi = Sgi::Reschedule;
    let before = stats();
    send_to_self(sgi);
    {
        let _outer = masked();
        {
            let _inner = masked();
            for _ in 0..10_000 {
                core::hint::spin_loop();
            }
            assert_ne!(daif() & DAIF_I, 0);
        }
        assert_eq!(daif(), entry, "the inner guard didn't restore DAIF");
    }
    assert_eq!(daif(), entry, "the outer guard didn't restore DAIF");
    assert_eq!(stats(), before, "an interrupt was taken while masked");
    assert!(signaled());
    deliver(sgi, &before);
    assert_eq!(daif(), entry);
});

crate::kernel_test!(an_unclaimed_interrupt_is_masked_and_logged, {
    let irq = irq();
    // The highest SPI: QEMU's virt wires no device there.
    let spi = Intid(irq.lines() - 1);
    assert!(spi.is_spi() && !irq.is_enabled(spi));
    let before = stats();
    irq.enable(spi);
    irq.set_pending(spi);
    assert!(
        take_interrupts_until(|| stats().unclaimed > before.unclaimed, ms(500)),
        "the SPI wasn't taken"
    );
    assert_eq!(stats().unclaimed, before.unclaimed + 1);
    assert!(!irq.is_enabled(spi), "the unclaimed SPI is still enabled");
    if irq.is_pending(spi) {
        irq.clear_pending(spi);
        panic!("the unclaimed SPI is still pending");
    }
    let mut want = crate::log::Line::new();
    let _ = core::fmt::write(
        &mut want,
        format_args!("INTID {} has no handler; disabled", spi.0),
    );
    let mut logged = 0;
    crate::log::for_each(|r| {
        if r.level == crate::log::Level::Warning && r.text == want.as_str() {
            logged += 1;
        }
    });
    assert_eq!(logged, 1, "the unclaimed SPI wasn't logged once");
    assert!(!pending());
});

crate::kernel_test!(pending_check_sees_a_masked_interrupt, {
    let mut p = IrqPending;
    assert!(!p.pending());
    let before = stats();
    send_to_self(Sgi::Reschedule);
    assert!(spin_until(|| p.pending(), ms(10)));
    // A preemption point stops for it.
    let mut b = Budget::with_threshold(IrqPending, 1);
    assert_eq!(b.tick(1), Err(Preempted));
    deliver(Sgi::Reschedule, &before);
    assert!(!p.pending());
    assert_eq!(b.tick(1), Ok(()));
});

crate::kernel_test!(wait_returns_for_a_pending_interrupt, {
    // WFI wakes for an interrupt pending while masked, so this can't hang
    // unless delivery is broken, and then the run's timeout ends it.
    let before = stats();
    send_to_self(Sgi::Reschedule);
    wait();
    if stats().reschedule == before.reschedule {
        // An implementation may wake WFI before the interrupt reaches the
        // core: take it as any window does.
        deliver(Sgi::Reschedule, &before);
    } else {
        assert_eq!(stats().reschedule, before.reschedule + 1);
        take_reschedule();
    }
    assert_ne!(daif() & DAIF_I, 0);
    assert!(!pending());
});

crate::kernel_test!(all_but_self_spares_this_core, {
    let irq = irq();
    let cores = irq.cores();
    let me = irq.this_core();
    let sgi = Sgi::Reschedule;
    let others = (0..cores.len()).filter(|&i| i != me);
    match &irq.gic {
        Gic::V2(_) => {
            // The others' pending state is banked at their interfaces,
            // which this core can't read; C12's `init_cpu` clears it.
            irq.send_sgi(sgi, Target::AllButSelf).unwrap();
        }
        Gic::V3(g) => {
            // As in the cross-core test: Group 1 at each target first.
            let mut groups = [0u32; MAX_CORES];
            for i in others.clone() {
                let f = g.rd(i).at(gicr::SGI_FRAME);
                groups[i] = f.read32(gicr::IGROUPR0);
                f.write32(gicr::IGROUPR0, groups[i] | Sgi::ENABLED_MASK);
            }
            irq.send_sgi(sgi, Target::AllButSelf).unwrap();
            let mut missed = None;
            for i in others {
                let f = g.rd(i).at(gicr::SGI_FRAME);
                if !spin_until(|| f.read32(gicr::ISPENDR0) & 1 << sgi as u32 != 0, ms(10)) {
                    missed = Some(i);
                }
                f.write32(gicr::ICPENDR0, Sgi::ENABLED_MASK);
                f.write32(gicr::IGROUPR0, groups[i]);
            }
            assert_eq!(missed, None, "a core didn't get the SGI");
        }
    }
    assert!(!irq.is_pending(sgi.intid()));
    assert!(!pending());
    let before = stats();
    window();
    assert_eq!(stats(), before);
});

crate::kernel_test!(a_stale_timer_entry_is_counted_apart, {
    // The timer's PPI taken while the timer doesn't assert it, as when a
    // level line drops late on hardware: it is counted apart, the timer
    // isn't touched, and the interrupt is ended.
    let irq = irq();
    let t = timer::intid().unwrap();
    assert_eq!(timer::compare_value(), timer::CVAL_DISARMED);
    let (before, fired) = (stats(), timer::last_fire());
    irq.set_pending(t);
    assert!(
        take_interrupts_until(|| stats().stale_timer > before.stale_timer, ms(500)),
        "the timer's PPI wasn't taken"
    );
    assert_eq!(
        stats(),
        Stats {
            stale_timer: before.stale_timer + 1,
            ..before
        }
    );
    assert_eq!(timer::last_fire(), fired);
    assert!(!irq.is_pending(t) && irq.idle());
    assert!(irq.is_enabled(t));
});

crate::kernel_test!(long_operations_stop_for_a_waiting_interrupt, {
    // ADR 0052, rule 2: a long operation stops at its next preemption point
    // for a pending interrupt, and a restart finishes it as an
    // uninterrupted run does (kernel specification, "The kernel lock and
    // long operations").
    use crate::cap::{self, testkit::Scratch, testkit::watermark};
    use kcap::ops::Error;
    use kmem::PAGE_SIZE;
    use kmem::untyped::ObjectType;
    let mut sc = Scratch::new(23);
    let piece = sc.make(ObjectType::Untyped(22));
    let size = 1u64 << 22;
    sc.try_make(piece, ObjectType::Frame2M, 2)
        .unwrap_or_else(|e| panic!("no frames: {e:?}"));
    cap::revoke(piece);
    assert_eq!(watermark(piece), size);

    // Masked, with an SGI pending: the reset stops after its first check.
    let before = stats();
    send_to_self(Sgi::Reschedule);
    assert!(signaled());
    assert_eq!(
        cap::reset_with(piece, &mut cap::budget()),
        Err(Error::Preempted)
    );
    let w = watermark(piece);
    assert!(w > 0, "the reset ran to the end with an interrupt pending");
    assert!(
        size - w >= u64::from(kcap::UNITS_PER_CHECK) * PAGE_SIZE,
        "the reset stopped before {} units of work",
        kcap::UNITS_PER_CHECK
    );
    // Taken, as C12's exit path will, then the restart runs to the end.
    deliver(Sgi::Reschedule, &before);
    assert_eq!(cap::reset_with(piece, &mut cap::budget()), Ok(()));
    assert_eq!(watermark(piece), 0);

    // The run-to-end wrappers finish with an interrupt pending all along.
    sc.try_make(piece, ObjectType::Frame2M, 2).unwrap();
    let before = stats();
    send_to_self(Sgi::Reschedule);
    assert!(signaled());
    cap::revoke(piece);
    assert!(!kcap::mdb::has_children(&cap::DirectSlots, piece));
    let frame = sc
        .try_make(piece, ObjectType::Frame4K, 1)
        .unwrap_or_else(|e| panic!("retype with an interrupt pending: {e:?}"));
    assert_eq!(watermark(piece), PAGE_SIZE);
    assert!(pending(), "the wrappers took the interrupt");
    assert_eq!(stats(), before);
    deliver(Sgi::Reschedule, &before);
    cap::delete(frame);
    sc.finish();
});

crate::kernel_test!(the_stop_sgi_stops_a_core, {
    // One core shows the stop's whole path but the halt: sent, taken,
    // counted, ended, and the core counted as stopped.
    let irq = irq();
    let entry = daif();
    let (before, stopped) = (stats(), STOPPED.load(Ordering::Relaxed));
    STOP_INTERCEPT.store(true, Ordering::Relaxed);
    send_to_self(Sgi::Stop);
    assert!(pending_at_gic(Sgi::Stop.intid()));
    assert!(
        take_interrupts_until(|| stats().stop > before.stop, ms(500)),
        "the stop wasn't taken"
    );
    assert!(!STOP_INTERCEPT.load(Ordering::Relaxed));
    assert_eq!(
        stats(),
        Stats {
            stop: before.stop + 1,
            ..before
        }
    );
    assert_eq!(STOPPED.load(Ordering::Relaxed), stopped + 1);
    // Ended: nothing active or pending, and the next acknowledge is
    // spurious.
    assert!(irq.idle(), "the stop wasn't ended");
    assert!(!irq.is_pending(Sgi::Stop.intid()));
    assert_eq!(handle(), Action::Spurious);
    assert_eq!(daif(), entry);
});

crate::kernel_test!(the_panic_stop_spares_the_panicking_core, {
    // The panic path's own send. C12 must rework this test once secondary
    // cores run: it would stop them.
    let irq = irq();
    let cores = irq.cores();
    let me = irq.this_core();
    let sgi = Sgi::Stop;
    let others = (0..cores.len()).filter(|&i| i != me);
    let before = stats();
    match &irq.gic {
        Gic::V2(_) => {
            // The others' pending state is banked at their interfaces;
            // C12's `init_cpu` clears it.
            assert!(send_stop_to_others());
        }
        Gic::V3(g) => {
            // Group 1 at each target first, as C12's `init_cpu` will set.
            let mut groups = [0u32; MAX_CORES];
            for i in others.clone() {
                let f = g.rd(i).at(gicr::SGI_FRAME);
                groups[i] = f.read32(gicr::IGROUPR0);
                f.write32(gicr::IGROUPR0, groups[i] | Sgi::ENABLED_MASK);
            }
            assert!(send_stop_to_others());
            let mut missed = None;
            for i in others {
                let f = g.rd(i).at(gicr::SGI_FRAME);
                if !spin_until(|| f.read32(gicr::ISPENDR0) & 1 << sgi as u32 != 0, ms(10)) {
                    missed = Some(i);
                }
                f.write32(gicr::ICPENDR0, Sgi::ENABLED_MASK);
                f.write32(gicr::IGROUPR0, groups[i]);
            }
            assert_eq!(missed, None, "a core didn't get the stop");
        }
    }
    if cores.len() == 1 {
        crate::uart::write("  (one core: the stop reaches no one)\n");
    }
    // Nothing reached this core.
    assert!(!irq.is_pending(sgi.intid()));
    assert!(!pending());
    window();
    assert_eq!(stats(), before);
    assert_eq!(handle(), Action::Spurious);
});
