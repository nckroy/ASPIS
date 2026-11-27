// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The kernel's clock and timer: the EL1 virtual timer (ADR 0051, rules 4
//! and 5; ADR 0007, Consequences; kernel specification, "The timer and
//! deadlines").
//!
//! The clock is the virtual count, `CNTVCT_EL0`, in counts of
//! `CNTFRQ_EL0`. The stub zeroes `CNTVOFF_EL2` when it is entered at EL2,
//! so the count has no offset. The kernel holds no nanoseconds.
//!
//! The timer is tickless, as in seL4 MCS: it fires only at a compare value
//! the kernel programs ([`set_deadline`]), and nothing is armed otherwise
//! ([`CVAL_DISARMED`]). When it fires, [`on_fire`] disarms it before the
//! end of interrupt, so the level-sensitive line drops, as seL4's
//! `ackDeadlineIRQ` does, then calls the scheduler's hook. The scheduler
//! programs the earliest of the running context's budget end, the next
//! release and the earliest deadline on the core (`crate::sched::run`).
//!
//! Each secondary core runs [`init_cpu`] for its own timer as it starts,
//! after its interrupt controller interface (C12; `crate::smp::start`).

use crate::irq;
use core::arch::asm;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use kirq::dt;
use kirq::intid::Intid;
use kirq::regs::cntv_ctl;

pub use kirq::timer::CVAL_DISARMED;

/// The virtual count now. It needs no setup. The `ISB` keeps the read in
/// program order, so a later read never returns an earlier count.
pub fn now() -> u64 {
    let t: u64;
    // SAFETY: reading the virtual counter has no side effects.
    unsafe {
        asm!("isb", "mrs {}, cntvct_el0", out(reg) t, options(nomem, nostack, preserves_flags))
    };
    t
}

/// `CNTFRQ_EL0`, which the firmware set.
fn cntfrq() -> u64 {
    let f: u64;
    // SAFETY: reading the frequency register has no side effects.
    unsafe { asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack, preserves_flags)) };
    f
}

/// The frequency [`init`] read, 0 before it.
static FREQUENCY: AtomicU64 = AtomicU64::new(0);

/// The counter's frequency in Hz: `CNTFRQ_EL0`, read once at [`init`].
pub fn frequency() -> u64 {
    match FREQUENCY.load(Ordering::Relaxed) {
        0 => cntfrq(),
        f => f,
    }
}

/// The virtual timer's INTID, once [`init`] has enabled it; `NONE` before.
static INTID: AtomicU32 = AtomicU32::new(NONE);
const NONE: u32 = u32::MAX;

/// The virtual timer's INTID, once [`init`] has enabled it.
pub fn intid() -> Option<Intid> {
    match INTID.load(Ordering::Acquire) {
        NONE => None,
        i => Some(Intid(i)),
    }
}

fn write_cval(v: u64) {
    // SAFETY: the EL1 virtual timer's compare value, which only this
    // module writes. The `ISB` makes the timer use it before the next
    // instruction, so a disarm drops the line before an end of interrupt.
    unsafe { asm!("msr cntv_cval_el0, {}", "isb", in(reg) v, options(nostack, preserves_flags)) };
}

/// `CNTV_CVAL_EL0`: the count the timer fires at.
pub fn compare_value() -> u64 {
    let v: u64;
    // SAFETY: reading the compare value has no side effects.
    unsafe { asm!("mrs {}, cntv_cval_el0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// `CNTV_CTL_EL0`.
pub fn control() -> u64 {
    let v: u64;
    // SAFETY: reading the control register has no side effects.
    unsafe { asm!("mrs {}, cntv_ctl_el0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Arms the timer to fire when the count reaches `count`, replacing any
/// earlier deadline. A count already passed fires at once: the timer
/// compares with "at or after".
pub fn set_deadline(count: u64) {
    write_cval(count);
}

/// Arms nothing: the compare value becomes [`CVAL_DISARMED`].
pub fn disarm() {
    write_cval(CVAL_DISARMED);
}

/// Finds the virtual timer's interrupt in the device tree, and sets up this
/// core's timer. Runs once, on the boot core, after `irq::init`. A device
/// tree with no timer, or one the kernel can't read, stops the boot: the
/// kernel has no clock without it (ADR 0051, rule 4).
pub fn init(fdt: Option<&fdt::Fdt<'_>>) {
    let f = cntfrq();
    if f == 0 {
        panic!("CNTFRQ_EL0 is 0: the firmware didn't set the counter's frequency");
    }
    FREQUENCY.store(f, Ordering::Relaxed);
    let Some(fdt) = fdt else {
        panic!("no device tree to find the timer in");
    };
    let i = virtual_timer(fdt);
    INTID.store(i.0, Ordering::Release);
    init_cpu();
    crate::klog!(Info, "timer", "virtual, INTID {}, {f} Hz", i.0);
}

/// `CNTKCTL_EL1` as [`init_cpu`] writes it: `EL0VCTEN` only (kernel
/// specification K19, settled with C12). EL0 may read the virtual count,
/// and so `CNTFRQ_EL0`, directly, as Linux's vDSO does, which gives POSIX's
/// `CLOCK_MONOTONIC`. It can reach neither timer (`EL0VTEN`, `EL0PTEN`),
/// read the physical count (`EL0PCTEN`), or get the event stream
/// (`EVNTEN`). Reading a count doesn't let a thread mask or move a deadline
/// (ADR 0055, rule 1).
pub const CNTKCTL: u64 = kirq::regs::cntkctl::EL0VCTEN;

/// `CNTKCTL_EL1`.
#[cfg_attr(not(aspis_test_build), allow(dead_code))]
pub fn kernel_control() -> u64 {
    let v: u64;
    // SAFETY: reading the EL1 timer control has no side effects.
    unsafe { asm!("mrs {}, cntkctl_el1", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Sets up this core's virtual timer: EL0 kept out of the timers, nothing
/// armed, the timer enabled with its interrupt unmasked, and its PPI
/// enabled at this core's GIC interface. The boot core runs it in
/// [`init`]; each secondary core runs it as it starts.
pub fn init_cpu() {
    let Some(i) = intid() else {
        panic!("timer::init_cpu before timer::init");
    };
    // SAFETY: the EL1 timer control, which the architecture doesn't reset
    // to a known value and the firmware may have left set. With only
    // EL0VCTEN set, a thread at EL0 can read the virtual count but can't
    // mask or move the kernel's deadline (ADR 0055, rule 1; ADR 0051,
    // rule 4). The kernel itself runs at EL1, which the register doesn't
    // gate.
    unsafe {
        asm!("msr cntkctl_el1, {}", "isb", in(reg) CNTKCTL, options(nostack, preserves_flags))
    };
    disarm();
    // SAFETY: enabling the EL1 virtual timer, with IMASK clear. The compare
    // value is disarmed, so it doesn't assert until a deadline is set.
    unsafe {
        asm!("msr cntv_ctl_el0, {}", "isb", in(reg) cntv_ctl::ENABLE, options(nostack, preserves_flags))
    };
    match irq::get() {
        Some(gic) => gic.enable(i),
        None => panic!("timer::init_cpu before irq::init"),
    }
}

/// The virtual timer's INTID: entry 2 of the timer node's `interrupts`, a
/// PPI, whose parent must be the interrupt controller the kernel drives.
fn virtual_timer(fdt: &fdt::Fdt<'_>) -> Intid {
    let Some(node) = fdt.find_compatible(kirq::timer::COMPATIBLE) else {
        panic!("the device tree has no arm,armv8-timer node");
    };
    // The node's own interrupt-parent, else the root's: C10 reads devices
    // only as direct children of /. The parent is named by phandle, and is
    // compared with the GIC node `mm` found by its phandle, not by address:
    // on the Pi 4 the GIC's `reg` is a bus address under /soc.
    let raw_parent = |n: fdt::node::FdtNode<'_, '_>| {
        n.property("interrupt-parent")
            .and_then(|p| dt::be_u32(p.value))
    };
    let Some(phandle) = raw_parent(node).or_else(|| fdt.find_node("/").and_then(raw_parent)) else {
        panic!("the timer node has no interrupt-parent");
    };
    let Some(parent) = fdt.find_phandle(phandle) else {
        panic!("the timer's interrupt-parent, phandle {phandle:#x}, names no node");
    };
    if crate::mm::gic_phandle() != Some(phandle) {
        panic!(
            "the timer's interrupt parent, {}, isn't the interrupt controller the kernel drives",
            parent.name
        );
    }
    let cells = parent
        .property("#interrupt-cells")
        .and_then(|p| dt::be_u32(p.value))
        .unwrap_or(0);
    let Some(prop) = node.property("interrupts") else {
        panic!("the timer node has no interrupts");
    };
    match kirq::timer::virtual_intid(prop.value, cells) {
        Ok(i) => i,
        Err(e) => panic!("the timer node can't be used: {e}"),
    }
}

/// The count at which the timer last fired, as [`on_fire`] read it.
static LAST_FIRE: AtomicU64 = AtomicU64::new(0);

/// The count at which the timer last fired.
#[cfg_attr(not(aspis_test_build), allow(dead_code))]
pub fn last_fire() -> u64 {
    LAST_FIRE.load(Ordering::Relaxed)
}

/// The timer's interrupt was acknowledged. If the timer still asserts it,
/// records the count, disarms the timer, so the level-sensitive line drops
/// before the end of interrupt, and calls C12's hook; returns true. If it
/// doesn't, the line dropped late after an earlier end of interrupt, which
/// hardware may do: returns false, and nothing else happens. Called by
/// `irq::handle` only, with interrupts masked.
pub fn on_fire() -> bool {
    if !kirq::timer::asserts(control()) {
        return false;
    }
    // Read after ISTATUS, so the count recorded is never below the
    // deadline it fired for.
    let at = now();
    LAST_FIRE.store(at, Ordering::Relaxed);
    disarm();
    hooks::deadline_reached();
    true
}

/// The scheduler's hook.
pub mod hooks {
    /// The timer fired: the scheduler notes it, and its exit path, after
    /// the end of interrupt, charges the running context, releases refills,
    /// ends the waits whose deadlines passed, and arms the next compare
    /// value (C12; K24).
    pub fn deadline_reached() {
        crate::sched::timer_fired();
    }
}

#[cfg(aspis_test_build)]
mod tests;
