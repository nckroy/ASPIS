// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Kernel entry from EL0 (kernel specification, "Fault delivery"; ADR 0048,
//! rule 5; ADR 0056, rule 1; K70; K77).
//!
//! The EL0 vectors (`crate::exceptions`) save the thread's registers, FP
//! and SIMD included, into its object, switch to the core's entry stack, and
//! call [`aspis_user_entry`], which takes the kernel lock, dispatches on the
//! exception and ends in the exit path ([`super::run::exit`]), which never
//! returns here and releases the lock as it leaves the kernel.
//!
//! - **SVC.** First the budget check: a call goes ahead only if the
//!   thread's budget still holds, with at least the minimum left; otherwise
//!   the call is made again once the context's refill comes, as seL4's
//!   `checkBudgetRestart` (ADR 0051, rule 1). In test builds, `svc #0x7e57`
//!   is the test trap (`crate::testing::trap`). Any other SVC, and every SVC
//!   in production, is an unknown-system-call fault carrying the call's
//!   number, the SVC's immediate. C17's system-call ABI and entry table
//!   replace both, and keep the restart ([`restart`]).
//! - **Aborts**, data or instruction, from EL0: the fault status code says
//!   which. A translation, access-flag or permission fault, or an address
//!   size fault, is an unmapped fault, with the address and the access. An
//!   alignment fault, a synchronous external abort, a parity or ECC error,
//!   or a TLB conflict is a user exception (kernel specification, "Fault
//!   delivery").
//! - **BRK** is a debug fault. No thread has hardware debug state, and
//!   `MDSCR_EL1` is clear, so no other debug exception reaches EL0; any that
//!   did would be a user exception (K70).
//! - **Everything else** synchronous is a user exception: an undefined
//!   instruction, a PC or SP alignment fault, a trapped system register (as
//!   the physical count, K19), SVE and SME, which `CPACR_EL1` traps, WFI and
//!   WFE.
//! - **IRQ**: [`crate::irq::handle`], one interrupt per entry.
//! - **FIQ** can't happen, since EL0 runs with FIQs masked: a panic.
//! - **SError**: reported, then a panic (K77; C20 and C78 revisit an
//!   SError from EL0).

use super::fault::{self, Kind};
use super::object::Tcb;
use super::percore::{ENTERING_OTHER, ENTERING_SVC, this_core};
use core::sync::atomic::Ordering;

/// The vectors' exception kinds: the offset of the vector in its group.
const SYNC: u64 = 0;
const IRQ: u64 = 1;
const FIQ: u64 = 2;
const SERROR: u64 = 3;

/// Exception classes (`ESR_EL1.EC`).
mod ec {
    pub const SVC64: u64 = 0x15;
    pub const IABT_LOWER: u64 = 0x20;
    pub const PC_ALIGN: u64 = 0x22;
    pub const DABT_LOWER: u64 = 0x24;
    pub const WATCHPOINT_LOWER: u64 = 0x34;
    pub const BRK64: u64 = 0x3c;
}

/// The entry from EL0: `kind` is the vector (synchronous, IRQ, FIQ or
/// SError), `esr` and `far` the syndrome and fault address registers.
///
/// It takes the kernel lock first. While it waits, another core may have
/// stalled the thread that entered, to change it (`crate::smp::remote`):
/// then the thread is no longer this core's current one, and the entry is
/// dropped without touching the thread again, since it may be gone
/// (kernel specification, "Cross-core signals and TLB maintenance"). The
/// stall moved a system call's PC back to its `SVC`, so the call runs when
/// the thread next runs; a fault is raised again as its instruction
/// re-executes; an IRQ is still handled. An FIQ or SError is never dropped:
/// it panics before the lock is taken.
#[unsafe(no_mangle)]
extern "C" fn aspis_user_entry(kind: u64, esr: u64, far: u64) -> ! {
    let c = this_core();
    let entered = c.current;
    if entered == 0 {
        panic!("an exception from EL0 with no thread running: kind {kind}, ESR {esr:#x}");
    }
    // The asynchronous kinds first, before the lock: nothing raises an
    // SError again, so it must not be dropped as a stalled entry is (below).
    // No other core has touched the thread yet: one that changes a thread
    // running here stalls it first, which waits for this core's lock spin.
    if kind == FIQ {
        panic!("an FIQ from EL0, which runs with FIQs masked: thread {entered:#x}");
    }
    if kind == SERROR {
        let pc = Tcb(entered).with(|b| b.ctx.pc);
        panic!("SError from EL0: thread {entered:#x}, ESR {esr:#x}, ELR {pc:#x}");
    }
    let svc = kind == SYNC && esr >> 26 == ec::SVC64;
    c.entering.store(
        if svc { ENTERING_SVC } else { ENTERING_OTHER },
        Ordering::Relaxed,
    );
    crate::smp::lock::lock();
    let c = this_core();
    c.entering.store(0, Ordering::Relaxed);
    c.stats.entries += 1;
    if c.current != entered {
        if kind == IRQ {
            crate::irq::handle();
        }
        super::run::exit()
    }
    let t = Tcb(entered);
    match kind {
        SYNC => sync(t, esr, far),
        IRQ => {
            crate::irq::handle();
        }
        _ => unreachable!("an entry of kind {kind} from EL0"),
    }
    super::run::exit()
}

fn sync(t: Tcb, esr: u64, far: u64) {
    let far = far_valid(esr, far);
    match esr >> 26 {
        ec::SVC64 => svc(t, esr & 0xffff),
        ec::DABT_LOWER | ec::IABT_LOWER => abort(t, esr, far),
        ec::BRK64 => fault::raise(t, Kind::Debug, esr, t.with(|b| b.ctx.pc)),
        _ => fault::raise(t, Kind::UserException, esr, far),
    }
}

/// `far` when `FAR_EL1` holds this exception's address, and 0 otherwise.
///
/// The Arm ARM makes `FAR_EL1` UNKNOWN except on an instruction or data
/// abort, a PC alignment fault and a watchpoint, and on an abort only when
/// `ESR_EL1.ISS.FnV` (bit 10) is clear. Cores keep the last value written,
/// the address of the last abort taken on that core, which may be another
/// job's. The fault message carries the address to an EL0 handler, so a
/// stale one would leak one address space's layout to another.
pub const fn far_valid(esr: u64, far: u64) -> u64 {
    const FNV: u64 = 1 << 10;
    match esr >> 26 {
        ec::DABT_LOWER | ec::IABT_LOWER if esr & FNV == 0 => far,
        ec::PC_ALIGN | ec::WATCHPOINT_LOWER => far,
        _ => 0,
    }
}

fn svc(t: Tcb, imm: u64) {
    if !super::run::budget_holds(t, crate::timer::now()) {
        restart(t);
        super::run::stop_current(super::run::Stop::BudgetEnd);
        return;
    }
    #[cfg(aspis_test_build)]
    if imm == crate::testing::trap::IMM {
        crate::testing::trap::handle(t);
        return;
    }
    fault::raise(t, Kind::UnknownSyscall, 0x15 << 26 | imm, imm);
}

/// Makes the system call that `t` trapped with run again when `t` next
/// runs: its PC goes back to the `svc`, and its registers still hold the
/// call's arguments (kernel specification, "The kernel lock and long
/// operations"). A call stopped at a preemption point picks up the progress
/// it recorded in its objects; the pending interrupt is taken as the thread
/// returns to EL0, or by the idle loop.
pub fn restart(t: Tcb) {
    t.with(|b| b.ctx.pc -= 4);
    this_core().stats.restarts += 1;
}

/// Whether a data or instruction fault status code (`ESR_EL1.ISS[5:0]`) is
/// one of no mapping, or one without the right: an address size,
/// translation, access-flag or permission fault, at any level.
pub const fn is_unmapped(fsc: u64) -> bool {
    matches!(fsc, 0x00..=0x0f)
}

fn abort(t: Tcb, esr: u64, far: u64) {
    if is_unmapped(esr & 0x3f) {
        fault::raise(t, Kind::Unmapped, esr, far);
    } else {
        fault::raise(t, Kind::UserException, esr, far);
    }
}
