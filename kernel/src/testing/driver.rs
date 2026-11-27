// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Running threads from a test (test builds only; kernel
//! specification, "Until C17: the test trap").
//!
//! A test body runs on the boot stack, in `kernel_main`'s context. To run
//! EL0 threads, [`run_until`] saves the body's callee-saved registers and
//! stack pointer, switches to the boot core's entry stack, and enters the
//! scheduler's exit path, which runs threads, takes their traps and
//! interrupts, and idles, as it always does. At every pass the exit path
//! asks [`check`] whether the condition holds or the time is up; then the
//! running thread is preempted, keeping its turn, and the body resumes
//! where it called [`run_until`]. Nothing else changes: the threads stay
//! queued until the test destroys them.
//!
//! IRQs stay masked throughout, outside the scheduler's own entries. The
//! test body holds the kernel lock, as the boot core does for any kernel
//! code; the scheduler releases it while threads run and while the core
//! idles, so the other cores run their threads meanwhile. Only the core
//! that called [`run_until`] checks its condition, and it wakes at least
//! every millisecond to do so, since the condition may be met on another
//! core.

use crate::mm::BootCell;
use crate::sched::percore;
use crate::sched::run::{self, Stop};
use core::arch::global_asm;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// x19 to x30, `sp`, and d8 to d15: what the AAPCS64 asks a callee to keep.
type Saved = [u64; 21];

static SAVED: BootCell<Saved> = BootCell::new([0; 21]);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static DEADLINE: AtomicU64 = AtomicU64::new(0);
static COND: BootCell<Option<fn() -> bool>> = BootCell::new(None);
/// The core that called [`run_until`].
static CORE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// How often the waiting core checks the condition: 1 ms.
fn poll() -> u64 {
    crate::timer::frequency() / 1000
}

fn mine() -> bool {
    ACTIVE.load(Ordering::Relaxed) && CORE.load(Ordering::Relaxed) == percore::index()
}

global_asm!(
    ".section .text.aspis_driver, \"ax\"",
    // aspis_driver_enter(save, stack): saves the caller's callee-saved
    // registers and stack pointer, then enters the scheduler on `stack`.
    // It returns 1 when aspis_driver_leave restores them.
    ".global aspis_driver_enter",
    "aspis_driver_enter:",
    "    stp x19, x20, [x0, #0]",
    "    stp x21, x22, [x0, #16]",
    "    stp x23, x24, [x0, #32]",
    "    stp x25, x26, [x0, #48]",
    "    stp x27, x28, [x0, #64]",
    "    stp x29, x30, [x0, #80]",
    "    mov x2, sp",
    "    str x2, [x0, #96]",
    "    stp d8, d9, [x0, #104]",
    "    stp d10, d11, [x0, #120]",
    "    stp d12, d13, [x0, #136]",
    "    stp d14, d15, [x0, #152]",
    "    mov sp, x1",
    "    mov x29, #0",
    "    bl aspis_driver_main",
    "    brk #0",
    // aspis_driver_leave(save): back into aspis_driver_enter's caller.
    ".global aspis_driver_leave",
    "aspis_driver_leave:",
    "    ldp x19, x20, [x0, #0]",
    "    ldp x21, x22, [x0, #16]",
    "    ldp x23, x24, [x0, #32]",
    "    ldp x25, x26, [x0, #48]",
    "    ldp x27, x28, [x0, #64]",
    "    ldp x29, x30, [x0, #80]",
    "    ldr x2, [x0, #96]",
    "    mov sp, x2",
    "    ldp d8, d9, [x0, #104]",
    "    ldp d10, d11, [x0, #120]",
    "    ldp d12, d13, [x0, #136]",
    "    ldp d14, d15, [x0, #152]",
    "    mov x0, #1",
    "    ret",
);

unsafe extern "C" {
    fn aspis_driver_enter(save: *mut Saved, stack: u64) -> u64;
    fn aspis_driver_leave(save: *const Saved) -> !;
}

/// The scheduler, entered on the entry stack.
#[unsafe(no_mangle)]
extern "C" fn aspis_driver_main() -> ! {
    run::exit()
}

/// Runs threads until `cond` holds, or for at most `counts` of the virtual
/// count, and says whether `cond` held.
pub fn run_until(cond: fn() -> bool, counts: u64) -> bool {
    if cond() {
        return true;
    }
    assert!(
        !ACTIVE.swap(true, Ordering::Relaxed),
        "run_until doesn't nest"
    );
    CORE.store(percore::index(), Ordering::Relaxed);
    // SAFETY: the boot core's test body is the only user; the scheduler
    // reads it in `check`, after this write, on the same core.
    unsafe { *COND.get_mut() = Some(cond) };
    DEADLINE.store(
        crate::timer::now().saturating_add(counts),
        Ordering::Relaxed,
    );
    // SAFETY: the save area is the driver's own; the entry stack is the
    // boot core's, unused while the kernel runs on the boot stack; the
    // scheduler returns here through `aspis_driver_leave` with every
    // callee-saved register as it was.
    unsafe { aspis_driver_enter(SAVED.get_mut(), percore::tpidr()) };
    // The threads stop; nothing is armed for them while the test body runs.
    crate::timer::disarm();
    cond()
}

/// While [`run_until`] waits, on its core, the compare value it needs: its
/// time limit, or the next poll if that comes first.
pub fn deadline() -> Option<u64> {
    mine().then(|| {
        DEADLINE
            .load(Ordering::Relaxed)
            .min(crate::timer::now().saturating_add(poll()))
    })
}

/// Called by the exit path at every pass: if [`run_until`] waits and its
/// condition holds or its time is up, preempts the running thread and
/// returns to the test body.
pub fn check(now: u64) {
    if !mine() {
        return;
    }
    // SAFETY: written by `run_until` before it entered the scheduler.
    let cond = unsafe { *COND.get() };
    let done = cond.is_some_and(|c| c()) || now >= DEADLINE.load(Ordering::Relaxed);
    if !done {
        return;
    }
    run::stop_current(Stop::Preempted);
    ACTIVE.store(false, Ordering::Relaxed);
    // SAFETY: `run_until` filled the save area before it entered the
    // scheduler, and its frame on the boot stack is still live.
    unsafe { aspis_driver_leave(SAVED.get()) }
}
