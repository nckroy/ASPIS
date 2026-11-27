// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Remote calls and the panic stop's flag (ADR 0052, rule 4; kernel
//! specification, "Cross-core signals and TLB maintenance"). The shared
//! state and its memory order are `ksched::smp::remote`'s.
//!
//! Only the holder of the kernel lock sends a request, so one is in flight.
//! It names the targets, sends each SGI 0, and spins until each is done. A
//! target serves it where it spins for the lock ([`spin`]): it gets there
//! from EL0, since the SGI's entry takes the lock, from its idle loop, or
//! right after its return to EL0. It works on the kernel's state with the
//! lock its requester holds and lends it for the request.
//!
//! The operations:
//!
//! - **Stall** a thread that runs on the target, before the requester
//!   changes it, as seL4's `remoteTCBStall` does. Any change to a thread
//!   current on another core stalls it first ([`stall`]): suspending it,
//!   writing or reading its registers, changing its priority, its spaces,
//!   its endpoints or its context, configuring its context, taking a
//!   donated context back from it, and destroying it. The target charges
//!   the thread's time to its context, as when it stops for any reason
//!   and puts it back in its run queue. A system
//!   call the thread was entering is made to run again: its PC goes back to
//!   the `SVC` (kernel specification, "Cross-core signals and TLB
//!   maintenance").
//! - **Drop an address space** that is being destroyed: the target
//!   deactivates it if its `TTBR0_EL1` holds it, as it may while it runs a
//!   thread in it or idles after one, and stalls its thread if that thread
//!   lost the space (`crate::mm::space`).
//! - **Probe** (test builds): records the target's registers, so the tests
//!   check each core's setup.

use crate::sched::object::Tcb;
use crate::sched::percore::{self, ENTERING_SVC, this_core};
use crate::sched::run::{self, Stop};
use core::sync::atomic::Ordering;
use ksched::smp::remote::{Outcome, Remote};

static REMOTE: Remote = Remote::new();

const STALL: u64 = 1;
const DROP_SPACE: u64 = 2;
#[cfg(aspis_test_build)]
const PROBE: u64 = 3;
#[cfg(aspis_test_build)]
const LOG: u64 = 4;

/// The panic path: every core that spins in the kernel, or idles, stops
/// from now on. Set before the stop SGI is sent.
pub fn stop() {
    REMOTE.stop();
}

/// Whether a panic asked every core to stop.
pub fn stopping() -> bool {
    REMOTE.stopping()
}

/// What every spin in the kernel calls on each turn, on core `index`: the
/// stop first, then a request for this core.
pub fn spin(index: usize) {
    if REMOTE.stopping() {
        crate::irq::stop_this_core();
    }
    REMOTE.serve(index, serve);
}

/// Sends `op` and `arg` to the cores in `targets`, and waits until each has
/// served it. The caller holds the kernel lock.
fn request(targets: u64, op: u64, arg: u64) {
    assert!(
        super::lock::holds_lock(),
        "a remote call is sent without the kernel lock"
    );
    let me = percore::index();
    assert!(
        targets & 1 << me == 0,
        "a core sends a remote call to itself"
    );
    let out = REMOTE.request(
        targets,
        op,
        arg,
        |c| {
            if crate::irq::send_sgi(crate::irq::Sgi::RemoteCall, crate::irq::Target::Core(c))
                .is_err()
            {
                panic!("can't send a remote call to core {c}");
            }
        },
        || {
            if REMOTE.stopping() {
                crate::irq::stop_this_core();
            }
        },
    );
    if out == Outcome::Stopped {
        crate::irq::stop_this_core();
    }
}

/// The core `t` is running on, if that is another core.
pub fn running_elsewhere(t: Tcb) -> Option<usize> {
    let k = t.with(|b| b.s.core) as usize;
    (k != percore::index() && percore::is_ready(k) && percore::core(k).current == t.0).then_some(k)
}

/// Stalls `t` if it runs on another core (module docs): when this returns,
/// it runs nowhere else, and its time there is charged.
pub fn stall(t: Tcb) {
    if let Some(k) = running_elsewhere(t) {
        request(1 << k, STALL, t.0);
    }
}

/// Deactivates the address space with level-0 table `space` on each core in
/// `cores` (module docs).
pub fn drop_space(cores: u64, space: u64) {
    if cores != 0 {
        request(cores, DROP_SPACE, space);
    }
}

/// Serves a request, on its target, with the requester's lock lent.
fn serve(op: u64, arg: u64) {
    let c = this_core();
    c.stats.served += 1;
    c.serving = true;
    serve_op(op, arg);
    this_core().serving = false;
}

fn serve_op(op: u64, arg: u64) {
    match op {
        STALL => {
            if this_core().current == arg {
                stall_current();
            }
        }
        DROP_SPACE => {
            if crate::mm::space::AddressSpace::from_object(arg).is_active() {
                crate::mm::space::deactivate();
            }
            let cur = this_core().current;
            if cur != 0 && !run::eligible(Tcb(cur)) {
                stall_current();
            }
        }
        #[cfg(aspis_test_build)]
        PROBE => probe(),
        #[cfg(aspis_test_build)]
        LOG => crate::klog!(Info, "smp", "a record from core {}", this_core().index),
        _ => panic!("unknown remote call {op}"),
    }
}

/// Stops this core's running thread for a requester: a system call it was
/// entering runs again when it next runs, its time is charged, and it
/// keeps its turn.
fn stall_current() {
    let c = this_core();
    let t = Tcb(c.current);
    if c.entering.swap(0, Ordering::Relaxed) == ENTERING_SVC {
        crate::sched::entry::restart(t);
    }
    run::stop_current(Stop::Preempted);
}

/// Records this core's registers in its [`percore::Probe`].
#[cfg(aspis_test_build)]
fn probe() {
    let vbar: u64;
    // SAFETY: reading VBAR_EL1 has no side effects.
    unsafe {
        core::arch::asm!("mrs {}, vbar_el1", out(reg) vbar, options(nomem, nostack, preserves_flags))
    };
    let irq = crate::irq::get();
    let enabled = |i: kirq::intid::Intid| irq.is_some_and(|g| g.is_enabled(i));
    let p = percore::Probe {
        done: true,
        daif: crate::irq::daif(),
        tpidr: percore::tpidr(),
        vbar,
        cntkctl: crate::timer::kernel_control(),
        count: crate::timer::now(),
        mdscr: crate::sched::boot::debug_controls().0,
        timer_ppi_enabled: crate::timer::intid().is_some_and(enabled),
        sgis_enabled: [
            crate::irq::Sgi::RemoteCall,
            crate::irq::Sgi::Reschedule,
            crate::irq::Sgi::Stop,
        ]
        .iter()
        .all(|s| enabled(s.intid())),
        sctlr: crate::mm::arch::sctlr(),
        ttbr0: crate::mm::arch::ttbr0(),
    };
    this_core().probe = p;
}

/// Probes core `k`, and returns what it recorded (test builds).
#[cfg(aspis_test_build)]
pub fn probe_core(k: usize) -> percore::Probe {
    if k == percore::index() {
        probe();
        return this_core().probe;
    }
    percore::core(k).probe = percore::Probe::default();
    request(1 << k, PROBE, 0);
    percore::core(k).probe
}

/// Has core `k` write a log record (test builds).
#[cfg(aspis_test_build)]
pub fn log_from(k: usize) {
    request(1 << k, LOG, 0);
}
