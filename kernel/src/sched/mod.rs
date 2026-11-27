// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Threads and scheduling (C12; ADR 0047, rules 2 and 3; ADR 0051, rules 1,
//! 2, 3 and 5; ADR 0052, rules 2 and 3; ADR 0061, rule 3; kernel
//! specification, "Threads and scheduling"). The pure logic is in the
//! `ksched` crate, tested on the host; this module runs it on the kernel's
//! objects.
//!
//! - [`object`]: the thread and scheduling-context layouts.
//! - [`percore`]: each core's data and entry stack.
//! - [`run`]: run queues, release and deadline trees, charging, the exit
//!   path and the tickless timer.
//! - [`thread`]: the operations on a thread through its capability.
//! - [`context`]: configuring scheduling contexts through scheduling
//!   control, and the share check's root-job stand-in.
//! - [`fault`]: raising faults, and the seam C14's IPC fills.
//! - [`donation`]: reply objects, donation along chains of calls, and taking
//!   a context back, over `ksched::donation`; the seams C14's call, reply
//!   and receive use.
//! - [`entry`]: the kernel entry from EL0.
//! - [`boot`]: the boot core's setup, and the first thread.
//!
//! **Every core** has its own data, run queues, trees and work list
//! ([`percore`]), and runs its own scheduler, under the one kernel lock;
//! `crate::smp` holds the lock, remote calls and the bring-up.
//!
//! **The test trap.** Until C17's system-call ABI exists, the in-QEMU tests'
//! EL0 programs reach the kernel through `svc #0x7e57`, in test builds only
//! (`crate::testing::trap`); `cargo xtask check-production` checks that
//! production images hold none of it. C17 replaces it.

pub mod boot;
pub mod context;
pub mod donation;
#[cfg(aspis_test_build)]
mod donation_tests;
pub mod entry;
pub mod fault;
pub mod object;
pub mod percore;
pub mod run;
#[cfg(aspis_test_build)]
pub mod testkit;
#[cfg(aspis_test_build)]
mod tests;
pub mod thread;

use kcap::SlotRef;
use kcap::cap::{Binding, Cap, ZombieKind};
use object::Tcb;

/// Why a scheduling operation failed. Nothing was changed. The names are
/// internal until C17 (K30).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A capability was missing, or a slot not as the operation needs it.
    Cap(kcap::ops::Error),
    /// A capability of the wrong kind.
    WrongKind,
    /// A capability without a right the operation needs.
    MissingRight,
    /// The thread already has a context, or the context is bound to another
    /// thread.
    Busy,
    /// The thread has no context of its own to unbind.
    NotBound,
    /// The value exceeds the authority's maximum controlled priority.
    Priority,
    /// A budget or period outside the limits.
    Limits(ksched::time::Invalid),
    /// More refills than the context can hold (K15).
    TooManyRefills,
    /// The share check refused it (K13).
    Share(ksched::share::Refused),
    /// The scheduling control names a core that isn't online.
    CoreOffline,
    /// The thread isn't waiting.
    NotWaiting,
}

impl From<ksched::donation::Error> for Error {
    fn from(e: ksched::donation::Error) -> Error {
        use ksched::donation::Error as D;
        match e {
            D::NotWaiting => Error::NotWaiting,
            D::NotBound => Error::NotBound,
            _ => Error::Busy,
        }
    }
}

/// `kcap`'s zombify hook: an object with slots is about to become a zombie.
/// A thread stops for good.
pub fn zombify(cap: &Cap) {
    if let Some(t) = Tcb::of(cap) {
        thread::zombify(t);
    }
}

/// `kcap`'s unbind hook, for a thread's binding in `slot`: its role says
/// what to undo, and the thread is the object that holds the slot.
pub fn unbind(slot: SlotRef, cap: &Cap) {
    let t = Tcb::holding(slot);
    match cap.binding() {
        Some(Binding::Context) => thread::unbind_context_step(t, cap),
        Some(role) => fault::unbind_endpoint(t, role, cap),
        None => panic!(
            "unbind of {cap:x?} at {:#x}, which isn't a thread's binding",
            slot.0
        ),
    }
}

/// `kcap`'s finish hook, for C12's kinds.
pub fn finish(cap: &Cap) {
    match *cap {
        Cap::SchedContext { ptr, .. } => context::finish(ptr),
        Cap::Zombie {
            kind: ZombieKind::Thread,
            ptr,
            ..
        } => {
            // Its zombify hook stopped it and cleared its donation links:
            // no reply object names it, and it holds no context.
            let t = Tcb(ptr);
            let s = t.state();
            assert!(
                s.flags & object::flag::QUEUED == 0
                    && s.sc == 0
                    && s.serving_reply == 0
                    && s.waiting_reply == 0,
                "a thread was finished while it could still run or was linked"
            );
        }
        // A reply object: a pending call on it is canceled, and a walk that
        // has it takes its step at once.
        Cap::Reply { ptr, .. } => donation::destroy_reply(object::Rp(ptr)),
        // Scheduling control names no memory.
        _ => {}
    }
}

/// The timer's hook (`timer::hooks::deadline_reached`).
pub fn timer_fired() {
    run::timer_fired();
}

/// Sets up the scheduler on the boot core, after `timer::init`.
pub fn init() {
    boot::init();
}
