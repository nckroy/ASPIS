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
//! - [`fault`]: raising faults, which C14's IPC carries to their handlers.
//! - [`donation`]: reply objects, donation along chains of calls, and taking
//!   a context back, over `ksched::donation`, whose store C14's IPC runs
//!   `kipc` over.
//! - [`entry`]: the kernel entry from EL0.
//! - [`boot`]: the boot core's setup, and the first thread.
//!
//! **Every core** has its own data, run queues, trees and work list
//! ([`percore`]), and runs its own scheduler, under the one kernel lock;
//! `crate::smp` holds the lock, remote calls and the bring-up.
//!
//! **The test trap.** Until C17's system-call ABI exists, the in-QEMU tests'
//! EL0 programs reach the kernel through `svc #0x7e57`, in test builds only
//! (`crate::testing::trap`), which calls C14's decoded IPC calls
//! (`crate::ipc::syscall`); `cargo xtask check-production` checks that
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
    /// Stopped at a preemption point while deleting a capability, with
    /// its progress recorded: make the call again (C14; ADR 0052, rule 2).
    Preempted,
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
/// A thread stops for good. Returns the units it took: those of the waits
/// it ends, a take-back's included (K23), at least 1.
pub fn zombify(cap: &Cap) -> u32 {
    match Tcb::of(cap) {
        Some(t) => thread::zombify(t),
        None => 1,
    }
}

/// `kcap`'s unbind hook, for a thread's binding in `slot`: its role says
/// what to undo, and the thread is the object that holds the slot. Returns
/// the units it took: 1, or a context's take-back's (K23).
pub fn unbind(slot: SlotRef, cap: &Cap) -> u32 {
    let t = Tcb::holding(slot);
    match cap.binding() {
        Some(Binding::Context) => return thread::unbind_context_step(t, cap),
        Some(role @ (Binding::FaultEndpoint | Binding::TimeoutEndpoint)) => {
            fault::unbind_endpoint(t, role)
        }
        // C14's thread roles: the bound eventcount's node leaves its tree,
        // and a receive goes on on the endpoint alone; the IPC buffer is
        // unregistered (K29).
        Some(Binding::BoundEventcount) => crate::ipc::unbind_bound(t),
        Some(Binding::IpcBuffer) => crate::ipc::buffer::unbind(t),
        Some(Binding::WaitSetEntry) | None => panic!(
            "unbind of {cap:x?} at {:#x}, which isn't a thread's binding",
            slot.0
        ),
    }
    1
}

/// `kcap`'s finish hook, for C12's kinds. Returns the units it took: 1, or
/// for a reply object or a context, its take-back's (K23).
pub fn finish(cap: &Cap) -> u32 {
    match *cap {
        Cap::SchedContext { ptr, .. } => return context::finish(ptr),
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
        // A reply object: a pending call on it, or a receive with it, ends
        // "object destroyed" (K30), and a walk that has it takes its step
        // at once.
        Cap::Reply { ptr, .. } => return donation::destroy_reply(object::Rp(ptr)),
        // Scheduling control names no memory.
        _ => {}
    }
    1
}

/// The timer's hook (`timer::hooks::deadline_reached`).
pub fn timer_fired() {
    run::timer_fired();
}

/// Sets up the scheduler on the boot core, after `timer::init`.
pub fn init() {
    boot::init();
}
