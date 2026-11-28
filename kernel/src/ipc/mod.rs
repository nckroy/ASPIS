// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! IPC endpoints, eventcounts and wait sets (C14; ADR 0053; ADR 0054;
//! kernel specification, "IPC" and "Eventcounts"). The pure logic is in
//! the `kipc` crate, tested on the host; this module runs it on the
//! kernel's objects, as `crate::sched::donation` runs `ksched::donation`.
//!
//! - [`object`]: the layouts of endpoints, eventcounts, wait sets and a
//!   thread's IPC state, and the views of them.
//! - [`store`]: `kipc`'s store over them, which is the donation store too.
//! - [`endpoint`]: the endpoint operations, with deadlines; canceling a
//!   badge's sends; draining a destroyed endpoint.
//! - [`message`]: copying messages, replies and fault messages, and
//!   capability transfer (K28).
//! - [`buffer`]: IPC buffer registration (K29).
//! - [`eventcount`]: eventcounts, the advance and its work-list units
//!   (K24, K31), and threads bound to an eventcount.
//! - [`waitset`]: wait sets (K08, K32, K33).
//! - [`fault`]: faults over endpoints.
//! - [`syscall`]: the calls, decoded from registers: what the test trap
//!   calls now, and C17's entry table later.
//!
//! **The seams the rest of the kernel calls.** The capability layer passes
//! C14's kinds here: an endpoint's or an eventcount's queue zombie is
//! drained one waiter per deletion step ([`drain`]) and then finished
//! ([`finish`]); a wait set's zombify ends its wait and unlinks its
//! entries ([`zombify`]); a wait-set entry's unbind step unlinks its node
//! ([`unbind_entry`]); a thread's bound eventcount's unbind step unlinks the
//! thread's node ([`unbind_bound`]). The donation store asks it to take a
//! thread out of an endpoint's queue or an eventcount's tree when its wait
//! ends ([`cancel_wait`]), and what ending a wait costs ([`wait_cost`]).
//! A core's batch runs an eventcount's pending wakes from its work list
//! ([`eventcount::work_unit`], at [`eventcount::unit_cost`]; K24), beside
//! the walks of take-backs. Binding a context to a thread tells a bound
//! receiver it may now hear its eventcount ([`eventcount::context_bound`]).
//!
//! **Seams for later chunks.** C13b: an interrupt's advance
//! ([`eventcount::advance_for_interrupt`]), and the handler's eventcount
//! binding. C15: memory objects behind IPC buffers
//! ([`buffer::Backing`]), the receiver's page marked dirty, word waits on
//! the same nodes, trees and costs, and `aspis.kernel.fault/1` in place of
//! the provisional fault message. C16: the job check of a buffer, and
//! memory requests as one-way kernel messages. C17: the system-call entry
//! and numbers around [`syscall`]. C70: a debugger reads a thread's wait
//! and its IPC state.

pub mod buffer;
#[cfg(aspis_test_build)]
mod ec_tests;
pub mod endpoint;
pub mod eventcount;
pub mod fault;
pub mod message;
pub mod object;
pub mod store;
pub mod syscall;
#[cfg(aspis_test_build)]
pub mod testkit;
#[cfg(aspis_test_build)]
mod tests;
pub mod waitset;

use crate::sched::donation::KStore;
use crate::sched::object::Tcb;
use kcap::SlotRef;
use kcap::cap::{Cap, ZombieKind};
use kipc::{Ec, Ws};
use ksched::donation::Tcb as DTcb;

/// Takes `t` out of the endpoint queue, badge tree or eventcount trees its
/// wait has it in, if any (K17); a thread in none is left as it is.
pub fn cancel_wait(t: Tcb) {
    kipc::cancel_wait(&mut KStore, DTcb(t.0));
}

/// The units ending `t`'s wait costs (K23, K24): one, or for a wait on a
/// wait set, the nodes it unlinks.
pub fn wait_cost(t: Tcb) -> u32 {
    kipc::wait_cost(&KStore, DTcb(t.0))
}

/// One step of an endpoint's or an eventcount's queue zombie: releases one
/// waiter (K30), and returns true when none is left.
pub fn drain(zombie: &Cap) -> bool {
    match *zombie {
        Cap::Zombie {
            kind: ZombieKind::Endpoint,
            ptr,
            ..
        } => endpoint::drain(ptr),
        Cap::Zombie {
            kind: ZombieKind::Eventcount,
            ptr,
            ..
        } => kipc::eventcount::drain(&mut KStore::begin(), Ec(ptr)),
        _ => panic!("drain of {zombie:x?}, which isn't a queue zombie"),
    }
}

/// A wait set's last capability becomes a zombie: its wait, if any, ends
/// "object destroyed", and its entries leave their eventcounts' trees.
/// Returns the units it took: one, and one per node it unlinks.
pub fn zombify(cap: &Cap) -> u32 {
    let Cap::WaitSet { ptr, bits, .. } = *cap else {
        return 1;
    };
    object::init_set(ptr, bits);
    kipc::eventcount::ws_zombify(&mut KStore::begin(), Ws(object::ws_name(ptr, bits)))
}

/// An endpoint, eventcount or wait set is finished: its queue is empty, or
/// its slots are clear. An eventcount leaves its core's work list first, so
/// its memory can be retyped with nothing pointing into it (K24).
pub fn finish(cap: &Cap) {
    match *cap {
        Cap::Zombie {
            kind: ZombieKind::Endpoint,
            ptr,
            ..
        } => endpoint::finish(ptr),
        Cap::Zombie {
            kind: ZombieKind::Eventcount,
            ptr,
            ..
        } => kipc::eventcount::finish(&mut KStore, Ec(ptr)),
        // A wait set's entries were unbound as its slots were cleared, and
        // its wait ended at its zombify.
        _ => {}
    }
}

/// A wait-set entry's copy of its eventcount, in `slot`, is being deleted:
/// its node leaves the eventcount's tree, and a wait on the set goes on on
/// the other entries (K08).
pub fn unbind_entry(slot: SlotRef, cap: &Cap) {
    let Cap::Eventcount { set_bits, .. } = *cap else {
        panic!("unbind of {cap:x?} as a wait-set entry");
    };
    let ws = slot.0 & !((1u64 << set_bits) - 1);
    let i = ((slot.0 - ws) / kcap::SLOT_SIZE - 1) as usize;
    object::init_set(ws, set_bits);
    kipc::eventcount::unbind_entry(&mut KStore, Ws(object::ws_name(ws, set_bits)), i);
}

/// Thread `t`'s copy of its bound eventcount, in slot 6, is being deleted
/// (its unbind step): a receive in progress goes on, on the endpoint alone
/// (ADR 0053, rule 5).
pub fn unbind_bound(t: Tcb) {
    kipc::eventcount::unbind(&mut KStore, DTcb(t.0));
}
