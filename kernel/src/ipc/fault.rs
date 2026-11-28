// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Faults over endpoints (ADR 0056, rules 1 to 3; ADR 0051, rule 1; kernel
//! specification, "Fault delivery"; K50): the bodies of C12's seams.
//!
//! A fault travels as a call the kernel makes on the faulting thread's
//! behalf, so the kernel never buffers a message: the thread waits queued
//! on the endpoint as a sender, with its fault record, until a handler
//! receives, and the message is composed then from the record
//! ([`super::message`]). A fault on the fault endpoint is delivered as a
//! call that donates the thread's context to a passive handler; a timeout
//! or context-withdrawn fault, on the timeout endpoint, as a plain call. A
//! delivered fault ends with no result however it ends, replied to,
//! canceled, or its reply object destroyed, and the thread goes on as its
//! fault's kind allows: after a fault on the fault endpoint it re-executes
//! the instruction, and faults again if the cause remains; after a timeout
//! fault it goes on where its budget ran out, once it has a refill; after
//! a context-withdrawn fault it stays without a context until something
//! gives it one (kernel specification, "Fault delivery"; K50).

use crate::sched::donation::KStore;
use crate::sched::object::Tcb;
use kcap::cap::{Binding, Cap};
use kipc::Ep;
use ksched::donation::Tcb as DTcb;

/// `t` raised a fault, written in its fault record, and `ep` is its copy
/// of its fault endpoint: it waits, sending the fault, delivered at once to
/// a waiting handler, otherwise queued, with the copy's badge.
pub fn raise(t: Tcb, ep: &Cap) {
    let Cap::Endpoint { ptr, badge, .. } = *ep else {
        panic!("thread {:#x}'s fault endpoint is {ep:x?}", t.0);
    };
    kipc::endpoint::fault(&mut KStore::begin(), DTcb(t.0), Ep(ptr), badge);
}

/// `t`, in donation's `Fault` state with its record written, sends a
/// timeout or context-withdrawn fault on its timeout endpoint, if it still
/// has one.
pub fn send_timeout(t: Tcb) {
    if let Cap::Endpoint { ptr, badge, .. } = t.slot_cap(Binding::TimeoutEndpoint.thread_slot()) {
        kipc::endpoint::send_fault(&mut KStore, DTcb(t.0), Ep(ptr), badge);
    }
}

/// `t`'s queued fault leaves its endpoint's queue (K50). A fault already
/// delivered is a call, and never comes here.
pub fn withdraw(t: Tcb) {
    kipc::endpoint::leave(&mut KStore, DTcb(t.0));
}
