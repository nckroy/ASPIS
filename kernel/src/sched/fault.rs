// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Raising faults (ADR 0056, rules 1 to 3; ADR 0051, rule 1; kernel
//! specification, "Fault delivery"; K50).
//!
//! A fault is written into the thread's fault record. With an endpoint in
//! the thread's slot for it (slot 3 for faults, slot 4 for timeout and
//! context-withdrawn faults), the thread waits, sending the fault as a call
//! the kernel makes on its behalf: delivered at once to a waiting handler,
//! or queued on the endpoint as a sender, so the kernel never buffers the
//! message (`crate::ipc::fault`, C14). A timeout fault donates no context.
//! Without a fault endpoint, the thread is suspended and the fault logged
//! (ADR 0042, rule 1). Without a timeout endpoint, a budget that runs out
//! waits for its refill instead ([`super::run`]).
//!
//! The handler's reply on the fault's reply object resumes the thread: it
//! re-executes the faulting instruction, or goes on after the call, the
//! trap or the budget end it faulted at. The kernel reads none of the
//! reply's contents (ADR 0061, rule 3), and writes none of the thread's
//! registers. A delivered fault that is canceled, or whose reply object is
//! destroyed, ends the same way, with no result, and the thread goes on as
//! above: a faulting instruction faults again only if its cause remains,
//! and a thread whose context was withdrawn stays without one (K50).

use super::object::{FaultRecord, Tcb, Wait, flag};
use super::run;
use kcap::cap::{Binding, Cap};

/// A fault's kind, as its record numbers it: the methods of
/// `aspis.kernel.fault/1` (kernel specification, "Fault delivery"). The
/// numbers are the kernel's own until C17 publishes the interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Kind {
    Capability = 1,
    /// No mapping for the access, or one without the right (C15 sends a
    /// missing page of a memory object to its pager instead).
    Unmapped = 2,
    UserException = 6,
    UnknownSyscall = 7,
    Timeout = 8,
    Withdrawn = 9,
    Debug = 10,
}

impl Kind {
    pub const fn name(self) -> &'static str {
        match self {
            Kind::Capability => "capability",
            Kind::Unmapped => "unmapped",
            Kind::UserException => "user exception",
            Kind::UnknownSyscall => "unknown system call",
            Kind::Timeout => "timeout",
            Kind::Withdrawn => "context withdrawn",
            Kind::Debug => "debug",
        }
    }

    pub fn from_record(v: u64) -> Option<Kind> {
        Some(match v {
            1 => Kind::Capability,
            2 => Kind::Unmapped,
            6 => Kind::UserException,
            7 => Kind::UnknownSyscall,
            8 => Kind::Timeout,
            9 => Kind::Withdrawn,
            10 => Kind::Debug,
            _ => return None,
        })
    }
}

/// Whether `t` has an endpoint in `role`'s slot.
pub fn has_endpoint(t: Tcb, role: Binding) -> bool {
    matches!(t.slot_cap(role.thread_slot()), Cap::Endpoint { binding: Some(b), .. } if b == role)
}

/// `t` raises a fault of `kind`, with its syndrome and address, at its
/// current PC.
pub fn raise(t: Tcb, kind: Kind, esr: u64, addr: u64) {
    let pc = t.with(|b| b.ctx.pc);
    t.update(|s| {
        s.fault = FaultRecord {
            kind: kind as u64,
            esr,
            pc,
            addr,
            extra: 0,
        }
    });
    if has_endpoint(t, Binding::FaultEndpoint) {
        // The protocol's `FaultWait`, then delivery or a place in the
        // endpoint's queue (`ksched::donation::FaultKind::Endpoint`).
        let ep = t.slot_cap(Binding::FaultEndpoint.thread_slot());
        crate::ipc::fault::raise(t, &ep);
    } else {
        no_handler(t, kind, esr, pc, addr);
    }
    run::place(t);
}

/// A fault with no fault endpoint: the thread is suspended and the fault
/// logged, unless the thread is being destroyed (K50).
fn no_handler(t: Tcb, kind: Kind, esr: u64, pc: u64, addr: u64) {
    t.set(flag::RESUMED, false);
    if t.has(flag::DEAD) {
        return;
    }
    crate::klog!(
        Warning,
        "fault",
        "thread {:#x}: {} fault at PC {pc:#x}, ESR {esr:#x}, address {addr:#x}; no fault endpoint, so it is suspended",
        t.0,
        kind.name()
    );
}

// A timeout fault and a context-withdrawn fault are `ksched::donation`'s
// (`super::donation`): the protocol sets the thread's wait, and the kernel
// writes the fault record and sends it (`crate::ipc::fault`). A timeout
// fault carries its context's badge and the time its context has used,
// donates nothing, and waits for the handler's reply, not for its refill
// (ADR 0051, rule 1; seL4 17.0.0's `handleTimeout`). A context-withdrawn
// fault carries the withdrawn context's badge (ADR 0056, rule 3).

/// The thread's copy of an endpoint in `role` is being removed (its unbind
/// step). A fault still queued on that endpoint is withdrawn (K50): the
/// thread is then one with no such endpoint. Without a fault endpoint it is
/// suspended and the fault logged; without a timeout endpoint, a timeout
/// fault becomes a wait for the refill, and a context-withdrawn fault a
/// silent strand (K08).
pub fn unbind_endpoint(t: Tcb, role: Binding) {
    if role == Binding::TimeoutEndpoint {
        // K08 and K50 through the protocol: from now on the thread gets no
        // timeout or context-withdrawn fault.
        super::donation::timeout_endpoint_removed(t);
        return;
    }
    // The fault endpoint, then: a context is no endpoint.
    if role != Binding::FaultEndpoint || t.wait() != Wait::FaultSend {
        return;
    }
    // Out of the endpoint's queue, with no result: the thread is then one
    // with no fault endpoint.
    let _ = super::donation::wake(t, ksched::donation::Res::None);
    let f = t.with(|b| b.s.fault);
    let kind = Kind::from_record(f.kind).unwrap_or(Kind::UserException);
    no_handler(t, kind, f.esr, f.pc, f.addr);
    run::place(t);
}
