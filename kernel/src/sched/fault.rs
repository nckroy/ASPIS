// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Raising faults (ADR 0056, rules 1 to 3; ADR 0051, rule 1; kernel
//! specification, "Fault delivery"; K50).
//!
//! A fault is written into the thread's fault record. With an endpoint in
//! the thread's slot for it (slot 3 for faults, slot 4 for timeout and
//! context-withdrawn faults), the thread waits, sending the fault, and
//! C14's IPC queues it on the endpoint as a sender ([`seam::queue_fault`]),
//! so the kernel never buffers the message. A timeout fault donates no
//! context. Without a fault endpoint, the thread is suspended and the fault
//! logged (ADR 0042, rule 1). Without a timeout endpoint, a budget that runs
//! out waits for its refill instead ([`super::run`]).
//!
//! The handler's reply resumes the thread ([`reply`]): C14's reply on the
//! fault's reply object calls it. The kernel reads none of the reply's
//! contents (ADR 0061, rule 3). Until C14, the tests call it.

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

/// The seams C14 fills: the IPC that carries a fault to its handler.
pub mod seam {
    use super::Tcb;
    use kcap::cap::Cap;

    /// `t` now sends its fault on the endpoint `ep`, its own copy: C14
    /// queues it as a sender, with the copy's badge. In C12 nothing is
    /// queued: the tests look at the thread itself, and at the order the
    /// faults were sent in ([`sent`]).
    pub fn queue_fault(_ep: &Cap, _t: Tcb) {
        #[cfg(aspis_test_build)]
        {
            let i = SENT_N.fetch_add(1, Ordering::Relaxed);
            if let Some(s) = SENT.get(i) {
                s.store(_t.0, Ordering::Relaxed);
            }
        }
    }

    #[cfg(aspis_test_build)]
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    /// The threads whose faults were queued, in order (test builds).
    #[cfg(aspis_test_build)]
    static SENT: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
    #[cfg(aspis_test_build)]
    static SENT_N: AtomicUsize = AtomicUsize::new(0);

    /// The `i`th fault queued since [`clear_sent`] (test builds).
    #[cfg(aspis_test_build)]
    pub fn sent(i: usize) -> Option<Tcb> {
        (i < SENT_N.load(Ordering::Relaxed))
            .then(|| SENT.get(i).map(|s| Tcb(s.load(Ordering::Relaxed))))
            .flatten()
    }

    /// How many faults were queued since [`clear_sent`] (test builds).
    #[cfg(aspis_test_build)]
    pub fn sent_count() -> usize {
        SENT_N.load(Ordering::Relaxed)
    }

    #[cfg(aspis_test_build)]
    pub fn clear_sent() {
        SENT_N.store(0, Ordering::Relaxed);
    }

    /// `t`'s queued fault is withdrawn from its endpoint `ep` (K50): C14
    /// removes it from the endpoint's queue. A fault already delivered
    /// stands until its reply object is replied to or destroyed.
    pub fn withdraw_fault(_ep: &Cap, _t: Tcb) {}
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
    let ep = t.slot_cap(Binding::FaultEndpoint.thread_slot());
    if has_endpoint(t, Binding::FaultEndpoint) {
        t.update(|s| s.wait = Wait::FaultSend as u8);
        seam::queue_fault(&ep, t);
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
// writes the fault record and queues it ([`seam::queue_fault`]). A timeout
// fault carries its context's badge and the time its context has used,
// donates nothing, and waits for the handler's reply, not for its refill
// (ADR 0051, rule 1; seL4 17.0.0's `handleTimeout`). A context-withdrawn
// fault carries the withdrawn context's badge (ADR 0056, rule 3).

/// The handler replied to `t`'s fault: it resumes, and re-executes the
/// faulting instruction, or goes on after the call, the trap or the budget
/// end it faulted at. Returns false if `t` isn't sending a fault.
pub fn reply(t: Tcb) -> bool {
    match t.wait() {
        Wait::TimeoutSend | Wait::WithdrawnSend => {
            return super::donation::fault_replied(t).is_ok();
        }
        Wait::FaultSend => {}
        _ => return false,
    }
    t.update(|s| s.wait = Wait::None as u8);
    if let Some(sc) = t.sc()
        && sc.is_configured()
    {
        let now = crate::timer::now();
        sc.refills(|r| r.unblock(now));
    }
    run::place(t);
    true
}

/// The thread's copy of an endpoint in `role` is being removed (its unbind
/// step). A fault still queued on that endpoint is withdrawn (K50): the
/// thread is then one with no such endpoint. Without a fault endpoint it is
/// suspended and the fault logged; without a timeout endpoint, a timeout
/// fault becomes a wait for the refill, and a context-withdrawn fault a
/// silent strand (K08).
pub fn unbind_endpoint(t: Tcb, role: Binding, ep: &Cap) {
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
    seam::withdraw_fault(ep, t);
    t.update(|s| s.wait = Wait::None as u8);
    let f = t.with(|b| b.s.fault);
    let kind = Kind::from_record(f.kind).unwrap_or(Kind::UserException);
    no_handler(t, kind, f.esr, f.pc, f.addr);
    run::place(t);
}
