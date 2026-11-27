// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The layouts of a thread and a scheduling context, and the kernel's views
//! of them through the direct map (kernel specification, "Untyped memory
//! and kernel records", K07 and K15).
//!
//! **A thread** is 2 KiB, aligned to its size:
//!
//! | Offset | Size | Contents |
//! |---|---|---|
//! | 0x000 | 256 | Eight capability slots: 0 park, 1 root CNode, 2 address space, 3 fault endpoint, 4 timeout endpoint, 5 scheduling context, 6 bound eventcount (C14), 7 IPC buffer (C14, K29) |
//! | 0x100 | 280 | The saved user context: x0 to x30, `SP_EL0`, the PC (`ELR_EL1`), `SPSR_EL1` and `TPIDR_EL0` |
//! | 0x218 | 8 | Padding |
//! | 0x220 | 528 | FP and SIMD: q0 to q31, `FPCR`, `FPSR` |
//! | 0x430 | 208 | [`SchedState`] |
//! | 0x500 | 768 | Kept for C14 (endpoint queue, IPC buffer), C15 (page wait), C16 (the job's thread list) and C70 (debug state) |
//!
//! While a thread runs at EL0, `SP_EL1` points at its saved context, so the
//! EL0 vectors store its registers straight into it, as seL4's AArch64 entry
//! does ([`crate::exceptions`]).
//!
//! **A scheduling context** is 2^8 to 2^12 bytes: a 192-byte [`ScHeader`],
//! then 16-byte refills, so it holds 4, 20, 52, 116 or 244 refills (K15).
//!
//! **A reply object** is 128 bytes: [`ReplyObj`], the donation fields that
//! `ksched::donation` keeps, its node in the walk tree and its links on a
//! core's work list.
//!
//! Retype makes both from zeroed memory, and zero is each one's initial
//! state: a thread suspended, ready, at priority 0 with maximum controlled
//! priority 0, with no context and zeroed registers; a context unconfigured,
//! so nothing runs on it.

use crate::mm::phys::{DirectMem, Window};
use core::mem::{offset_of, size_of};
use kcap::SlotRef;
use kcap::cap::{Cap, SlotArray};
use kmem::untyped::THREAD_BITS;
use ksched::refill::{Refill, Refills, State as RefillState};
use ksched::runq::QLinks;
use ksched::tree::Links;

/// Where the saved user context starts in a thread.
pub const TCB_CONTEXT: u64 = 0x100;
/// Where the FP and SIMD state starts, from the saved context.
pub const CONTEXT_FP: u64 = 0x120;
/// The size of a thread.
pub const TCB_SIZE: u64 = 1 << THREAD_BITS;
/// Where the scheduling state starts in a thread.
pub const TCB_SCHED: u64 = 0x430;
/// The most the scheduling state may take: up to the reserve at 0x500.
pub const SCHED_STATE_MAX: usize = 0x500 - 0x430;
/// The size of a scheduling context's header.
pub const SC_HEADER: u64 = 192;
/// The size of one refill.
pub const REFILL_SIZE: u64 = 16;

/// The saved user registers, as the EL0 vectors store them.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserContext {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub spsr: u64,
    pub tpidr: u64,
}

/// The saved FP and SIMD registers.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FpState {
    pub q: [u128; 32],
    pub fpcr: u64,
    pub fpsr: u64,
}

/// A thread's wait (kernel specification, "Passive servers and taking a context back";
/// K17). [`Wait::None`] is a thread that is running,
/// ready, or stranded without a context.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum Wait {
    #[default]
    None = 0,
    /// Sending a fault on its fault endpoint, and waiting for the reply
    /// (ADR 0056, rule 1). C14 queues the thread on the endpoint.
    FaultSend = 1,
    /// Sending a timeout fault on its timeout endpoint (ADR 0051, rule 1).
    TimeoutSend = 2,
    /// Sending a context-withdrawn fault (ADR 0056, rule 3; C12's stage 3).
    WithdrawnSend = 3,
    /// A test build's sleep: the stand-in for C14's waits, with a deadline
    /// or none. Never in production.
    TestSleep = 4,
    /// Waiting to receive a call, with a reply object
    /// ([`SchedState::waiting_reply`]): C14's receive on an endpoint wraps
    /// it.
    Receive = 5,
    /// Waiting for the reply to its call, on the server's reply object
    /// ([`SchedState::waiting_reply`]).
    Call = 6,
    // C14: Send, Eventcount and WaitSet. C15: Page. C16: Memory. Each chunk
    // fills in its own cancel, through `super::donation`'s `cancel_other`
    // (K17).
}

impl Wait {
    pub const fn from_u8(v: u8) -> Wait {
        match v {
            1 => Wait::FaultSend,
            2 => Wait::TimeoutSend,
            3 => Wait::WithdrawnSend,
            4 => Wait::TestSleep,
            5 => Wait::Receive,
            6 => Wait::Call,
            _ => Wait::None,
        }
    }

    /// Whether the wait is a system call's, whose result goes into the
    /// thread's x0 when it ends. A fault send isn't: the thread re-executes
    /// its instruction, or goes on where its budget ran out, with its
    /// registers as they were.
    pub const fn is_call(self) -> bool {
        matches!(self, Wait::TestSleep | Wait::Receive | Wait::Call)
    }
}

/// How a wait ended, written into the thread's x0 at once, and seen when it
/// next runs (K20). The numbers are the test trap's; C17's ABI names them
/// (K30).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Ended {
    Done = 0,
    Canceled = 1,
    TimedOut = 2,
}

/// The fault a thread raised, kept in the thread until its handler replies
/// (kernel specification, "Fault delivery").
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FaultRecord {
    /// The kind, as [`crate::sched::fault::Kind`] numbers it; 0 for none.
    pub kind: u64,
    pub esr: u64,
    pub pc: u64,
    /// The faulting address, a call's number, or a context's badge.
    pub addr: u64,
    /// The time used, for a timeout fault, in counts.
    pub extra: u64,
}

/// A thread's flags.
pub mod flag {
    /// Resumed: not suspended (ADR 0061, rule 3). Zero, as retype makes a
    /// thread, is suspended.
    pub const RESUMED: u8 = 1 << 0;
    /// In a run queue.
    pub const QUEUED: u8 = 1 << 1;
    /// In its core's deadline tree.
    pub const DEADLINE: u8 = 1 << 2;
    /// Its object is a zombie: it never runs again, and its slots' unbinds
    /// log nothing (K50).
    pub const DEAD: u8 = 1 << 3;
    /// It ended its test program (test builds).
    pub const DONE: u8 = 1 << 4;
}

/// A thread's scheduling state, at [`TCB_SCHED`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SchedState {
    pub wait: u8,
    pub flags: u8,
    pub priority: u8,
    /// Its maximum controlled priority (ADR 0051, rule 2).
    pub mcp: u8,
    /// The core it is queued on, or last ran on (K18).
    pub core: u8,
    /// How its last wait ended, as `ksched::donation::Res` numbers it,
    /// until its next wait starts (K20).
    pub result: u8,
    pub _pad: [u8; 2],
    /// The context it runs on, its own or one donated to it, by physical
    /// address; 0 for none.
    pub sc: u64,
    /// Its run-queue links.
    pub q: QLinks,
    /// Its deadline, a value of the virtual count; 0 for none (ADR 0064,
    /// rule 5).
    pub deadline: u64,
    /// Its node in its core's deadline tree.
    pub dl: Links,
    pub fault: FaultRecord,
    /// The reply object it waits on, receiving or calling, and the donating
    /// one it serves (`super::donation`).
    pub waiting_reply: u64,
    pub serving_reply: u64,
    /// The context bound to it, its home one, in slot 5; 0 for none.
    pub home: u64,
    /// Kept for C13b and C14: a thread's links on a core's work list.
    pub work: [u64; 2],
    /// A test's tag for the thread (test builds).
    pub test_tag: u64,
    /// Kept: at least two spare words (K07).
    pub spare: [u64; 2],
}

/// A thread's state after its slots.
#[repr(C)]
pub struct Body {
    pub ctx: UserContext,
    _pad: u64,
    pub fp: FpState,
    pub s: SchedState,
}

const _: () = assert!(offset_of!(Body, fp) as u64 == CONTEXT_FP);
const _: () = assert!(TCB_CONTEXT + offset_of!(Body, s) as u64 == TCB_SCHED);
const _: () = assert!(size_of::<SchedState>() <= SCHED_STATE_MAX);
const _: () = assert!(TCB_CONTEXT + size_of::<Body>() as u64 <= 0x500);
const _: () = assert!(size_of::<UserContext>() == 280);
const _: () = assert!(size_of::<FpState>() == 528);
// The vectors' offsets (`crate::exceptions`) depend on these.
const _: () = assert!(offset_of!(UserContext, sp) == 248);
const _: () = assert!(offset_of!(UserContext, spsr) == 264);

/// A context's flags.
pub mod sc_flag {
    /// Configured: it has a budget, a period and a core.
    pub const CONFIGURED: u8 = 1 << 0;
    /// In its core's release tree.
    pub const RELEASE: u8 = 1 << 1;
}

/// A scheduling context's header.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ScHeader {
    pub refill: RefillState,
    /// The configured budget and period, in microseconds, for the share
    /// check (K13).
    pub budget_us: u64,
    pub period_us: u64,
    /// The badge its timeout and context-withdrawn faults report.
    pub badge: u64,
    /// The counts its threads have used, in total.
    pub consumed: u64,
    /// The thread that holds it, its home thread (whose slot 5 binds it),
    /// and C12's stage 3's top donating reply.
    pub holder: u64,
    pub home: u64,
    pub top: u64,
    /// Its release time, the key in its core's release tree, and its node.
    pub release: u64,
    pub rl: Links,
    pub core: u8,
    /// log2 of its size, as retype made it, recorded at configure.
    pub bits: u8,
    pub flags: u8,
    pub _pad: [u8; 5],
    /// C16: the job whose share it counts against.
    pub job: u64,
    /// Kept.
    pub spare: [u64; 5],
}

const _: () = assert!(size_of::<ScHeader>() as u64 == SC_HEADER);
const _: () = assert!(size_of::<Refill>() as u64 == REFILL_SIZE);

/// The refills a context of `2^bits` bytes can hold (K15).
pub const fn capacity(bits: u8) -> u32 {
    (((1u64 << bits) - SC_HEADER) / REFILL_SIZE) as u32
}

/// A reply object: 128 bytes, aligned to its size (K07).
/// Retype makes it from zeroed memory, which is its idle state.
///
/// | Words | Contents |
/// |---|---|
/// | 0 | Its state (bits 0-7), whether it is on a work list (bit 8), and that list's core (bits 16-23) |
/// | 1-7 | The caller, the server, the context it donated, its sequence number, the older and newer replies of its context's stack or walk, and a walk's badge |
/// | 8-12 | Its node in the walk tree: left, right, parent with the color in bit 0, its interval's end, and the largest end below it |
/// | 13-14 | Its links on a core's work list |
/// | 15 | Kept |
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ReplyObj {
    pub word: u64,
    pub caller: u64,
    pub server: u64,
    pub sc: u64,
    pub seq: u64,
    pub prev: u64,
    pub next: u64,
    pub badge: u64,
    pub left: u64,
    pub right: u64,
    pub parent: u64,
    pub hi: u64,
    pub max_hi: u64,
    pub wnext: u64,
    pub wprev: u64,
    pub spare: u64,
}

const _: () = assert!(size_of::<ReplyObj>() as u64 == 1 << kmem::untyped::REPLY_BITS);

/// The reply object's word 0.
pub mod reply_word {
    /// Its state, `ksched::donation::RState` as a number.
    pub const STATE: u64 = 0xff;
    /// On a work list: a walk's cursor.
    pub const QUEUED: u64 = 1 << 8;
    /// The core whose work list it is on.
    pub const CORE_SHIFT: u32 = 16;
    pub const CORE: u64 = 0xff << CORE_SHIFT;
}

/// A reply object, by its object's physical address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rp(pub u64);

impl Rp {
    /// The reply object a capability names, if it names one.
    pub fn of(cap: &Cap) -> Option<Rp> {
        match *cap {
            Cap::Reply { ptr, .. } => Some(Rp(ptr)),
            _ => None,
        }
    }

    fn ptr(self) -> *mut ReplyObj {
        debug_assert!(self.0 != 0 && self.0.is_multiple_of(1 << kmem::untyped::REPLY_BITS));
        DirectMem.va(self.0) as *mut ReplyObj
    }

    /// Runs `f` on the reply object.
    pub fn with<R>(self, f: impl FnOnce(&mut ReplyObj) -> R) -> R {
        // SAFETY: a reply object, 128 bytes of RAM aligned to its size and
        // retyped from untyped memory, in the direct map, read-write, which
        // only the kernel touches, under its lock; the reference lives only
        // for `f`, which doesn't reach this object again.
        f(unsafe { &mut *self.ptr() })
    }

    pub fn get(self) -> ReplyObj {
        self.with(|r| *r)
    }
}

/// A thread, by its object's physical address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tcb(pub u64);

impl Tcb {
    /// The thread whose object holds `slot`: the slot's address rounded
    /// down to the thread's 2 KiB. Binding slots never move, so a binding's
    /// unbind finds its thread this way.
    pub const fn holding(slot: SlotRef) -> Tcb {
        Tcb(slot.0 & !(TCB_SIZE - 1))
    }

    /// The thread a capability names, if it names one.
    pub fn of(cap: &Cap) -> Option<Tcb> {
        match *cap {
            Cap::Thread { ptr, .. } => Some(Tcb(ptr)),
            _ => None,
        }
    }

    /// The thread's slot `i`.
    pub const fn slot(self, i: u64) -> SlotRef {
        SlotArray::of_thread(self.0).slot(i)
    }

    /// The capability in the thread's slot `i`.
    pub fn slot_cap(self, i: u64) -> Cap {
        crate::cap::cap(self.slot(i))
    }

    fn body_ptr(self) -> *mut Body {
        debug_assert!(self.0 != 0 && self.0.is_multiple_of(TCB_SIZE));
        DirectMem.va(self.0 + TCB_CONTEXT) as *mut Body
    }

    /// The direct-map address of its saved context, which `SP_EL1` holds
    /// while it runs at EL0.
    pub fn context_va(self) -> u64 {
        DirectMem.va(self.0 + TCB_CONTEXT)
    }

    /// Runs `f` on the thread's state after its slots.
    pub fn with<R>(self, f: impl FnOnce(&mut Body) -> R) -> R {
        // SAFETY: a thread object, 2 KiB of RAM retyped from untyped memory
        // (or a boot page) and in the direct map, read-write. Only the kernel
        // touches it, under the kernel lock,
        // and the reference lives only for `f`, which doesn't reach this
        // thread's body again.
        f(unsafe { &mut *self.body_ptr() })
    }

    /// A copy of its scheduling state.
    pub fn state(self) -> SchedState {
        self.with(|b| b.s)
    }

    /// Changes its scheduling state.
    pub fn update(self, f: impl FnOnce(&mut SchedState)) {
        self.with(|b| f(&mut b.s));
    }

    pub fn flags(self) -> u8 {
        self.with(|b| b.s.flags)
    }

    pub fn has(self, f: u8) -> bool {
        self.flags() & f != 0
    }

    pub fn set(self, f: u8, on: bool) {
        self.update(|s| {
            if on {
                s.flags |= f;
            } else {
                s.flags &= !f;
            }
        });
    }

    pub fn wait(self) -> Wait {
        Wait::from_u8(self.with(|b| b.s.wait))
    }

    pub fn sc(self) -> Option<Sc> {
        match self.with(|b| b.s.sc) {
            0 => None,
            pa => Some(Sc(pa)),
        }
    }

    pub fn priority(self) -> u8 {
        self.with(|b| b.s.priority)
    }

    /// The context bound to it, its home one.
    pub fn home(self) -> Option<Sc> {
        match self.with(|b| b.s.home) {
            0 => None,
            pa => Some(Sc(pa)),
        }
    }
}

/// A scheduling context, by its object's physical address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sc(pub u64);

impl Sc {
    fn header_ptr(self) -> *mut ScHeader {
        debug_assert!(self.0 != 0 && self.0.is_multiple_of(256));
        DirectMem.va(self.0) as *mut ScHeader
    }

    /// Runs `f` on the context's header.
    pub fn with<R>(self, f: impl FnOnce(&mut ScHeader) -> R) -> R {
        // SAFETY: a scheduling context, at least 256 bytes of RAM aligned to
        // its size, in the direct map, read-write, touched only by the
        // kernel under its lock; the reference lives only for `f`.
        f(unsafe { &mut *self.header_ptr() })
    }

    pub fn header(self) -> ScHeader {
        self.with(|h| *h)
    }

    pub fn is_configured(self) -> bool {
        self.with(|h| h.flags & sc_flag::CONFIGURED != 0)
    }

    /// Runs `f` on its refills: the header's state and the ring after it,
    /// of the capacity its size gives. `bits` is its size, from its
    /// capability or its header.
    pub fn with_refills<R>(self, bits: u8, f: impl FnOnce(&mut Refills<'_>) -> R) -> R {
        let n = capacity(bits) as usize;
        let hdr = self.header_ptr();
        let ring = DirectMem.va(self.0 + SC_HEADER) as *mut Refill;
        // SAFETY: the header and the ring are disjoint parts of the
        // context's object, `2^bits` bytes of RAM in the direct map: the
        // ring is `n` refills after the 192-byte header. Only the kernel
        // touches them, under its lock, and both references live only for
        // `f`.
        let (st, ring) = unsafe { (&mut (*hdr).refill, core::slice::from_raw_parts_mut(ring, n)) };
        f(&mut Refills::new(st, ring))
    }

    /// Its refills, once configured, which recorded its size.
    pub fn refills<R>(self, f: impl FnOnce(&mut Refills<'_>) -> R) -> R {
        let bits = self.with(|h| h.bits);
        self.with_refills(bits, f)
    }
}
