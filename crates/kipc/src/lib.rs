// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The kernel's IPC and eventcount logic (ADR 0053, eventcounts; ADR 0054,
//! IPC endpoints), kept apart from the kernel so that it can be tested on
//! the host.
//!
//! The mechanism is in `docs/design/kernel-specification.md`, sections
//! "IPC" (endpoint operations and messages, IPC buffers, IPC deadlines and
//! cancellation), "Eventcounts" (operations, wait sets, threads bound to
//! an eventcount), "Ordered kernel queues" and "Model checking", with the
//! answers C14 settles there: K28 (the message and buffer layout), K29
//! (IPC buffer registration), K30 (results and error names), K31, K32,
//! K33. It follows seL4 17.0.0 with MCS (ADR 0047, rules 1 and 2): its
//! design, not its code. No seL4 source is copied.
//!
//! Nothing here touches hardware. The kernel runs this logic over its own
//! objects through store traits, as it runs `ksched::donation`, which stays
//! the one implementation of scheduling contexts and reply objects: this
//! crate never touches a context. The crate is `no_std`, has no `unsafe`,
//! allocates nothing, and never panics on its input: every word a user
//! writes is range-checked as a `u64` before it is narrowed, and every
//! target is computed with checked arithmetic.
//!
//! - [`msg`]: the message info word, the IPC buffer's layout, receive
//!   slots, the results and error names, and the provisional fault message
//!   (K28, K30).
//! - [`store`]: the objects' records and the effects the kernel supplies,
//!   as an extension of `ksched::donation`'s store.
//! - [`endpoint`]: synchronous endpoints, their priority-ordered queues and
//!   badge trees, delivery, faults over endpoints, canceling a badge's
//!   sends, and destruction: the protocol `specs/IpcEndpoint.tla` models.
//! - [`eventcount`]: eventcounts, wait sets and bound eventcounts, the
//!   preemptible advance and the work list's units: the protocol
//!   `specs/Eventcount.tla` models.
//!
//! Each module's operations are the TLA+ actions of its spec, and the host
//! tests write traces of their states that TLC checks against the spec's
//! steps (ADR 0068, rule 10), as `ksched`'s donation traces are.

#![no_std]
#![forbid(unsafe_code)]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreachable
)]

pub mod endpoint;
pub mod eventcount;
pub mod msg;
pub mod store;

pub use endpoint::cancel_wait;
pub use eventcount::wait_cost;
pub use kcap::rights::Rights;
pub use ksched::NIL;

/// An endpoint, by its object's physical address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ep(pub u64);
/// An eventcount.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ec(pub u64);
/// A wait set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ws(pub u64);

/// How an operation that wasn't refused left its thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// It returns now: its status is ok, and anything it gets is written.
    Done,
    /// It waits: the kernel inserts its deadline, if it gave one, and the
    /// wait's end writes its status.
    Blocked,
}

/// The longest message, in octets: 120 words of 8 (ADR 0054, rule 3).
pub const MAX_LEN: u64 = 960;
/// The most capabilities one message carries (ADR 0054, rule 7).
pub const MAX_CAPS: usize = 3;
/// The most units one unit of batch work may cost: a deadline on a donated
/// call, 1 for the call, plus 60 when its context's holder waits on a wait
/// set of 60 entries, whose wait unlinks 60 nodes. A wake of a wait-set
/// waiter costs the 60 alone, and a walk's step at most 2, itself and the
/// onward call it ends (kernel specification K24). The batches' bound,
/// `ksched::batch`'s.
pub const MAX_UNIT_COST: u32 = ksched::batch::MAX_UNIT_COST;
