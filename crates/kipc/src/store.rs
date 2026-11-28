// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The memory and effects the IPC protocols run on: the objects' records,
//! as the kernel keeps them in its objects and the host tests in vectors,
//! and the effects this crate can't do itself (crate docs).
//!
//! [`IpcStore`] extends `ksched::donation`'s store, since every wait here
//! is also a donation state: a thread queued on an endpoint is in
//! [`TState::Send`](ksched::donation::TState::Send),
//! [`TState::Fault`](ksched::donation::TState::Fault) or
//! [`TState::Recv`](ksched::donation::TState::Recv), and a thread waiting
//! on an eventcount or a wait set is in
//! [`TState::Other`](ksched::donation::TState::Other). The kernel's
//! donation store implements `cancel_other` with [`crate::cancel_wait`],
//! `withdraw_fault` with [`crate::endpoint::leave`] and `wait_cost` with
//! [`crate::wait_cost`], so donation's cancels, deadlines and take-backs
//! take a thread out of what this crate keeps for it (K17).

use crate::{Ec, Ep, Ws};
use ksched::donation::{Store, Tcb};
use ksched::tree::Links;

/// An endpoint's fields (kernel specification, "Endpoint operations and
/// messages"; K25). Zero is an idle endpoint, as retype leaves it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EpRec {
    /// The root of its queue: threads keyed by priority, highest first,
    /// then by arrival.
    pub root: u64,
    /// The root of its queued senders' badge tree: keyed by badge, then
    /// arrival, for canceling a badge's sends (K23).
    pub broot: u64,
    /// The next arrival number. It never wraps: 2^64 arrivals don't fit in
    /// a machine's life.
    pub next: u64,
    /// Whether its queue holds receivers; otherwise senders. Meaningless
    /// when the queue is empty. A queue never holds both, as in seL4.
    pub recv: bool,
}

/// What a thread queued on an endpoint is there for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Role {
    /// Waiting to receive.
    #[default]
    Recv,
    /// A plain send, not yet delivered.
    Send,
    /// A call, not yet delivered.
    Call,
    /// A fault the kernel sends on the thread's behalf: on its fault
    /// endpoint, or a timeout or context-withdrawn fault on its timeout
    /// endpoint (kernel specification, "Fault delivery").
    Fault,
}

/// A thread's endpoint fields: in the kernel, part of the thread's IPC
/// state in its kept bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpcRec {
    /// The endpoint it is queued on, if any.
    pub ep: Option<Ep>,
    /// Its node in the endpoint's queue.
    pub links: Links,
    /// Its node in the endpoint's badge tree: queued senders only.
    pub blinks: Links,
    /// Its arrival number on the endpoint.
    pub arrival: u64,
    /// Its priority when it joined: the queue's key, which a priority
    /// change updates by leaving and rejoining (K25).
    pub prio: u8,
    pub role: Role,
    /// A queued sender's info word, checked when it was sent.
    pub info: u64,
    /// A queued sender's badge: its capability's, or for a fault, the
    /// badge of the endpoint copy it is sent on.
    pub badge: u64,
    /// Whether a queued sender's capability has the grant right, so its
    /// message may carry capabilities (ADR 0049, rule 6).
    pub grant: bool,
}

/// An eventcount's fields (kernel specification, "Eventcount operations";
/// K24, K31).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EcRec {
    /// The count. It never wraps: an advance at 2^64 - 1 fails (ADR 0053,
    /// rule 3).
    pub count: u64,
    /// The root of its waiters' tree, keyed by target, then by node.
    pub root: u64,
    /// A wake is pending: some linked waiter's target may be reached.
    pub pending: bool,
    /// It is on a core's work list. Set exactly while [`EcRec::pending`]
    /// is: an eventcount is queued once, on the core that first queued it,
    /// and leaves the list when its last pending wake is done or when it is
    /// finished.
    pub listed: bool,
}

/// A node in an eventcount's waiters' tree: a thread's (a direct wait, or a
/// receive with a bound eventcount) or a wait-set entry's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Node {
    pub links: Links,
    /// The count it waits for. A wait-set entry keeps its target while it
    /// is present, linked or not; a thread's node has target 0 while it is
    /// unlinked.
    pub target: u64,
    /// The eventcount whose tree it is in, or [`crate::NIL`].
    pub ec: u64,
}

/// Whose a waiters'-tree node is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    Thread(Tcb),
    /// Entry `i`, from 0, of a wait set.
    Entry(Ws, usize),
}

/// A thread's eventcount fields: its bound eventcount (thread slot 6) and
/// the count it last saw of it (ADR 0053, rule 5), and the wait set it
/// waits on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ThreadEc {
    pub bound: Option<Ec>,
    /// The last-seen count; 0 while unbound.
    pub last: u64,
    pub set: Option<Ws>,
}

/// A wait set's header (kernel specification, "Wait sets"; K33).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WsRec {
    /// The thread waiting on it: one at a time.
    pub waiter: Option<Tcb>,
    /// How many entries it holds: 1, 3, 7, 15, 31 or 60, from its size.
    pub entries: u8,
}

/// What the kernel copies when a message is delivered (kernel
/// specification, "Endpoint operations and messages" and "Capability
/// transfer"). The kernel reads the words from the sender's saved
/// registers and IPC buffer, which stay as they were while it waits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transfer {
    /// A send's or a call's message: the endpoint it travels through (an
    /// endpoint capability to it is unwrapped, not transferred: ADR 0054,
    /// rule 7), its info word, the badge of the capability it was sent
    /// with, and whether that capability has the grant right.
    Message {
        ep: Ep,
        info: u64,
        badge: u64,
        grant: bool,
    },
    /// A reply: its info word, and whether the reply capability has the
    /// grant right.
    Reply { info: u64, grant: bool },
    /// A fault message, composed from the sender's fault record, with the
    /// badge of the endpoint copy it is sent on.
    Fault { badge: u64 },
}

/// What a thread gets besides its status when its wait ends, or when it
/// returns at once: the kernel writes it into x1, and for an advance, x6
/// (K28).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    /// An eventcount wait or read: the count.
    Count(u64),
    /// A wait-set wait: the mask of entries that reached their targets.
    Mask(u64),
    /// A receive that reports its bound eventcount's advance: the count.
    Advance(u64),
}

/// The memory and effects of IPC (module docs). Records are read and
/// written whole; the kernel's are views over its objects.
pub trait IpcStore: Store {
    fn ep(&self, e: Ep) -> EpRec;
    fn set_ep(&mut self, e: Ep, rec: EpRec);
    fn ipc(&self, t: Tcb) -> IpcRec;
    fn set_ipc(&mut self, t: Tcb, rec: IpcRec);
    /// `t`'s priority now (ADR 0051, rule 2).
    fn priority(&self, t: Tcb) -> u8;

    fn ec(&self, e: Ec) -> EcRec;
    fn set_ec(&mut self, e: Ec, rec: EcRec);
    /// The node at `n`: a thread's or a wait-set entry's.
    fn node(&self, n: u64) -> Node;
    fn set_node(&mut self, n: u64, node: Node);
    /// Whose node `n` is. The kernel tells from the node's own flags.
    fn owner(&self, n: u64) -> Owner;
    /// `t`'s node, never [`crate::NIL`].
    fn thread_node(&self, t: Tcb) -> u64;
    /// Entry `i`'s node, never [`crate::NIL`].
    fn entry_node(&self, w: Ws, i: usize) -> u64;
    fn thread_ec(&self, t: Tcb) -> ThreadEc;
    fn set_thread_ec(&mut self, t: Tcb, rec: ThreadEc);
    fn ws(&self, w: Ws) -> WsRec;
    fn set_ws(&mut self, w: Ws, rec: WsRec);
    /// The eventcount whose copy entry `i`'s slot holds, if any. While the
    /// entry's unbind step runs, the copy is still there.
    fn entry(&self, w: Ws, i: usize) -> Option<Ec>;

    /// Copies the eventcount capability the caller presented into entry
    /// `i`'s slot, as a binding (K07). The checks are done.
    fn bind_entry(&mut self, w: Ws, i: usize, e: Ec);
    /// Puts `e` on this core's work list. Called only when it is on none.
    fn queue_work(&mut self, e: Ec);
    /// Takes `e` off the work list it is on.
    fn unqueue_work(&mut self, e: Ec);
    /// Copies a message, a reply or a fault from `from` to `to` (module
    /// docs). The receiver's status is donation's.
    fn transfer(&mut self, from: Tcb, to: Tcb, what: Transfer);
    /// `t`'s wait ended with `v` besides its status.
    fn woke(&mut self, t: Tcb, v: Value);
    /// `t`'s send was canceled under a released badge: its PC goes back to
    /// its `SVC`, so it makes the call again, as seL4's Restart state does.
    fn restart(&mut self, t: Tcb);
}
