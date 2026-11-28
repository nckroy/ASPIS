// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Eventcounts, wait sets and threads bound to an eventcount (ADR 0053;
//! kernel specification, "Eventcount operations", "Wait sets" and "Threads
//! bound to an eventcount"). `specs/Eventcount.tla` models this module,
//! and the host tests check traces of it against the spec's steps.
//!
//! **Waiters.** An eventcount's waiters are nodes in a red-black tree
//! keyed by target, then by the node's address (K25): a thread's own node,
//! for a direct wait or for a receive with a bound eventcount, or a
//! wait-set entry's. An advance visits only the waiters it wakes, in target
//! order.
//!
//! **Units.** One unit is one waiter node linked or unlinked (K23, K24).
//! Waking a thread's node is one unit; waking a wait set's waiter unlinks
//! every node of the set, up to 60, and costs that many ([`wake_cost`]). A
//! wake's other tree work is a small constant, counted in its base unit: a
//! bound receiver's report also leaves its endpoint's queue, and a wait's
//! end also removes its deadline.
//!
//! **An advance** adds one, or fails with "count at maximum" at 2^64 - 1
//! with the count unchanged (ADR 0053, rule 3). From a system call, it
//! wakes the reached waiters itself, ticking the caller's budget with each
//! wake's cost; when a preemption point finds an interrupt pending, it
//! marks the eventcount pending, queues it on its core's work list unless
//! it is on one already, and returns the count. The rest wake in batches,
//! as an interrupt's advance does ([`work_unit`]). So an advance is never
//! restarted, and adds one exactly once (K31). The pending mark clears only
//! when no linked waiter's target is reached.
//!
//! **Wait sets** (K08, K32, K33). A wait links every present entry's node
//! into its eventcount's tree; the first entry reached wakes the waiter,
//! which unlinks them all and returns the mask of reached entries. Removing
//! an entry during a wait, or revoking its copy, unlinks it, and the wait
//! goes on on the others; removing the last linked entry ends the wait with
//! an empty mask. Adding an entry during a wait links it, and ends the wait
//! at once if its target is reached.
//!
//! **Bound eventcounts** (ADR 0053, rule 5). A receive by a thread that
//! holds a context reports an advance past its last-seen count at once,
//! before any message, and otherwise links the thread's node with target
//! last-seen + 1 while it waits; at the count's maximum nothing is linked,
//! since no advance can come. A receive by a thread that holds no context,
//! a passive server, neither reports nor links: woken, it would hold no
//! context to run on. An advance that reaches the node of a receiver that
//! has since lost its context only unlinks it; the advance is reported at
//! its next receive made with a context, or when a context is bound to it
//! ([`context_bound`]).

use crate::msg::Status;
use crate::store::{EcRec, IpcStore, Node, Owner, ThreadEc, Value, WsRec};
use crate::{Ec, NIL, Outcome, Rights, Ws, endpoint};
use kcap::preempt::{Budget, Pending};
use ksched::donation::{self, Res, TState, Tcb};
use ksched::tree::{self, Links, TreeStore};

/// The most entries a wait set holds (ADR 0053, rule 4; K33).
pub const MAX_ENTRIES: usize = 60;

// ---------------------------------------------------------------------------
// The waiters' tree.

struct Waiters<'a, S>(&'a mut S);

impl<S: IpcStore> TreeStore for Waiters<'_, S> {
    type Key = (u64, u64);

    fn key(&self, n: u64) -> Self::Key {
        (self.0.node(n).target, n)
    }

    fn links(&self, n: u64) -> Links {
        self.0.node(n).links
    }

    fn set_links(&mut self, n: u64, l: Links) {
        let mut node = self.0.node(n);
        node.links = l;
        self.0.set_node(n, node);
    }
}

/// Links node `n` into `e`'s tree with `target`.
fn link<S: IpcStore>(s: &mut S, e: Ec, n: u64, target: u64) {
    s.set_node(
        n,
        Node {
            links: Links::default(),
            target,
            ec: e.0,
        },
    );
    let mut rec = s.ec(e);
    tree::insert(&mut Waiters(s), &mut rec.root, n);
    // The insert wrote the nodes' links, not the record's other fields.
    let mut now = s.ec(e);
    now.root = rec.root;
    s.set_ec(e, now);
}

/// Takes node `n` out of its tree, if it is in one. A thread's node loses
/// its target; an entry's keeps it.
fn unlink<S: IpcStore>(s: &mut S, n: u64) {
    let node = s.node(n);
    if node.ec == NIL {
        return;
    }
    let e = Ec(node.ec);
    let mut root = s.ec(e).root;
    tree::remove(&mut Waiters(s), &mut root, n);
    let mut rec = s.ec(e);
    rec.root = root;
    s.set_ec(e, rec);
    let target = match s.owner(n) {
        Owner::Thread(_) => 0,
        Owner::Entry(..) => node.target,
    };
    s.set_node(
        n,
        Node {
            links: Links::default(),
            target,
            ec: NIL,
        },
    );
}

/// Whether node `n` is in a tree.
pub fn is_linked<S: IpcStore>(s: &S, n: u64) -> bool {
    s.node(n).ec != NIL
}

/// The first waiter of `e`, lowest target first, or [`NIL`].
fn first<S: IpcStore>(s: &mut S, e: Ec) -> u64 {
    let root = s.ec(e).root;
    tree::first(&Waiters(s), root)
}

/// `e`'s first waiter if its target is reached, else [`NIL`].
fn first_reached<S: IpcStore>(s: &mut S, e: Ec) -> u64 {
    let n = first(s, e);
    if n != NIL && s.node(n).target <= s.ec(e).count {
        n
    } else {
        NIL
    }
}

/// Whether `e` has a linked waiter whose target is reached.
pub fn has_reached<S: IpcStore>(s: &mut S, e: Ec) -> bool {
    first_reached(s, e) != NIL
}

fn holds_context<S: IpcStore>(s: &S, t: Tcb) -> bool {
    s.thread(t).sc.is_some()
}

/// Entry `i` is present.
fn present<S: IpcStore>(s: &S, w: Ws, i: usize) -> bool {
    s.entry(w, i).is_some()
}

/// The entries of `w` linked now.
fn linked_entries<S: IpcStore>(s: &S, w: Ws) -> u32 {
    let n = usize::from(s.ws(w).entries).min(MAX_ENTRIES);
    (0..n).filter(|&i| is_linked(s, s.entry_node(w, i))).count() as u32
}

/// The mask of `w`'s present entries, but `skip`, whose eventcounts have
/// reached their targets: bit i for entry i.
fn mask<S: IpcStore>(s: &S, w: Ws, skip: Option<usize>) -> u64 {
    let n = usize::from(s.ws(w).entries).min(MAX_ENTRIES);
    let mut m = 0;
    for i in 0..n {
        if Some(i) == skip {
            continue;
        }
        if let Some(e) = s.entry(w, i)
            && s.ec(e).count >= s.node(s.entry_node(w, i)).target
        {
            m |= 1 << i;
        }
    }
    m
}

/// Unlinks every linked node of `w`; returns how many.
fn unlink_set<S: IpcStore>(s: &mut S, w: Ws) -> u32 {
    let n = usize::from(s.ws(w).entries).min(MAX_ENTRIES);
    let mut k = 0;
    for i in 0..n {
        let node = s.entry_node(w, i);
        if is_linked(s, node) {
            unlink(s, node);
            k += 1;
        }
    }
    k
}

/// Ends the wait on `w` of its waiter with `res`, after unlinking every
/// entry; a success returns the mask, computed without `skip`.
fn end_set_wait<S: IpcStore>(s: &mut S, w: Ws, res: Res, skip: Option<usize>) {
    let rec = s.ws(w);
    let Some(t) = rec.waiter else {
        unlink_set(s, w);
        return;
    };
    unlink_set(s, w);
    let m = mask(s, w, skip);
    s.set_ws(
        w,
        WsRec {
            waiter: None,
            ..rec
        },
    );
    let mut te = s.thread_ec(t);
    te.set = None;
    s.set_thread_ec(t, te);
    let _ = donation::wake(s, t, res);
    if res == Res::Replied {
        s.woke(t, Value::Mask(m));
    }
}

/// The units waking the waiter at node `n` costs: one, or for a wait-set
/// entry, the nodes of the set it unlinks (module docs).
pub fn wake_cost<S: IpcStore>(s: &S, n: u64) -> u32 {
    match s.owner(n) {
        Owner::Thread(_) => 1,
        Owner::Entry(w, _) => linked_entries(s, w).max(1),
    }
}

/// Reports `e`'s advance to `t`, a bound receiver that holds a context,
/// ending its receive: it leaves the endpoint's queue and the tree, and
/// last-seen becomes the count.
fn report<S: IpcStore>(s: &mut S, t: Tcb, e: Ec) {
    let count = s.ec(e).count;
    endpoint::leave(s, t);
    unlink(s, s.thread_node(t));
    let _ = donation::wake(s, t, Res::Replied);
    let mut te = s.thread_ec(t);
    te.last = count;
    s.set_thread_ec(t, te);
    s.woke(t, Value::Advance(count));
}

/// Wakes the waiter at node `n` of `e`, whose target is reached: one unit
/// of [`wake_cost`].
fn wake_node<S: IpcStore>(s: &mut S, e: Ec, n: u64) {
    match s.owner(n) {
        Owner::Thread(t) => {
            if let TState::Recv(_) = s.thread(t).state {
                if holds_context(s, t) {
                    report(s, t, e);
                } else {
                    // A passive receiver: it stays receiving, unlinked.
                    unlink(s, n);
                }
            } else {
                let count = s.ec(e).count;
                unlink(s, n);
                let _ = donation::wake(s, t, Res::Replied);
                s.woke(t, Value::Count(count));
            }
        }
        Owner::Entry(w, _) => end_set_wait(s, w, Res::Replied, None),
    }
}

/// Marks `e` pending and puts it on this core's work list, unless it is on
/// one already.
fn mark_pending<S: IpcStore>(s: &mut S, e: Ec) {
    let mut rec = s.ec(e);
    rec.pending = true;
    let queue = !rec.listed;
    rec.listed = true;
    s.set_ec(e, rec);
    if queue {
        s.queue_work(e);
    }
}

// ---------------------------------------------------------------------------
// Eventcount operations.

/// `Read`: the count. Needs the read right.
pub fn read<S: IpcStore>(s: &S, e: Ec, rights: Rights) -> Result<u64, Status> {
    if !rights.contains(Rights::READ) {
        return Err(Status::MissingRight);
    }
    Ok(s.ec(e).count)
}

/// `Wait(t, e, g)`: `t`, running, waits until `e`'s count reaches
/// `target`. Needs the read right. A target already reached returns at
/// once with the count, so no wake-up is lost between a read and a wait.
/// The kernel inserts the deadline when it blocks.
pub fn wait<S: IpcStore>(
    s: &mut S,
    t: Tcb,
    e: Ec,
    rights: Rights,
    target: u64,
) -> Result<Outcome, Status> {
    if !rights.contains(Rights::READ) {
        return Err(Status::MissingRight);
    }
    let count = s.ec(e).count;
    if count >= target {
        s.woke(t, Value::Count(count));
        return Ok(Outcome::Done);
    }
    link(s, e, s.thread_node(t), target);
    donation::wait_other(s, t);
    Ok(Outcome::Blocked)
}

/// `Advance(e)` from a system call: adds one, and wakes the reached
/// waiters until `budget` finds an interrupt pending, leaving the rest to
/// the work list (module docs; K31). Needs the write right. Returns the new
/// count.
pub fn advance<S: IpcStore, P: Pending>(
    s: &mut S,
    e: Ec,
    rights: Rights,
    budget: &mut Budget<P>,
) -> Result<u64, Status> {
    if !rights.contains(Rights::WRITE) {
        return Err(Status::MissingRight);
    }
    let mut rec = s.ec(e);
    let Some(count) = rec.count.checked_add(1) else {
        return Err(Status::CountAtMaximum);
    };
    rec.count = count;
    s.set_ec(e, rec);
    loop {
        let n = first_reached(s, e);
        if n == NIL {
            break;
        }
        let cost = wake_cost(s, n);
        wake_node(s, e, n);
        // Work comes before the check, so every advance makes progress.
        if budget.tick(cost).is_err() {
            if has_reached(s, e) {
                mark_pending(s, e);
            }
            break;
        }
    }
    Ok(count)
}

/// An advance for an interrupt (C13b's seam): adds one at once and leaves
/// every wake to the work list. Returns the new count.
pub fn advance_irq<S: IpcStore>(s: &mut S, e: Ec) -> Result<u64, Status> {
    let mut rec = s.ec(e);
    let Some(count) = rec.count.checked_add(1) else {
        return Err(Status::CountAtMaximum);
    };
    rec.count = count;
    s.set_ec(e, rec);
    if has_reached(s, e) {
        mark_pending(s, e);
    }
    Ok(count)
}

/// The units the next [`work_unit`] of `e` costs (K24): its first reached
/// waiter's wake, or 1 to clear the mark.
pub fn unit_cost<S: IpcStore>(s: &mut S, e: Ec) -> u32 {
    let n = first_reached(s, e);
    if n == NIL { 1 } else { wake_cost(s, n) }
}

/// One unit of `e`'s pending wake, from a core's work list: wakes its
/// first reached waiter; then, if none is reached, clears the mark and
/// takes `e` off its list. Returns whether work remains, so the list moves
/// `e` to its back.
pub fn work_unit<S: IpcStore>(s: &mut S, e: Ec) -> bool {
    let n = first_reached(s, e);
    if n != NIL {
        wake_node(s, e, n);
    }
    if has_reached(s, e) {
        return true;
    }
    let mut rec = s.ec(e);
    rec.pending = false;
    let listed = rec.listed;
    rec.listed = false;
    s.set_ec(e, rec);
    if listed {
        s.unqueue_work(e);
    }
    false
}

/// One step of an eventcount's queue zombie (K30): releases its first
/// waiter. A waiter whose target is reached is woken with the count; the
/// others end "object destroyed". Entries and bindings hold copies of the
/// eventcount, so no wait set or bound receiver waits on a zombie. Returns
/// true when no waiter is left.
pub fn drain<S: IpcStore>(s: &mut S, e: Ec) -> bool {
    let n = first(s, e);
    if n == NIL {
        return true;
    }
    if s.node(n).target <= s.ec(e).count {
        wake_node(s, e, n);
    } else {
        match s.owner(n) {
            Owner::Thread(t) => {
                unlink(s, n);
                if !matches!(s.thread(t).state, TState::Recv(_)) {
                    let _ = donation::wake(s, t, Res::Destroyed);
                }
            }
            Owner::Entry(w, i) => unbind_entry(s, w, i),
        }
    }
    first(s, e) == NIL
}

/// `e` is finished: its waiters are gone. It leaves its work list first,
/// so the memory can be retyped with nothing pointing into it (K24).
pub fn finish<S: IpcStore>(s: &mut S, e: Ec) {
    if s.ec(e).listed {
        s.unqueue_work(e);
    }
    s.set_ec(e, EcRec::default());
}

// ---------------------------------------------------------------------------
// Wait sets.

/// `WsAdd`: entry `i` of `w` waits for `e` to reach `target` (K32: the
/// write right on the set, and the read right on the eventcount, ADR 0053,
/// rule 4). The entry must be empty. During a wait the entry is linked, and
/// ends the wait at once if its target is reached (K08).
pub fn ws_add<S: IpcStore>(
    s: &mut S,
    w: Ws,
    wrights: Rights,
    i: usize,
    e: Ec,
    erights: Rights,
    target: u64,
) -> Result<(), Status> {
    if !wrights.contains(Rights::WRITE) || !erights.contains(Rights::READ) {
        return Err(Status::MissingRight);
    }
    let rec = s.ws(w);
    if i >= usize::from(rec.entries).min(MAX_ENTRIES) {
        return Err(Status::InvalidArgument);
    }
    if present(s, w, i) {
        return Err(Status::Busy);
    }
    s.bind_entry(w, i, e);
    let n = s.entry_node(w, i);
    s.set_node(
        n,
        Node {
            links: Links::default(),
            target,
            ec: NIL,
        },
    );
    if rec.waiter.is_some() {
        link(s, e, n, target);
        if s.ec(e).count >= target {
            end_set_wait(s, w, Res::Replied, None);
        }
    }
    Ok(())
}

/// The checks of `WsRemove`: the write right, and an index in range (K32).
/// The kernel then deletes the entry's slot with the deletion's budget,
/// whose unbind step is [`unbind_entry`]. An empty entry is nothing to do,
/// so a restarted removal ends as one that ran through.
pub fn ws_remove_check<S: IpcStore>(s: &S, w: Ws, rights: Rights, i: usize) -> Result<(), Status> {
    if !rights.contains(Rights::WRITE) {
        return Err(Status::MissingRight);
    }
    if i >= usize::from(s.ws(w).entries).min(MAX_ENTRIES) {
        return Err(Status::InvalidArgument);
    }
    Ok(())
}

/// Entry `i`'s copy is being deleted, by a removal or a revocation (K08):
/// its node leaves its tree and loses its target. A wait on the set goes
/// on on the other entries; if none is left linked, it ends with the mask
/// of the others, which is empty.
pub fn unbind_entry<S: IpcStore>(s: &mut S, w: Ws, i: usize) {
    let n = s.entry_node(w, i);
    let was = is_linked(s, n);
    unlink(s, n);
    if was && s.ws(w).waiter.is_some() && linked_entries(s, w) == 0 {
        end_set_wait(s, w, Res::Replied, Some(i));
    }
    s.set_node(n, Node::default());
}

/// `WsWait(t, w)`: `t`, running, waits on `w` (K32: the read right). One
/// wait at a time: a second fails "busy". If an entry has reached its
/// target, or the set has no entries, it returns the mask at once;
/// otherwise every present entry is linked, at most 60 links.
pub fn ws_wait<S: IpcStore>(s: &mut S, t: Tcb, w: Ws, rights: Rights) -> Result<Outcome, Status> {
    if !rights.contains(Rights::READ) {
        return Err(Status::MissingRight);
    }
    let rec = s.ws(w);
    if rec.waiter.is_some() {
        return Err(Status::Busy);
    }
    let m = mask(s, w, None);
    let n = usize::from(rec.entries).min(MAX_ENTRIES);
    if m != 0 || !(0..n).any(|i| present(s, w, i)) {
        s.woke(t, Value::Mask(m));
        return Ok(Outcome::Done);
    }
    for i in 0..n {
        if let Some(e) = s.entry(w, i) {
            let node = s.entry_node(w, i);
            let target = s.node(node).target;
            link(s, e, node, target);
        }
    }
    s.set_ws(
        w,
        WsRec {
            waiter: Some(t),
            ..rec
        },
    );
    let mut te = s.thread_ec(t);
    te.set = Some(w);
    s.set_thread_ec(t, te);
    donation::wait_other(s, t);
    Ok(Outcome::Blocked)
}

/// `w`'s last capability becomes a zombie: its wait ends "object
/// destroyed", and its entries leave their trees. The zombie's steps then
/// clear the entries' slots, each with [`unbind_entry`]. Returns the
/// units: one, and one per node unlinked.
pub fn ws_zombify<S: IpcStore>(s: &mut S, w: Ws) -> u32 {
    let units = 1 + linked_entries(s, w);
    end_set_wait(s, w, Res::Destroyed, None);
    units
}

// ---------------------------------------------------------------------------
// Bound eventcounts.

/// `Bind(t, e)`: binds `e` to `t` (the read right on `e`); last-seen is the
/// count now. Refused "busy" if `t` has one, so binding never deletes. A
/// thread receiving with a context links its node at once.
pub fn bind<S: IpcStore>(s: &mut S, t: Tcb, e: Ec, rights: Rights) -> Result<(), Status> {
    if !rights.contains(Rights::READ) {
        return Err(Status::MissingRight);
    }
    let mut te = s.thread_ec(t);
    if te.bound.is_some() {
        return Err(Status::Busy);
    }
    te.bound = Some(e);
    te.last = s.ec(e).count;
    s.set_thread_ec(t, te);
    if matches!(s.thread(t).state, TState::Recv(_)) {
        recv_link(s, t);
    }
    Ok(())
}

/// `t`'s binding is being deleted (thread slot 6's unbind step): a receive
/// in progress goes on, on the endpoint alone.
pub fn unbind<S: IpcStore>(s: &mut S, t: Tcb) {
    if matches!(s.thread(t).state, TState::Recv(_)) {
        unlink(s, s.thread_node(t));
    }
    s.set_thread_ec(
        t,
        ThreadEc {
            bound: None,
            last: 0,
            ..s.thread_ec(t)
        },
    );
}

/// A context was bound to `t` (donation's `bind_sc`). If `t` receives with
/// a bound eventcount, an advance it hasn't seen is reported now; otherwise
/// its node is linked, as a receive made with a context does.
pub fn context_bound<S: IpcStore>(s: &mut S, t: Tcb) {
    if matches!(s.thread(t).state, TState::Recv(_)) && !recv_report(s, t) {
        recv_link(s, t);
    }
}

/// At a receive by `t`, waiting in `Recv`: reports its bound eventcount's
/// advance if it holds a context and the count is past last-seen. Returns
/// whether it did.
pub(crate) fn recv_report<S: IpcStore>(s: &mut S, t: Tcb) -> bool {
    let te = s.thread_ec(t);
    match te.bound {
        Some(e) if holds_context(s, t) && s.ec(e).count > te.last => {
            report(s, t, e);
            true
        }
        _ => false,
    }
}

/// While `t` waits to receive: links its node into its bound eventcount's
/// tree, with target last-seen + 1, if it holds a context and isn't linked.
/// At the maximum no advance can come, so nothing is linked.
pub(crate) fn recv_link<S: IpcStore>(s: &mut S, t: Tcb) {
    let te = s.thread_ec(t);
    let n = s.thread_node(t);
    if let Some(e) = te.bound
        && holds_context(s, t)
        && !is_linked(s, n)
        && let Some(target) = te.last.checked_add(1)
    {
        link(s, e, n, target);
    }
}

// ---------------------------------------------------------------------------
// Ending waits.

/// Takes `t` out of every eventcount tree its wait has it in: its own node,
/// and if it waits on a wait set, every entry's, ending its tenure as the
/// set's waiter. Nothing else changes; the caller ends the wait.
pub fn unlink_waits<S: IpcStore>(s: &mut S, t: Tcb) {
    unlink(s, s.thread_node(t));
    let mut te = s.thread_ec(t);
    if let Some(w) = te.set {
        unlink_set(s, w);
        let rec = s.ws(w);
        if rec.waiter == Some(t) {
            s.set_ws(
                w,
                WsRec {
                    waiter: None,
                    ..rec
                },
            );
        }
        te.set = None;
        s.set_thread_ec(t, te);
    }
}

/// The units ending `t`'s wait costs (K23): the nodes of a wait set it
/// unlinks, or one.
pub fn wait_cost<S: IpcStore>(s: &S, t: Tcb) -> u32 {
    match s.thread_ec(t).set {
        Some(w) => linked_entries(s, w).max(1),
        None => 1,
    }
}

// ---------------------------------------------------------------------------
// Invariants, for the host tests and the kernel's test builds.

/// The invariant that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Violation {
    /// A waiters' tree is malformed, or holds a node that names another.
    Tree,
    /// A linked waiter's target is reached, but no wake is pending.
    LostWakeup,
    /// The pending mark and the work list disagree.
    Listed,
    /// A thread's node is linked, or not, against its wait.
    ThreadNode,
    /// A wait set's waiter, or its entries' nodes, disagree with its wait.
    WaitSet,
    /// A bound thread's last-seen count is past the count.
    LastSeen,
}

/// Checks the eventcount invariants over the objects given (the spec's,
/// in this crate's form). O(n log n): for tests.
pub fn check<S: IpcStore>(
    s: &mut S,
    ecs: &[Ec],
    sets: &[Ws],
    threads: &[Tcb],
) -> Result<(), Violation> {
    for &e in ecs {
        let rec = s.ec(e);
        if tree::check(&Waiters(s), rec.root, usize::MAX).is_err() {
            return Err(Violation::Tree);
        }
        let mut n = tree::first(&Waiters(s), rec.root);
        while n != NIL {
            if s.node(n).ec != e.0 {
                return Err(Violation::Tree);
            }
            n = tree::next(&Waiters(s), n);
        }
        if rec.pending != rec.listed {
            return Err(Violation::Listed);
        }
        if has_reached(s, e) && !rec.pending {
            return Err(Violation::LostWakeup);
        }
    }
    for &t in threads {
        let tr = s.thread(t);
        let te = s.thread_ec(t);
        let node = s.node(s.thread_node(t));
        let linked = node.ec != NIL;
        match tr.state {
            TState::Other if te.set.is_some() => {
                if linked {
                    return Err(Violation::ThreadNode);
                }
            }
            TState::Recv(_) => {
                if linked
                    && (te.bound.map(|e| e.0) != Some(node.ec)
                        || Some(node.target) != te.last.checked_add(1))
                {
                    return Err(Violation::ThreadNode);
                }
                let want = te.bound.is_some() && tr.sc.is_some() && te.last < u64::MAX;
                if want && !linked {
                    return Err(Violation::ThreadNode);
                }
            }
            TState::Other => {}
            _ => {
                if linked {
                    return Err(Violation::ThreadNode);
                }
            }
        }
        if te.set.is_some() && tr.state != TState::Other {
            return Err(Violation::WaitSet);
        }
        if let Some(e) = te.bound
            && te.last > s.ec(e).count
        {
            return Err(Violation::LastSeen);
        }
    }
    for &w in sets {
        let rec = s.ws(w);
        let n = usize::from(rec.entries).min(MAX_ENTRIES);
        for i in 0..n {
            let node = s.node(s.entry_node(w, i));
            let entry = s.entry(w, i);
            let ok = match (rec.waiter, entry) {
                (_, None) => node.ec == NIL && node.target == 0,
                (Some(_), Some(e)) => node.ec == e.0,
                (None, Some(_)) => node.ec == NIL,
            };
            if !ok {
                return Err(Violation::WaitSet);
            }
        }
        if let Some(t) = rec.waiter
            && (s.thread_ec(t).set != Some(w) || linked_entries(s, w) == 0)
        {
            return Err(Violation::WaitSet);
        }
    }
    Ok(())
}
