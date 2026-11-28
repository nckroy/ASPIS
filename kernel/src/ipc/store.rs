// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! `kipc`'s store over the kernel's objects: the records of endpoints,
//! eventcounts, wait sets and threads' IPC state ([`super::object`]), and the
//! effects `kipc` leaves to the kernel. It is the donation store
//! ([`KStore`]) too, since every IPC wait is a donation state, so `kipc`
//! runs `ksched::donation` and its own logic over one store.

use super::object::{
    self, IpcState, NodeOwner, ec_word, entry_node, ep_word, node_flags, role, with_ipc, ws_header,
    ws_name, ws_of, ws_word,
};
use crate::cap::DirectSlots;
use crate::sched::donation::KStore;
use crate::sched::object::Tcb;
use crate::sched::percore::{self, this_core};
use core::sync::atomic::{AtomicU64, Ordering};
use kcap::SlotRef;
use kcap::cap::Cap;
use kipc::store::{
    EcRec, EpRec, IpcRec, IpcStore, Node, Owner, Role, ThreadEc, Transfer, Value, WsRec,
};
use kipc::{Ec, Ep, NIL, Ws};
use ksched::donation::Tcb as DTcb;
use ksched::tree::Links;
use ksched::worklist::{Tagged, WLinks, WorkStore};

fn links(w: [u64; 3]) -> Links {
    Links {
        left: w[0],
        right: w[1],
        parent: w[2] & !node_flags::RED,
        red: w[2] & node_flags::RED != 0,
    }
}

fn words(l: Links) -> [u64; 3] {
    [l.left, l.right, l.parent | l.red as u64]
}

fn nz(v: u64) -> Option<u64> {
    (v != 0).then_some(v)
}

const fn role_of(flags: u64) -> Role {
    match flags & role::MASK {
        role::SEND => Role::Send,
        role::CALL => Role::Call,
        role::FAULT => Role::Fault,
        _ => Role::Recv,
    }
}

const fn role_num(r: Role) -> u64 {
    match r {
        Role::Recv => role::RECV,
        Role::Send => role::SEND,
        Role::Call => role::CALL,
        Role::Fault => role::FAULT,
    }
}

/// The slot of the eventcount capability a wait-set add presented, which
/// [`IpcStore::bind_entry`] copies: `kipc` names only the eventcount. Set by
/// the add before it calls `kipc`, under the kernel lock.
pub static PRESENTED: AtomicU64 = AtomicU64::new(0);

/// Entry `i`'s slot in the wait set named `w`.
pub fn entry_slot(w: Ws, i: usize) -> SlotRef {
    let (ws, _) = ws_of(w.0);
    SlotRef(ws + kcap::SLOT_SIZE * (i as u64 + 1))
}

impl IpcStore for KStore {
    fn ep(&self, e: Ep) -> EpRec {
        EpRec {
            root: object::get(e.0, ep_word::ROOT),
            broot: object::get(e.0, ep_word::BROOT),
            next: object::get(e.0, ep_word::NEXT),
            recv: object::get(e.0, ep_word::STATE) & ep_word::RECEIVERS != 0,
        }
    }

    fn set_ep(&mut self, e: Ep, rec: EpRec) {
        object::set(e.0, ep_word::STATE, rec.recv as u64);
        object::set(e.0, ep_word::ROOT, rec.root);
        object::set(e.0, ep_word::BROOT, rec.broot);
        object::set(e.0, ep_word::NEXT, rec.next);
    }

    fn ipc(&self, t: DTcb) -> IpcRec {
        let s = object::ipc(Tcb(t.0));
        IpcRec {
            ep: nz(s.ep).map(Ep),
            links: links(s.q),
            blinks: links(s.bq),
            arrival: s.arrival,
            prio: (s.flags >> role::PRIO_SHIFT) as u8,
            role: role_of(s.flags),
            info: s.info,
            badge: s.badge,
            grant: s.flags & role::GRANT != 0,
        }
    }

    fn set_ipc(&mut self, t: DTcb, rec: IpcRec) {
        with_ipc(Tcb(t.0), |s| {
            s.ep = rec.ep.map_or(0, |e| e.0);
            s.q = words(rec.links);
            s.bq = words(rec.blinks);
            s.arrival = rec.arrival;
            s.flags = role_num(rec.role)
                | if rec.grant { role::GRANT } else { 0 }
                | (rec.prio as u64) << role::PRIO_SHIFT;
            s.info = rec.info;
            s.badge = rec.badge;
        });
    }

    fn priority(&self, t: DTcb) -> u8 {
        Tcb(t.0).priority()
    }

    fn ec(&self, e: Ec) -> EcRec {
        let w = object::get(e.0, ec_word::WORD);
        EcRec {
            count: object::get(e.0, ec_word::COUNT),
            root: object::get(e.0, ec_word::ROOT),
            pending: w & ec_word::PENDING != 0,
            listed: w & ec_word::QUEUED != 0,
        }
    }

    /// Writes the count, the root and the pending mark. The work-list bits
    /// are the list's: [`IpcStore::queue_work`] and
    /// [`IpcStore::unqueue_work`] set and clear them, as `kipc` sets
    /// `listed` around those calls.
    fn set_ec(&mut self, e: Ec, rec: EcRec) {
        object::set(e.0, ec_word::COUNT, rec.count);
        object::set(e.0, ec_word::ROOT, rec.root);
        // Off a list, the core it was on is forgotten too, so a finished
        // eventcount's words are all zero.
        let w = object::get(e.0, ec_word::WORD);
        let list = if w & ec_word::QUEUED != 0 {
            w & (ec_word::QUEUED | ec_word::CORE)
        } else {
            0
        };
        let pending = if rec.pending { ec_word::PENDING } else { 0 };
        object::set(e.0, ec_word::WORD, list | pending);
    }

    fn node(&self, n: u64) -> Node {
        let w = [object::get(n, 0), object::get(n, 8), object::get(n, 16)];
        let ec = match object::node_owner(n) {
            NodeOwner::Thread(t) => object::ipc(t).node_ec,
            NodeOwner::Entry { ws, bits, i } => {
                let linked = object::get(ws_header(ws, bits), ws_word::LINKED);
                if linked & 1 << i != 0 {
                    self.entry(Ws(ws_name(ws, bits)), i).map_or(NIL, |e| e.0)
                } else {
                    NIL
                }
            }
        };
        Node {
            links: Links {
                left: w[0],
                right: w[1],
                parent: w[2] & !node_flags::ALL,
                red: w[2] & node_flags::RED != 0,
            },
            target: object::get(n, 24),
            ec,
        }
    }

    /// Writes the node, keeping its owner flags. Whether an entry's node is
    /// linked is a bit of its set's header: the eventcount it is linked
    /// into is its entry's own.
    fn set_node(&mut self, n: u64, node: Node) {
        let flags = object::get(n, 16) & (node_flags::ENTRY | node_flags::BITS);
        object::set(n, 0, node.links.left);
        object::set(n, 8, node.links.right);
        object::set(n, 16, node.links.parent | flags | node.links.red as u64);
        object::set(n, 24, node.target);
        match object::node_owner(n) {
            NodeOwner::Thread(t) => with_ipc(t, |s| s.node_ec = node.ec),
            NodeOwner::Entry { ws, bits, i } => {
                let h = ws_header(ws, bits);
                let linked = object::get(h, ws_word::LINKED);
                let linked = if node.ec != NIL {
                    linked | 1 << i
                } else {
                    linked & !(1 << i)
                };
                object::set(h, ws_word::LINKED, linked);
            }
        }
    }

    fn owner(&self, n: u64) -> Owner {
        match object::node_owner(n) {
            NodeOwner::Thread(t) => Owner::Thread(DTcb(t.0)),
            NodeOwner::Entry { ws, bits, i } => Owner::Entry(Ws(ws_name(ws, bits)), i),
        }
    }

    fn thread_node(&self, t: DTcb) -> u64 {
        object::thread_node(Tcb(t.0))
    }

    fn entry_node(&self, w: Ws, i: usize) -> u64 {
        let (ws, bits) = ws_of(w.0);
        entry_node(ws, bits, i)
    }

    fn thread_ec(&self, t: DTcb) -> ThreadEc {
        let s: IpcState = object::ipc(Tcb(t.0));
        ThreadEc {
            bound: nz(s.bound).map(Ec),
            last: s.last,
            set: nz(s.set).map(Ws),
        }
    }

    fn set_thread_ec(&mut self, t: DTcb, rec: ThreadEc) {
        with_ipc(Tcb(t.0), |s| {
            s.bound = rec.bound.map_or(0, |e| e.0);
            s.last = rec.last;
            s.set = rec.set.map_or(0, |w| w.0);
        });
    }

    fn ws(&self, w: Ws) -> WsRec {
        let (ws, bits) = ws_of(w.0);
        let h = ws_header(ws, bits);
        WsRec {
            waiter: nz(object::get(h, ws_word::WAITER)).map(DTcb),
            entries: object::get(h, ws_word::ENTRIES) as u8,
        }
    }

    /// Writes the waiter. The number of entries is the set's size's, which
    /// [`object::init_set`] wrote.
    fn set_ws(&mut self, w: Ws, rec: WsRec) {
        let (ws, bits) = ws_of(w.0);
        object::set(
            ws_header(ws, bits),
            ws_word::WAITER,
            rec.waiter.map_or(0, |t| t.0),
        );
    }

    fn entry(&self, w: Ws, i: usize) -> Option<Ec> {
        match crate::cap::cap(entry_slot(w, i)) {
            Cap::Eventcount { ptr, .. } => Some(Ec(ptr)),
            _ => None,
        }
    }

    fn bind_entry(&mut self, w: Ws, i: usize, _e: Ec) {
        let (_, bits) = ws_of(w.0);
        let src = SlotRef(PRESENTED.load(Ordering::Relaxed));
        if let Err(e) = kcap::ops::bind_entry(&mut DirectSlots, src, entry_slot(w, i), bits) {
            panic!("wait-set entry {i}'s copy failed after its checks: {e:?}");
        }
    }

    /// Puts `e` on this core's work list (K24), recording the core, so a
    /// later advance on another core, or its finish, finds the list.
    fn queue_work(&mut self, e: Ec) {
        let c = this_core();
        let core = c.index as u64;
        c.work.push_back(&mut WorkItems, ec_item(e.0));
        let w = object::get(e.0, ec_word::WORD) & !ec_word::CORE;
        object::set(e.0, ec_word::WORD, w | core << ec_word::CORE_SHIFT);
    }

    fn unqueue_work(&mut self, e: Ec) {
        let w = object::get(e.0, ec_word::WORD);
        if w & ec_word::QUEUED == 0 {
            return;
        }
        let core = ((w & ec_word::CORE) >> ec_word::CORE_SHIFT) as usize;
        percore::core(core)
            .work
            .remove(&mut WorkItems, ec_item(e.0));
    }

    fn transfer(&mut self, from: DTcb, to: DTcb, what: Transfer) {
        super::message::transfer(Tcb(from.0), Tcb(to.0), what);
    }

    fn woke(&mut self, t: DTcb, v: Value) {
        super::message::woke(Tcb(t.0), v);
    }

    /// A send canceled under a released badge makes its call again (ADR
    /// 0049, rule 5): its PC goes back to its `SVC`, and its registers
    /// still hold the call's arguments, since its wait ended with no
    /// result.
    fn restart(&mut self, t: DTcb) {
        crate::sched::entry::restart(Tcb(t.0));
    }
}

/// How many times core `k`'s work list holds the eventcount at `e`: 0 or 1
/// while K24 holds (test builds). Walked under the kernel lock.
#[cfg(aspis_test_build)]
pub fn times_on_list(k: usize, e: Ec) -> usize {
    let me = ec_item(e.0);
    let mut n = 0;
    let mut at = percore::core(k).work.front();
    while let Some(i) = at {
        n += usize::from(i == me);
        at = Tagged::from_raw(WorkItems.wlinks(i).next);
    }
    n
}

/// An eventcount, as a work-list item.
pub fn ec_item(e: u64) -> Tagged {
    match Tagged::new(e, Tagged::EVENTCOUNT) {
        Some(t) => t,
        None => panic!("eventcount {e:#x} isn't aligned"),
    }
}

/// The links of every item on a core's work list: a walk's cursor, a reply
/// object, keeps them in its words 13 and 14; an eventcount in its words 3
/// and 4 (K24). One store serves both, since a list's neighbors may be of
/// either kind.
pub struct WorkItems;

impl WorkStore for WorkItems {
    fn wlinks(&self, item: Tagged) -> WLinks {
        match item.tag() {
            Tagged::EVENTCOUNT => {
                let a = item.addr();
                WLinks {
                    next: object::get(a, ec_word::WNEXT),
                    prev: object::get(a, ec_word::WPREV),
                    queued: object::get(a, ec_word::WORD) & ec_word::QUEUED != 0,
                }
            }
            _ => crate::sched::donation::Replies.wlinks(item),
        }
    }

    fn set_wlinks(&mut self, item: Tagged, l: WLinks) {
        match item.tag() {
            Tagged::EVENTCOUNT => {
                let a = item.addr();
                object::set(a, ec_word::WNEXT, l.next);
                object::set(a, ec_word::WPREV, l.prev);
                let w = object::get(a, ec_word::WORD);
                let w = if l.queued {
                    w | ec_word::QUEUED
                } else {
                    w & !ec_word::QUEUED
                };
                object::set(a, ec_word::WORD, w);
            }
            _ => crate::sched::donation::Replies.set_wlinks(item, l),
        }
    }
}
