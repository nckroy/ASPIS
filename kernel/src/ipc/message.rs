// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Copying a message, a reply or a fault message from one thread to another
//! (ADR 0054, rules 3, 4 and 7; ADR 0049, rule 6; kernel specification,
//! "Endpoint operations and messages", "Capability transfer" and "Fault
//! delivery"; K28).
//!
//! The registers and the info word are `kipc::msg`'s. Words 0 to 3 move from
//! the sender's saved x2 to x5 into the receiver's, zero past the length.
//! Words 4 and up move from the sender's IPC buffer page to the receiver's,
//! a word at a time, through the direct map, only when both threads have a
//! buffer; otherwise the message is cut to its first 32 octets, and the
//! length says so. The kernel never reads a word's meaning (ADR 0054, rule
//! 4).
//!
//! **Reading the buffer.** Each word the kernel interprets, the capability
//! addresses to send and the receive-slot triples, is read once, with a
//! volatile load, into a local array before any check, since other threads
//! of the address space may write the page at the same time. A page is
//! reached only through its pin: the physical address registration checked
//! (K29; [`super::buffer`]), which the copy in thread slot 7 keeps alive. So
//! the kernel never dereferences a user address, and never faults here (ADR
//! 0048, rule 5). C15 adds the dirty mark on the receiver's page.

use super::object;
use crate::cap::DirectSlots;
use crate::mm::phys::{DirectMem, Window};
use crate::sched::object::Tcb;
use kcap::SlotRef;
use kcap::cap::Cap;
use kcap::lookup;
use kcap::transfer::Send;
use kipc::MAX_CAPS;
use kipc::msg::{self, Info, RecvSlot, buffer, fault};
use kipc::store::{Transfer, Value};

/// The IPC buffer page of `t`, by its physical address, if it has one.
fn buffer_of(t: Tcb) -> Option<u64> {
    let pa = object::ipc(t).buf_pa;
    (pa != 0).then_some(pa)
}

/// Reads the word at offset `off` of the buffer page at `pa`, once.
fn read(pa: u64, off: u64) -> u64 {
    debug_assert!(off.is_multiple_of(8) && off < buffer::SIZE);
    let p = DirectMem.va(pa + off) as *const u64;
    // SAFETY: a page of RAM that registration found in the direct map
    // read-write, kept alive by the copy of its capability in the thread's
    // slot 7 (K29). User threads may write it at the same time, so it is
    // read once, volatile, as memory shared with a device is.
    unsafe { core::ptr::read_volatile(p) }
}

/// Writes the word at offset `off` of the buffer page at `pa`.
fn write(pa: u64, off: u64, v: u64) {
    debug_assert!(off.is_multiple_of(8) && off < buffer::SIZE);
    let p = DirectMem.va(pa + off) as *mut u64;
    // SAFETY: as for `read`; registration checked the direct map covers the
    // page read-write.
    unsafe { core::ptr::write_volatile(p, v) }
}

/// Writes the badge words of the buffer page at `pa`: `badges`, the
/// badges of the capabilities a message unwrapped, at their positions, and
/// zero elsewhere. Every message, reply or fault received into a buffer
/// writes all three, so none is left from an earlier message (K28).
fn badges(pa: u64, badges: &[u64; MAX_CAPS]) {
    for (i, b) in badges.iter().enumerate() {
        write(pa, buffer::BADGES + i as u64 * msg::WORD, *b);
    }
}

/// Copies the message, reply or fault `what` from `from` to `to` (module
/// docs).
///
/// A message or a fault writes the receiver's status, ok, in x0 (K28). The
/// receiver may have blocked in receive with x0 still holding its endpoint
/// capability's address, and a call or a fault that ends its wait leaves
/// donation's result empty, so nothing else writes it. A reply's status is
/// donation's, written as the caller's wait ended.
pub fn transfer(from: Tcb, to: Tcb, what: Transfer) {
    match what {
        Transfer::Message {
            ep,
            info,
            badge,
            grant,
        } => {
            message(from, to, ep.0, info, badge, grant);
            received(to);
        }
        // A reply unwraps nothing, as seL4's reply passes no endpoint, and
        // carries no badge.
        Transfer::Reply { info, grant } => message(from, to, 0, info, 0, grant),
        Transfer::Fault { badge } => {
            fault_message(from, to, badge);
            received(to);
        }
    }
}

/// Writes ok in the x0 of `to`, which has just received.
fn received(to: Tcb) {
    to.with(|b| b.ctx.x[msg::regs::STATUS] = msg::Status::Ok.word(false));
}

/// A message or a reply, sent through the endpoint at `ep` (0 for a
/// reply).
fn message(from: Tcb, to: Tcb, ep: u64, info: u64, badge: u64, grant: bool) {
    let (fb, tb) = (buffer_of(from), buffer_of(to));
    let both = fb.zip(tb);
    let info = Info::decode(info).as_sent(both.is_some());
    let words = info.words();
    let regs = from.with(|b| b.ctx.x);
    to.with(|b| {
        for (w, &r) in msg::regs::MSG.iter().enumerate() {
            b.ctx.x[r] = if (w as u64) < words { regs[r] } else { 0 };
        }
    });
    let (count, unwrapped) = match both {
        Some((fb, tb)) => {
            for i in 0..info.buffer_words() {
                let off = buffer::BUFFER_WORDS + i * msg::WORD;
                write(tb, off, read(fb, off));
            }
            caps(from, to, fb, tb, ep, &info, grant)
        }
        // No capabilities move, but a receiver's buffer still gets its
        // badge words.
        None => {
            if let Some(tb) = tb {
                badges(tb, &[0; MAX_CAPS]);
            }
            (0, 0)
        }
    };
    let out = info.received(count, unwrapped);
    to.with(|b| {
        b.ctx.x[msg::regs::INFO] = out.encode();
        b.ctx.x[msg::regs::BADGE] = badge;
    });
}

/// Transfers the capabilities a message carries, both threads having
/// buffers at `fb` and `tb`, and writes the receiver's badges: how many
/// were transferred, and the unwrapped mask (ADR 0049, rule 6; K28).
fn caps(from: Tcb, to: Tcb, fb: u64, tb: u64, ep: u64, info: &Info, grant: bool) -> (u8, u8) {
    let n = msg::cap_count(info, true);
    let mut done = kcap::transfer::Transferred::default();
    if n > 0 && grant {
        // Read once, each, before anything is checked.
        let mut addrs = [0u64; MAX_CAPS];
        for (i, a) in addrs.iter_mut().enumerate().take(n) {
            *a = read(fb, buffer::CAPS + i as u64 * msg::WORD);
        }
        let mut words = [0u64; buffer::RECV_SLOT_WORDS];
        for (i, w) in words.iter_mut().enumerate() {
            *w = read(tb, buffer::RECV_SLOTS + i as u64 * msg::WORD);
        }
        let (named, k) = msg::recv_slots(&words);
        let mut slots = [SlotRef(0); MAX_CAPS];
        let mut m = 0;
        for s in &named[..k] {
            match resolve(to, s) {
                Some(slot) => {
                    slots[m] = slot;
                    m += 1;
                }
                // A slot that doesn't resolve ends the list.
                None => break,
            }
        }
        done = crate::cap::transfer(
            &Send {
                root: from.slot_cap(1),
                addrs: &addrs[..n],
                grant,
                endpoint: ep,
            },
            &slots[..m],
        );
    }
    badges(tb, &done.badges);
    (done.count as u8, done.unwrapped)
}

/// The receive slot `s` names in `to`'s capability space, as seL4's
/// `lookupTargetSlot`: the CNode at its address, then the index at its
/// depth in that CNode.
fn resolve(to: Tcb, s: &RecvSlot) -> Option<SlotRef> {
    let root = to.slot_cap(1);
    let (_, cnode @ Cap::CNode { .. }) = lookup::lookup_cap(&DirectSlots, root, s.cnode).ok()?
    else {
        return None;
    };
    lookup::lookup_slot(&DirectSlots, cnode, s.index, s.depth).ok()
}

/// The fault message of `from`'s fault record, sent on an endpoint copy
/// with `badge` (provisional until C15 writes `aspis.kernel.fault/1`;
/// kernel specification, "Fault delivery"). Its header travels in x2 to
/// x5; its body, as big-endian octets, in the handler's buffer, or not at
/// all without one. It carries no capabilities, so the buffer's badge words
/// are zero.
fn fault_message(from: Tcb, to: Tcb, badge: u64) {
    let f = from.with(|b| b.s.fault);
    let words = fault::encode(&fault::Fields {
        method: f.kind as u16,
        pc: f.pc,
        syndrome: f.esr,
        addr: f.addr,
        extra: f.extra,
    });
    let tb = buffer_of(to);
    if let Some(tb) = tb {
        for (i, &w) in words[msg::REG_WORDS as usize..].iter().enumerate() {
            let v = u64::from_ne_bytes(fault::body_octets(w));
            write(tb, buffer::BUFFER_WORDS + i as u64 * msg::WORD, v);
        }
        badges(tb, &[0; MAX_CAPS]);
    }
    let info = fault::info().as_sent(tb.is_some());
    to.with(|b| {
        for (w, &r) in msg::regs::MSG.iter().enumerate() {
            b.ctx.x[r] = words[w];
        }
        b.ctx.x[msg::regs::INFO] = info.encode();
        b.ctx.x[msg::regs::BADGE] = badge;
    });
}

/// What a thread gets besides its status when an eventcount wait, a
/// wait-set wait or a bound eventcount's advance ends its wait (K28): the
/// count or the mask in x1; for an advance, the advance info word in x1,
/// no words, and the count in x6. None writes the buffer, whose badge words
/// keep the last message's (K28).
pub fn woke(t: Tcb, v: Value) {
    t.with(|b| match v {
        Value::Count(c) | Value::Mask(c) => b.ctx.x[msg::regs::INFO] = c,
        Value::Advance(c) => {
            b.ctx.x[msg::regs::INFO] = Info::advance().encode();
            for &r in &msg::regs::MSG {
                b.ctx.x[r] = 0;
            }
            b.ctx.x[msg::regs::BADGE] = c;
        }
    });
}
