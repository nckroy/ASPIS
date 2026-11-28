// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! In-QEMU tests of endpoints, messages, IPC buffers and faults over
//! endpoints (C14; ADR 0054; ADR 0049, rules 5 and 6; ADR 0047, rules 4
//! and 6; ADR 0052, rule 2; ADR 0056; K17, K19, K20, K23, K28, K29, K30,
//! K50).
//!
//! Most drive the operations on threads that stay suspended
//! ([`super::testkit`]), so long queues are built in the kernel and every
//! step is checked as it happens; a few run at EL0 through the test trap:
//! the long operations restarted at every preemption point, faults raised
//! by real instructions, and calls across cores. Each checks the endpoint
//! and donation invariants after the steps that change them, and ends with
//! the scheduler's baseline check (`crate::sched::testkit::finish`). The
//! tests count and order; none measures time spent.

use super::endpoint;
use super::object;
use super::syscall::{self, Args};
use super::testkit::{
    answer_fault, badged, buf, caller_of, caller_thread, check, copy_with, endpoint_obj, epc,
    give_buffer, idle_thread, idle_thread_in, info, many, on_this_core, others, queue, queue_len,
    queued_at, reply_obj, rpc, scratch, set_buf, set_words, slots_of, status, tcb, words, x,
};
use crate::cap::testkit::Scratch;
use crate::cap::{self, map};
use crate::sched::fault::Kind;
use crate::sched::object::{Tcb, UserContext, Wait, flag};
use crate::sched::percore::this_core;
use crate::sched::testkit::{self, STACK_VA, Spec, UNMAPPED_VA, make_room, ms, space, spawn_in};
use crate::sched::{Error, thread};
use crate::testing::driver::run_until;
use crate::testing::report;
use crate::testing::trap::{CANCEL_BADGED_SENDS, DELETE, FORCE_PREEMPT};
use crate::testing::user::Program;
use core::sync::atomic::{AtomicU64, Ordering};
use kcap::SlotRef;
use kcap::cap::{Binding, Cap};
use kcap::ops::MintData;
use kcap::preempt::{Always, Budget};
use kcap::rights::Rights;
use kipc::Outcome::{Blocked, Done};
use kipc::msg::{Info, Status, buffer, fault};
use kmem::desc::UserPerm;
use kmem::untyped::ObjectType;
use ksched::donation::Reply;

/// The thread a test's condition watches.
static W: AtomicU64 = AtomicU64::new(0);

fn watch(t: Tcb) {
    W.store(t.0, Ordering::Relaxed);
}

fn w() -> Tcb {
    Tcb(W.load(Ordering::Relaxed))
}

fn w_ready() -> bool {
    w().wait() == Wait::None
}

fn w_done() -> bool {
    w().has(flag::DONE)
}

fn w_not_receiving() -> bool {
    w().wait() != Wait::Receive
}

fn w_fault_queued() -> bool {
    w().wait() == Wait::FaultSend
}

fn w_suspended() -> bool {
    !w().has(flag::RESUMED)
}

fn walks_done() -> bool {
    this_core().work.is_empty()
}

/// A word of a test pattern.
const fn pattern(i: u64) -> u64 {
    0x0101_0101_0101_0101u64.wrapping_mul(i + 1) ^ 0xa5
}

const OK: (Status, bool) = (Status::Ok, false);

// ---------------------------------------------------------------------------
// Messages.

crate::kernel_test!(ipc_send_recv_960_octets, {
    // ADR 0054, rule 3; K28: a message of 960 octets, both orders, arrives
    // octet for octet with its exact length, label and badge.
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (e, _) = endpoint_obj(&mut sc);
    let b = badged(&mut sc, e, 0x5eed, Rights::ALL);
    let (ss, st) = idle_thread_in(&mut sc, s, 10);
    let (rs, rt) = idle_thread_in(&mut sc, s, 10);
    let (_, spa) = give_buffer(&mut sc, s, ss, 0);
    let (_, rpa) = give_buffer(&mut sc, s, rs, 1);
    let (_, r) = reply_obj(&mut sc);
    for i in 4..120 {
        set_buf(spa, i * 8, pattern(i));
    }
    let inf = info(0x1234_5678_9abc, 960, 0);
    for receiver_first in [true, false] {
        for i in 4..120 {
            set_buf(rpa, i * 8, 0);
        }
        set_words(st, [pattern(0), pattern(1), pattern(2), pattern(3)]);
        if receiver_first {
            assert_eq!(endpoint::recv(rt, epc(e), r, 0), Ok(Blocked));
            check(&[e], &[st, rt], &[r]);
            assert_eq!(endpoint::send(st, epc(b), inf, true, 0), Ok(Done));
        } else {
            assert_eq!(endpoint::send(st, epc(b), inf, true, 0), Ok(Blocked));
            assert_eq!(st.wait(), Wait::Send);
            check(&[e], &[st, rt], &[r]);
            assert_eq!(endpoint::recv(rt, epc(e), r, 0), Ok(Done));
            assert_eq!(st.wait(), Wait::None);
        }
        assert_eq!((status(st), status(rt)), (OK, OK));
        assert_eq!(x(rt, 1), inf);
        assert_eq!(words(rt), [pattern(0), pattern(1), pattern(2), pattern(3)]);
        assert_eq!(x(rt, 6), 0x5eed);
        for i in 4..120 {
            assert_eq!(buf(rpa, i * 8), pattern(i), "word {i}");
        }
        check(&[e], &[st, rt], &[r]);
    }
    // A length over 960 is refused, and nothing is sent (K28).
    assert_eq!(
        endpoint::send(st, epc(e), info(0, 961, 0), true, 0),
        Err(Status::InvalidArgument)
    );
    assert_eq!(
        (st.wait(), status(st)),
        (Wait::None, (Status::InvalidArgument, false))
    );
    testkit::finish(sc);
});

crate::kernel_test!(ipc_no_buffer_cuts_to_registers, {
    // K28: without a buffer on either side, the message is cut to its
    // first 32 octets and carries no capabilities; words past the length
    // arrive as zero.
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (e, _) = endpoint_obj(&mut sc);
    let (ss, st) = idle_thread_in(&mut sc, s, 10);
    let (_, rt) = idle_thread(&mut sc, 10);
    let (_, spa) = give_buffer(&mut sc, s, ss, 0);
    set_buf(spa, buffer::CAPS, sc.addr_of(e));
    let (_, r) = reply_obj(&mut sc);
    set_words(st, [1, 2, 3, 4]);
    assert_eq!(endpoint::recv(rt, epc(e), r, 0), Ok(Blocked));
    assert_eq!(
        endpoint::send(st, epc(e), info(9, 100, 2), true, 0),
        Ok(Done)
    );
    let got = Info::decode(x(rt, 1));
    assert_eq!((got.label, got.len, got.caps), (9, 32, 0));
    assert_eq!(words(rt), [1, 2, 3, 4]);
    // Twenty octets: three words, the last partly, and the fourth zero.
    assert_eq!(endpoint::recv(rt, epc(e), r, 0), Ok(Blocked));
    set_words(st, [5, 6, 7, 8]);
    assert_eq!(
        endpoint::send(st, epc(e), info(0, 20, 0), true, 0),
        Ok(Done)
    );
    assert_eq!(Info::decode(x(rt, 1)).len, 20);
    assert_eq!(words(rt), [5, 6, 7, 0]);
    check(&[e], &[st, rt], &[r]);
    testkit::finish(sc);
});

crate::kernel_test!(ipc_nbsend_drops, {
    // ADR 0054, rule 2: a send without blocking and no receiver drops the
    // message, and returns at once.
    let mut sc = scratch(20);
    let (e, _) = endpoint_obj(&mut sc);
    let (_, st) = idle_thread(&mut sc, 10);
    let (_, rt) = idle_thread(&mut sc, 10);
    let (_, r) = reply_obj(&mut sc);
    assert_eq!(
        endpoint::send(st, epc(e), info(0, 8, 0), false, 0),
        Ok(Done)
    );
    assert_eq!((st.wait(), status(st), queue_len(e)), (Wait::None, OK, 0));
    assert_eq!(endpoint::recv(rt, epc(e), r, 0), Ok(Blocked));
    // With a receiver waiting, it is delivered.
    set_words(st, [77, 0, 0, 0]);
    assert_eq!(
        endpoint::send(st, epc(e), info(0, 8, 0), false, 0),
        Ok(Done)
    );
    assert_eq!((rt.wait(), x(rt, 2)), (Wait::None, 77));
    check(&[e], &[st, rt], &[r]);
    testkit::finish(sc);
});

crate::kernel_test!(ipc_badge_words_always_written, {
    // K28: a message received into a buffer writes its three badge words,
    // zero where nothing was unwrapped, even from a sender without a
    // buffer, whose message carries no capabilities: none is left from an
    // earlier message. (A fault's are checked in ipc_faults_over_endpoints.)
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (e, _) = endpoint_obj(&mut sc);
    let (_, st) = idle_thread(&mut sc, 10);
    let (rs, rt) = idle_thread_in(&mut sc, s, 10);
    let (_, rpa) = give_buffer(&mut sc, s, rs, 0);
    let (_, r) = reply_obj(&mut sc);
    for i in 0..3 {
        set_buf(rpa, buffer::BADGES + 8 * i, 7);
    }
    assert_eq!(endpoint::recv(rt, epc(e), r, 0), Ok(Blocked));
    assert_eq!(endpoint::send(st, epc(e), info(0, 8, 0), true, 0), Ok(Done));
    assert_eq!(Info::decode(x(rt, 1)).unwrapped, 0);
    for i in 0..3 {
        assert_eq!(buf(rpa, buffer::BADGES + 8 * i), 0, "badge word {i}");
    }
    check(&[e], &[st, rt], &[r]);
    testkit::finish(sc);
});

crate::kernel_test!(ipc_call_reply_active_and_passive, {
    // ADR 0051, rule 3: a passive server runs on its caller's context,
    // which comes back with the reply; an active one keeps its own.
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (e, _) = endpoint_obj(&mut sc);
    let (_, c) = caller_thread(&mut sc, s, 10, 0);
    let own = c.sc().unwrap();
    let (_, srv) = idle_thread(&mut sc, 10);
    let (_, r) = reply_obj(&mut sc);
    // K28: x0 holds the endpoint's address on the way in; a blocked
    // receive leaves it, and the call that ends the wait writes ok.
    srv.with(|b| b.ctx.x[0] = 0xdead);
    assert_eq!(endpoint::recv(srv, epc(e), r, 0), Ok(Blocked));
    // K28: the caller's words past the reply's length, and its x6, start
    // nonzero, as does the replier's x6, so the reply is seen to zero them.
    set_words(c, [41, 0xaa, 0xbb, 0xcc]);
    c.with(|b| b.ctx.x[6] = 0xdead);
    assert_eq!(endpoint::call(c, epc(e), info(0, 8, 0), 0), Ok(Blocked));
    assert_eq!((c.wait(), srv.sc()), (Wait::Call, Some(own)));
    assert_eq!((status(srv), words(srv)), (OK, [41, 0, 0, 0]));
    check(&[e], &[c, srv], &[r]);
    set_words(srv, [42, 0x11, 0x22, 0x33]);
    srv.with(|b| b.ctx.x[6] = 0x5eed);
    assert_eq!(endpoint::reply(srv, r, false, info(0, 8, 0)), Ok(()));
    assert_eq!((c.wait(), status(c)), (Wait::None, OK));
    // A reply carries no badge: x6 is 0, and the words past its length are
    // zero.
    assert_eq!((words(c), x(c, 6)), ([42, 0, 0, 0], 0));
    assert_eq!((c.sc(), srv.sc()), (Some(own), None));
    check(&[e], &[c, srv], &[r]);
    // An active server.
    let (_, act) = caller_thread(&mut sc, s, 10, 0);
    let its = act.sc().unwrap();
    act.with(|b| b.ctx.x[0] = 0xdead);
    assert_eq!(endpoint::recv(act, epc(e), r, 0), Ok(Blocked));
    set_words(c, [7, 0, 0, 0]);
    assert_eq!(endpoint::call(c, epc(e), info(0, 8, 0), 0), Ok(Blocked));
    assert_eq!((act.sc(), c.sc()), (Some(its), Some(own)));
    assert_eq!(status(act), OK);
    set_words(act, [8, 0, 0, 0]);
    assert_eq!(endpoint::reply(act, r, false, info(0, 8, 0)), Ok(()));
    assert_eq!((c.wait(), x(c, 2)), (Wait::None, 8));
    check(&[e], &[c, act], &[r]);
    testkit::finish(sc);
});

crate::kernel_test!(ipc_priority_order, {
    // ADR 0054, rule 1; K25: senders and receivers are served by priority,
    // first come first served within one; a priority change rejoins the
    // queue as a new arrival.
    let mut sc = scratch(20);
    let (e, _) = endpoint_obj(&mut sc);
    let mut senders = [Tcb(0); 4];
    for (i, p) in [1u8, 3, 2, 3].into_iter().enumerate() {
        let b = badged(&mut sc, e, i as u64 + 1, Rights::ALL);
        let (_, t) = idle_thread(&mut sc, p);
        assert_eq!(
            endpoint::send(t, epc(b), info(0, 0, 0), true, 0),
            Ok(Blocked)
        );
        senders[i] = t;
    }
    let (q, n) = queue::<4>(e);
    assert_eq!(n, 4);
    assert_eq!(q, [senders[1], senders[3], senders[2], senders[0]]);
    check(&[e], &senders, &[]);
    let (_, rt) = idle_thread(&mut sc, 10);
    let (_, r) = reply_obj(&mut sc);
    let mut got = [0; 4];
    for g in &mut got {
        assert_eq!(endpoint::recv(rt, epc(e), r, 0), Ok(Done));
        *g = x(rt, 6);
    }
    assert_eq!(got, [2, 4, 3, 1]);
    // Receivers.
    let mut recv = [Tcb(0); 3];
    let mut rr = [Reply(0); 3];
    for (i, p) in [2u8, 5, 2].into_iter().enumerate() {
        let (_, t) = idle_thread(&mut sc, p);
        let (_, r) = reply_obj(&mut sc);
        assert_eq!(endpoint::recv(t, epc(e), r, 0), Ok(Blocked));
        (recv[i], rr[i]) = (t, r);
    }
    let (_, st) = idle_thread(&mut sc, 1);
    for want in [recv[1], recv[0], recv[2]] {
        assert_eq!(endpoint::send(st, epc(e), info(0, 0, 0), true, 0), Ok(Done));
        assert_eq!(want.wait(), Wait::None);
    }
    // A priority change while queued.
    let mut ss = [SlotRef(0); 3];
    let mut ts = [Tcb(0); 3];
    for i in 0..3 {
        let (s, t) = idle_thread(&mut sc, 2);
        assert_eq!(
            endpoint::send(t, epc(e), info(0, 0, 0), true, 0),
            Ok(Blocked)
        );
        (ss[i], ts[i]) = (s, t);
    }
    thread::set_priority(ss[0], testkit::first_thread(), 2).unwrap();
    assert_eq!(queue::<3>(e).0, [ts[1], ts[2], ts[0]]);
    thread::set_priority(ss[2], testkit::first_thread(), 3).unwrap();
    assert_eq!(queue::<3>(e).0, [ts[2], ts[1], ts[0]]);
    check(&[e], &ts, &[]);
    testkit::finish(sc);
});

/// A receive CNode of 16 slots in the scratch space, its address and its
/// first slot; and three receive-slot triples naming its slots 0, 1 and 2,
/// or fewer, in the buffer page at `pa`.
fn recv_cnode(sc: &mut Scratch, pa: u64, n: u64) -> SlotRef {
    let cn = sc.make(ObjectType::CNode(4));
    let a = sc.addr_of(cn);
    for i in 0..3 {
        let (c, idx, d) = if i < n { (a, i, 4) } else { (0, 0, 0) };
        set_buf(pa, buffer::RECV_SLOTS + 24 * i, c);
        set_buf(pa, buffer::RECV_SLOTS + 24 * i + 8, idx);
        set_buf(pa, buffer::RECV_SLOTS + 24 * i + 16, d);
    }
    slots_of(cn)
}

crate::kernel_test!(ipc_caps_three_slots, {
    // ADR 0049, rule 6; ADR 0054, rule 7; K28: three capabilities into the
    // receive slots the receiver names; an endpoint capability to the
    // endpoint the message goes through is unwrapped to its badge.
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (e, _) = endpoint_obj(&mut sc);
    let (other, _) = endpoint_obj(&mut sc);
    let fx = sc.make(ObjectType::Frame4K);
    let b7 = badged(&mut sc, e, 7, Rights::ALL);
    let (ss, st) = idle_thread_in(&mut sc, s, 10);
    let (rs, rt) = idle_thread_in(&mut sc, s, 10);
    let (_, spa) = give_buffer(&mut sc, s, ss, 0);
    let (_, rpa) = give_buffer(&mut sc, s, rs, 1);
    let (rsl, r) = reply_obj(&mut sc);
    for (i, c) in [fx, b7, other].into_iter().enumerate() {
        set_buf(spa, buffer::CAPS + 8 * i as u64, sc.addr_of(c));
    }
    let slots = recv_cnode(&mut sc, rpa, 3);
    assert_eq!(endpoint::recv(rt, epc(e), r, 0), Ok(Blocked));
    assert_eq!(endpoint::send(st, epc(e), info(0, 0, 3), true, 0), Ok(Done));
    let got = Info::decode(x(rt, 1));
    assert_eq!((got.caps, got.unwrapped), (3, 0b010));
    assert_eq!(
        [
            buf(rpa, buffer::BADGES),
            buf(rpa, buffer::BADGES + 8),
            buf(rpa, buffer::BADGES + 16)
        ],
        [0, 7, 0]
    );
    assert!(cap::cap(slots).same_object(&cap::cap(fx)));
    assert!(cap::cap(slots.offset(1)).same_object(&cap::cap(other)));
    assert!(cap::cap(slots.offset(2)).is_null());
    assert!(kcap::mdb::has_children(&cap::DirectSlots, fx));
    // One receive slot: the frame and the unwrapped endpoint, then no slot
    // for the third.
    cap::delete(slots);
    cap::delete(slots.offset(1));
    let slots = recv_cnode(&mut sc, rpa, 1);
    assert_eq!(endpoint::recv(rt, epc(e), r, 0), Ok(Blocked));
    assert_eq!(endpoint::send(st, epc(e), info(0, 0, 3), true, 0), Ok(Done));
    assert_eq!(Info::decode(x(rt, 1)).caps, 2);
    assert!(cap::cap(slots.offset(1)).is_null());
    // Without the grant right, nothing moves.
    let ng = badged(&mut sc, e, 9, Rights::READ.union(Rights::WRITE));
    let slots = recv_cnode(&mut sc, rpa, 3);
    assert_eq!(endpoint::recv(rt, epc(e), r, 0), Ok(Blocked));
    assert_eq!(
        endpoint::send(st, epc(ng), info(0, 0, 3), true, 0),
        Ok(Done)
    );
    assert_eq!(Info::decode(x(rt, 1)).caps, 0);
    assert!(cap::cap(slots).is_null());
    // A reply carries capabilities only if the reply capability has the
    // grant right (ADR 0054, rule 7), which reply and reply-and-receive
    // read from the capability they name. First reply-and-receive, without
    // the right and then with it; then reply.
    let (cs, c) = caller_thread(&mut sc, s, 10, 0);
    let (_, cpa) = give_buffer(&mut sc, s, cs, 2);
    let no_grant = copy_with(&mut sc, rsl, Rights::READ.union(Rights::WRITE));
    let (ea, full_a, no_grant_a) = (sc.addr_of(e), sc.addr_of(rsl), sc.addr_of(no_grant));
    let args = |reply: u64| Args {
        cap: ea,
        info: info(0, 0, 1),
        reply,
        deadline: 0,
    };
    set_buf(rpa, buffer::CAPS, sc.addr_of(fx));
    assert_eq!(endpoint::recv(rt, epc(e), r, 0), Ok(Blocked));
    for (reply, caps) in [(no_grant_a, 0), (full_a, 1)] {
        let cslots = recv_cnode(&mut sc, cpa, 1);
        assert_eq!(endpoint::call(c, epc(e), info(0, 0, 0), 0), Ok(Blocked));
        assert_eq!(syscall::reply_recv(rt, &args(reply)), Ok(Blocked));
        assert_eq!((status(c), Info::decode(x(c, 1)).caps), (OK, caps));
        assert_eq!(cap::cap(cslots).is_null(), caps == 0);
    }
    for (reply, caps) in [(no_grant_a, 0), (full_a, 1)] {
        let cslots = recv_cnode(&mut sc, cpa, 1);
        assert_eq!(endpoint::call(c, epc(e), info(0, 0, 0), 0), Ok(Blocked));
        assert_eq!(syscall::reply(rt, &args(reply)), Ok(()));
        assert_eq!((status(c), Info::decode(x(c, 1)).caps), (OK, caps));
        assert_eq!(cap::cap(cslots).is_null(), caps == 0);
        if caps == 0 {
            assert_eq!(endpoint::recv(rt, epc(e), r, 0), Ok(Blocked));
        } else {
            assert!(cap::cap(cslots).same_object(&cap::cap(fx)));
        }
    }
    check(&[e], &[st, rt, c], &[r]);
    testkit::finish(sc);
});

crate::kernel_test!(ipc_caps_bad_sender_address_sends_none, {
    // K28, as seL4's `lookupExtraCaps`: one address that doesn't resolve,
    // and the message is delivered with no capabilities.
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (e, _) = endpoint_obj(&mut sc);
    let fx = sc.make(ObjectType::Frame4K);
    let (ss, st) = idle_thread_in(&mut sc, s, 10);
    let (rs, rt) = idle_thread_in(&mut sc, s, 10);
    let (_, spa) = give_buffer(&mut sc, s, ss, 0);
    let (_, rpa) = give_buffer(&mut sc, s, rs, 1);
    let (_, r) = reply_obj(&mut sc);
    set_buf(spa, buffer::CAPS, sc.addr_of(fx));
    set_buf(spa, buffer::CAPS + 8, 0xdead_0000_0000);
    let slots = recv_cnode(&mut sc, rpa, 3);
    set_words(st, [5, 0, 0, 0]);
    assert_eq!(endpoint::recv(rt, epc(e), r, 0), Ok(Blocked));
    assert_eq!(endpoint::send(st, epc(e), info(0, 8, 2), true, 0), Ok(Done));
    assert_eq!((status(rt), x(rt, 2)), (OK, 5));
    assert_eq!(Info::decode(x(rt, 1)).caps, 0);
    assert!(cap::cap(slots).is_null());
    testkit::finish(sc);
});

crate::kernel_test!(ipc_call_rights_and_lookups, {
    // ADR 0047, rule 3; K30: each refused at once, with nothing changed.
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (e, _) = endpoint_obj(&mut sc);
    let (cs, c) = caller_thread(&mut sc, s, 10, 0);
    let (rs, _) = reply_obj(&mut sc);
    let w_only = badged(&mut sc, e, 1, Rights::WRITE);
    let r_only = badged(&mut sc, e, 2, Rights::READ);
    let args = |cap: SlotRef| Args {
        cap: sc.addr_of(cap),
        info: info(0, 8, 0),
        reply: sc.addr_of(rs),
        deadline: 0,
    };
    let a = args(w_only);
    assert_eq!(syscall::call(c, &a), Err(Status::MissingRight));
    assert_eq!(status(c), (Status::MissingRight, false));
    assert_eq!(syscall::recv(c, &a), Err(Status::MissingRight));
    let a = args(r_only);
    assert_eq!(syscall::send(c, &a, true), Err(Status::MissingRight));
    let mut a = args(e);
    a.cap = 0xffff_0000;
    assert_eq!(syscall::send(c, &a, true), Err(Status::InvalidCapability));
    assert_eq!(status(c), (Status::InvalidCapability, false));
    let a = args(cs);
    assert_eq!(syscall::call(c, &a), Err(Status::WrongKind));
    let mut a = args(e);
    a.reply = sc.addr_of(e);
    assert_eq!(syscall::recv(c, &a), Err(Status::WrongKind));
    let mut a = args(e);
    a.info = info(0, 961, 0);
    assert_eq!(syscall::call(c, &a), Err(Status::InvalidArgument));
    a.info = 1 << 15;
    assert_eq!(syscall::send(c, &a, false), Err(Status::InvalidArgument));
    assert_eq!((c.wait(), queue_len(e)), (Wait::None, 0));
    testkit::finish(sc);
});

crate::kernel_test!(ipc_reply_recv_checks_first, {
    // A server's reply and receive checks everything before it replies, so
    // a refusal leaves its caller waiting.
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (e, _) = endpoint_obj(&mut sc);
    let w_only = badged(&mut sc, e, 1, Rights::WRITE);
    let (_, c) = caller_thread(&mut sc, s, 10, 0);
    let own = c.sc();
    let (_, srv) = idle_thread(&mut sc, 10);
    let (_, r) = reply_obj(&mut sc);
    assert_eq!(endpoint::recv(srv, epc(e), r, 0), Ok(Blocked));
    assert_eq!(endpoint::call(c, epc(e), info(0, 0, 0), 0), Ok(Blocked));
    assert_eq!(
        endpoint::reply_recv(srv, epc(w_only), r, false, info(0, 0, 0), 0),
        Err(Status::MissingRight)
    );
    assert_eq!(
        endpoint::reply_recv(srv, epc(e), r, false, info(0, 961, 0), 0),
        Err(Status::InvalidArgument)
    );
    assert_eq!((c.wait(), srv.sc()), (Wait::Call, own));
    check(&[e], &[c, srv], &[r]);
    set_words(srv, [3, 0, 0, 0]);
    assert_eq!(
        endpoint::reply_recv(srv, epc(e), r, false, info(0, 8, 0), 0),
        Ok(Blocked)
    );
    assert_eq!((c.wait(), x(c, 2), c.sc()), (Wait::None, 3, own));
    assert_eq!((srv.wait(), srv.sc()), (Wait::Receive, None));
    // With no caller, the reply is skipped and the receive goes on.
    let (_, r2) = reply_obj(&mut sc);
    let (_, idle) = idle_thread(&mut sc, 10);
    assert_eq!(
        endpoint::reply_recv(idle, epc(e), r2, false, 0, 0),
        Ok(Blocked)
    );
    check(&[e], &[c, srv, idle], &[r, r2]);
    testkit::finish(sc);
});

crate::kernel_test!(ipc_deadlines, {
    // ADR 0054, rule 5; ADR 0064, rule 5; K19: every blocking operation
    // times out, and the result says whether a call was delivered.
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (e, _) = endpoint_obj(&mut sc);
    // A queued send.
    let (_, st) = idle_thread(&mut sc, 10);
    let dl = crate::timer::now() + ms(20);
    assert_eq!(
        endpoint::send(st, epc(e), info(0, 0, 0), true, dl),
        Ok(Blocked)
    );
    watch(st);
    assert!(run_until(w_ready, ms(2_000)), "the send didn't time out");
    assert_eq!((status(st), queue_len(e)), ((Status::TimedOut, false), 0));
    // A receive.
    let (_, rt) = idle_thread(&mut sc, 10);
    let (_, r) = reply_obj(&mut sc);
    let dl = crate::timer::now() + ms(20);
    assert_eq!(endpoint::recv(rt, epc(e), r, dl), Ok(Blocked));
    watch(rt);
    assert!(run_until(w_ready, ms(2_000)), "the receive didn't time out");
    assert_eq!((status(rt), queue_len(e)), ((Status::TimedOut, false), 0));
    // A delivered call: its context comes back within the batches.
    let (_, c) = caller_thread(&mut sc, s, 10, 0);
    let own = c.sc();
    assert_eq!(endpoint::recv(rt, epc(e), r, 0), Ok(Blocked));
    let dl = crate::timer::now() + ms(20);
    assert_eq!(endpoint::call(c, epc(e), info(0, 0, 0), dl), Ok(Blocked));
    assert_eq!(rt.sc(), own);
    watch(c);
    assert!(run_until(w_ready, ms(2_000)), "the call didn't time out");
    assert_eq!((status(c), c.sc()), ((Status::TimedOut, true), own));
    assert!(run_until(walks_done, ms(2_000)));
    assert_eq!(endpoint::reply(rt, r, false, 0), Err(Status::NoCaller));
    // A deadline already passed times out only what would block (K19).
    assert_eq!(endpoint::recv(rt, epc(e), r, 0), Ok(Blocked));
    assert_eq!(
        endpoint::call(c, epc(e), info(0, 0, 0), 1),
        Err(Status::TimedOut)
    );
    assert_eq!((rt.wait(), c.wait()), (Wait::Receive, Wait::None));
    // A refused call reports its error, not "timed out": here a caller
    // with no context.
    assert_eq!(
        endpoint::call(st, epc(e), info(0, 0, 0), 1),
        Err(Status::InvalidArgument)
    );
    assert_eq!(status(st), (Status::InvalidArgument, false));
    assert_eq!(endpoint::send(st, epc(e), info(0, 0, 0), true, 1), Ok(Done));
    assert_eq!((status(st), rt.wait()), (OK, Wait::None));
    endpoint::send(st, epc(e), info(0, 0, 0), true, 1).unwrap();
    assert_eq!(
        (st.wait(), status(st), queue_len(e)),
        (Wait::None, (Status::TimedOut, false), 0)
    );
    check(&[e], &[st, rt, c], &[r]);
    testkit::finish(sc);
});

crate::kernel_test!(ipc_cancel, {
    // ADR 0054, rule 6: a canceled call says whether it was delivered; one
    // canceled before delivery is never seen by the server.
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (e, _) = endpoint_obj(&mut sc);
    let (cs, c) = caller_thread(&mut sc, s, 10, 0);
    let (_, srv) = idle_thread(&mut sc, 10);
    let (_, r) = reply_obj(&mut sc);
    // Queued.
    assert_eq!(endpoint::call(c, epc(e), info(0, 0, 0), 0), Ok(Blocked));
    assert_eq!(c.wait(), Wait::Send);
    thread::cancel(cs).unwrap();
    assert_eq!((status(c), queue_len(e)), ((Status::Canceled, false), 0));
    assert_eq!(endpoint::recv(srv, epc(e), r, 0), Ok(Blocked));
    // Delivered: the server's reply then finds no caller.
    assert_eq!(endpoint::call(c, epc(e), info(0, 0, 0), 0), Ok(Blocked));
    assert_eq!(c.wait(), Wait::Call);
    thread::cancel(cs).unwrap();
    assert_eq!(status(c), (Status::Canceled, true));
    assert!(run_until(walks_done, ms(2_000)));
    assert_eq!(endpoint::reply(srv, r, false, 0), Err(Status::NoCaller));
    // A receive, and a send.
    let (rs, rt) = idle_thread(&mut sc, 10);
    let (_, r2) = reply_obj(&mut sc);
    assert_eq!(endpoint::recv(rt, epc(e), r2, 0), Ok(Blocked));
    thread::cancel(rs).unwrap();
    assert_eq!((status(rt), queue_len(e)), ((Status::Canceled, false), 0));
    let (ss, st) = idle_thread(&mut sc, 10);
    assert_eq!(
        endpoint::send(st, epc(e), info(0, 0, 0), true, 0),
        Ok(Blocked)
    );
    thread::cancel(ss).unwrap();
    assert_eq!((status(st), queue_len(e)), ((Status::Canceled, false), 0));
    // Cancel at the system-call surface needs the write right on the
    // thread: without it, the wait stands.
    let (_, m) = idle_thread(&mut sc, 10);
    assert_eq!(endpoint::recv(rt, epc(e), r2, 0), Ok(Blocked));
    let weak = sc.take();
    cap::mint(rs, weak, Rights::READ, MintData::None).unwrap();
    syscall::cancel(m, sc.addr_of(weak));
    assert_eq!(status(m), (Status::MissingRight, false));
    assert_eq!(rt.wait(), Wait::Receive);
    syscall::cancel(m, sc.addr_of(rs));
    assert_eq!(status(m), OK);
    assert_eq!((status(rt), queue_len(e)), ((Status::Canceled, false), 0));
    check(&[e], &[c, srv, rt, st], &[r, r2]);
    testkit::finish(sc);
});

crate::kernel_test!(ipc_suspended_k20, {
    // ADR 0061, rule 3; K20: a suspended receiver gets its message, and a
    // suspended sender's queued message is delivered, each written at once.
    let mut sc = scratch(20);
    let (e, _) = endpoint_obj(&mut sc);
    let (_, rt) = idle_thread(&mut sc, 10);
    let (_, st) = idle_thread(&mut sc, 10);
    let (_, r) = reply_obj(&mut sc);
    assert!(!rt.has(flag::RESUMED) && !st.has(flag::RESUMED));
    assert_eq!(endpoint::recv(rt, epc(e), r, 0), Ok(Blocked));
    set_words(st, [11, 0, 0, 0]);
    assert_eq!(endpoint::send(st, epc(e), info(0, 8, 0), true, 0), Ok(Done));
    assert_eq!((rt.wait(), status(rt), x(rt, 2)), (Wait::None, OK, 11));
    assert!(!rt.has(flag::RESUMED));
    set_words(st, [12, 0, 0, 0]);
    assert_eq!(
        endpoint::send(st, epc(e), info(0, 8, 0), true, 0),
        Ok(Blocked)
    );
    assert_eq!(endpoint::recv(rt, epc(e), r, 0), Ok(Done));
    assert_eq!((st.wait(), status(st), x(rt, 2)), (Wait::None, OK, 12));
    assert!(!st.has(flag::RESUMED));
    testkit::finish(sc);
});

crate::kernel_test!(ipc_stranded_k17, {
    // K17: C → S1, and S1's own call is queued on another endpoint.
    // Canceling C cancels S1's queued call, undelivered, and its walk step
    // then sends S1 its context-withdrawn fault.
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (e, _) = endpoint_obj(&mut sc);
    let (e2, _) = endpoint_obj(&mut sc);
    let (tep, _) = endpoint_obj(&mut sc);
    let (cs, c) = caller_thread(&mut sc, s, 10, 0x17);
    let (s1s, s1) = idle_thread(&mut sc, 10);
    thread::set_endpoint(s1s, Binding::TimeoutEndpoint, Some(tep)).unwrap();
    let (_, r) = reply_obj(&mut sc);
    assert_eq!(endpoint::recv(s1, epc(e), r, 0), Ok(Blocked));
    assert_eq!(endpoint::call(c, epc(e), info(0, 0, 0), 0), Ok(Blocked));
    assert_eq!(endpoint::call(s1, epc(e2), info(0, 0, 0), 0), Ok(Blocked));
    assert_eq!((s1.wait(), queue_len(e2)), (Wait::Send, 1));
    thread::cancel(cs).unwrap();
    assert_eq!(status(c), (Status::Canceled, true));
    assert_eq!((status(s1), queue_len(e2)), ((Status::Canceled, false), 0));
    assert!(run_until(walks_done, ms(2_000)));
    assert_eq!(s1.wait(), Wait::WithdrawnSend);
    assert_eq!(queued_at(tep, 0), Some(s1));
    assert_eq!(s1.state().fault.addr, 0x17);
    check(&[e, e2, tep], &[c, s1], &[r]);
    testkit::finish(sc);
});

// ---------------------------------------------------------------------------
// Destruction and long operations.

/// `n` threads, made in the kernel, each queued on the endpoint in `e`:
/// senders, or receivers with reply objects of their own. Returns the
/// threads' and the replies' first slots.
fn queue_many(sc: &mut Scratch, e: SlotRef, n: u64, receivers: bool) -> (SlotRef, SlotRef) {
    let ts = many(sc, ObjectType::Thread, n);
    let rs = if receivers {
        many(sc, ObjectType::Reply, n)
    } else {
        SlotRef(0)
    };
    for i in 0..n {
        let t = tcb(ts.offset(i));
        on_this_core(t);
        let out = if receivers {
            endpoint::recv(t, epc(e), rpc(rs.offset(i)).0, 0)
        } else {
            endpoint::send(t, epc(e), info(0, 0, 0), true, 0)
        };
        assert_eq!(out, Ok(Blocked));
    }
    (ts, rs)
}

crate::kernel_test!(ipc_destroy_endpoint_drains, {
    // K30; ADR 0052, rule 2: deleting the last capability to an endpoint
    // with 300 queued threads releases one per step, each "object
    // destroyed", and the delete, made from EL0, restarts at its
    // preemption points.
    const N: u64 = 300;
    for receivers in [false, true] {
        let mut sc = scratch(21);
        let s = space(&mut sc);
        let (e, _) = endpoint_obj(&mut sc);
        let (ts, _) = queue_many(&mut sc, e, N, receivers);
        assert_eq!(queue_len(e), N as usize);
        let restarts = this_core().stats.restarts;
        let mut spec = Spec::of(Program::TrapReport);
        spec.args[0] = sc.addr_of(e);
        spec.more[0] = DELETE;
        FORCE_PREEMPT.store(true, Ordering::Relaxed);
        let u = spawn_in(&mut sc, s, spec);
        watch(u.tcb);
        let ended = run_until(w_done, ms(10_000));
        FORCE_PREEMPT.store(false, Ordering::Relaxed);
        assert!(ended, "the delete didn't end");
        assert!(this_core().stats.restarts > restarts, "never restarted");
        assert!(report::values_of(u.tcb.0).eq([Status::Ok as u64]));
        assert!(cap::cap(e).is_null());
        for i in 0..N {
            let t = tcb(ts.offset(i));
            assert_eq!(
                (t.wait(), status(t)),
                (Wait::None, (Status::ObjectDestroyed, false)),
                "thread {i}"
            );
        }
        testkit::finish(sc);
    }
});

crate::kernel_test!(ipc_delete_last_copy_in_setter_restarts, {
    // ADR 0052, rule 2: unsetting a fault endpoint whose copy is the last
    // capability to an endpoint with 300 queued senders deletes it under the
    // caller's budget, and is made again at every preemption point.
    const N: u64 = 300;
    let mut sc = scratch(21);
    let (e, cap0) = endpoint_obj(&mut sc);
    let (ts_slot, _) = idle_thread(&mut sc, 10);
    thread::set_endpoint(ts_slot, Binding::FaultEndpoint, Some(e)).unwrap();
    let (ts, _) = queue_many(&mut sc, e, N, false);
    cap::delete(e);
    assert!(matches!(
        cap::cap(tcb(ts_slot).slot(3)),
        Cap::Endpoint { ptr, .. } if ptr == cap0.ep.0
    ));
    let mut restarts = 0;
    loop {
        let mut b = Budget::with_threshold(Always, 1);
        match thread::set_endpoint_with(ts_slot, Binding::FaultEndpoint, None, &mut b) {
            Err(Error::Preempted) => restarts += 1,
            r => {
                assert_eq!(r, Ok(()));
                break;
            }
        }
    }
    // A drain step a call: one waiter released between preemption points.
    assert!(restarts >= N, "only {restarts} restarts");
    assert!(cap::cap(tcb(ts_slot).slot(3)).is_null());
    for i in 0..N {
        let t = tcb(ts.offset(i));
        assert_eq!(status(t), (Status::ObjectDestroyed, false), "thread {i}");
    }
    testkit::finish(sc);
});

crate::kernel_test!(ipc_destroy_reply_or_server, {
    // K30: destroying a delivered call's reply object or its server ends the
    // call "object destroyed", delivered, with the context back; a receiver
    // whose reply object is destroyed leaves its queue.
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (e, _) = endpoint_obj(&mut sc);
    let (_, c) = caller_thread(&mut sc, s, 10, 0);
    let own = c.sc();
    let (_, srv) = idle_thread(&mut sc, 10);
    let (rs, r) = reply_obj(&mut sc);
    assert_eq!(endpoint::recv(srv, epc(e), r, 0), Ok(Blocked));
    assert_eq!(endpoint::call(c, epc(e), info(0, 0, 0), 0), Ok(Blocked));
    cap::delete(rs);
    assert_eq!((status(c), c.sc()), ((Status::ObjectDestroyed, true), own));
    assert!(run_until(walks_done, ms(2_000)));
    let (ss2, srv2) = idle_thread(&mut sc, 10);
    let (_, r2) = reply_obj(&mut sc);
    assert_eq!(endpoint::recv(srv2, epc(e), r2, 0), Ok(Blocked));
    assert_eq!(endpoint::call(c, epc(e), info(0, 0, 0), 0), Ok(Blocked));
    cap::delete(ss2);
    assert_eq!((status(c), c.sc()), ((Status::ObjectDestroyed, true), own));
    assert!(run_until(walks_done, ms(2_000)));
    let (_, rt) = idle_thread(&mut sc, 10);
    let (rs3, r3) = reply_obj(&mut sc);
    assert_eq!(endpoint::recv(rt, epc(e), r3, 0), Ok(Blocked));
    cap::delete(rs3);
    assert_eq!(
        (rt.wait(), status(rt), queue_len(e)),
        (Wait::None, (Status::ObjectDestroyed, false), 0)
    );
    check(&[e], &[c, rt], &[]);
    testkit::finish(sc);
});

crate::kernel_test!(ipc_badge_release, {
    // ADR 0049, rule 5; K23: the manager revokes its badged copy, cancels
    // the sends queued under the badge from EL0, restarted at every
    // preemption point, then deletes it. The canceled senders restart at
    // their `SVC`, registers untouched; the other badge's stay queued, in
    // order. A fault queued under the badge is withdrawn when its endpoint
    // copy is revoked (K50).
    const N: u64 = 300;
    const PC: u64 = 0x40_0104;
    let mut sc = scratch(21);
    let s = space(&mut sc);
    let (e, _) = endpoint_obj(&mut sc);
    let ka = badged(&mut sc, e, 0xa, Rights::ALL);
    let kb = badged(&mut sc, e, 0xb, Rights::ALL);
    let ts = many(&mut sc, ObjectType::Thread, N);
    for i in 0..N {
        let t = tcb(ts.offset(i));
        on_this_core(t);
        t.with(|b| {
            b.ctx.pc = PC;
            b.ctx.x[0] = 0xdead;
        });
        let k = if i % 2 == 0 { ka } else { kb };
        assert_eq!(
            endpoint::send(t, epc(k), info(0, 0, 0), true, 0),
            Ok(Blocked)
        );
    }
    let (fs, f) = idle_thread(&mut sc, 10);
    thread::set_endpoint(fs, Binding::FaultEndpoint, Some(kb)).unwrap();
    f.with(|b| b.ctx.pc = 0x5000);
    crate::sched::fault::raise(f, Kind::UserException, 0, 0);
    assert_eq!((f.wait(), queue_len(e)), (Wait::FaultSend, N as usize + 1));
    cap::revoke(kb);
    assert_eq!((f.wait(), f.with(|b| b.ctx.pc)), (Wait::None, 0x5000));
    assert!(!f.has(flag::RESUMED));
    let restarts = this_core().stats.restarts;
    let mut spec = Spec::of(Program::TrapReport);
    spec.args[0] = sc.addr_of(kb);
    spec.more[0] = CANCEL_BADGED_SENDS;
    FORCE_PREEMPT.store(true, Ordering::Relaxed);
    let u = spawn_in(&mut sc, s, spec);
    watch(u.tcb);
    let ended = run_until(w_done, ms(10_000));
    FORCE_PREEMPT.store(false, Ordering::Relaxed);
    assert!(ended, "the cancel didn't end");
    assert!(this_core().stats.restarts > restarts + N / 2);
    assert!(report::values_of(u.tcb.0).eq([Status::Ok as u64]));
    cap::delete(kb);
    let (q, n) = queue::<512>(e);
    assert_eq!(n, N as usize / 2);
    for i in 0..N {
        let t = tcb(ts.offset(i));
        if i % 2 == 0 {
            assert_eq!(q[i as usize / 2], t, "badge a's sender {i} out of order");
        } else {
            assert_eq!(t.wait(), Wait::None, "sender {i} still waits");
            assert_eq!(t.with(|b| (b.ctx.pc, b.ctx.x[0])), (PC - 4, 0xdead));
        }
    }
    // Refused: an unbadged capability, and a badged one without every
    // right.
    let (_, m) = idle_thread(&mut sc, 10);
    let mut a = Args {
        cap: sc.addr_of(e),
        ..Args::default()
    };
    syscall::cancel_badged_sends(m, &a, &mut cap::budget()).unwrap();
    assert_eq!(status(m), (Status::InvalidArgument, false));
    let weak = sc.take();
    cap::mint(ka, weak, Rights::READ.union(Rights::WRITE), MintData::None).unwrap();
    a.cap = sc.addr_of(weak);
    syscall::cancel_badged_sends(m, &a, &mut cap::budget()).unwrap();
    assert_eq!(status(m), (Status::MissingRight, false));
    assert_eq!(queue_len(e), N as usize / 2);
    testkit::finish(sc);
});

// ---------------------------------------------------------------------------
// Faults over endpoints.

/// `program` with x0 = `a`, on 50 µs in 1 ms, so a test can run several.
fn light(program: Program, a: u64) -> Spec {
    let mut spec = Spec::of(program);
    spec.args[0] = a;
    spec.budget_us = 50;
    spec
}

/// The context whose capability is in `s`.
fn sc_of(s: SlotRef) -> crate::sched::object::Sc {
    match cap::cap(s) {
        Cap::SchedContext { ptr, .. } => crate::sched::object::Sc(ptr),
        c => panic!("{c:x?} isn't a context"),
    }
}

/// A fault message's body word `i` in the buffer page at `pa`, as the value
/// the kernel wrote big-endian.
fn body(pa: u64, i: u64) -> u64 {
    u64::from_be_bytes(buf(pa, buffer::BUFFER_WORDS + 8 * i).to_ne_bytes())
}

crate::kernel_test!(ipc_faults_over_endpoints, {
    // ADR 0056, rules 1 and 2; kernel specification, "Fault delivery": a
    // fault reaches a waiting handler as a message, donating the thread's
    // context; the handler fixes the thread and replies, and it resumes.
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (e, _) = endpoint_obj(&mut sc);
    let fe = badged(&mut sc, e, 0xfa17, Rights::ALL);
    let (hs, h) = idle_thread_in(&mut sc, s, 10);
    let (_, hpa) = give_buffer(&mut sc, s, hs, 0);
    let (_, r) = reply_obj(&mut sc);
    // The fault that ends the wait writes ok over the 0xdead x0 the
    // blocked receive left (K28), and zero over badge words an earlier
    // message that unwrapped capabilities left.
    h.with(|b| b.ctx.x[0] = 0xdead);
    for i in 0..3 {
        set_buf(hpa, buffer::BADGES + 8 * i, 7);
    }
    assert_eq!(endpoint::recv(h, epc(e), r, 0), Ok(Blocked));
    let u = spawn_in(&mut sc, s, light(Program::Load, UNMAPPED_VA));
    thread::set_endpoint(u.thread, Binding::FaultEndpoint, Some(fe)).unwrap();
    watch(h);
    assert!(run_until(w_not_receiving, ms(2_000)), "no fault came");
    assert_eq!((status(h), x(h, 6)), (OK, 0xfa17));
    assert_eq!(Info::decode(x(h, 1)), fault::info());
    assert_eq!(words(h), [fault::word0(Kind::Unmapped as u16), 0, 0, 0]);
    let pc = u.tcb.with(|b| b.ctx.pc);
    assert_eq!((body(hpa, 0), body(hpa, 2)), (pc, UNMAPPED_VA));
    assert_eq!(body(hpa, 1), u.tcb.state().fault.esr);
    for i in 0..3 {
        assert_eq!(buf(hpa, buffer::BADGES + 8 * i), 0, "badge word {i}");
    }
    assert_eq!((u.tcb.wait(), h.sc()), (Wait::Call, Some(sc_of(u.context))));
    assert!(u.tcb.sc().is_none());
    assert_eq!(caller_of(r), Some(u.tcb));
    // The handler points the load at the stack and replies: the thread
    // re-executes it, and reports what it read.
    let mut regs: UserContext = thread::read_registers(u.thread).unwrap();
    regs.x[0] = STACK_VA;
    thread::write_registers(u.thread, &regs).unwrap();
    assert_eq!(endpoint::reply(h, r, false, 0), Ok(()));
    assert!(h.sc().is_none());
    watch(u.tcb);
    assert!(run_until(w_done, ms(2_000)), "the thread didn't resume");
    assert!(report::values_of(u.tcb.0).eq([0]));
    // An undefined instruction in another address space, on the same core.
    // FAR_EL1 still holds the load's address from the abort above, and the
    // architecture makes it UNKNOWN for this exception, so the message
    // carries 0, not the other space's address.
    let s2 = space(&mut sc);
    h.with(|b| b.ctx.x[0] = 0xdead);
    assert_eq!(endpoint::recv(h, epc(e), r, 0), Ok(Blocked));
    let z = spawn_in(&mut sc, s2, light(Program::Udf, 0));
    thread::set_endpoint(z.thread, Binding::FaultEndpoint, Some(fe)).unwrap();
    watch(h);
    assert!(run_until(w_not_receiving, ms(2_000)), "no udf fault");
    assert_eq!((status(h), x(h, 6)), (OK, 0xfa17));
    assert_eq!(
        words(h),
        [fault::word0(Kind::UserException as u16), 0, 0, 0]
    );
    assert_eq!(body(hpa, 1) >> 26, 0, "not an unknown-instruction syndrome");
    assert_eq!(body(hpa, 2), 0, "a stale fault address reached the handler");
    assert_eq!(z.tcb.state().fault.addr, 0);
    let mut regs: UserContext = thread::read_registers(z.thread).unwrap();
    regs.pc += 4;
    thread::write_registers(z.thread, &regs).unwrap();
    assert_eq!(endpoint::reply(h, r, false, 0), Ok(()));
    watch(z.tcb);
    assert!(run_until(w_done, ms(2_000)), "the udf thread didn't resume");
    assert!(report::values_of(z.tcb.0).eq([0xdf]));
    // An unknown system call, to a handler without a buffer: the header
    // alone.
    let (_, h2) = idle_thread(&mut sc, 10);
    h2.with(|b| b.ctx.x[0] = 0xdead);
    assert_eq!(endpoint::recv(h2, epc(e), r, 0), Ok(Blocked));
    let v = spawn_in(&mut sc, s, light(Program::SvcUnknown, 0));
    thread::set_endpoint(v.thread, Binding::FaultEndpoint, Some(e)).unwrap();
    watch(h2);
    assert!(run_until(w_not_receiving, ms(2_000)));
    assert_eq!((status(h2), Info::decode(x(h2, 1)).len), (OK, 32));
    assert_eq!(x(h2, 2), fault::word0(Kind::UnknownSyscall as u16));
    assert_eq!(endpoint::reply(h2, r, false, 0), Ok(()));
    watch(v.tcb);
    assert!(run_until(w_done, ms(2_000)));
    assert!(report::values_of(v.tcb.0).eq([0x51]));
    // Canceling a delivered fault: the context comes back at once, and the
    // thread faults again, queued now. Until the take-back's walk passes
    // the handler's reply object, the handler, which lost the context, is
    // "not the holder"; once it has passed, the reply finds no caller.
    let (_, h3) = idle_thread(&mut sc, 10);
    let (_, r3) = reply_obj(&mut sc);
    assert_eq!(endpoint::recv(h3, epc(e), r3, 0), Ok(Blocked));
    let u3 = spawn_in(&mut sc, s, light(Program::Load, UNMAPPED_VA));
    thread::set_endpoint(u3.thread, Binding::FaultEndpoint, Some(e)).unwrap();
    watch(h3);
    assert!(run_until(w_not_receiving, ms(2_000)));
    thread::cancel(u3.thread).unwrap();
    assert!(h3.sc().is_none());
    assert!(run_until(walks_done, ms(2_000)));
    assert_eq!(endpoint::reply(h3, r3, false, 0), Err(Status::NoCaller));
    watch(u3.tcb);
    assert!(run_until(w_fault_queued, ms(2_000)), "no second fault");
    // A timeout fault, to a handler with a buffer: a plain call, which
    // donates nothing, with the context's badge and the time used.
    let (t, _) = endpoint_obj(&mut sc);
    let te = badged(&mut sc, t, 0x7e, Rights::ALL);
    let (_, r4) = reply_obj(&mut sc);
    assert_eq!(endpoint::recv(h, epc(t), r4, 0), Ok(Blocked));
    let mut spec = Spec::of(Program::Spin);
    spec.budget_us = 500;
    spec.period_us = 5_000;
    spec.badge = 0xbad;
    let w4 = spawn_in(&mut sc, s, spec);
    thread::set_endpoint(w4.thread, Binding::TimeoutEndpoint, Some(te)).unwrap();
    watch(h);
    assert!(run_until(w_not_receiving, ms(5_000)), "no timeout fault");
    assert_eq!(
        (x(h, 2), x(h, 6)),
        (fault::word0(Kind::Timeout as u16), 0x7e)
    );
    assert_eq!(body(hpa, 2), 0xbad);
    assert!(body(hpa, 3) > 0, "no time used");
    assert!(h.sc().is_none(), "a timeout fault donated");
    assert_eq!(w4.tcb.wait(), Wait::Call);
    assert_eq!(endpoint::reply(h, r4, false, 0), Ok(()));
    assert_ne!(w4.tcb.wait(), Wait::Call);
    testkit::finish(sc);
});

crate::kernel_test!(ipc_fault_endpoint_revoked_k50, {
    // K50: unsetting a fault endpoint withdraws a queued fault, and the
    // thread is suspended and logged; a delivered fault stands until its
    // reply. Unsetting the timeout endpoint (K08) leaves a fault queued on
    // the fault endpoint, which isn't its.
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (e, _) = endpoint_obj(&mut sc);
    let (te, _) = endpoint_obj(&mut sc);
    let mut spec = Spec::of(Program::Load);
    spec.args[0] = UNMAPPED_VA;
    let u = spawn_in(&mut sc, s, spec);
    thread::set_endpoint(u.thread, Binding::FaultEndpoint, Some(e)).unwrap();
    thread::set_endpoint(u.thread, Binding::TimeoutEndpoint, Some(te)).unwrap();
    watch(u.tcb);
    assert!(run_until(w_fault_queued, ms(2_000)));
    assert_eq!(queue_len(e), 1);
    thread::set_endpoint(u.thread, Binding::TimeoutEndpoint, None).unwrap();
    assert_eq!(
        (u.tcb.wait(), queued_at(e, 0) == Some(u.tcb)),
        (Wait::FaultSend, true)
    );
    thread::set_endpoint(u.thread, Binding::FaultEndpoint, None).unwrap();
    assert_eq!((u.tcb.wait(), queue_len(e)), (Wait::None, 0));
    assert!(!u.tcb.has(flag::RESUMED));
    // Delivered: it stands; replied to, the thread faults again, now with
    // no fault endpoint, and is suspended.
    let (_, h) = idle_thread(&mut sc, 10);
    let (_, r) = reply_obj(&mut sc);
    assert_eq!(endpoint::recv(h, epc(e), r, 0), Ok(Blocked));
    let mut spec = Spec::of(Program::Load);
    spec.args[0] = UNMAPPED_VA;
    let v = spawn_in(&mut sc, s, spec);
    thread::set_endpoint(v.thread, Binding::FaultEndpoint, Some(e)).unwrap();
    watch(h);
    assert!(run_until(w_not_receiving, ms(2_000)));
    thread::set_endpoint(v.thread, Binding::FaultEndpoint, None).unwrap();
    assert_eq!(v.tcb.wait(), Wait::Call);
    assert_eq!(endpoint::reply(h, r, false, 0), Ok(()));
    watch(v.tcb);
    assert!(run_until(w_suspended, ms(2_000)));
    assert_eq!(v.tcb.wait(), Wait::None);
    testkit::finish(sc);
});

crate::kernel_test!(ipc_queued_fault_taken_by_receive, {
    // A fault queued with no handler waiting is taken by the next receive,
    // and the reply resumes the thread.
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (e, _) = endpoint_obj(&mut sc);
    let u = spawn_in(&mut sc, s, Spec::of(Program::SvcUnknown));
    thread::set_endpoint(u.thread, Binding::FaultEndpoint, Some(e)).unwrap();
    watch(u.tcb);
    assert!(run_until(w_fault_queued, ms(2_000)));
    assert_eq!(answer_fault(&mut sc, e), u.tcb);
    assert!(run_until(w_done, ms(2_000)));
    assert!(report::values_of(u.tcb.0).eq([0x51]));
    testkit::finish(sc);
});

// ---------------------------------------------------------------------------
// IPC buffers.

/// Puts the leaf capability in `s` at the deepest level, as a chain of
/// copies, each made from the last and the last then deleted, would; gives
/// back the depth it had.
fn deepest(s: SlotRef) -> u16 {
    let mut sl = kcap::slot::read(&cap::DirectSlots, s);
    let was = sl.depth;
    sl.depth = kcap::slot::MAX_DEPTH;
    kcap::slot::write(&mut cap::DirectSlots, s, &sl);
    was
}

/// Gives the capability in `s` back its depth `d`.
fn restore_depth(s: SlotRef, d: u16) {
    let mut sl = kcap::slot::read(&cap::DirectSlots, s);
    sl.depth = d;
    kcap::slot::write(&mut cap::DirectSlots, s, &sl);
}

crate::kernel_test!(ipc_buffer_registration, {
    // K29; ADR 0048, rule 5: every check before anything changes, and the
    // copy in slot 7 pins the page until it is revoked.
    let mut sc = Scratch::with_device(20);
    make_room();
    report::clear();
    let s = space(&mut sc);
    let (_, m) = idle_thread(&mut sc, 10);
    let (ts, t) = idle_thread_in(&mut sc, s, 10);
    let rw = UserPerm {
        write: true,
        exec: false,
    };
    let ro = UserPerm {
        write: false,
        exec: false,
    };
    let va = super::testkit::BUF_VA;
    let f = sc.make(ObjectType::Frame4K);
    map(f, s, va, rw, sc.ram).unwrap();
    let fro = sc.make(ObjectType::Frame4K);
    map(fro, s, va + 0x1000, ro, sc.ram).unwrap();
    let other = sc.make(ObjectType::Frame4K);
    let dev = sc.make_from(sc.dev(), ObjectType::Frame4K);
    let weak = sc.take();
    cap::mint(f, weak, Rights::READ, MintData::None).unwrap();
    let thread_addr = sc.addr_of(ts);
    let set = |frame: SlotRef, at: u64| {
        let a = sc.addr_of(frame);
        syscall::set_ipc_buffer(m, thread_addr, a, at, &mut cap::budget()).unwrap();
        status(m).0
    };
    assert_eq!(set(f, va + 8), Status::InvalidArgument);
    assert_eq!(set(f, va + 0x10_0000), Status::NotMapped);
    assert_eq!(set(fro, va + 0x1000), Status::MissingRight);
    assert_eq!(set(other, va), Status::InvalidArgument);
    assert_eq!(set(dev, va), Status::NotRam);
    assert_eq!(set(weak, va), Status::MissingRight);
    assert_eq!(object::ipc(t).buf_pa, 0);
    assert!(t.slot_cap(7).is_null());
    assert_eq!(set(f, va), Status::Ok);
    let pa = cap::cap(f).object().unwrap().0;
    assert_eq!((object::ipc(t).buf_va, object::ipc(t).buf_pa), (va, pa));
    assert!(matches!(
        t.slot_cap(7),
        Cap::Frame { binding: Some(Binding::IpcBuffer), base, .. } if base == pa
    ));
    // Revoking the frame's capability unregisters it.
    cap::revoke(f);
    assert_eq!(object::ipc(t).buf_pa, 0);
    assert!(t.slot_cap(7).is_null());
    // Registered again, then unregistered with address 0.
    map(f, s, va, rw, sc.ram).unwrap();
    let deep = sc.take();
    let (e, _) = endpoint_obj(&mut sc);
    let deep_e = sc.take();
    // A copy of the thread capability without the write right, and a second
    // buffer page.
    let weak_t = sc.take();
    cap::mint(ts, weak_t, Rights::READ, MintData::None).unwrap();
    let g = sc.make(ObjectType::Frame4K);
    let g_va = va + 0x2000;
    map(g, s, g_va, rw, sc.ram).unwrap();
    let gpa = cap::cap(g).object().unwrap().0;
    let set = |frame: SlotRef, at: u64| {
        let a = sc.addr_of(frame);
        syscall::set_ipc_buffer(m, thread_addr, a, at, &mut cap::budget()).unwrap();
        status(m).0
    };
    assert_eq!(set(f, va), Status::Ok);
    // A source at the deepest level, whose copy couldn't be made, is
    // refused before the old copy is deleted: the buffer stays registered.
    // So is a fault endpoint's (thread.rs's setters check first too).
    cap::copy(f, deep).unwrap();
    let depth = deepest(deep);
    assert_eq!(set(deep, va), Status::InvalidArgument);
    assert_eq!((object::ipc(t).buf_va, object::ipc(t).buf_pa), (va, pa));
    assert!(!t.slot_cap(7).is_null());
    thread::set_endpoint(ts, Binding::FaultEndpoint, Some(e)).unwrap();
    cap::copy(e, deep_e).unwrap();
    let depth_e = deepest(deep_e);
    assert_eq!(
        thread::set_endpoint(ts, Binding::FaultEndpoint, Some(deep_e)),
        Err(Error::Cap(kcap::ops::Error::TooDeep))
    );
    assert!(matches!(
        t.slot_cap(Binding::FaultEndpoint.thread_slot()),
        Cap::Endpoint { .. }
    ));
    restore_depth(deep, depth);
    restore_depth(deep_e, depth_e);
    cap::delete(deep);
    cap::delete(deep_e);
    // ADR 0054, rule 3: a thread capability without the write right is
    // refused, to register and to unregister, and nothing changes.
    for at in [g_va, 0] {
        let (wa, ga) = (sc.addr_of(weak_t), sc.addr_of(g));
        syscall::set_ipc_buffer(m, wa, ga, at, &mut cap::budget()).unwrap();
        assert_eq!(status(m), (Status::MissingRight, false));
        assert_eq!((object::ipc(t).buf_va, object::ipc(t).buf_pa), (va, pa));
        assert!(matches!(t.slot_cap(7), Cap::Frame { base, .. } if base == pa));
    }
    // K29: replacing a registered buffer deletes the old copy first, then
    // keeps a copy of the new one. Revoking the old frame afterwards
    // leaves the new registration.
    assert_eq!(set(g, g_va), Status::Ok);
    assert_eq!((object::ipc(t).buf_va, object::ipc(t).buf_pa), (g_va, gpa));
    assert!(matches!(
        t.slot_cap(7),
        Cap::Frame { binding: Some(Binding::IpcBuffer), base, .. } if base == gpa
    ));
    cap::revoke(f);
    assert_eq!((object::ipc(t).buf_va, object::ipc(t).buf_pa), (g_va, gpa));
    assert!(matches!(t.slot_cap(7), Cap::Frame { base, .. } if base == gpa));
    map(f, s, va, rw, sc.ram).unwrap();
    assert_eq!(set(f, 0), Status::Ok);
    assert!(t.slot_cap(7).is_null() && object::ipc(t).buf_pa == 0);
    // Destroying the thread deletes its copy.
    assert_eq!(set(f, va), Status::Ok);
    cap::delete(ts);
    testkit::finish(sc);
});

crate::kernel_test!(thread_root_replaced_from_inside_itself, {
    // K23 (C14), as seL4's `checkCapAt`: a thread's root CNode and address
    // space set from slots inside its old root, whose last capability the
    // thread holds. Deleting the old root destroys that CNode and clears
    // the sources, so the copies are skipped: both slots end empty, and
    // nothing else changes.
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (ts, t) = idle_thread_in(&mut sc, s, 10);
    let x = sc.make(ObjectType::CNode(2));
    let c2 = sc.make(ObjectType::CNode(2));
    let xs = slots_of(x);
    cap::copy(c2, xs).unwrap();
    cap::copy(s, xs.offset(1)).unwrap();
    thread::configure_space(ts, x, s).unwrap();
    cap::delete(x);
    assert!(
        kcap::mdb::is_final(&cap::DirectSlots, t.slot(1)),
        "the thread holds the old root's last capability"
    );
    assert_eq!(thread::configure_space(ts, xs, xs.offset(1)), Ok(()));
    assert!(t.slot_cap(1).is_null() && t.slot_cap(2).is_null());
    assert!(cap::cap(xs).is_null() && cap::cap(xs.offset(1)).is_null());
    // The sources stand: set from them, the thread has both again.
    assert_eq!(thread::configure_space(ts, c2, s), Ok(()));
    assert!(t.slot_cap(1).same_object(&cap::cap(c2)));
    assert!(t.slot_cap(2).same_object(&cap::cap(s)));
    testkit::finish(sc);
});

crate::kernel_test!(thread_root_replaced_from_inside_itself_restarts, {
    // ADR 0052, rule 2 (C14): the same, with an old root of 512 slots and
    // the sources in its top slots, which its deletion clears first, made
    // again at every preemption point. Each restart resumes the deletion
    // before it checks the sources, so the call ends as the run without
    // preemption above does: both slots empty, the sources skipped.
    let mut sc = scratch(21);
    let s = space(&mut sc);
    let (ts, t) = idle_thread_in(&mut sc, s, 10);
    let x = sc.make(ObjectType::CNode(9));
    let c2 = sc.make(ObjectType::CNode(2));
    let (cn_src, sp_src) = (slots_of(x).offset(511), slots_of(x).offset(510));
    cap::copy(c2, cn_src).unwrap();
    cap::copy(s, sp_src).unwrap();
    thread::configure_space(ts, x, s).unwrap();
    cap::delete(x);
    let mut restarts = 0;
    loop {
        let mut b = Budget::with_threshold(Always, 1);
        match thread::configure_space_with(ts, cn_src, sp_src, restarts > 0, &mut b) {
            Err(Error::Preempted) => restarts += 1,
            r => {
                assert_eq!(r, Ok(()));
                break;
            }
        }
    }
    // One deletion unit a call: the old root's 512 slots take far more
    // restarts than the two sources' slots, so most come after the sources
    // are gone.
    assert!(restarts > 100, "only {restarts} restarts");
    assert!(t.slot_cap(1).is_null() && t.slot_cap(2).is_null());
    assert!(cap::cap(cn_src).is_null() && cap::cap(sp_src).is_null());
    assert!(!t.has(flag::DEAD));
    // With no deletion left to resume, an empty source is refused again.
    assert_eq!(
        thread::configure_space(ts, cn_src, sp_src),
        Err(Error::Cap(kcap::ops::Error::Empty))
    );
    assert_eq!(thread::configure_space(ts, c2, s), Ok(()));
    testkit::finish(sc);
});

/// A budget that finds an interrupt pending after every unit.
fn always() -> Budget<Always> {
    Budget::with_threshold(Always, 1)
}

crate::kernel_test!(thread_root_replaced_through_its_restart_loop, {
    // ADR 0052, rule 2 (C14): `thread_root_replaced_from_inside_itself_restarts`
    // through the kernel's own restart loop, `configure_space`'s, with every
    // preemption point finding an interrupt pending. The loop makes its
    // first call a first attempt and the rest restarts, so it ends as the
    // run without preemption does: both slots empty, the sources skipped.
    let mut sc = scratch(21);
    let s = space(&mut sc);
    let (ts, t) = idle_thread_in(&mut sc, s, 10);
    let x = sc.make(ObjectType::CNode(9));
    let c2 = sc.make(ObjectType::CNode(2));
    let (cn_src, sp_src) = (slots_of(x).offset(511), slots_of(x).offset(510));
    cap::copy(c2, cn_src).unwrap();
    cap::copy(s, sp_src).unwrap();
    thread::configure_space(ts, x, s).unwrap();
    cap::delete(x);
    let mut calls = 0;
    let r = thread::configure_space_under(ts, cn_src, sp_src, || {
        calls += 1;
        always()
    });
    assert_eq!(r, Ok(()));
    assert!(calls > 100, "only {calls} calls");
    assert!(t.slot_cap(1).is_null() && t.slot_cap(2).is_null());
    assert!(cap::cap(cn_src).is_null() && cap::cap(sp_src).is_null());
    assert!(!t.has(flag::DEAD));
    assert_eq!(thread::configure_space(ts, c2, s), Ok(()));
    testkit::finish(sc);
});

crate::kernel_test!(thread_root_zombie_of_another_call_is_no_restart, {
    // ADR 0052, rule 2 (C14): a zombie in the thread's slot 1 that another
    // call's deletion left, stopped at a preemption point, doesn't make a
    // first attempt a restart. Its sources are checked before anything
    // changes: refused, it leaves the zombie and the old address space as
    // they were, through the kernel's own restart loop too, whose first call
    // is a first attempt. A first attempt with good sources resumes the
    // zombie's deletion, and a restart of that call skips the checks and
    // goes on with it.
    let mut sc = scratch(21);
    let s = space(&mut sc);
    let (ts, t) = idle_thread_in(&mut sc, s, 10);
    let x = sc.make(ObjectType::CNode(9));
    let c2 = sc.make(ObjectType::CNode(2));
    thread::configure_space(ts, x, s).unwrap();
    cap::delete(x);
    let mut b = Budget::with_threshold(Always, 1);
    assert_eq!(
        thread::configure_space_with(ts, c2, s, false, &mut b),
        Err(Error::Preempted)
    );
    assert!(matches!(t.slot_cap(1), Cap::Zombie { .. }));
    let empty = slots_of(c2);
    for (cn, sp, e) in [
        (s, s, Error::WrongKind),
        (c2, c2, Error::WrongKind),
        (empty, s, Error::Cap(kcap::ops::Error::Empty)),
        (c2, empty, Error::Cap(kcap::ops::Error::Empty)),
    ] {
        let mut b = Budget::with_threshold(Always, 1);
        assert_eq!(
            thread::configure_space_with(ts, cn, sp, false, &mut b),
            Err(e)
        );
        assert!(matches!(t.slot_cap(1), Cap::Zombie { .. }));
        assert!(t.slot_cap(2).same_object(&cap::cap(s)));
    }
    assert_eq!(
        thread::configure_space_under(ts, s, s, always),
        Err(Error::WrongKind)
    );
    assert!(matches!(t.slot_cap(1), Cap::Zombie { .. }));
    assert!(t.slot_cap(2).same_object(&cap::cap(s)));
    // A first attempt with good sources resumes the deletion, preempted
    // again at its first unit, with the zombie still in slot 1.
    assert_eq!(
        thread::configure_space_with(ts, c2, s, false, &mut always()),
        Err(Error::Preempted)
    );
    assert!(matches!(t.slot_cap(1), Cap::Zombie { .. }));
    // The call made again: a restart, which resumes.
    loop {
        let mut b = Budget::with_threshold(Always, 1);
        match thread::configure_space_with(ts, c2, s, true, &mut b) {
            Err(Error::Preempted) => {}
            r => {
                assert_eq!(r, Ok(()));
                break;
            }
        }
    }
    assert!(t.slot_cap(1).same_object(&cap::cap(c2)));
    assert!(t.slot_cap(2).same_object(&cap::cap(s)));
    testkit::finish(sc);
});

crate::kernel_test!(thread_named_inside_its_old_root_restarts, {
    // ADR 0052, rule 2 (C14), as seL4's re-decode: the thread is named by a
    // copy of its capability inside its old root, not the last one. The
    // deletion of the old root deletes that copy, so a restart after it can
    // no longer name the thread and fails with the lookup's error, where
    // the run without preemption ends with `Ok`. The zombie stays in slot 1,
    // and the thread's next configuration, through its other capability,
    // resumes it.
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (ts, t) = idle_thread_in(&mut sc, s, 10);
    let x = sc.make(ObjectType::CNode(2));
    let c2 = sc.make(ObjectType::CNode(2));
    let named = slots_of(x).offset(1);
    cap::copy(ts, named).unwrap();
    thread::configure_space(ts, x, s).unwrap();
    cap::delete(x);
    assert!(kcap::mdb::is_final(&cap::DirectSlots, t.slot(1)));
    let mut restarts = 0;
    let r = loop {
        let mut b = Budget::with_threshold(Always, 1);
        match thread::configure_space_with(named, c2, s, restarts > 0, &mut b) {
            Err(Error::Preempted) => restarts += 1,
            r => break r,
        }
    };
    assert_eq!(r, Err(Error::Cap(kcap::ops::Error::Empty)));
    assert!(restarts > 0 && !t.has(flag::DEAD));
    assert!(cap::cap(named).is_null());
    assert!(matches!(t.slot_cap(1), Cap::Zombie { .. }));
    assert!(t.slot_cap(2).same_object(&cap::cap(s)));
    assert_eq!(thread::configure_space(ts, c2, s), Ok(()));
    assert!(t.slot_cap(1).same_object(&cap::cap(c2)));
    assert!(t.slot_cap(2).same_object(&cap::cap(s)));
    testkit::finish(sc);
});

crate::kernel_test!(thread_destroyed_by_its_own_root, {
    // As seL4's `sameObjectAs(tCap, slot->cap)` (C14): the thread's only
    // capability lies in its old root, whose last capability the thread
    // holds. Deleting the old root destroys the thread, so nothing is
    // copied into it, though the new address space's source, outside the
    // old root, still stands: a copy left in the finished thread would
    // stay linked as the space capability's child while the thread's
    // memory is reset.
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (ts, t) = idle_thread_in(&mut sc, s, 10);
    let x = sc.make(ObjectType::CNode(2));
    let c2 = sc.make(ObjectType::CNode(2));
    let s2 = sc.make(ObjectType::AddressSpace);
    let xs = slots_of(x);
    cap::move_cap(ts, xs).unwrap();
    cap::copy(c2, xs.offset(1)).unwrap();
    thread::configure_space(xs, x, s).unwrap();
    cap::delete(x);
    assert!(kcap::mdb::is_final(&cap::DirectSlots, t.slot(1)));
    assert_eq!(thread::configure_space(xs, xs.offset(1), s2), Ok(()));
    assert!(t.has(flag::DEAD));
    assert!(cap::cap(xs).is_null() && cap::cap(xs.offset(1)).is_null());
    assert!(t.slot_cap(1).is_null() && t.slot_cap(2).is_null());
    assert!(
        !kcap::mdb::has_children(&cap::DirectSlots, s2),
        "a copy was made in the finished thread"
    );
    // The thread's memory resets with the tree whole (`Scratch::finish`).
    testkit::finish(sc);
});

crate::kernel_test!(thread_destroyed_by_its_own_root_restarts, {
    // ADR 0052, rule 2 (C14): the same, made again at every preemption
    // point. The call whose deletion stops the thread ends with `Ok`, as
    // the run without preemption does, since a restart couldn't name the
    // thread: its capability is a zombie by then. Nothing is copied into
    // it. What is left of the deletion, here just the old root and the
    // thread holding each other's last capabilities, no lookup can name,
    // and revoking the scratch memory finishes it (`testkit::finish`).
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (ts, t) = idle_thread_in(&mut sc, s, 10);
    let x = sc.make(ObjectType::CNode(2));
    let c2 = sc.make(ObjectType::CNode(2));
    let s2 = sc.make(ObjectType::AddressSpace);
    let xs = slots_of(x);
    cap::move_cap(ts, xs).unwrap();
    cap::copy(c2, xs.offset(1)).unwrap();
    thread::configure_space(xs, x, s).unwrap();
    cap::delete(x);
    let mut restarts = 0;
    loop {
        let mut b = Budget::with_threshold(Always, 1);
        match thread::configure_space_with(xs, xs.offset(1), s2, restarts > 0, &mut b) {
            Err(Error::Preempted) => restarts += 1,
            r => {
                assert_eq!(r, Ok(()));
                break;
            }
        }
    }
    assert!(restarts > 0, "the deletion was never preempted");
    assert!(t.has(flag::DEAD));
    assert!(
        !kcap::mdb::has_children(&cap::DirectSlots, s2),
        "a copy was made in the finished thread"
    );
    testkit::finish(sc);
});

// ---------------------------------------------------------------------------
// Across cores.

crate::kernel_smp_test!(ipc_cross_core, {
    // A client on one core calls an active server on another, 200 round
    // trips, each reply checked by the client.
    let Some(mut cores) = others(2) else { return };
    let (k1, k2) = (cores.next().unwrap(), cores.next().unwrap());
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (e, _) = endpoint_obj(&mut sc);
    let (r, _) = reply_obj(&mut sc);
    let mut spec = Spec::of(Program::Serve).on(k1);
    spec.args = [sc.addr_of(e), 1, sc.addr_of(r)];
    let srv = spawn_in(&mut sc, s, spec);
    let mut spec = Spec::of(Program::CallCount).on(k2);
    spec.args = [sc.addr_of(e), 200, 0];
    let cl = spawn_in(&mut sc, s, spec);
    watch(cl.tcb);
    assert!(run_until(w_done, ms(10_000)), "the calls didn't end");
    assert!(report::values_of(cl.tcb.0).eq([200]));
    assert!(report::values_of(srv.tcb.0).eq(1..=200));
    testkit::finish(sc);
});

crate::kernel_smp_test!(ipc_server_never_replies, {
    // ADR 0047, rule 4: a caller blocked on a server that never replies
    // holds up nothing else: a thread on another core keeps running, and
    // the caller's deadline ends its call, delivered.
    let Some(mut cores) = others(2) else { return };
    let (k1, k2) = (cores.next().unwrap(), cores.next().unwrap());
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (e, _) = endpoint_obj(&mut sc);
    let (_, srv) = idle_thread(&mut sc, 10);
    let (_, r) = reply_obj(&mut sc);
    assert_eq!(endpoint::recv(srv, epc(e), r, 0), Ok(Blocked));
    // Few enough reports that the log keeps the caller's.
    let mut spec = Spec::of(Program::CountReport).on(k2);
    spec.args = [0, 1_000_000, 0];
    let counter = spawn_in(&mut sc, s, spec);
    let mut spec = Spec::of(Program::CallReport).on(k1);
    spec.args = [sc.addr_of(e), crate::timer::now() + ms(200), 9];
    let cl = spawn_in(&mut sc, s, spec);
    watch(cl.tcb);
    assert!(run_until(w_done, ms(5_000)), "the call never ended");
    assert_eq!(
        report::values_of(cl.tcb.0).next(),
        Some(Status::TimedOut.word(true))
    );
    assert!(
        report::count_of(counter.tcb.0) > 1,
        "the other core's thread didn't run"
    );
    assert!(run_until(walks_done, ms(2_000)));
    testkit::finish(sc);
});
