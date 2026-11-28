// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Endpoints (ADR 0054; kernel specification, "Endpoint operations and
//! messages" and "IPC deadlines and cancellation"): delivery in each
//! order, donation to passive servers, priority order, rights and checks,
//! cancels, deadlines and the delivered bit, destruction (K30), canceling
//! a badge's sends, and faults over endpoints. Every test checks every
//! invariant at its end.

mod common;

use common::store::{Host, Shape, badged, c, cap, ec, ep, r, t};
use kcap::preempt::{Always, Budget, Never};
use kipc::msg::{Info, Status};
use kipc::store::Transfer;
use kipc::{Outcome, Rights, endpoint, eventcount};
use ksched::donation::{self, FaultKind, RState, Res, TState};

fn host(threads: usize, replies: usize) -> Host {
    Host::new(Shape {
        threads,
        replies,
        eps: 2,
        ecs: 1,
        sets: 0,
        entries: 0,
    })
}

/// An info word with `len` octets and label `label`.
fn info(label: u64, len: u16) -> u64 {
    Info {
        label,
        len,
        caps: 0,
        unwrapped: 0,
        advance: false,
    }
    .encode()
}

/// Thread `i` gives up its context while it receives: a passive server.
fn passive(h: &mut Host, i: usize, reply: usize) {
    endpoint::recv(h, t(i), cap(1), r(reply)).unwrap();
    donation::unbind_sc(h, c(i)).unwrap();
}

const RW: Rights = Rights::READ.union(Rights::WRITE);

#[test]
fn send_then_recv() {
    let mut h = host(2, 1);
    let sent = badged(1, 7, Rights::ALL);
    assert_eq!(
        endpoint::send(&mut h, t(1), sent, info(1, 8), true),
        Ok(Outcome::Blocked)
    );
    assert_eq!(h.threads[1].state, TState::Send);
    assert_eq!(
        endpoint::recv(&mut h, t(2), cap(1), r(1)),
        Ok(Outcome::Done)
    );
    assert_eq!(h.threads[1].state, TState::Ready);
    assert_eq!(h.threads[1].result, Res::Replied);
    assert_eq!(h.threads[2].state, TState::Ready);
    assert_eq!(h.replies[1].state, RState::Idle);
    assert_eq!(
        h.received(2),
        vec![(
            1,
            Transfer::Message {
                ep: ep(1),
                info: info(1, 8),
                badge: 7,
                grant: true
            }
        )]
    );
    h.check();
}

#[test]
fn recv_then_send() {
    let mut h = host(2, 1);
    assert_eq!(
        endpoint::recv(&mut h, t(2), cap(1), r(1)),
        Ok(Outcome::Blocked)
    );
    assert_eq!(h.queue(1), vec![2]);
    let sent = badged(1, 3, RW);
    assert_eq!(
        endpoint::send(&mut h, t(1), sent, info(2, 0), true),
        Ok(Outcome::Done)
    );
    assert_eq!(h.threads[2].state, TState::Ready);
    assert_eq!(h.threads[2].result, Res::Replied);
    assert_eq!(
        h.received(2),
        vec![(
            1,
            Transfer::Message {
                ep: ep(1),
                info: info(2, 0),
                badge: 3,
                grant: false
            }
        )]
    );
    assert!(h.queue(1).is_empty());
    h.check();
}

#[test]
fn nbsend_drops_without_receiver() {
    let mut h = host(2, 1);
    assert_eq!(
        endpoint::send(&mut h, t(1), cap(1), info(1, 8), false),
        Ok(Outcome::Done)
    );
    assert_eq!(h.threads[1].state, TState::Ready);
    assert!(h.queue(1).is_empty());
    assert!(h.transfers.is_empty());
    h.check();
}

#[test]
fn call_plain_to_active_server() {
    let mut h = host(2, 1);
    endpoint::recv(&mut h, t(2), cap(1), r(1)).unwrap();
    assert_eq!(
        endpoint::call(&mut h, t(1), cap(1), info(1, 16)),
        Ok(Outcome::Blocked)
    );
    assert_eq!(h.threads[1].state, TState::Call(r(1)));
    assert_eq!(
        h.threads[1].sc,
        Some(c(1)),
        "an active server takes no context"
    );
    assert_eq!(h.threads[2].sc, Some(c(2)));
    endpoint::reply(&mut h, t(2), r(1), info(9, 4), true).unwrap();
    assert_eq!(h.threads[1].state, TState::Ready);
    assert_eq!(h.threads[1].result, Res::Replied);
    assert_eq!(
        h.received(1),
        vec![(
            2,
            Transfer::Reply {
                info: info(9, 4),
                grant: true
            }
        )]
    );
    h.check();
}

#[test]
fn call_donates_to_passive_server_and_reply_returns_it() {
    let mut h = host(2, 1);
    passive(&mut h, 2, 1);
    endpoint::call(&mut h, t(1), cap(1), info(1, 8)).unwrap();
    assert_eq!(
        h.threads[2].sc,
        Some(c(1)),
        "the caller's context is donated"
    );
    assert_eq!(h.threads[1].sc, None);
    h.check();
    endpoint::reply(&mut h, t(2), r(1), 0, false).unwrap();
    assert_eq!(h.threads[1].sc, Some(c(1)), "the reply returns it");
    assert_eq!(h.threads[2].sc, None);
    h.check();
}

#[test]
fn reply_recv_takes_next_queued_caller_and_donates() {
    let mut h = host(3, 1);
    passive(&mut h, 2, 1);
    endpoint::call(&mut h, t(1), cap(1), info(1, 8)).unwrap();
    endpoint::call(&mut h, t(3), cap(1), info(3, 8)).unwrap();
    assert_eq!(
        h.queue(1),
        vec![3],
        "the server is busy: the second call queues"
    );
    let out = endpoint::reply_recv(&mut h, t(2), cap(1), r(1), 0, false);
    assert_eq!(out, Ok(Outcome::Done));
    assert_eq!(h.threads[1].result, Res::Replied);
    assert_eq!(h.threads[1].sc, Some(c(1)));
    assert_eq!(h.threads[3].state, TState::Call(r(1)));
    assert_eq!(
        h.threads[2].sc,
        Some(c(3)),
        "the queued call donates as a call does"
    );
    h.check();
}

#[test]
fn reply_recv_checks_everything_before_the_reply() {
    let mut h = host(3, 2);
    endpoint::recv(&mut h, t(2), cap(1), r(1)).unwrap();
    endpoint::call(&mut h, t(1), cap(1), info(1, 8)).unwrap();
    let before = (h.threads.clone(), h.replies.clone());
    let no_read = badged(1, 0, Rights::WRITE);
    let refused = [
        endpoint::reply_recv(&mut h, t(2), no_read, r(1), 0, false),
        endpoint::reply_recv(&mut h, t(2), cap(1), r(1), info(0, 961), false),
        endpoint::reply_recv(&mut h, t(2), cap(1), r(1), 1 << 15, false),
    ];
    assert_eq!(
        refused.map(|x| x.unwrap_err()),
        [
            Status::MissingRight,
            Status::InvalidArgument,
            Status::InvalidArgument
        ]
    );
    // A reply object another thread receives with is busy.
    endpoint::recv(&mut h, t(3), cap(2), r(2)).unwrap();
    let before2 = (h.threads.clone(), h.replies.clone());
    assert_eq!(
        endpoint::reply_recv(&mut h, t(2), cap(1), r(2), 0, false),
        Err(Status::Busy)
    );
    assert_eq!((h.threads.clone(), h.replies.clone()), before2);
    assert_eq!(
        h.threads[1].state,
        TState::Call(r(1)),
        "the caller still waits"
    );
    assert_eq!(before.0[1], h.threads[1]);
    h.check();
}

#[test]
fn reply_by_another_than_the_holder_is_refused() {
    let mut h = host(3, 1);
    passive(&mut h, 2, 1);
    endpoint::call(&mut h, t(1), cap(1), info(1, 8)).unwrap();
    assert_eq!(
        endpoint::reply(&mut h, t(3), r(1), 0, false),
        Err(Status::NotHolder)
    );
    assert_eq!(
        endpoint::reply_recv(&mut h, t(3), cap(1), r(1), 0, false),
        Err(Status::NotHolder)
    );
    assert_eq!(h.threads[1].state, TState::Call(r(1)));
    h.check();
}

#[test]
fn senders_served_by_priority_then_arrival() {
    let mut h = host(5, 1);
    for (i, p) in [(1, 1), (2, 3), (3, 2), (4, 3)] {
        h.prio[i] = p;
        endpoint::send(&mut h, t(i), cap(1), info(i as u64, 8), true).unwrap();
    }
    assert_eq!(h.queue(1), vec![2, 4, 3, 1]);
    let mut got = vec![];
    for _ in 0..4 {
        endpoint::recv(&mut h, t(5), cap(1), r(1)).unwrap();
        got.push(h.transfers.last().unwrap().0.0);
    }
    assert_eq!(got, vec![2, 4, 3, 1]);
    h.check();
}

#[test]
fn receivers_served_by_priority_then_arrival() {
    let mut h = host(5, 4);
    for (i, p) in [(1, 2), (2, 2), (3, 5), (4, 1)] {
        h.prio[i] = p;
        endpoint::recv(&mut h, t(i), cap(1), r(i)).unwrap();
    }
    assert_eq!(h.queue(1), vec![3, 1, 2, 4]);
    for want in [3, 1, 2, 4] {
        endpoint::send(&mut h, t(5), cap(1), 0, true).unwrap();
        assert_eq!(h.transfers.last().unwrap().1.0, want);
    }
    h.check();
}

#[test]
fn priority_change_requeues_both_trees_as_new_arrival() {
    let mut h = host(4, 1);
    for i in 1..=3 {
        endpoint::send(&mut h, t(i), badged(1, 5, Rights::ALL), 0, true).unwrap();
    }
    endpoint::requeue(&mut h, t(1));
    assert_eq!(
        h.queue(1),
        vec![2, 3, 1],
        "a new arrival, at the back of its priority"
    );
    h.prio[3] = 2;
    endpoint::requeue(&mut h, t(3));
    assert_eq!(h.queue(1), vec![3, 2, 1]);
    h.check();
    // The badge tree was requeued too: canceling the badge takes them in
    // its arrival order.
    let mut b = Budget::with_threshold(Always, 1);
    let _ = endpoint::cancel_badged(&mut h, ep(1), 5, &mut b);
    assert_eq!(h.restarts, vec![t(2)]);
    h.check();
}

#[test]
fn rights() {
    let mut h = host(2, 1);
    let read = badged(1, 0, Rights::READ);
    let write = badged(1, 0, Rights::WRITE);
    assert_eq!(
        endpoint::send(&mut h, t(1), read, 0, true),
        Err(Status::MissingRight)
    );
    assert_eq!(
        endpoint::recv(&mut h, t(1), write, r(1)),
        Err(Status::MissingRight)
    );
    // A call needs grant or grant-reply as well as write.
    assert_eq!(
        endpoint::call(&mut h, t(1), write, 0),
        Err(Status::MissingRight)
    );
    let gr = badged(1, 0, Rights::WRITE.union(Rights::GRANT_REPLY));
    assert_eq!(endpoint::call(&mut h, t(1), gr, 0), Ok(Outcome::Blocked));
    let mut h = host(2, 1);
    let g = badged(1, 0, Rights::WRITE.union(Rights::GRANT));
    assert_eq!(endpoint::call(&mut h, t(1), g, 0), Ok(Outcome::Blocked));
    h.check();
}

#[test]
fn info_out_of_range_is_refused_and_nothing_sent() {
    let mut h = host(2, 1);
    for bad in [info(0, 961), 1 << 12, 1 << 15] {
        assert_eq!(
            endpoint::send(&mut h, t(1), cap(1), bad, true),
            Err(Status::InvalidArgument)
        );
        assert_eq!(
            endpoint::call(&mut h, t(1), cap(1), bad),
            Err(Status::InvalidArgument)
        );
    }
    assert!(h.queue(1).is_empty());
    assert_eq!(
        endpoint::send(&mut h, t(1), cap(1), info(0, 960), true),
        Ok(Outcome::Blocked)
    );
    h.check();
}

#[test]
fn cancel_queued_call_not_delivered_server_never_sees() {
    let mut h = host(2, 1);
    endpoint::call(&mut h, t(1), cap(1), 0).unwrap();
    donation::cancel(&mut h, t(1)).unwrap();
    assert_eq!(h.threads[1].result, Res::Canceled);
    assert!(!h.dbit[1], "not delivered");
    assert!(h.queue(1).is_empty());
    assert_eq!(
        endpoint::recv(&mut h, t(2), cap(1), r(1)),
        Ok(Outcome::Blocked)
    );
    assert!(h.transfers.is_empty());
    h.check();
}

#[test]
fn cancel_delivered_call_delivered_reply_fails_no_caller() {
    let mut h = host(2, 1);
    endpoint::recv(&mut h, t(2), cap(1), r(1)).unwrap();
    endpoint::call(&mut h, t(1), cap(1), 0).unwrap();
    donation::cancel(&mut h, t(1)).unwrap();
    assert_eq!(h.threads[1].result, Res::Canceled);
    assert!(h.dbit[1], "delivered");
    assert_eq!(
        endpoint::reply(&mut h, t(2), r(1), 0, false),
        Err(Status::NoCaller)
    );
    assert!(h.received(1).is_empty());
    h.check();
}

#[test]
fn deadline_queued_and_delivered() {
    let mut h = host(3, 1);
    endpoint::call(&mut h, t(1), cap(1), 0).unwrap();
    donation::deadline(&mut h, t(1)).unwrap();
    assert_eq!((h.threads[1].result, h.dbit[1]), (Res::TimedOut, false));
    endpoint::recv(&mut h, t(2), cap(1), r(1)).unwrap();
    endpoint::call(&mut h, t(3), cap(1), 0).unwrap();
    donation::deadline(&mut h, t(3)).unwrap();
    assert_eq!((h.threads[3].result, h.dbit[3]), (Res::TimedOut, true));
    // A receive times out too.
    endpoint::recv(&mut h, t(2), cap(1), r(1)).unwrap();
    donation::deadline(&mut h, t(2)).unwrap();
    assert_eq!(h.threads[2].result, Res::TimedOut);
    assert!(h.queue(1).is_empty());
    h.check();
}

#[test]
fn drain_releases_each_waiter_destroyed_one_per_step() {
    let mut h = host(4, 1);
    endpoint::send(&mut h, t(1), cap(1), 0, true).unwrap();
    endpoint::call(&mut h, t(2), cap(1), 0).unwrap();
    endpoint::fault(&mut h, t(3), ep(1), 9);
    assert!(!endpoint::drain(&mut h, ep(1)));
    assert_eq!(h.threads[1].result, Res::Destroyed);
    assert_eq!(h.threads[2].state, TState::Send, "still queued");
    assert!(!endpoint::drain(&mut h, ep(1)));
    assert_eq!((h.threads[2].result, h.dbit[2]), (Res::Destroyed, false));
    assert!(endpoint::drain(&mut h, ep(1)));
    // The drain's defensive fault branch, which the kernel never reaches:
    // the thread's own copy of the endpoint, in slot 3 or 4, keeps it from
    // being destroyed, and that copy's unbind withdraws the fault first
    // (K50). Found here, the fault is withdrawn with no result.
    assert_eq!(
        (h.threads[3].state, h.threads[3].result),
        (TState::Ready, Res::None)
    );
    endpoint::finish(&mut h, ep(1));
    assert!(h.transfers.is_empty());
    h.check();
    // Receivers too.
    endpoint::recv(&mut h, t(4), cap(2), r(1)).unwrap();
    assert_eq!(h.destroy_ep(2), 1);
    assert_eq!(h.threads[4].result, Res::Destroyed);
    assert_eq!(h.replies[1].state, RState::Idle);
    h.check();
}

#[test]
fn destroyed_reply_object_ends_call_destroyed_delivered() {
    let mut h = host(2, 1);
    endpoint::recv(&mut h, t(2), cap(1), r(1)).unwrap();
    endpoint::call(&mut h, t(1), cap(1), 0).unwrap();
    donation::destroy_reply(&mut h, r(1));
    assert_eq!((h.threads[1].result, h.dbit[1]), (Res::Destroyed, true));
    h.check();
}

#[test]
fn destroyed_reply_object_dequeues_its_receiver() {
    let mut h = host(2, 1);
    endpoint::recv(&mut h, t(2), cap(1), r(1)).unwrap();
    donation::destroy_reply(&mut h, r(1));
    assert_eq!(h.threads[2].result, Res::Destroyed);
    assert!(h.queue(1).is_empty());
    h.check();
}

#[test]
fn cancel_badged_needs_a_badged_cap_with_all_rights() {
    assert_eq!(
        endpoint::cancel_badged_check(badged(1, 0, Rights::ALL)),
        Err(Status::InvalidArgument)
    );
    let partial = Rights::READ.union(Rights::WRITE).union(Rights::GRANT);
    assert_eq!(
        endpoint::cancel_badged_check(badged(1, 4, partial)),
        Err(Status::MissingRight)
    );
    assert_eq!(
        endpoint::cancel_badged_check(badged(1, 4, Rights::ALL)),
        Ok(())
    );
}

/// Queues senders under badges 1 and 2 on endpoint 1, alternately, with a
/// fault under badge 1 among them.
fn badged_queue(h: &mut Host, n: usize) {
    for i in 1..=n {
        let b = 1 + (i as u64 % 2);
        if i == 3 {
            endpoint::fault(h, t(i), ep(1), b);
        } else if i % 3 == 0 {
            endpoint::call(h, t(i), badged(1, b, Rights::ALL), 0).unwrap();
        } else {
            endpoint::send(h, t(i), badged(1, b, Rights::ALL), 0, true).unwrap();
        }
    }
}

#[test]
fn cancel_badged_sends_exact_and_restart_equivalent() {
    let n = 40;
    let mut once = host(n, 0);
    badged_queue(&mut once, n);
    let mut b = Budget::new(Never);
    assert_eq!(endpoint::cancel_badged(&mut once, ep(1), 2, &mut b), Ok(()));
    let mut again = host(n, 0);
    badged_queue(&mut again, n);
    let mut stops = 0;
    loop {
        let mut b = Budget::with_threshold(Always, 1);
        match endpoint::cancel_badged(&mut again, ep(1), 2, &mut b) {
            Ok(()) => break,
            Err(_) => stops += 1,
        }
        again.check();
    }
    assert_eq!(stops, n / 2, "one sender per unit");
    assert_eq!(once.threads, again.threads);
    assert_eq!(once.restarts, again.restarts);
    assert_eq!(once.queue(1), again.queue(1));
    // Badge 1's senders are untouched, in order; badge 2's restarted, first
    // come first.
    assert_eq!(
        once.queue(1),
        (1..=n).filter(|i| i % 2 == 0).collect::<Vec<_>>()
    );
    let want: Vec<_> = (1..=n).filter(|i| i % 2 == 1 && *i != 3).map(t).collect();
    assert_eq!(once.restarts, want);
    once.check();
}

#[test]
fn cancel_badged_fault_sender_not_rewound() {
    let mut h = host(4, 0);
    badged_queue(&mut h, 4);
    let mut b = Budget::new(Never);
    endpoint::cancel_badged(&mut h, ep(1), 2, &mut b).unwrap();
    assert_eq!(h.threads[3].state, TState::Ready, "the fault was withdrawn");
    assert_eq!(h.threads[3].result, Res::None);
    assert!(
        !h.restarts.contains(&t(3)),
        "its PC stays at the faulting instruction"
    );
    h.check();
}

#[test]
fn fault_queued_then_delivered_donating() {
    let mut h = host(2, 1);
    endpoint::fault(&mut h, t(1), ep(1), 6);
    assert_eq!(h.threads[1].state, TState::Fault(FaultKind::Endpoint));
    // A passive handler receives: the fault donates as a call does.
    endpoint::recv(&mut h, t(2), cap(1), r(1)).unwrap();
    assert_eq!(h.threads[1].state, TState::Call(r(1)));
    assert_eq!(h.threads[1].fault, Some(FaultKind::Endpoint));
    assert_eq!(h.received(2), vec![(1, Transfer::Fault { badge: 6 })]);
    let mut h2 = host(2, 1);
    passive(&mut h2, 2, 1);
    endpoint::fault(&mut h2, t(1), ep(1), 6);
    assert_eq!(h2.threads[2].sc, Some(c(1)), "delivered at once, donating");
    // The reply resumes it with no result, and carries nothing.
    endpoint::reply(&mut h2, t(2), r(1), info(1, 8), false).unwrap();
    assert_eq!(
        (h2.threads[1].state, h2.threads[1].result),
        (TState::Ready, Res::None)
    );
    assert_eq!(h2.threads[1].sc, Some(c(1)));
    assert!(h2.received(1).is_empty());
    h.check();
    h2.check();
}

#[test]
fn delivered_fault_canceled_reexecutes_and_late_reply_fails() {
    let mut h = host(2, 1);
    endpoint::recv(&mut h, t(2), cap(1), r(1)).unwrap();
    endpoint::fault(&mut h, t(1), ep(1), 0);
    donation::cancel(&mut h, t(1)).unwrap();
    assert_eq!((h.threads[1].result, h.dbit[1]), (Res::None, false));
    assert_eq!(
        endpoint::reply(&mut h, t(2), r(1), 0, false),
        Err(Status::NoCaller)
    );
    // Faults have no deadline.
    endpoint::recv(&mut h, t(2), cap(1), r(1)).unwrap();
    endpoint::fault(&mut h, t(1), ep(1), 0);
    assert!(donation::deadline(&mut h, t(1)).is_err());
    h.check();
}

#[test]
fn timeout_fault_delivered_plain() {
    let mut h = host(2, 1);
    h.threads[1].tep = true;
    h.tep[1] = Some(ep(1));
    passive(&mut h, 2, 1);
    assert!(donation::budget_out(&mut h, t(1)));
    assert_eq!(h.threads[1].state, TState::Call(r(1)));
    assert_eq!(h.threads[1].fault, Some(FaultKind::Timeout));
    assert_eq!(
        h.threads[1].sc,
        Some(c(1)),
        "a timeout fault donates nothing"
    );
    assert_eq!(h.threads[2].sc, None);
    assert_eq!(h.received(2), vec![(1, Transfer::Fault { badge: 0x101 })]);
    h.check();
}

#[test]
fn queued_timeout_fault_withdrawn_k50() {
    let mut h = host(2, 1);
    h.threads[1].tep = true;
    h.tep[1] = Some(ep(1));
    donation::budget_out(&mut h, t(1));
    assert_eq!(h.queue(1), vec![1]);
    donation::set_tep(&mut h, t(1), false);
    assert!(h.queue(1).is_empty());
    assert_eq!(
        (h.threads[1].state, h.threads[1].result),
        (TState::Ready, Res::None)
    );
    h.check();
}

#[test]
fn stranded_server_queued_send_canceled_k17() {
    let mut h = host(3, 1);
    passive(&mut h, 2, 1);
    endpoint::call(&mut h, t(1), cap(1), 0).unwrap();
    // The server, on the caller's context, sends to a third endpoint queue.
    endpoint::send(&mut h, t(2), cap(2), 0, true).unwrap();
    assert_eq!(h.queue(2), vec![2]);
    donation::cancel(&mut h, t(1)).unwrap();
    assert_eq!(h.threads[1].sc, Some(c(1)), "the context is back");
    assert!(
        h.queue(2).is_empty(),
        "the stranded server's send left its queue"
    );
    assert_eq!(h.threads[2].result, Res::Canceled);
    h.check();
    h.walks.clone().into_iter().for_each(|q| {
        donation::walk_step(&mut h, q);
    });
    h.check();
}

#[test]
fn send_to_bound_receiver_unlinks_its_eventcount_node() {
    let mut h = host(2, 1);
    eventcount::bind(&mut h, t(2), ec(1), Rights::ALL).unwrap();
    endpoint::recv(&mut h, t(2), cap(1), r(1)).unwrap();
    assert!(eventcount::is_linked(&h, 2));
    endpoint::send(&mut h, t(1), cap(1), 0, true).unwrap();
    assert!(!eventcount::is_linked(&h, 2));
    assert_eq!(h.threads[2].state, TState::Ready);
    h.check();
}

#[test]
fn plain_send_to_passive_receiver_leaves_it_without_context() {
    let mut h = host(2, 1);
    passive(&mut h, 2, 1);
    endpoint::send(&mut h, t(1), cap(1), 0, true).unwrap();
    assert_eq!(h.threads[2].state, TState::Ready);
    assert_eq!(
        h.threads[2].sc, None,
        "as in seL4: it runs when it next gets one"
    );
    h.check();
}

#[test]
fn suspended_receiver_gets_message_k20() {
    let mut h = host(2, 1);
    endpoint::recv(&mut h, t(2), cap(1), r(1)).unwrap();
    donation::set_suspended(&mut h, t(2), true);
    endpoint::send(&mut h, t(1), cap(1), info(4, 8), true).unwrap();
    assert_eq!(h.threads[2].state, TState::Ready);
    assert!(h.threads[2].suspended);
    assert_eq!(h.received(2).len(), 1);
    h.check();
}
