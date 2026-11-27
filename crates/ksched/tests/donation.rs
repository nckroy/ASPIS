// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Donation scenarios (kernel specification, "Passive servers and taking a
//! context back"): chains, take-back on a cancel and on a deadline, at the
//! bottom and in the middle of a chain, two take-backs on one context, the
//! walk and its faults, unbinding and destroying mid-chain, K08, K17 and
//! K50. The invariants are checked after every operation.

mod common;

use common::store::{Host, c, r, t};
use ksched::donation::{self, Delivered, Error, FaultKind, RState, Res, Step, TState, Tcb};

/// Thread 1 is the home of context 1; threads 2 to 4 are passive servers
/// receiving on replies 1 to 3.
fn chain(tep: &[usize]) -> Host {
    Host::init(4, 3, 1, tep)
}

/// C (1) calls S1 (2), which calls S2 (3), which calls S3 (4).
fn call_down(h: &mut Host, depth: usize) {
    for i in 1..=depth {
        assert_eq!(
            donation::call(h, t(i), t(i + 1)),
            Ok(Delivered::Donated(c(1)))
        );
        h.check();
    }
}

fn withdrawn(h: &Host) -> Vec<Tcb> {
    h.faults
        .iter()
        .filter(|f| f.1 == FaultKind::Withdrawn)
        .map(|f| f.0)
        .collect()
}

#[test]
fn the_context_moves_along_a_chain_and_back() {
    let mut h = chain(&[]);
    call_down(&mut h, 3);
    assert_eq!(h.scs[1].holder, Some(t(4)));
    assert_eq!(h.scs[1].top, Some(r(3)));
    assert_eq!(h.threads[1].sc, None);
    assert_eq!(h.threads[4].serving, Some(r(3)));
    // A server that doesn't hold the context can't answer its call.
    assert_eq!(donation::reply(&mut h, t(3), r(2)), Err(Error::NotHolder));
    // Nor can the holder answer a live call below the top.
    assert_eq!(donation::reply(&mut h, t(4), r(1)), Err(Error::NotHolder));
    // Each reply returns the context one step.
    for (srv, rep, caller) in [(4, 3, 3), (3, 2, 2), (2, 1, 1)] {
        assert_eq!(donation::reply(&mut h, t(srv), r(rep)), Ok(()));
        h.check();
        assert_eq!(h.scs[1].holder, Some(t(caller)));
        assert_eq!(h.threads[caller].result, Res::Replied);
        assert_eq!(h.replies[rep].state, RState::Idle);
    }
    assert_eq!(h.scs[1].top, None);
    assert!(h.work.is_empty());
}

#[test]
fn a_cancel_takes_the_context_back_at_once() {
    let mut h = chain(&[2, 3, 4]);
    call_down(&mut h, 3);
    donation::cancel(&mut h, t(1)).unwrap();
    h.check();
    // At once: C holds its context, its call canceled.
    assert_eq!(h.scs[1].holder, Some(t(1)));
    assert_eq!(h.threads[1].sc, Some(c(1)));
    assert_eq!(h.threads[1].result, Res::Canceled);
    assert_eq!(h.scs[1].top, None);
    assert_eq!(h.threads[4].sc, None);
    // The walk is queued at r1, and nothing is faulted yet.
    assert_eq!(h.work, vec![r(1)]);
    assert!(withdrawn(&h).is_empty());
    for i in 1..=3 {
        assert!(donation::is_stale(&mut h, r(i)));
    }
    h.drain();
    h.check();
    // S1's fault first, then S2's, then S3's, each with C's badge.
    assert_eq!(withdrawn(&h), vec![t(2), t(3), t(4)]);
    assert!(h.faults.iter().all(|f| f.2 == 0x101));
    // K17: each server's onward call ended "canceled".
    assert_eq!(h.threads[2].result, Res::Canceled);
    assert_eq!(h.threads[3].result, Res::Canceled);
    for i in 1..=3 {
        assert_eq!(h.replies[i].state, RState::Invalid);
        assert_eq!(h.threads[i + 1].serving, None);
    }
    // A stranded server's later reply fails with "no caller".
    donation::fault_replied(&mut h, t(2)).unwrap();
    assert_eq!(donation::reply(&mut h, t(2), r(1)), Err(Error::NoCaller));
    assert_eq!(h.replies[1].state, RState::Idle);
}

#[test]
fn a_one_hop_chain_still_faults_its_server() {
    let mut h = chain(&[2]);
    call_down(&mut h, 1);
    donation::deadline(&mut h, t(1)).unwrap();
    assert_eq!(h.threads[1].result, Res::TimedOut);
    assert_eq!(h.work, vec![r(1)]);
    h.drain();
    h.check();
    assert_eq!(withdrawn(&h), vec![t(2)]);
    assert_eq!(h.threads[2].state, TState::Fault(FaultKind::Withdrawn));
}

/// The critics' case: S1's onward call times out mid-chain. S1 gets the
/// context back, and its reply to C still works.
#[test]
fn a_mid_chain_deadline_returns_the_context_to_the_middle() {
    let mut h = chain(&[3, 4]);
    call_down(&mut h, 3);
    donation::deadline(&mut h, t(2)).unwrap();
    h.check();
    assert_eq!(h.scs[1].holder, Some(t(2)));
    assert_eq!(h.threads[2].result, Res::TimedOut);
    assert_eq!(h.scs[1].top, Some(r(1)));
    assert!(donation::is_live(&mut h, r(1)));
    assert!(donation::is_stale(&mut h, r(2)));
    assert!(donation::is_stale(&mut h, r(3)));
    // Before the walk: S1 replies to C, and C has its context.
    assert_eq!(donation::reply(&mut h, t(2), r(1)), Ok(()));
    h.check();
    assert_eq!(h.scs[1].holder, Some(t(1)));
    assert_eq!(h.threads[1].result, Res::Replied);
    h.drain();
    h.check();
    assert_eq!(withdrawn(&h), vec![t(3), t(4)]);
}

#[test]
fn two_take_backs_on_one_context_while_a_walk_is_pending() {
    let mut h = chain(&[2, 3, 4]);
    call_down(&mut h, 3);
    // S2's call to S3 is canceled: a walk at r3.
    donation::cancel(&mut h, t(3)).unwrap();
    assert_eq!(h.scs[1].holder, Some(t(3)));
    // Then C's call: a second walk, at r1, from the live part.
    donation::cancel(&mut h, t(1)).unwrap();
    h.check();
    assert_eq!(h.scs[1].holder, Some(t(1)));
    assert_eq!(h.work, vec![r(3), r(1)]);
    for i in 1..=3 {
        assert!(donation::is_stale(&mut h, r(i)), "r{i}");
    }
    h.drain();
    h.check();
    // Each server faulted once.
    let mut w = withdrawn(&h);
    w.sort();
    assert_eq!(w, vec![t(2), t(3), t(4)]);
}

/// A new push after a cut gets a later number, so it is live although an
/// interval below it is pending; a second cut above it adds a disjoint
/// interval.
#[test]
fn pushes_after_a_cut_stay_live() {
    let mut h = Host::init(5, 4, 1, &[]);
    call_down(&mut h, 3); // r1 C->2, r2 2->3, r3 3->4
    donation::cancel(&mut h, t(3)).unwrap(); // walk at r3; 3 holds
    // 3 calls 5, which receives on r4.
    assert_eq!(
        donation::call(&mut h, t(3), t(5)),
        Ok(Delivered::Donated(c(1)))
    );
    h.check();
    assert!(donation::is_live(&mut h, r(4)));
    assert!(donation::is_stale(&mut h, r(3)));
    donation::cancel(&mut h, t(3)).unwrap(); // a cut at r4
    h.check();
    assert!(donation::is_live(&mut h, r(2)));
    assert!(donation::is_stale(&mut h, r(4)));
    assert_eq!(h.work, vec![r(3), r(4)]);
    h.drain();
    h.check();
    assert!(donation::is_live(&mut h, r(1)));
}

#[test]
fn stranded_servers_without_a_timeout_endpoint_get_no_fault() {
    let mut h = chain(&[3]);
    call_down(&mut h, 3);
    donation::cancel(&mut h, t(1)).unwrap();
    h.drain();
    h.check();
    assert_eq!(withdrawn(&h), vec![t(3)]);
    // S1 and S3 are stranded, ready without a context.
    for i in [2, 4] {
        assert_eq!(h.threads[i].state, TState::Ready);
        assert_eq!(h.threads[i].sc, None);
    }
}

/// K17: the holder's own wait is canceled at the cut.
#[test]
fn the_holders_wait_ends_at_the_cut() {
    let mut h = chain(&[2, 3]);
    call_down(&mut h, 2);
    donation::wait_other(&mut h, t(3));
    donation::cancel(&mut h, t(1)).unwrap();
    assert_eq!(h.threads[3].state, TState::Ready);
    assert_eq!(h.threads[3].result, Res::Canceled);
    h.drain();
    assert_eq!(withdrawn(&h), vec![t(2), t(3)]);
    // A holder in its own timeout fault: the fault is withdrawn.
    let mut h = chain(&[2]);
    call_down(&mut h, 1);
    assert!(donation::budget_out(&mut h, t(2)));
    assert_eq!(h.faults, vec![(t(2), FaultKind::Timeout, 0x101)]);
    donation::cancel(&mut h, t(1)).unwrap();
    assert_eq!(h.withdrawn, vec![(t(2), FaultKind::Timeout)]);
    h.drain();
    assert_eq!(h.threads[2].state, TState::Fault(FaultKind::Withdrawn));
}

/// K08: removing the timeout endpoint while donated is allowed; the later
/// take-back strands the server silently.
#[test]
fn removing_the_timeout_endpoint_while_donated() {
    let mut h = chain(&[2]);
    call_down(&mut h, 1);
    donation::set_tep(&mut h, t(2), false);
    donation::cancel(&mut h, t(1)).unwrap();
    h.drain();
    h.check();
    assert!(withdrawn(&h).is_empty());
}

/// K50: a queued fault is withdrawn when its endpoint is unset.
#[test]
fn a_queued_fault_is_withdrawn_with_its_endpoint() {
    let mut h = chain(&[2]);
    call_down(&mut h, 1);
    donation::cancel(&mut h, t(1)).unwrap();
    h.drain();
    assert_eq!(h.threads[2].state, TState::Fault(FaultKind::Withdrawn));
    donation::set_tep(&mut h, t(2), false);
    assert_eq!(h.withdrawn, vec![(t(2), FaultKind::Withdrawn)]);
    assert_eq!(h.threads[2].state, TState::Ready);
    h.check();
}

#[test]
fn unbinding_a_donated_context_takes_it_back_first() {
    let mut h = chain(&[2, 3]);
    call_down(&mut h, 2);
    donation::unbind_sc(&mut h, c(1)).unwrap();
    h.check();
    assert_eq!(h.scs[1].home, None);
    assert_eq!(h.scs[1].holder, None);
    assert_eq!(h.threads[1].result, Res::Canceled);
    assert_eq!(h.threads[1].sc, None);
    h.drain();
    assert_eq!(withdrawn(&h), vec![t(2), t(3)]);
    // The context can be bound again.
    donation::bind_sc(&mut h, c(1), t(1)).unwrap();
    h.check();
}

/// A server destroyed while it serves a donated call: its caller gets
/// the context back, and the servers above it are walked.
#[test]
fn destroying_a_server_mid_chain() {
    let mut h = chain(&[2, 3, 4]);
    call_down(&mut h, 3);
    h.destroy_thread(3);
    h.check();
    assert_eq!(h.scs[1].holder, Some(t(2)));
    assert_eq!(h.threads[2].result, Res::Canceled);
    h.drain();
    h.check();
    // S2 is gone; S3 above it is faulted; S1 keeps the context.
    assert_eq!(withdrawn(&h), vec![t(4)]);
    assert_eq!(donation::reply(&mut h, t(2), r(1)), Ok(()));
    assert_eq!(h.scs[1].holder, Some(t(1)));
    h.check();
}

/// A reply destroyed while its walk is pending takes its own step at
/// once; a destroyed live reply is a cut.
#[test]
fn destroying_replies_mid_walk() {
    let mut h = chain(&[2, 3, 4]);
    call_down(&mut h, 3);
    donation::cancel(&mut h, t(1)).unwrap();
    // r2, stale and not the cursor: S2 faulted at once, S1's call on it ends.
    h.destroy_reply(2);
    h.check();
    assert_eq!(withdrawn(&h), vec![t(3)]);
    assert_eq!(h.threads[2].result, Res::Canceled);
    h.drain();
    h.check();
    assert_eq!(withdrawn(&h), vec![t(3), t(2), t(4)]);
    // Every fault, the one sent at the destroy too, carries the context's
    // badge.
    assert!(h.faults.iter().all(|f| f.2 == 0x101), "{:x?}", h.faults);
    // A live reply destroyed: a cut at it, and its own step at once.
    let mut h = chain(&[2, 3]);
    call_down(&mut h, 2);
    h.destroy_reply(2);
    h.check();
    assert_eq!(h.scs[1].holder, Some(t(2)));
    assert_eq!(withdrawn(&h), vec![t(3)]);
    assert!(h.work.is_empty());
}

/// A stale reply destroyed inside a walk that encloses an older one: its
/// server's fault carries the badge its own walk took at its cut, not the
/// nested walk's.
#[test]
fn a_destroyed_reply_faults_with_its_own_walks_badge() {
    let mut h = Host::init(5, 4, 1, &[2, 3, 4, 5]);
    call_down(&mut h, 3); // r1 C->2, r2 2->3, r3 3->4
    donation::cancel(&mut h, t(3)).unwrap(); // walk A at r3, badge 0x101
    assert_eq!(
        donation::call(&mut h, t(3), t(5)),
        Ok(Delivered::Donated(c(1)))
    ); // r4 3->5
    h.scs[1].badge = 0x999; // reconfigured, as a context in use may be
    donation::cancel(&mut h, t(1)).unwrap(); // walk B at r1: r1, r2, r4
    h.check();
    // r4 is above walk A's interval and inside B's; r2 is below A's.
    h.destroy_reply(4);
    h.check();
    h.destroy_reply(2);
    h.check();
    h.drain();
    h.check();
    let badge = |i: usize| {
        let f: Vec<_> = h.faults.iter().filter(|f| f.0 == t(i)).collect();
        assert_eq!(f.len(), 1, "{:x?}", h.faults);
        f[0].2
    };
    assert_eq!(badge(4), 0x101);
    assert_eq!(badge(5), 0x999);
    assert_eq!(badge(3), 0x999);
    assert_eq!(badge(2), 0x999);
}

#[test]
fn destroying_a_context_leaves_its_walks_running() {
    let mut h = chain(&[2, 3]);
    call_down(&mut h, 2);
    h.destroy_sc(1);
    h.check();
    assert_eq!(h.work, vec![r(1)]);
    h.drain();
    h.check();
    assert_eq!(withdrawn(&h), vec![t(2), t(3)]);
    assert!(h.threads[1].sc.is_none());
}

/// A thread that serves a donated call can't be given a context.
#[test]
fn binding_a_serving_thread_is_refused() {
    let mut h = Host::init(4, 3, 2, &[]);
    // Context 2 is free once unbound from thread 2.
    donation::unbind_sc(&mut h, c(2)).unwrap();
    assert_eq!(
        donation::call(&mut h, t(1), t(3)),
        Ok(Delivered::Donated(c(1)))
    );
    assert_eq!(donation::bind_sc(&mut h, c(2), t(3)), Err(Error::Bound));
    donation::cancel(&mut h, t(1)).unwrap();
    assert_eq!(donation::bind_sc(&mut h, c(2), t(3)), Err(Error::Bound));
    h.drain();
    assert_eq!(donation::bind_sc(&mut h, c(2), t(3)), Ok(()));
    h.check();
}

#[test]
fn a_server_with_its_own_context_isnt_donated_to() {
    let mut h = Host::init(3, 2, 2, &[]);
    // Thread 2 has context 2 and receives on reply 2.
    donation::recv(&mut h, t(2), r(2)).unwrap();
    assert_eq!(donation::call(&mut h, t(1), t(2)), Ok(Delivered::Plain));
    h.check();
    // The caller keeps its context while it waits.
    assert_eq!(h.scs[1].holder, Some(t(1)));
    assert_eq!(h.threads[1].sc, Some(c(1)));
    donation::cancel(&mut h, t(1)).unwrap();
    assert_eq!(h.replies[2].state, RState::Invalid);
    assert_eq!(donation::reply(&mut h, t(2), r(2)), Err(Error::NoCaller));
    h.check();
}

#[test]
fn suspend_keeps_a_donated_call() {
    let mut h = chain(&[2]);
    call_down(&mut h, 1);
    donation::set_suspended(&mut h, t(1), true);
    // The server keeps running on the donated context.
    assert_eq!(h.scs[1].holder, Some(t(2)));
    assert!(withdrawn(&h).is_empty());
    // The reply is held: the caller is ready but suspended. The server,
    // a passive one, replies and receives again.
    donation::reply_recv(&mut h, t(2), r(1)).unwrap();
    assert_eq!(h.threads[1].result, Res::Replied);
    assert!(h.threads[1].suspended);
    assert!(!h.runs(1));
    donation::set_suspended(&mut h, t(1), false);
    assert!(h.runs(1));
    // Suspending a server that holds a donated context takes nothing back.
    call_down(&mut h, 1);
    donation::set_suspended(&mut h, t(2), true);
    assert_eq!(h.scs[1].holder, Some(t(2)));
    assert!(h.work.is_empty());
    h.check();
    assert_eq!(
        h.steps
            .iter()
            .filter(|s| matches!(s, Step::Suspend(_)))
            .count(),
        2
    );
}
