// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Eventcounts, wait sets and bound eventcounts (ADR 0053; kernel
//! specification, "Eventcount operations", "Wait sets" and "Threads bound
//! to an eventcount"): waits and advances, the maximum, the preemptible
//! advance and the work list's units and costs (K24, K31), destruction
//! (K30), wait sets (K08, K32), and the bound receive with passive servers.
//! Every test checks every invariant at its end.

mod common;

use common::store::{Host, Shape, c, cap, ec, ep, r, t, ws};
use kcap::preempt::{Always, Budget, Never};
use kipc::msg::Status;
use kipc::store::Value;
use kipc::{Outcome, Rights, endpoint, eventcount};
use ksched::batch::{Batcher, Sources};
use ksched::donation::{self, Res, TState};

fn host(threads: usize, ecs: usize, sets: usize, entries: usize) -> Host {
    Host::new(Shape {
        threads,
        replies: threads,
        eps: 1,
        ecs,
        sets,
        entries,
    })
}

const ALL: Rights = Rights::ALL;

fn advance(h: &mut Host, e: usize) -> Result<u64, Status> {
    eventcount::advance(h, ec(e), ALL, &mut Budget::new(Never))
}

#[test]
fn read_and_wait() {
    let mut h = host(2, 1, 0, 0);
    assert_eq!(eventcount::read(&h, ec(1), ALL), Ok(0));
    assert_eq!(
        eventcount::read(&h, ec(1), Rights::WRITE),
        Err(Status::MissingRight)
    );
    assert_eq!(
        eventcount::wait(&mut h, t(1), ec(1), Rights::WRITE, 1),
        Err(Status::MissingRight)
    );
    assert_eq!(
        eventcount::wait(&mut h, t(1), ec(1), ALL, 2),
        Ok(Outcome::Blocked)
    );
    assert_eq!(advance(&mut h, 1), Ok(1));
    assert_eq!(h.threads[1].state, TState::Other);
    assert_eq!(advance(&mut h, 1), Ok(2));
    assert_eq!(h.threads[1].state, TState::Ready);
    assert_eq!(h.threads[1].result, Res::Replied);
    assert_eq!(h.got[1], Some(Value::Count(2)));
    assert_eq!(
        eventcount::advance(&mut h, ec(1), Rights::READ, &mut Budget::new(Never)),
        Err(Status::MissingRight)
    );
    h.check();
}

#[test]
fn wait_reached_returns_at_once() {
    let mut h = host(1, 1, 0, 0);
    advance(&mut h, 1).unwrap();
    assert_eq!(
        eventcount::wait(&mut h, t(1), ec(1), ALL, 1),
        Ok(Outcome::Done)
    );
    assert_eq!(h.threads[1].state, TState::Ready);
    assert_eq!(h.got[1], Some(Value::Count(1)));
    h.check();
}

#[test]
fn advance_at_maximum_refused_count_unchanged() {
    let mut h = host(1, 1, 0, 0);
    h.ecs[1].count = u64::MAX - 1;
    assert_eq!(advance(&mut h, 1), Ok(u64::MAX));
    assert_eq!(advance(&mut h, 1), Err(Status::CountAtMaximum));
    assert_eq!(
        eventcount::advance_irq(&mut h, ec(1)),
        Err(Status::CountAtMaximum)
    );
    assert_eq!(h.ecs[1].count, u64::MAX);
    // A wait for the maximum returns at once; nothing can wait past it.
    assert_eq!(
        eventcount::wait(&mut h, t(1), ec(1), ALL, u64::MAX),
        Ok(Outcome::Done)
    );
    h.check();
}

#[test]
fn advance_wakes_exactly_reached() {
    let mut h = host(4, 1, 0, 0);
    for (i, g) in [(1, 1), (2, 2), (3, 2), (4, 3)] {
        eventcount::wait(&mut h, t(i), ec(1), ALL, g).unwrap();
    }
    advance(&mut h, 1).unwrap();
    let woken = |h: &Host| {
        (1..=4)
            .filter(|&i| h.threads[i].state == TState::Ready)
            .count()
    };
    assert_eq!(woken(&h), 1);
    advance(&mut h, 1).unwrap();
    assert_eq!(woken(&h), 3);
    assert_eq!(h.threads[4].state, TState::Other);
    h.check();
}

#[test]
fn advance_preempted_queues_rest_once() {
    let n = 300;
    let mut h = host(n, 1, 0, 0);
    for i in 1..=n {
        eventcount::wait(&mut h, t(i), ec(1), ALL, 1).unwrap();
    }
    let mut b = Budget::new(Always);
    assert_eq!(eventcount::advance(&mut h, ec(1), ALL, &mut b), Ok(1));
    let woken = |h: &Host| {
        (1..=n)
            .filter(|&i| h.threads[i].state == TState::Ready)
            .count()
    };
    assert_eq!(
        woken(&h),
        100,
        "the advance stops at its first preemption point"
    );
    assert!(h.ecs[1].pending);
    assert_eq!(h.work, vec![ec(1)]);
    h.check();
    // A second advance while pending wakes more, and queues nothing again.
    let mut b = Budget::new(Always);
    assert_eq!(eventcount::advance(&mut h, ec(1), ALL, &mut b), Ok(2));
    assert_eq!(woken(&h), 200);
    assert_eq!(h.work, vec![ec(1)]);
    h.check();
    h.run_work();
    assert_eq!(woken(&h), n);
    assert!(!h.ecs[1].pending && h.work.is_empty());
    assert_eq!(h.ecs[1].count, 2, "each advance added one, once");
    h.check();
}

/// The eventcounts' work list as a batch's only source.
struct WorkSource<'a>(&'a mut Host);

impl Sources for WorkSource<'_> {
    fn count(&self) -> usize {
        1
    }
    fn has_work(&mut self, _: usize) -> bool {
        !self.0.work.is_empty()
    }
    fn cost(&mut self, _: usize) -> u32 {
        let e = self.0.work[0];
        eventcount::unit_cost(self.0, e)
    }
    fn unit(&mut self, _: usize) {
        let e = self.0.work[0];
        if eventcount::work_unit(self.0, e) {
            self.0.work.retain(|&x| x != e);
            self.0.work.push(e);
        }
    }
}

#[test]
fn advance_preempted_wait_set_waiters_cost() {
    // 30 waiters, each on a wait set of 60 entries all on one eventcount.
    let n = 30;
    let mut h = host(n, 1, n, 60);
    for w in 1..=n {
        for i in 0..60 {
            eventcount::ws_add(&mut h, ws(w), ALL, i, ec(1), ALL, 1).unwrap();
        }
        assert_eq!(
            eventcount::ws_wait(&mut h, t(w), ws(w), ALL),
            Ok(Outcome::Blocked)
        );
        assert_eq!(kipc::wait_cost(&h, t(w)), 60);
    }
    let mut b = Budget::new(Always);
    eventcount::advance(&mut h, ec(1), ALL, &mut b).unwrap();
    let woken = |h: &Host| {
        (1..=n)
            .filter(|&i| h.threads[i].state == TState::Ready)
            .count()
    };
    // 60 units, then 120: the first check comes after the second wake.
    assert_eq!(woken(&h), 2);
    assert_eq!(h.got[1], Some(Value::Mask((1 << 60) - 1)));
    h.check();
    let mut batcher = Batcher::new();
    let mut batches = 0;
    while !h.work.is_empty() {
        let ran = batcher.run(&mut WorkSource(&mut h), ksched::BATCH_UNITS);
        assert!(ran.units <= ksched::BATCH_UNITS, "a batch passed its units");
        assert!(ran.units >= 60, "every batch makes progress");
        batches += 1;
        h.check();
    }
    assert_eq!(woken(&h), n);
    assert_eq!(batches, n - 2, "one wake of 60 units per batch of 100");
    h.check();
}

#[test]
fn irq_advance_wakes_in_units_and_the_mark_clears_last() {
    let mut h = host(3, 1, 0, 0);
    for i in 1..=3 {
        eventcount::wait(&mut h, t(i), ec(1), ALL, 1).unwrap();
    }
    assert_eq!(eventcount::advance_irq(&mut h, ec(1)), Ok(1));
    assert!(h.ecs[1].pending);
    for k in 1..=3 {
        assert_eq!(eventcount::unit_cost(&mut h, ec(1)), 1);
        let more = eventcount::work_unit(&mut h, ec(1));
        assert_eq!(more, k < 3);
        assert_eq!(
            h.ecs[1].pending,
            k < 3,
            "the mark clears with the last reached waiter"
        );
        h.check();
    }
    assert!(h.work.is_empty());
    // Without a reached waiter, an interrupt's advance queues nothing.
    eventcount::wait(&mut h, t(1), ec(1), ALL, 5).unwrap();
    eventcount::advance_irq(&mut h, ec(1)).unwrap();
    assert!(!h.ecs[1].pending && h.work.is_empty());
    h.check();
}

#[test]
fn advance_on_other_core_leaves_list() {
    // K24: an eventcount stays on the list of the core that first queued
    // it, once; a later advance on another core that stops at a preemption
    // point only sets the mark; and its finish, on yet another core, takes
    // it off the first core's list.
    let n = 300;
    let mut h = host(n, 1, 0, 0);
    for i in 1..=n {
        eventcount::wait(&mut h, t(i), ec(1), ALL, 1).unwrap();
    }
    eventcount::advance_irq(&mut h, ec(1)).unwrap();
    assert_eq!((h.ecs[1].pending, h.queued_on[1]), (true, Some(0)));
    h.core = 1;
    let mut b = Budget::new(Always);
    assert_eq!(eventcount::advance(&mut h, ec(1), ALL, &mut b), Ok(2));
    assert_eq!(h.work, vec![ec(1)], "queued again");
    assert_eq!(h.queued_on[1], Some(0), "the mark moved");
    h.check();
    h.core = 2;
    h.destroy_ec(1);
    assert!(h.work.is_empty() && h.queued_on[1].is_none());
    h.check();
}

#[test]
fn drain_reached_waiters_get_count_others_destroyed() {
    let mut h = host(3, 1, 0, 0);
    eventcount::wait(&mut h, t(1), ec(1), ALL, 1).unwrap();
    eventcount::wait(&mut h, t(2), ec(1), ALL, 5).unwrap();
    eventcount::advance_irq(&mut h, ec(1)).unwrap();
    assert!(h.ecs[1].pending);
    assert_eq!(h.destroy_ec(1), 2, "one waiter per step");
    assert_eq!(
        (h.threads[1].result, h.got[1]),
        (Res::Replied, Some(Value::Count(1)))
    );
    assert_eq!(h.threads[2].result, Res::Destroyed);
    assert!(h.work.is_empty(), "the finish took it off its list");
    h.check();
    // The memory is reused: a fresh eventcount at the same address.
    eventcount::wait(&mut h, t(3), ec(1), ALL, 1).unwrap();
    eventcount::advance_irq(&mut h, ec(1)).unwrap();
    h.run_work();
    assert_eq!(h.threads[3].state, TState::Ready);
    h.check();
}

#[test]
fn destroy_an_idle_eventcount_takes_one_step() {
    let mut h = host(1, 1, 0, 0);
    assert_eq!(h.destroy_ec(1), 1);
    h.check();
}

// ---------------------------------------------------------------------------
// Wait sets.

#[test]
fn wait_set_rights_and_range() {
    let mut h = host(1, 1, 1, 3);
    let read = Rights::READ;
    let write = Rights::WRITE;
    assert_eq!(
        eventcount::ws_add(&mut h, ws(1), read, 0, ec(1), ALL, 1),
        Err(Status::MissingRight)
    );
    assert_eq!(
        eventcount::ws_add(&mut h, ws(1), ALL, 0, ec(1), write, 1),
        Err(Status::MissingRight)
    );
    assert_eq!(
        eventcount::ws_add(&mut h, ws(1), ALL, 3, ec(1), ALL, 1),
        Err(Status::InvalidArgument)
    );
    assert_eq!(
        eventcount::ws_add(&mut h, ws(1), write, 0, ec(1), read, 1),
        Ok(())
    );
    assert_eq!(
        eventcount::ws_add(&mut h, ws(1), ALL, 0, ec(1), ALL, 1),
        Err(Status::Busy)
    );
    assert_eq!(
        eventcount::ws_remove_check(&h, ws(1), read, 0),
        Err(Status::MissingRight)
    );
    assert_eq!(
        eventcount::ws_remove_check(&h, ws(1), write, 3),
        Err(Status::InvalidArgument)
    );
    assert_eq!(
        eventcount::ws_wait(&mut h, t(1), ws(1), write),
        Err(Status::MissingRight)
    );
    assert_eq!(
        eventcount::ws_wait(&mut h, t(1), ws(1), read),
        Ok(Outcome::Blocked)
    );
    h.check();
}

#[test]
fn wait_returns_mask_of_reached() {
    let mut h = host(1, 2, 1, 3);
    eventcount::ws_add(&mut h, ws(1), ALL, 0, ec(1), ALL, 2).unwrap();
    eventcount::ws_add(&mut h, ws(1), ALL, 1, ec(2), ALL, 1).unwrap();
    eventcount::ws_add(&mut h, ws(1), ALL, 2, ec(1), ALL, 1).unwrap();
    eventcount::ws_wait(&mut h, t(1), ws(1), ALL).unwrap();
    advance(&mut h, 1).unwrap();
    assert_eq!(h.threads[1].state, TState::Ready);
    assert_eq!(h.got[1], Some(Value::Mask(0b100)));
    // The next wait returns at once: entry 2 is still reached.
    assert_eq!(
        eventcount::ws_wait(&mut h, t(1), ws(1), ALL),
        Ok(Outcome::Done)
    );
    assert_eq!(h.got[1], Some(Value::Mask(0b100)));
    h.check();
}

#[test]
fn empty_set_returns_empty_mask_and_one_wait_at_a_time() {
    let mut h = host(2, 1, 1, 1);
    assert_eq!(
        eventcount::ws_wait(&mut h, t(1), ws(1), ALL),
        Ok(Outcome::Done)
    );
    assert_eq!(h.got[1], Some(Value::Mask(0)));
    eventcount::ws_add(&mut h, ws(1), ALL, 0, ec(1), ALL, 1).unwrap();
    eventcount::ws_wait(&mut h, t(1), ws(1), ALL).unwrap();
    assert_eq!(
        eventcount::ws_wait(&mut h, t(2), ws(1), ALL),
        Err(Status::Busy)
    );
    h.check();
}

#[test]
fn remove_during_wait_continues_and_last_ends_empty_k08() {
    let mut h = host(1, 2, 1, 2);
    eventcount::ws_add(&mut h, ws(1), ALL, 0, ec(1), ALL, 1).unwrap();
    eventcount::ws_add(&mut h, ws(1), ALL, 1, ec(2), ALL, 1).unwrap();
    eventcount::ws_wait(&mut h, t(1), ws(1), ALL).unwrap();
    h.remove_entry(1, 0);
    assert_eq!(
        h.threads[1].state,
        TState::Other,
        "the wait goes on on entry 1"
    );
    advance(&mut h, 1).unwrap();
    assert_eq!(h.threads[1].state, TState::Other, "entry 0 is gone");
    h.check();
    h.remove_entry(1, 1);
    assert_eq!(h.threads[1].state, TState::Ready);
    assert_eq!(
        h.got[1],
        Some(Value::Mask(0)),
        "the last removal ends it empty"
    );
    h.check();
}

#[test]
fn add_during_wait_links_and_may_end() {
    let mut h = host(1, 2, 1, 2);
    eventcount::ws_add(&mut h, ws(1), ALL, 0, ec(1), ALL, 1).unwrap();
    eventcount::ws_wait(&mut h, t(1), ws(1), ALL).unwrap();
    eventcount::ws_add(&mut h, ws(1), ALL, 1, ec(2), ALL, 3).unwrap();
    assert_eq!(h.threads[1].state, TState::Other);
    assert_eq!(kipc::wait_cost(&h, t(1)), 2);
    h.check();
    advance(&mut h, 2).unwrap();
    // Reached at once when added.
    h.remove_entry(1, 1);
    eventcount::ws_add(&mut h, ws(1), ALL, 1, ec(2), ALL, 1).unwrap();
    assert_eq!(h.threads[1].state, TState::Ready);
    assert_eq!(h.got[1], Some(Value::Mask(0b10)));
    h.check();
}

#[test]
fn two_entries_on_one_eventcount() {
    let mut h = host(1, 1, 1, 2);
    eventcount::ws_add(&mut h, ws(1), ALL, 0, ec(1), ALL, 1).unwrap();
    eventcount::ws_add(&mut h, ws(1), ALL, 1, ec(1), ALL, 2).unwrap();
    eventcount::ws_wait(&mut h, t(1), ws(1), ALL).unwrap();
    advance(&mut h, 1).unwrap();
    assert_eq!(h.got[1], Some(Value::Mask(0b01)));
    h.check();
}

#[test]
fn cancel_and_deadline_unlink_every_entry() {
    let mut h = host(1, 2, 1, 2);
    eventcount::ws_add(&mut h, ws(1), ALL, 0, ec(1), ALL, 1).unwrap();
    eventcount::ws_add(&mut h, ws(1), ALL, 1, ec(2), ALL, 1).unwrap();
    eventcount::ws_wait(&mut h, t(1), ws(1), ALL).unwrap();
    donation::cancel(&mut h, t(1)).unwrap();
    assert_eq!(h.threads[1].result, Res::Canceled);
    assert_eq!(h.ecs[1].root, 0);
    assert_eq!(h.ecs[2].root, 0);
    eventcount::ws_wait(&mut h, t(1), ws(1), ALL).unwrap();
    donation::deadline(&mut h, t(1)).unwrap();
    assert_eq!(h.threads[1].result, Res::TimedOut);
    assert!(h.wss[1].waiter.is_none());
    h.check();
}

#[test]
fn zombify_ends_wait_destroyed() {
    let mut h = host(1, 1, 1, 3);
    for i in 0..3 {
        eventcount::ws_add(&mut h, ws(1), ALL, i, ec(1), ALL, 1).unwrap();
    }
    eventcount::ws_wait(&mut h, t(1), ws(1), ALL).unwrap();
    assert_eq!(h.destroy_set(1), 4, "one unit, and one per node unlinked");
    assert_eq!(h.threads[1].result, Res::Destroyed);
    assert_eq!(h.ecs[1].root, 0);
    h.check();
}

// ---------------------------------------------------------------------------
// Bound eventcounts.

/// Thread 1 bound to eventcount 1.
fn bound() -> Host {
    let mut h = host(2, 1, 0, 0);
    assert_eq!(
        eventcount::bind(&mut h, t(1), ec(1), Rights::WRITE),
        Err(Status::MissingRight)
    );
    eventcount::bind(&mut h, t(1), ec(1), ALL).unwrap();
    assert_eq!(
        eventcount::bind(&mut h, t(1), ec(1), ALL),
        Err(Status::Busy)
    );
    h
}

#[test]
fn advance_reported_before_queued_message() {
    let mut h = bound();
    endpoint::send(&mut h, t(2), cap(1), 0, true).unwrap();
    advance(&mut h, 1).unwrap();
    assert_eq!(
        endpoint::recv(&mut h, t(1), cap(1), r(1)),
        Ok(Outcome::Done)
    );
    assert_eq!(h.got[1], Some(Value::Advance(1)));
    assert_eq!(h.tecs[1].last, 1);
    assert_eq!(h.queue(1), vec![2], "the message stays queued");
    assert_eq!(
        endpoint::recv(&mut h, t(1), cap(1), r(1)),
        Ok(Outcome::Done)
    );
    assert_eq!(h.received(1).len(), 1);
    h.check();
}

#[test]
fn blocked_receive_woken_by_advance_sets_last_seen() {
    let mut h = bound();
    endpoint::recv(&mut h, t(1), cap(1), r(1)).unwrap();
    advance(&mut h, 1).unwrap();
    assert_eq!(h.threads[1].state, TState::Ready);
    assert_eq!(h.got[1], Some(Value::Advance(1)));
    assert_eq!(h.tecs[1].last, 1);
    assert!(h.queue(1).is_empty(), "it left the endpoint's queue");
    // No advance is missed between receives.
    advance(&mut h, 1).unwrap();
    endpoint::recv(&mut h, t(1), cap(1), r(1)).unwrap();
    assert_eq!(h.got[1], Some(Value::Advance(2)));
    // A direct read or wait doesn't move last-seen.
    advance(&mut h, 1).unwrap();
    eventcount::wait(&mut h, t(1), ec(1), ALL, 3).unwrap();
    assert_eq!(h.tecs[1].last, 2);
    h.check();
}

#[test]
fn unbind_during_receive_keeps_endpoint_wait() {
    let mut h = bound();
    endpoint::recv(&mut h, t(1), cap(1), r(1)).unwrap();
    eventcount::unbind(&mut h, t(1));
    advance(&mut h, 1).unwrap();
    assert!(matches!(h.threads[1].state, TState::Recv(_)));
    endpoint::send(&mut h, t(2), cap(1), 0, true).unwrap();
    assert_eq!(h.threads[1].state, TState::Ready);
    h.check();
}

#[test]
fn reply_recv_reports_advance_for_an_active_server() {
    let mut h = bound();
    endpoint::recv(&mut h, t(1), cap(1), r(1)).unwrap();
    endpoint::call(&mut h, t(2), cap(1), 0).unwrap();
    advance(&mut h, 1).unwrap();
    assert_eq!(
        endpoint::reply_recv(&mut h, t(1), cap(1), r(1), 0, false),
        Ok(Outcome::Done)
    );
    assert_eq!(h.threads[2].result, Res::Replied);
    assert_eq!(h.got[1], Some(Value::Advance(1)));
    h.check();
}

#[test]
fn passive_server_is_not_woken_and_hears_with_a_context() {
    let mut h = host(3, 1, 0, 0);
    eventcount::bind(&mut h, t(1), ec(1), ALL).unwrap();
    endpoint::recv(&mut h, t(1), cap(1), r(1)).unwrap();
    donation::unbind_sc(&mut h, c(1)).unwrap();
    // A passive server keeps serving calls on its callers' contexts.
    endpoint::call(&mut h, t(2), cap(1), 0).unwrap();
    assert_eq!(h.threads[1].sc, Some(c(2)));
    advance(&mut h, 1).unwrap();
    // Its reply and receive returns the donated context: it receives
    // without one, so it neither hears the advance nor links.
    endpoint::reply_recv(&mut h, t(1), cap(1), r(1), 0, false).unwrap();
    assert!(matches!(h.threads[1].state, TState::Recv(_)));
    assert!(!eventcount::is_linked(&h, 1));
    advance(&mut h, 1).unwrap();
    assert!(
        matches!(h.threads[1].state, TState::Recv(_)),
        "never woken without a context"
    );
    assert_eq!(h.tecs[1].last, 0);
    h.check();
    // Given a home context, it hears the advances at once.
    donation::bind_sc(&mut h, c(1), t(1)).unwrap();
    eventcount::context_bound(&mut h, t(1));
    assert_eq!(h.threads[1].state, TState::Ready);
    assert_eq!(h.got[1], Some(Value::Advance(2)));
    h.check();
}

#[test]
fn context_lost_mid_receive_unlinks_only() {
    let mut h = bound();
    endpoint::recv(&mut h, t(1), cap(1), r(1)).unwrap();
    donation::unbind_sc(&mut h, c(1)).unwrap();
    assert!(eventcount::is_linked(&h, 1), "the node stays until a wake");
    advance(&mut h, 1).unwrap();
    assert!(matches!(h.threads[1].state, TState::Recv(_)));
    assert!(!eventcount::is_linked(&h, 1));
    assert_eq!(h.tecs[1].last, 0);
    h.check();
    // A context bound while it receives, with nothing new: it links.
    let mut h = bound();
    endpoint::recv(&mut h, t(1), cap(1), r(1)).unwrap();
    donation::unbind_sc(&mut h, c(1)).unwrap();
    donation::bind_sc(&mut h, c(1), t(1)).unwrap();
    eventcount::context_bound(&mut h, t(1));
    assert!(eventcount::is_linked(&h, 1));
    h.check();
}

#[test]
fn bound_at_maximum_never_reports() {
    let mut h = host(1, 1, 0, 0);
    h.ecs[1].count = u64::MAX;
    eventcount::bind(&mut h, t(1), ec(1), ALL).unwrap();
    assert_eq!(
        endpoint::recv(&mut h, t(1), cap(1), r(1)),
        Ok(Outcome::Blocked)
    );
    assert!(!eventcount::is_linked(&h, 1), "no advance can come");
    assert_eq!(advance(&mut h, 1), Err(Status::CountAtMaximum));
    assert!(matches!(h.threads[1].state, TState::Recv(_)));
    h.check();
}

#[test]
fn bind_while_receiving_links() {
    let mut h = host(1, 1, 0, 0);
    endpoint::recv(&mut h, t(1), cap(1), r(1)).unwrap();
    eventcount::bind(&mut h, t(1), ec(1), ALL).unwrap();
    assert!(eventcount::is_linked(&h, 1));
    advance(&mut h, 1).unwrap();
    assert_eq!(h.got[1], Some(Value::Advance(1)));
    let _ = ep(1);
    h.check();
}
