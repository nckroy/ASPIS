// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The run queues serve the highest priority first, first in, first out
//! within a priority, against a model.

mod common;

use common::Lcg;
use ksched::prio;
use ksched::runq::{QLinks, QueueStore, RunQueues};
use std::collections::VecDeque;

struct Links(Vec<QLinks>);

impl QueueStore for Links {
    fn qlinks(&self, t: u64) -> QLinks {
        self.0[t as usize]
    }
    fn set_qlinks(&mut self, t: u64, l: QLinks) {
        self.0[t as usize] = l;
    }
}

#[test]
fn highest_first_and_fifo() {
    let mut s = Links(vec![QLinks::default(); 8]);
    let mut q = RunQueues::new();
    assert!(q.is_empty());
    q.push_back(&mut s, 10, 1);
    q.push_back(&mut s, 200, 2);
    q.push_back(&mut s, 200, 3);
    q.push_back(&mut s, 0, 4);
    q.push_back(&mut s, 255, 5);
    assert_eq!(q.next_to_run(), Some((255, 5)));
    q.remove(&mut s, 255, 5);
    assert_eq!(q.next_to_run(), Some((200, 2)));
    q.push_front(&mut s, 200, 6);
    assert_eq!(q.next_to_run(), Some((200, 6)));
    q.remove(&mut s, 200, 2); // from the middle
    q.remove(&mut s, 200, 6);
    assert_eq!(q.next_to_run(), Some((200, 3)));
    q.remove(&mut s, 200, 3);
    assert_eq!(q.highest(), Some(10));
    q.remove(&mut s, 10, 1);
    q.remove(&mut s, 0, 4);
    assert!(q.is_empty());
    assert_eq!(q.highest(), None);
}

#[test]
fn random_against_a_model() {
    let n = 64usize;
    let mut rng = Lcg(11);
    for _ in 0..common::runs(50) {
        let mut s = Links(vec![QLinks::default(); n + 1]);
        let mut q = RunQueues::new();
        let mut model: Vec<VecDeque<u64>> = vec![VecDeque::new(); prio::LEVELS];
        let mut at: Vec<Option<u8>> = vec![None; n + 1];
        for _ in 0..2000 {
            let t = rng.below(n as u64) + 1;
            match at[t as usize] {
                Some(p) => {
                    q.remove(&mut s, p, t);
                    model[p as usize].retain(|&x| x != t);
                    at[t as usize] = None;
                }
                None => {
                    // Cluster priorities so lists get long.
                    let p = [0u8, 63, 64, 127, 128, 200, 255][rng.below(7) as usize];
                    if rng.chance(30) {
                        q.push_front(&mut s, p, t);
                        model[p as usize].push_front(t);
                    } else {
                        q.push_back(&mut s, p, t);
                        model[p as usize].push_back(t);
                    }
                    at[t as usize] = Some(p);
                }
            }
            let want = (0..prio::LEVELS)
                .rev()
                .find(|&p| !model[p].is_empty())
                .map(|p| (p as u8, model[p][0]));
            assert_eq!(q.next_to_run(), want);
        }
    }
}

#[test]
fn mcp_bounds_priorities() {
    assert!(prio::may_set(255, 255));
    assert!(prio::may_set(100, 100));
    assert!(!prio::may_set(100, 101));
    assert!(prio::may_set(0, 0));
    assert!(!prio::may_set(0, 1));
}
