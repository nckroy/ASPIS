// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! A core's run queues (kernel specification, "Ordered kernel queues"), as
//! seL4 builds them: a list for each of the 256 priorities, and a two-level
//! bitmap of the priorities whose lists aren't empty. Every operation takes
//! constant time.
//!
//! The lists are intrusive, doubly linked through the threads, so a thread
//! leaves its queue in constant time from anywhere in it. Threads of one
//! priority are served first in, first out (ADR 0051, rule 2: threads of
//! equal priority take turns).

use crate::NIL;
use crate::prio::LEVELS;

/// A thread's run-queue links.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QLinks {
    pub next: u64,
    pub prev: u64,
}

/// The memory that holds the threads' links.
pub trait QueueStore {
    fn qlinks(&self, t: u64) -> QLinks;
    fn set_qlinks(&mut self, t: u64, l: QLinks);
}

/// One core's run queues: about 4.1 KiB, in the core's per-core data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunQueues {
    head: [u64; LEVELS],
    tail: [u64; LEVELS],
    /// Bit i: some priority in 64·i to 64·i + 63 is non-empty.
    top: u64,
    /// Bit j of word i: priority 64·i + j is non-empty.
    words: [u64; LEVELS / 64],
}

impl Default for RunQueues {
    fn default() -> Self {
        RunQueues::new()
    }
}

impl RunQueues {
    pub const fn new() -> RunQueues {
        RunQueues {
            head: [NIL; LEVELS],
            tail: [NIL; LEVELS],
            top: 0,
            words: [0; LEVELS / 64],
        }
    }

    fn mark(&mut self, p: u8) {
        let (i, j) = (p as usize / 64, p as usize % 64);
        self.words[i] |= 1 << j;
        self.top |= 1 << i;
    }

    fn unmark(&mut self, p: u8) {
        let (i, j) = (p as usize / 64, p as usize % 64);
        self.words[i] &= !(1 << j);
        if self.words[i] == 0 {
            self.top &= !(1 << i);
        }
    }

    /// The highest priority with a runnable thread.
    pub fn highest(&self) -> Option<u8> {
        if self.top == 0 {
            return None;
        }
        let i = 63 - self.top.leading_zeros() as usize;
        let j = 63 - self.words[i].leading_zeros() as usize;
        Some((i * 64 + j) as u8)
    }

    /// The first thread of priority `p`, or [`NIL`].
    pub fn front(&self, p: u8) -> u64 {
        self.head[p as usize]
    }

    /// The thread that runs next: the first of the highest priority.
    pub fn next_to_run(&self) -> Option<(u8, u64)> {
        self.highest().map(|p| (p, self.head[p as usize]))
    }

    pub fn is_empty(&self) -> bool {
        self.top == 0
    }

    /// Queues `t` at the back of priority `p`.
    pub fn push_back<S: QueueStore>(&mut self, s: &mut S, p: u8, t: u64) {
        let tail = self.tail[p as usize];
        s.set_qlinks(
            t,
            QLinks {
                next: NIL,
                prev: tail,
            },
        );
        if tail == NIL {
            self.head[p as usize] = t;
            self.mark(p);
        } else {
            let mut l = s.qlinks(tail);
            l.next = t;
            s.set_qlinks(tail, l);
        }
        self.tail[p as usize] = t;
    }

    /// Queues `t` at the front of priority `p`: a preempted thread keeps its
    /// turn, as in seL4.
    pub fn push_front<S: QueueStore>(&mut self, s: &mut S, p: u8, t: u64) {
        let head = self.head[p as usize];
        s.set_qlinks(
            t,
            QLinks {
                next: head,
                prev: NIL,
            },
        );
        if head == NIL {
            self.tail[p as usize] = t;
            self.mark(p);
        } else {
            let mut l = s.qlinks(head);
            l.prev = t;
            s.set_qlinks(head, l);
        }
        self.head[p as usize] = t;
    }

    /// Takes `t` out of priority `p`'s list, which must hold it.
    pub fn remove<S: QueueStore>(&mut self, s: &mut S, p: u8, t: u64) {
        let l = s.qlinks(t);
        if l.prev == NIL {
            self.head[p as usize] = l.next;
        } else {
            let mut pl = s.qlinks(l.prev);
            pl.next = l.next;
            s.set_qlinks(l.prev, pl);
        }
        if l.next == NIL {
            self.tail[p as usize] = l.prev;
        } else {
            let mut nl = s.qlinks(l.next);
            nl.prev = l.prev;
            s.set_qlinks(l.next, nl);
        }
        s.set_qlinks(t, QLinks::default());
        if self.head[p as usize] == NIL {
            self.unmark(p);
        }
    }
}
