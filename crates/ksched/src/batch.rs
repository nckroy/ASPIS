// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Bounded batches of interrupt work (ADR 0052, rule 2; kernel
//! specification, "The kernel lock and long operations"; K24).
//!
//! Some work has no calling thread to restart: refills that come due at a
//! tick, the waits whose deadlines passed, and the walks of take-backs. A
//! core runs it in batches of at most [`crate::BATCH_UNITS`] units, one at
//! each exit from the kernel, after the end of interrupt. A batch has no
//! preemption check inside it: its size is the bound.
//!
//! **Fairness.** One source with endless work must not starve the others:
//! many short-period contexts could bring refills due at every batch, and a
//! deadline's take-back must still come within the bounded batches (ADR
//! 0051, rule 3). So a batch takes one unit at a time from the sources that
//! have work, in turn, starting from a source that moves on by one each
//! batch. With three sources, each source that has work gets at least 33
//! units of every batch.

/// The most sources a batch draws from.
pub const MAX_SOURCES: usize = 4;

/// The work a batch draws from. Source `i` is in `0..count()`.
pub trait Sources {
    fn count(&self) -> usize;
    /// Whether source `i` has a unit ready now.
    fn has_work(&mut self, i: usize) -> bool;
    /// Runs one unit of source `i`, which has work.
    fn unit(&mut self, i: usize);
}

/// What one batch did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ran {
    pub units: u32,
    pub per_source: [u32; MAX_SOURCES],
    /// Whether work was left when the batch ended.
    pub more: bool,
}

/// A core's batch state: the source the next batch starts from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Batcher {
    start: usize,
}

impl Batcher {
    pub const fn new() -> Batcher {
        Batcher { start: 0 }
    }

    /// Runs one batch of at most `units` units.
    pub fn run<S: Sources>(&mut self, s: &mut S, units: u32) -> Ran {
        let n = s.count().min(MAX_SOURCES);
        let mut ran = Ran::default();
        if n == 0 {
            return ran;
        }
        let mut i = self.start % n;
        let mut idle = 0;
        while ran.units < units && idle < n {
            if s.has_work(i) {
                s.unit(i);
                ran.units += 1;
                ran.per_source[i] += 1;
                idle = 0;
            } else {
                idle += 1;
            }
            i = (i + 1) % n;
        }
        self.start = (self.start + 1) % n;
        ran.more = (0..n).any(|i| s.has_work(i));
        ran
    }
}
