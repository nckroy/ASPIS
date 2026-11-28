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
//! batch. With three sources whose units each cost one, each source that
//! has work gets at least 33 units of every batch.
//!
//! **Costs** (C14). A unit costs as many units of work as waiter nodes it
//! links or unlinks, so waking a wait-set waiter costs as many as the nodes
//! it unlinks, up to [`MAX_UNIT_COST`] (kernel specification K24). The rest
//! of a unit's tree work, such as an endpoint queue or a deadline, is a
//! small constant, counted in its base unit. A
//! batch runs a unit only if its cost fits in what is left of the batch, so
//! a batch never passes its units. A unit that doesn't fit leaves its source
//! idle for the rest of the batch. The batch's first source always fits,
//! since a batch holds more than any unit costs, and the first source moves
//! on each batch; so every source with work progresses at least once in
//! every [`MAX_SOURCES`] batches, whatever the others' costs, and in every
//! batch while the units ahead of it leave room.

/// The most sources a batch draws from.
pub const MAX_SOURCES: usize = 4;

/// The most units one unit of work may cost: a deadline on a donated call
/// costs 1 for the call, plus 60 when its context's holder waits on a wait
/// set of 60 entries, whose wait unlinks 60 nodes. A wake of a wait-set
/// waiter costs the 60 alone, and a walk's step at most 2, itself and the
/// onward call it ends (C14; K24).
pub const MAX_UNIT_COST: u32 = 61;

// A batch's first unit always fits, so no source waits for ever.
const _: () = assert!(crate::BATCH_UNITS >= MAX_UNIT_COST);

/// The work a batch draws from. Source `i` is in `0..count()`.
pub trait Sources {
    fn count(&self) -> usize;
    /// Whether source `i` has a unit ready now.
    fn has_work(&mut self, i: usize) -> bool;
    /// The units source `i`'s next unit costs, at most [`MAX_UNIT_COST`];
    /// called only when it has work. Nothing changes under the kernel lock
    /// between this and the unit, so the cost is the unit's, or more.
    fn cost(&mut self, _i: usize) -> u32 {
        1
    }
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

    /// Runs one batch of at most `units` units: each source's units in
    /// turn, each only if its cost fits in what is left (module docs).
    /// `per_source` counts the units of work each did.
    pub fn run<S: Sources>(&mut self, s: &mut S, units: u32) -> Ran {
        let n = s.count().min(MAX_SOURCES);
        let mut ran = Ran::default();
        if n == 0 {
            return ran;
        }
        let mut i = self.start % n;
        let mut idle = 0;
        // Sources whose next unit didn't fit: idle for the rest.
        let mut full = [false; MAX_SOURCES];
        while ran.units < units && idle < n {
            let cost = if !full[i] && s.has_work(i) {
                s.cost(i).max(1)
            } else {
                0
            };
            if cost > 0 && cost <= units - ran.units {
                s.unit(i);
                ran.units += cost;
                ran.per_source[i] += cost;
                idle = 0;
            } else {
                full[i] |= cost > 0;
                idle += 1;
            }
            i = (i + 1) % n;
        }

        self.start = (self.start + 1) % n;
        ran.more = (0..n).any(|i| s.has_work(i));
        ran
    }
}
