// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Shared test support: a seeded generator, and a donation store in vectors
//! with the projection onto the TLA+ spec's state.

#![allow(dead_code)]

pub mod actions;
pub mod store;

/// A small seeded generator (Knuth's MMIX constants), so failures repeat.
pub struct Lcg(pub u64);

impl Lcg {
    pub fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    /// A number below `n`, which must not be 0.
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    pub fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

/// The number of seeded runs: the per-change count, times
/// `KSCHED_RUNS_SCALE` if it is set, as the nightly workflow sets it. Each
/// test's count scales alike, so their ratios stay.
pub fn runs(per_change: u64) -> u64 {
    let scale = std::env::var("KSCHED_RUNS_SCALE")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1)
        .max(1);
    per_change.saturating_mul(scale)
}
