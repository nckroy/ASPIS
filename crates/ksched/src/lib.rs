// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The kernel's scheduling, donation and SMP logic (ADRs 0051 and 0052),
//! kept apart from the kernel so that it can be tested on the host.
//!
//! The mechanism is in `docs/design/kernel-specification.md`, sections
//! "Scheduling contexts and budgets", "Priorities and bands", "Passive
//! servers and taking a context back", "The timer and deadlines", "The
//! kernel lock and long operations", "Ordered kernel queues", "Cross-core
//! signals and TLB maintenance" and "Model checking". It follows seL4 17.0.0
//! with MCS (ADR 0047, rules 1 and 2): its design, not its code. No seL4
//! source is copied.
//!
//! Nothing here touches hardware. Every structure is intrusive: the kernel
//! keeps the links in its own objects and reaches them through a store
//! trait, so the kernel needs no memory beyond its objects (ADR 0048,
//! rule 1). The crate is `no_std`, has no `unsafe`, allocates nothing, and
//! never panics on its input.
//!
//! - [`time`]: microseconds and counts of the virtual timer, and the compare
//!   value (ADR 0051, rules 1 and 5).
//! - [`refill`]: the sporadic server's refills (ADR 0051, rule 1).
//! - [`share`]: the share check against a job's share of a core (ADR 0058,
//!   rule 8; K13).
//! - [`prio`]: priorities and maximum controlled priorities (ADR 0051,
//!   rule 2).
//! - [`runq`]: each core's run queues: a list for each priority and a
//!   bitmap.
//! - [`tree`]: an intrusive red-black tree, optionally augmented, for the
//!   release, deadline and walk queues (ADR 0052, rule 2; K25).
//! - [`worklist`]: a core's list of pending interrupt work (K24).
//! - [`batch`]: bounded batches of interrupt work over several sources
//!   (ADR 0052, rule 2; K24).
//! - [`donation`]: scheduling-context donation along chains of calls, and
//!   taking a context back (ADR 0051, rule 3), the protocol that
//!   `specs/SchedDonation.tla` models (ADR 0068, rule 10).
//! - [`smp`]: the kernel's CLH lock, remote-call state and PSCI (ADR 0052).

#![no_std]
#![forbid(unsafe_code)]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreachable
)]

pub mod batch;
pub mod donation;
pub mod prio;
pub mod refill;
pub mod runq;
pub mod share;
pub mod smp;
pub mod time;
pub mod tree;
pub mod worklist;

/// No object: the null reference of every intrusive link here. Every object
/// the kernel links is made from RAM, so its physical address is never 0.
pub const NIL: u64 = 0;

/// Units of work in one batch of interrupt work: the same 100 that
/// separate preemption checks (K22, K24).
pub const BATCH_UNITS: u32 = 100;
