// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! SMP: the kernel lock, remote calls and PSCI (ADR 0052; kernel
//! specification, "SMP").
//!
//! - [`clh`]: the kernel's one lock, a CLH queue lock, so cores take it in
//!   the order they ask (ADR 0052, rule 2).
//! - [`remote`]: requests from the lock holder to other cores, served while
//!   they spin, and the panic stop's flag (ADR 0052, rule 4).
//! - [`psci`]: finding PSCI in the device tree, its function IDs and its
//!   return codes (ADR 0052, rule 1; K21).

pub mod clh;
pub mod psci;
pub mod remote;

/// The most cores the kernel runs on: kirq's bound, which C12 adopts
/// (kernel specification, "Starting secondary cores").
pub const MAX_CORES: usize = 8;
