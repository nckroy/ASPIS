// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Units of work and preemption points (ADR 0052, rule 2; kernel
//! specification, "The kernel lock and long operations", K22 and K23).
//!
//! A long operation counts its work in units: one step of a deletion, one
//! unlink, one copy, or 4 KiB of memory cleared. A deletion step that ends
//! waits counts more: the waiter nodes its hooks unlink (C14,
//! [`crate::delete::Hooks`]). Every [`UNITS_PER_CHECK`]
//! units it asks whether an interrupt is pending, as seL4's
//! `preemptionPoint` does. If one is, the operation stops with
//! [`Preempted`], having recorded its progress in the objects it works on:
//! a deletion in the derivation tree and its zombies, a reset in the
//! untyped capability's watermark. The caller restarts the whole operation,
//! which resumes from that record. Work always comes before the check, so
//! every call makes progress.
//!
//! Since C13a the kernel's check is `ISR_EL1.I` (`kernel/src/irq`,
//! `IrqPending`), and [`Never`] is a check that never finds one. C12
//! restarts the system call.
//!
//! [`UNITS_PER_CHECK`]: crate::UNITS_PER_CHECK

/// The operation stopped at a preemption point. Its progress is recorded;
/// call it again to go on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preempted;

/// Says whether an interrupt is waiting.
pub trait Pending {
    fn pending(&mut self) -> bool;
}

/// Nothing is ever pending.
#[derive(Clone, Copy, Debug, Default)]
pub struct Never;

impl Pending for Never {
    fn pending(&mut self) -> bool {
        false
    }
}

/// Something is always pending: every check preempts. For tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct Always;

impl Pending for Always {
    fn pending(&mut self) -> bool {
        true
    }
}

/// Counts units of work, and checks for a pending interrupt every
/// `threshold` units.
#[derive(Clone, Copy, Debug)]
pub struct Budget<P> {
    pending: P,
    used: u32,
    threshold: u32,
}

impl<P: Pending> Budget<P> {
    /// A budget that checks every [`crate::UNITS_PER_CHECK`] units.
    pub const fn new(pending: P) -> Self {
        Self::with_threshold(pending, crate::UNITS_PER_CHECK)
    }

    /// A budget that checks every `threshold` units, at least 1.
    pub const fn with_threshold(pending: P, threshold: u32) -> Self {
        Self {
            pending,
            used: 0,
            threshold: if threshold == 0 { 1 } else { threshold },
        }
    }

    /// Counts `units` of work just done, and checks for a pending interrupt
    /// once enough have been done since the last check.
    pub fn tick(&mut self, units: u32) -> Result<(), Preempted> {
        self.used = self.used.saturating_add(units);
        if self.used >= self.threshold {
            self.used = 0;
            if self.pending.pending() {
                return Err(Preempted);
            }
        }
        Ok(())
    }

    /// The pending-interrupt source.
    pub fn pending_mut(&mut self) -> &mut P {
        &mut self.pending
    }
}
