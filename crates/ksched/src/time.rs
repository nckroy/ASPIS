// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Microseconds and counts of the virtual timer (kernel specification, "The
//! timer and deadlines").
//!
//! Budgets and periods are configured in microseconds (ADR 0051, rule 1)
//! and enforced in counts of `CNTVCT_EL0`, whose frequency is `CNTFRQ_EL0`.
//! Every conversion is in u128, so none overflows, and each rounds in the
//! direction that keeps the guarantee: a budget rounds down and a period
//! rounds up, so the enforced bandwidth never exceeds the configured one.
//! A result past `u64::MAX` saturates: the count never gets there.

/// The shortest budget a context may be configured with, in microseconds.
/// seL4 takes twice its worst-case kernel execution time; this is a fixed,
/// round bound well above the kernel's entry cost on every target.
pub const MIN_BUDGET_US: u64 = 10;
/// The longest period, in microseconds: one hour.
pub const MAX_PERIOD_US: u64 = 3_600_000_000;
/// While a core has batch work left, its compare value is at most this far
/// ahead, so a thread that never enters the kernel can't hold the work off
/// (K24).
pub const BATCH_GAP_US: u64 = 100;
/// The compare value that never fires: the timer's "disarmed" value.
pub const NEVER: u64 = u64::MAX;

const MICROS: u128 = 1_000_000;

/// The virtual counter's frequency, from `CNTFRQ_EL0`. Never 0: the kernel
/// stops the boot without it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {
    freq: u64,
}

fn saturate(v: u128) -> u64 {
    u64::try_from(v).unwrap_or(u64::MAX)
}

impl Clock {
    /// A clock of `freq` Hz, or None for 0.
    pub const fn new(freq: u64) -> Option<Clock> {
        if freq == 0 {
            None
        } else {
            Some(Clock { freq })
        }
    }

    pub const fn freq(self) -> u64 {
        self.freq
    }

    /// `us` microseconds in counts, rounded down.
    pub fn counts_floor(self, us: u64) -> u64 {
        saturate(us as u128 * self.freq as u128 / MICROS)
    }

    /// `us` microseconds in counts, rounded up.
    pub fn counts_ceil(self, us: u64) -> u64 {
        saturate((us as u128 * self.freq as u128).div_ceil(MICROS))
    }

    /// `counts` in microseconds, rounded down: for reports.
    pub fn us_floor(self, counts: u64) -> u64 {
        saturate(counts as u128 * MICROS / self.freq as u128)
    }

    /// `counts` in microseconds, rounded up.
    pub fn us_ceil(self, counts: u64) -> u64 {
        saturate((counts as u128 * MICROS).div_ceil(self.freq as u128))
    }

    /// A configured budget in counts: rounded down, and at least one count,
    /// so a context always makes progress.
    pub fn budget(self, us: u64) -> u64 {
        self.counts_floor(us).max(1)
    }

    /// A configured period in counts: rounded up, and never shorter than
    /// the budget.
    pub fn period(self, us: u64, budget: u64) -> u64 {
        self.counts_ceil(us).max(budget)
    }
}

/// Why a budget and period can't be configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalid {
    /// The budget is below [`MIN_BUDGET_US`].
    BudgetTooShort,
    /// The budget is longer than the period.
    BudgetPastPeriod,
    /// The period is longer than [`MAX_PERIOD_US`].
    PeriodTooLong,
}

/// Checks a configuration's limits: `MIN_BUDGET_US ≤ budget ≤ period ≤
/// MAX_PERIOD_US`. A budget equal to its period is round-robin.
pub fn check_limits(budget_us: u64, period_us: u64) -> Result<(), Invalid> {
    if budget_us < MIN_BUDGET_US {
        Err(Invalid::BudgetTooShort)
    } else if budget_us > period_us {
        Err(Invalid::BudgetPastPeriod)
    } else if period_us > MAX_PERIOD_US {
        Err(Invalid::PeriodTooLong)
    } else {
        Ok(())
    }
}

/// What a core's next compare value depends on (kernel specification,
/// "The timer and deadlines": tickless, as in seL4 MCS).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Wakeups {
    /// The running context's budget end: its dispatch time plus the head
    /// refill's amount. None while the core is idle.
    pub budget_end: Option<u64>,
    /// The release tree's earliest refill.
    pub release: Option<u64>,
    /// The deadline tree's earliest deadline.
    pub deadline: Option<u64>,
    /// Whether the core has interrupt work left (K24).
    pub batch_pending: bool,
}

/// The compare value for `w` at count `now`: the earliest of its times, or
/// [`NEVER`]. A time already passed is returned as is, and fires at once.
pub fn compare_value(clock: Clock, now: u64, w: Wakeups) -> u64 {
    let gap = if w.batch_pending {
        Some(now.saturating_add(clock.counts_ceil(BATCH_GAP_US)))
    } else {
        None
    };
    [w.budget_end, w.release, w.deadline, gap]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(NEVER)
}
