// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The share check (ADR 0058, rule 8; kernel specification, "Scheduling
//! contexts and budgets"; K13).
//!
//! A job's share of a core is a budget and a period, in microseconds, as
//! ADR 0058, rule 8 sets it ([`Share`]). The kernel refuses to configure a
//! context that would take the job's contexts on that core past the share.
//! The check is exact: each (job, core) keeps the sum of budget / period
//! over its contexts as a reduced fraction, and a configuration is admitted
//! iff the new sum, cross multiplied with the share's budget and period, is
//! at most the share. So three contexts of 1 ms in 3 ms fit a whole core, a
//! context of exactly the share fits it, and a context never fits past it.
//!
//! - Every number fits in u128. Budgets and periods, the share's too, are
//!   below 2^32 µs (an hour is 3.6 × 10^9), and a sum's reduced denominator
//!   is kept at most 2^95, so every product below stays under 2^128.
//! - A configuration whose sum would need a larger denominator is refused as
//!   [`Refused::TooFine`]. That takes three or more pairwise coprime periods
//!   near an hour, which no real manifest has. Refusing is always safe for
//!   ADR 0058, rule 8.
//! - Releasing a context subtracts it exactly. In the same rare case, where
//!   the difference's denominator would pass 2^95, the sum is kept as it is:
//!   larger than exact, so still safe. When the (job, core)'s last context
//!   is released, the sum returns to zero, exactly.
//! - A round-robin context, whose budget equals its period, counts a whole
//!   core, so it needs a whole core's share (ADR 0051, rule 1 with ADR 0058,
//!   rule 8).
//!
//! Until C16 makes jobs, every context belongs to the root job, whose share
//! is the whole of each core ([`Share::WHOLE`]). C16 keeps a [`Used`] per
//! job and core, with shares carved from the parent's.

/// A job's share of one core: `budget_us` in every `period_us` (ADR 0058,
/// rule 8). A budget past the period counts as the whole core; a period of
/// 0 is no share at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Share {
    pub budget_us: u64,
    pub period_us: u64,
}

impl Share {
    /// A whole core: the root job's share of each core until C16.
    pub const WHOLE: Share = Share {
        budget_us: 1,
        period_us: 1,
    };

    pub const fn new(budget_us: u64, period_us: u64) -> Share {
        Share {
            budget_us,
            period_us,
        }
    }
}
/// The largest reduced denominator a sum may have.
pub const MAX_DEN: u128 = 1 << 95;

/// Why a configuration is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// It would take the job's contexts on the core past its share.
    PastShare,
    /// Its sum needs a denominator past [`MAX_DEN`] (module docs).
    TooFine,
}

/// The bandwidth a job's contexts use on one core: `num / den`, reduced,
/// and how many contexts count in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Used {
    num: u128,
    den: u128,
    count: u32,
}

impl Default for Used {
    fn default() -> Self {
        Used::EMPTY
    }
}

/// The greatest common divisor, by Stein's algorithm. `gcd(0, b) = b`.
pub fn gcd(mut a: u128, mut b: u128) -> u128 {
    if a == 0 {
        return b;
    }
    if b == 0 {
        return a;
    }
    let shift = (a | b).trailing_zeros();
    a >>= a.trailing_zeros();
    loop {
        b >>= b.trailing_zeros();
        if a > b {
            core::mem::swap(&mut a, &mut b);
        }
        b -= a;
        if b == 0 {
            return a << shift;
        }
    }
}

impl Used {
    /// No contexts.
    pub const EMPTY: Used = Used {
        num: 0,
        den: 1,
        count: 0,
    };

    /// The sum, as (numerator, denominator), reduced.
    pub const fn fraction(self) -> (u128, u128) {
        (self.num, self.den)
    }

    /// How many contexts count in it.
    pub const fn count(self) -> u32 {
        self.count
    }

    /// Whether the sum is at most the share: `num / den ≤ budget / period`.
    pub fn within(self, share: Share) -> bool {
        if share.period_us == 0 {
            return self.num == 0;
        }
        let (b, p) = (
            share.budget_us.min(share.period_us) as u128,
            share.period_us as u128,
        );
        // den ≤ 2^95 and the share's numbers are below 2^32, so the right
        // side fits; the left overflows only for a sum past two cores,
        // which is past any share. Checked anyway.
        match (self.num.checked_mul(p), b.checked_mul(self.den)) {
            (Some(l), Some(r)) => l <= r,
            _ => false,
        }
    }

    /// `self + sign · b / p`, reduced, or None if it needs a denominator
    /// past [`MAX_DEN`] or would be negative.
    fn combine(self, b: u64, p: u64, add: bool) -> Option<(u128, u128)> {
        if p == 0 {
            return None;
        }
        let (b, p) = (b as u128, p as u128);
        let l = (self.den / gcd(self.den, p)).checked_mul(p)?;
        let a = self.num.checked_mul(l / self.den)?;
        let c = b.checked_mul(l / p)?;
        let n = if add {
            a.checked_add(c)?
        } else {
            a.checked_sub(c)?
        };
        let g = gcd(n, l);
        let (n, d) = if n == 0 { (0, 1) } else { (n / g, l / g) };
        if d > MAX_DEN { None } else { Some((n, d)) }
    }

    /// The sum with a context of `budget_us` in `period_us` added, if it
    /// stays within `share`.
    pub fn admit(self, share: Share, budget_us: u64, period_us: u64) -> Result<Used, Refused> {
        let (num, den) = self
            .combine(budget_us, period_us, true)
            .ok_or(Refused::TooFine)?;
        let next = Used {
            num,
            den,
            count: self.count.saturating_add(1),
        };
        if next.within(share) {
            Ok(next)
        } else {
            Err(Refused::PastShare)
        }
    }

    /// The sum with a context of `budget_us` in `period_us`, admitted
    /// earlier, taken out. Never fails (module docs).
    pub fn release(self, budget_us: u64, period_us: u64) -> Used {
        let count = self.count.saturating_sub(1);
        if count == 0 {
            return Used::EMPTY;
        }
        match self.combine(budget_us, period_us, false) {
            Some((num, den)) => Used { num, den, count },
            // Too fine to subtract exactly, or a release of something never
            // admitted: keep the larger sum.
            None => Used { count, ..self },
        }
    }

    /// Reconfiguring a context: its old budget and period released, its new
    /// ones admitted. On a refusal the caller keeps `self`.
    pub fn reconfigure(
        self,
        share: Share,
        old: (u64, u64),
        new: (u64, u64),
    ) -> Result<Used, Refused> {
        self.release(old.0, old.1).admit(share, new.0, new.1)
    }
}
