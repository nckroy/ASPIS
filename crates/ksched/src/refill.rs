// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! A scheduling context's refills (ADR 0051, rule 1; kernel specification,
//! "Scheduling contexts and budgets"; K15).
//!
//! As in seL4 MCS, a context that isn't round-robin is a sporadic server: a
//! list of refills, each an amount of budget and the count from which it
//! may be used. The amounts always sum to the budget. A thread runs on the
//! head refill once its time has come; budget it uses comes back one period
//! after the use began. So in any window of one period, a context's thread
//! uses at most its budget, however it blocks and wakes. This is written
//! fresh from seL4's design (Lyons and others, "Scheduling-context
//! capabilities", EuroSys 2018), not from its code.
//!
//! Every change below moves budget later, never earlier, except a refill
//! that merges into one that begins before it ends, which is used no sooner
//! than it would have been. That is what keeps the window property.
//!
//! - **Refills are kept in a ring** in the context, after its header: the
//!   head, the count and the configured maximum, at most the ring's
//!   capacity. A context's size, chosen when it is retyped, sets the
//!   capacity (K15). Configuring sets the maximum: two plus the extra
//!   refills, as seL4's `MIN_REFILLS` is 2.
//! - **When the list is full**, a new refill merges into the last one, which
//!   moves the last one later.
//! - **A head smaller than the minimum budget** merges into the next refill,
//!   so the thread isn't dispatched for a sliver.
//! - **An overrun** — the timer interrupt is taken a little after the
//!   budget's end — is charged to the next refills, as if used at their
//!   times, so the amounts still sum to the budget. A charge is capped at
//!   the whole budget.
//! - **Round-robin**, a budget equal to its period, has one refill. When it
//!   runs out, it is refilled whole and the thread goes to the back of its
//!   queue.
//!
//! All times and amounts are counts of the virtual timer.

/// The fewest refills a sporadic context has: seL4's `MIN_REFILLS`.
pub const MIN_REFILLS: u32 = 2;

/// One refill.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Refill {
    /// The count from which it may be used.
    pub time: u64,
    pub amount: u64,
}

/// A context's refill state, kept in its header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub budget: u64,
    pub period: u64,
    /// The smallest amount worth dispatching a thread for.
    pub min_budget: u64,
    pub head: u32,
    pub count: u32,
    /// The ring's configured size: at most the capacity.
    pub max: u32,
}

/// Why a configuration's refills don't fit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalid {
    /// More refills than the context can hold.
    TooManyRefills,
    /// A zero budget, or a budget past the period.
    Budget,
}

/// The result of charging time to a context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charged {
    /// The head refill is still ready, with at least the minimum budget.
    Ready,
    /// The budget ran out: round-robin was refilled whole and its thread
    /// goes to the back of its queue; a sporadic context waits for its next
    /// refill, or raises a timeout fault (ADR 0051, rule 1).
    Exhausted,
}

/// The refills of one context: its state and its ring.
pub struct Refills<'a> {
    pub st: &'a mut State,
    pub ring: &'a mut [Refill],
}

impl<'a> Refills<'a> {
    pub fn new(st: &'a mut State, ring: &'a mut [Refill]) -> Refills<'a> {
        Refills { st, ring }
    }

    /// A context configured with `budget` in `period`, and `max` refills
    /// (round-robin always has one), its whole budget usable from `now`.
    pub fn configure(
        &mut self,
        budget: u64,
        period: u64,
        max: u32,
        min_budget: u64,
        now: u64,
    ) -> Result<(), Invalid> {
        if budget == 0 || budget > period {
            return Err(Invalid::Budget);
        }
        let max = if budget == period {
            1
        } else {
            max.max(MIN_REFILLS)
        };
        if max as usize > self.ring.len() {
            return Err(Invalid::TooManyRefills);
        }
        *self.st = State {
            budget,
            period,
            min_budget: min_budget.min(budget),
            head: 0,
            count: 1,
            max,
        };
        self.ring[0] = Refill {
            time: now,
            amount: budget,
        };
        Ok(())
    }

    /// Reconfiguring a context that has run, as seL4's `refill_update`: the
    /// head refill is kept, cut to the new budget, and any more budget comes
    /// one new period after it.
    pub fn reconfigure(
        &mut self,
        budget: u64,
        period: u64,
        max: u32,
        min_budget: u64,
        now: u64,
    ) -> Result<(), Invalid> {
        if self.st.count == 0 {
            return self.configure(budget, period, max, min_budget, now);
        }
        let mut head = self.head();
        if budget == 0 || budget > period {
            return Err(Invalid::Budget);
        }
        let max = if budget == period {
            1
        } else {
            max.max(MIN_REFILLS)
        };
        if max as usize > self.ring.len() {
            return Err(Invalid::TooManyRefills);
        }
        if head.time <= now {
            head.time = now;
        }
        *self.st = State {
            budget,
            period,
            min_budget: min_budget.min(budget),
            head: 0,
            count: 1,
            max,
        };
        if budget == period || head.amount >= budget {
            head.amount = budget;
            self.ring[0] = head;
        } else {
            let rest = budget - head.amount;
            self.ring[0] = head;
            self.add_tail(Refill {
                time: head.time.saturating_add(period),
                amount: rest,
            });
        }
        Ok(())
    }

    pub fn is_round_robin(&self) -> bool {
        self.st.budget == self.st.period
    }

    fn idx(&self, i: u32) -> usize {
        ((self.st.head + i) % self.st.max.max(1)) as usize
    }

    /// The `i`th refill from the head.
    pub fn get(&self, i: u32) -> Refill {
        self.ring[self.idx(i)]
    }

    fn set(&mut self, i: u32, r: Refill) {
        let k = self.idx(i);
        self.ring[k] = r;
    }

    pub fn head(&self) -> Refill {
        self.get(0)
    }

    pub fn count(&self) -> u32 {
        self.st.count
    }

    /// Whether the head refill may be used at `now`.
    pub fn ready(&self, now: u64) -> bool {
        self.st.count > 0 && self.head().time <= now
    }

    /// Whether the head refill is ready with at least the minimum budget.
    pub fn sufficient(&self, now: u64) -> bool {
        self.ready(now) && self.head().amount >= self.st.min_budget
    }

    /// When the head refill becomes ready, if it isn't at `now`: the key in
    /// the core's release tree.
    pub fn next_release(&self, now: u64) -> Option<u64> {
        if self.st.count == 0 || self.ready(now) {
            None
        } else {
            Some(self.head().time)
        }
    }

    /// The count at which a thread dispatched at `dispatch` runs out.
    pub fn budget_end(&self, dispatch: u64) -> u64 {
        dispatch.saturating_add(self.head().amount)
    }

    /// The sum of the refills: always the budget.
    pub fn sum(&self) -> u64 {
        (0..self.st.count).map(|i| self.get(i).amount).sum()
    }

    fn pop_head(&mut self) {
        self.st.head = (self.st.head + 1) % self.st.max.max(1);
        self.st.count -= 1;
    }

    /// Appends `r`, merging it into the last refill when they touch, or
    /// when the ring is full.
    fn add_tail(&mut self, r: Refill) {
        if r.amount == 0 {
            return;
        }
        if self.st.count == 0 {
            self.st.head = 0;
            self.st.count = 1;
            self.ring[0] = r;
            return;
        }
        let last_i = self.st.count - 1;
        let last = self.get(last_i);
        let last_end = last.time.saturating_add(last.amount);
        if last_end >= r.time {
            // They touch: r's budget is used after last's, no sooner than
            // r.time.
            self.set(
                last_i,
                Refill {
                    time: last.time,
                    amount: last.amount + r.amount,
                },
            );
        } else if self.st.count == self.st.max {
            // Full: merge last into r, moving last's budget later.
            self.set(
                last_i,
                Refill {
                    time: r.time - last.amount,
                    amount: last.amount + r.amount,
                },
            );
        } else {
            self.st.count += 1;
            self.set(last_i + 1, r);
        }
    }

    /// Merges into the head the refills it reaches, and a head below the
    /// minimum budget into the next refill.
    fn tidy_head(&mut self) {
        while self.st.count >= 2 {
            let h = self.get(0);
            let n = self.get(1);
            if h.time.saturating_add(h.amount) >= n.time {
                // The merged refill takes the second's place and the head
                // is dropped: O(1), with no shifting.
                self.set(
                    1,
                    Refill {
                        time: h.time,
                        amount: h.amount + n.amount,
                    },
                );
                self.pop_head();
            } else if h.amount < self.st.min_budget {
                // Too small to run on: its budget joins the next refill,
                // later than it was.
                self.set(
                    1,
                    Refill {
                        time: n.time,
                        amount: n.amount + h.amount,
                    },
                );
                self.pop_head();
            } else {
                break;
            }
        }
    }

    /// A thread wakes and becomes runnable on this context, as seL4's
    /// `refill_unblock_check`: a ready head counts from `now`, and takes in
    /// the refills it then reaches.
    pub fn unblock(&mut self, now: u64) {
        if self.is_round_robin() || !self.ready(now) {
            return;
        }
        let mut h = self.head();
        h.time = now;
        self.set(0, h);
        self.tidy_head();
    }

    /// Charges `usage` counts, used contiguously from `start`, to the head
    /// refill. `now` is the count at the charge.
    pub fn charge(&mut self, start: u64, usage: u64, now: u64) -> Charged {
        if self.st.count == 0 {
            return Charged::Exhausted;
        }
        if self.is_round_robin() {
            let mut h = self.head();
            h.amount = h.amount.saturating_sub(usage);
            if h.amount < self.st.min_budget {
                self.set(
                    0,
                    Refill {
                        time: now,
                        amount: self.st.budget,
                    },
                );
                return Charged::Exhausted;
            }
            self.set(0, h);
            return Charged::Ready;
        }
        let usage = usage.min(self.st.budget);
        let mut h = self.head();
        let start = start.max(h.time);
        let used = usage.min(h.amount);
        // The rest of the head is usable right after this use.
        h.amount -= used;
        h.time = start.saturating_add(used);
        if h.amount == 0 {
            self.pop_head();
        } else {
            self.set(0, h);
        }
        self.add_tail(Refill {
            time: start.saturating_add(self.st.period),
            amount: used,
        });
        // An overrun: charged to the next refills at their own times.
        let mut over = usage - used;
        while over > 0 && self.st.count > 0 {
            let mut r = self.head();
            let y = over.min(r.amount);
            over -= y;
            r.amount -= y;
            let back = Refill {
                time: r.time.saturating_add(self.st.period),
                amount: y,
            };
            if r.amount == 0 {
                self.pop_head();
            } else {
                r.time = r.time.saturating_add(y);
                self.set(0, r);
            }
            self.add_tail(back);
        }
        self.tidy_head();
        if self.sufficient(now) {
            Charged::Ready
        } else {
            Charged::Exhausted
        }
    }

    /// Checks the invariants: the count within the maximum, the amounts
    /// positive and summing to the budget, and the refills in order without
    /// overlap. For tests, in the kernel's test builds too.
    pub fn check(&self) -> bool {
        let st = &*self.st;
        if st.count == 0 || st.count > st.max || st.max as usize > self.ring.len() {
            return false;
        }
        if st.head >= st.max {
            return false;
        }
        let mut sum = 0u64;
        for i in 0..st.count {
            let r = self.get(i);
            if r.amount == 0 {
                return false;
            }
            sum = sum.saturating_add(r.amount);
            if i + 1 < st.count {
                let n = self.get(i + 1);
                if r.time.saturating_add(r.amount) > n.time {
                    return false;
                }
            }
        }
        sum == st.budget
    }
}
