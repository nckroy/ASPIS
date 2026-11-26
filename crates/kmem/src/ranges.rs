// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Sets of address ranges with a fixed capacity, for the boot memory map.
//!
//! A set holds half-open ranges `[start, end)`, sorted, disjoint and
//! coalesced: two ranges never touch. So a range is covered by the set
//! exactly when one of its ranges covers it.
//!
//! The kernel keeps these sets in statics and changes them in place, so a
//! set is never moved by value on the small boot stack.

/// The set is full: the operation would need more than `N` ranges. The set
/// is unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

/// A set of at most `N` ranges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeSet<const N: usize> {
    ranges: [(u64, u64); N],
    len: usize,
}

impl<const N: usize> Default for RangeSet<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RangeSet<N> {
    /// The empty set.
    pub const fn new() -> Self {
        Self {
            ranges: [(0, 0); N],
            len: 0,
        }
    }

    /// Empties the set.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Makes this set a copy of `other`, in place.
    pub fn copy_from<const M: usize>(&mut self, other: &RangeSet<M>) -> Result<(), Full> {
        if other.len > N {
            return Err(Full);
        }
        self.ranges[..other.len].copy_from_slice(other.as_slice());
        self.len = other.len;
        Ok(())
    }

    /// The ranges, in order.
    pub fn as_slice(&self) -> &[(u64, u64)] {
        &self.ranges[..self.len]
    }

    /// The ranges, in order.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (u64, u64)> + '_ {
        self.as_slice().iter().copied()
    }

    /// How many ranges the set holds.
    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The number of bytes the set covers.
    pub fn total(&self) -> u64 {
        self.iter().map(|(s, e)| e - s).sum()
    }

    /// Whether one range of the set covers all of `[start, end)`. An empty
    /// range is covered.
    pub fn contains(&self, start: u64, end: u64) -> bool {
        start >= end || self.iter().any(|(s, e)| s <= start && end <= e)
    }

    /// Whether any part of `[start, end)` is in the set.
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        start < end && self.iter().any(|(s, e)| s < end && start < e)
    }

    /// Whether the two sets share any address.
    pub fn intersects<const M: usize>(&self, other: &RangeSet<M>) -> bool {
        other.iter().any(|(s, e)| self.overlaps(s, e))
    }

    /// Adds `[start, end)`, merging it with the ranges it overlaps or
    /// touches.
    pub fn insert(&mut self, start: u64, end: u64) -> Result<(), Full> {
        if start >= end {
            return Ok(());
        }
        // The ranges that overlap or touch the new one are a run [lo, hi).
        let lo = self.as_slice().partition_point(|&(_, e)| e < start);
        let hi = self.as_slice().partition_point(|&(s, _)| s <= end);
        if lo == hi {
            // Nothing to merge with: insert at lo.
            if self.len == N {
                return Err(Full);
            }
            self.ranges.copy_within(lo..self.len, lo + 1);
            self.ranges[lo] = (start, end);
            self.len += 1;
            return Ok(());
        }
        let merged = (start.min(self.ranges[lo].0), end.max(self.ranges[hi - 1].1));
        self.ranges[lo] = merged;
        // Close the gap left by ranges lo+1..hi.
        self.ranges.copy_within(hi..self.len, lo + 1);
        self.len -= hi - lo - 1;
        Ok(())
    }

    /// Removes `[start, end)`. Splitting a range in two needs one more slot.
    pub fn remove(&mut self, start: u64, end: u64) -> Result<(), Full> {
        if start >= end {
            return Ok(());
        }
        // The ranges that overlap the removed one are a run [lo, hi).
        let lo = self.as_slice().partition_point(|&(_, e)| e <= start);
        let hi = self.as_slice().partition_point(|&(s, _)| s < end);
        if lo >= hi {
            return Ok(());
        }
        let first = self.ranges[lo];
        let last = self.ranges[hi - 1];
        let left = (first.0 < start).then_some((first.0, start));
        let right = (last.1 > end).then_some((end, last.1));
        let keep = left.is_some() as usize + right.is_some() as usize;
        let removed = hi - lo;
        if self.len - removed + keep > N {
            return Err(Full);
        }
        // Move the tail to its new place, then write the pieces kept.
        self.ranges.copy_within(hi..self.len, lo + keep);
        self.len = self.len - removed + keep;
        for (at, piece) in (lo..).zip([left, right].into_iter().flatten()) {
            self.ranges[at] = piece;
        }
        Ok(())
    }

    /// Adds every range of `other`.
    pub fn insert_set<const M: usize>(&mut self, other: &RangeSet<M>) -> Result<(), Full> {
        other.iter().try_for_each(|(s, e)| self.insert(s, e))
    }

    /// Removes every range of `other`.
    pub fn remove_set<const M: usize>(&mut self, other: &RangeSet<M>) -> Result<(), Full> {
        other.iter().try_for_each(|(s, e)| self.remove(s, e))
    }

    /// Keeps only the part of the set inside `[start, end)`.
    pub fn clip(&mut self, start: u64, end: u64) {
        // Removing the outside never splits a range, so it never fails.
        let _ = self.remove(0, start);
        let _ = self.remove(end, u64::MAX);
    }
}
