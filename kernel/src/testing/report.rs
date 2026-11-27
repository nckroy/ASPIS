// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The log that EL0 test programs report into, through the test trap's
//! REPORT (test builds only). Each record says which core and thread
//! reported which value, when and in what order, so the tests assert order
//! from the log rather than from elapsed time.

use crate::mm::BootCell;
use core::sync::atomic::{AtomicUsize, Ordering};

/// One report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub core: usize,
    pub thread: u64,
    pub value: u64,
    /// The virtual count at the report.
    pub at: u64,
}

/// How many reports the log keeps; later ones are counted, not kept.
pub const CAPACITY: usize = 1024;

static LOG: BootCell<[Report; CAPACITY]> = BootCell::new(
    [Report {
        core: 0,
        thread: 0,
        value: 0,
        at: 0,
    }; CAPACITY],
);
static COUNT: AtomicUsize = AtomicUsize::new(0);
/// The last value reported, kept or not.
static LAST: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Records a report.
pub fn push(core: usize, thread: u64, value: u64) {
    LAST.store(value, Ordering::Relaxed);
    let i = COUNT.fetch_add(1, Ordering::Relaxed);
    if i < CAPACITY {
        let r = Report {
            core,
            thread,
            value,
            at: crate::timer::now(),
        };
        // SAFETY: under the kernel lock, and
        // the reference lives only for this write.
        unsafe { LOG.get_mut()[i] = r };
    }
}

/// The last value reported, even past the log's capacity.
pub fn last() -> u64 {
    LAST.load(Ordering::Relaxed)
}

/// How many reports were made since the last [`clear`].
pub fn count() -> usize {
    COUNT.load(Ordering::Relaxed)
}

/// Report `i`, if it was kept.
pub fn get(i: usize) -> Option<Report> {
    if i < count().min(CAPACITY) {
        // SAFETY: as for `push`; a copy is taken.
        Some(unsafe { LOG.get()[i] })
    } else {
        None
    }
}

/// Every kept report, in order.
pub fn all() -> impl Iterator<Item = Report> {
    (0..count().min(CAPACITY)).filter_map(get)
}

/// The values `thread` reported, in order.
pub fn values_of(thread: u64) -> impl Iterator<Item = u64> {
    all().filter(move |r| r.thread == thread).map(|r| r.value)
}

/// How many reports `thread` made.
pub fn count_of(thread: u64) -> usize {
    all().filter(|r| r.thread == thread).count()
}

/// Empties the log: each test starts with its own.
pub fn clear() {
    COUNT.store(0, Ordering::Relaxed);
}
