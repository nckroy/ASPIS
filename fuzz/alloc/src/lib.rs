// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The fuzz targets' memory bound (ADR 0068, rule 5: "within time and
//! memory bounds"; docs/design/call-language.md, "The harness").
//!
//! libFuzzer's `-malloc_limit_mb` needs malloc hooks that only a sanitizer
//! runtime installs, so under `--sanitizer none` it does nothing, and
//! `-rss_limit_mb` only polls peak RSS once a second, blaming whatever
//! input is running then. So each target declares [`Bounded`] as its global
//! allocator. A single request over the limit, or live bytes over it,
//! writes one line to stderr and aborts. libFuzzer's deadly-signal handler
//! then saves the input that allocated as the crash artifact.
//!
//! This is harness code, not a parser: ADR 0068, rule 2's
//! `#![forbid(unsafe_code)]` binds the crates that parse input, and the
//! `unsafe` here only forwards to the system allocator. It also counts
//! the peak, which `fuzz-gate measure` reads to set each target's limit.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    io::Write,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

/// Bytes allocated and not yet freed, through [`Bounded`].
static LIVE: AtomicUsize = AtomicUsize::new(0);
/// The most bytes live at once since the last [`reset_peak`].
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// Set once an allocation is over the limit, so the report is written
/// once, even if another thread is over it at the same time.
static OVER: AtomicBool = AtomicBool::new(false);

/// A counting allocator over [`System`] that aborts over its limit.
pub struct Bounded {
    /// The limit in bytes; `usize::MAX` counts without a limit.
    limit: usize,
}

impl Bounded {
    /// A limit of `mib` MiB, as `Target::malloc_limit_mb` gives it.
    pub const fn mib(mib: u32) -> Self {
        Bounded {
            limit: (mib as usize).saturating_mul(1 << 20),
        }
    }

    /// Counts, with no limit (for `fuzz-gate measure`).
    pub const fn unlimited() -> Self {
        Bounded { limit: usize::MAX }
    }
}

/// Bytes live now.
pub fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

/// The most bytes live at once since the last [`reset_peak`].
pub fn peak() -> usize {
    PEAK.load(Ordering::Relaxed)
}

/// Starts a new peak from the bytes live now.
pub fn reset_peak() {
    PEAK.store(live(), Ordering::Relaxed);
}

/// Whether a request of `size` bytes, with `live` bytes already live, is
/// over `limit`: alone, or with what is live.
pub const fn over(live: usize, size: usize, limit: usize) -> bool {
    size > limit || live.saturating_add(size) > limit
}

/// Writes `n` in decimal, without allocating.
fn decimal(out: &mut impl Write, n: usize) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    let mut n = n;
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let _ = out.write_all(&buf[i..]);
}

impl Bounded {
    /// Reserves `size` bytes against the limit, or reports and aborts.
    fn reserve(&self, size: usize) {
        let before = LIVE.fetch_add(size, Ordering::Relaxed);
        if over(before, size, self.limit) {
            // Give the request back first: writing the report may itself
            // allocate (the first use of stderr's lock on a thread that
            // Rust didn't start, such as libFuzzer's), and that must not
            // count as over the limit too.
            LIVE.fetch_sub(size, Ordering::Relaxed);
            self.abort(before, size);
        }
        PEAK.fetch_max(before.saturating_add(size), Ordering::Relaxed);
    }

    #[cold]
    fn abort(&self, live: usize, size: usize) -> ! {
        if !OVER.swap(true, Ordering::Relaxed) {
            // Stderr is unbuffered, and the numbers are written without
            // formatting, so this allocates little or nothing.
            let mut e = std::io::stderr().lock();
            let _ = e.write_all(b"fuzz-alloc: a request of ");
            decimal(&mut e, size);
            let _ = e.write_all(b" bytes, with ");
            decimal(&mut e, live);
            let _ = e.write_all(b" live, is over the limit of ");
            decimal(&mut e, self.limit >> 20);
            let _ = e.write_all(b" MiB\n");
        }
        std::process::abort()
    }
}

// SAFETY: every method forwards to `System` with the caller's own layout
// and pointer, so `System`'s guarantees are the caller's. The counting
// around each call only reads and writes atomics, and an allocation over
// the limit aborts the process instead of returning.
unsafe impl GlobalAlloc for Bounded {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.reserve(layout.size());
        // SAFETY: the caller's layout has a nonzero size, as
        // `GlobalAlloc::alloc` requires of it.
        let p = unsafe { System.alloc(layout) };
        if p.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.reserve(layout.size());
        // SAFETY: as for `alloc`.
        let p = unsafe { System.alloc_zeroed(layout) };
        if p.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller allocated `ptr` with `layout` through this
        // allocator, which got it from `System` with the same layout.
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let old = layout.size();
        if new_size > old {
            self.reserve(new_size - old);
        }
        // SAFETY: the caller allocated `ptr` with `layout` through this
        // allocator (so through `System`), and `new_size` is nonzero and
        // fits `isize` when rounded to the alignment, as
        // `GlobalAlloc::realloc` requires of the caller.
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if p.is_null() {
            // The old block is still allocated: undo the reservation.
            if new_size > old {
                LIVE.fetch_sub(new_size - old, Ordering::Relaxed);
            }
        } else if new_size < old {
            LIVE.fetch_sub(old - new_size, Ordering::Relaxed);
        }
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limit_counts_one_request_and_what_is_live() {
        let mib = 1 << 20;
        assert!(!over(0, 64 * mib, 64 * mib));
        assert!(over(0, 64 * mib + 1, 64 * mib));
        assert!(over(60 * mib, 5 * mib, 64 * mib));
        assert!(!over(60 * mib, 4 * mib, 64 * mib));
        // A request near usize::MAX is over any limit, without overflow.
        assert!(over(mib, usize::MAX, 64 * mib));
        assert!(!over(usize::MAX - 1, 0, usize::MAX));
    }

    #[test]
    fn limits_in_mib() {
        assert_eq!(Bounded::mib(64).limit, 64 << 20);
        assert_eq!(Bounded::unlimited().limit, usize::MAX);
    }

    #[test]
    fn decimals() {
        for n in [0usize, 7, 10, 4096, usize::MAX] {
            let mut out = Vec::new();
            decimal(&mut out, n);
            assert_eq!(out, n.to_string().into_bytes());
        }
    }
}
