// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The kernel log ring and console output (ADR 0042).
//!
//! The ring is a fixed-size ring of variable-length records in kernel
//! memory, 256 KiB by default (rule 1). Each record holds a sequence number
//! counting from zero at boot, the kernel's clock (the virtual count, from
//! `timer::now`), a level, the CPU that wrote it, a short ASCII source tag
//! and up to 1024 bytes of UTF-8 text (rule 2). Writing never blocks, and
//! the oldest records are overwritten (rule 3). The ring keeps every level;
//! the UART and the framebuffer show records at or above `log.level` (rule
//! 4).
//!
//! **Writers.** A writer reserves its record's bytes with one atomic
//! update of the ring's head, so no writer waits for another (rule 3),
//! marks the record as being written, fills it, and commits it by writing
//! its first word last, with release; a reader stops at a record not yet
//! committed. The oldest position only moves forward, by compare-and-swap.
//! Every record but the panic path's is also written under the kernel lock
//! (C12; `crate::smp::lock`), with exceptions masked, so records land in
//! sequence order and the UART lines and the console of two cores never
//! interleave; [`log`] checks that the lock is held once the other cores
//! have started. The panic path writes without the lock (rule 7), after it
//! has stopped the other cores or waited a bounded time for them, and
//! writes even over a record half written. Reading through a capability
//! comes with the kernel interfaces in M2 (rule 5); until then only the
//! kernel reads the ring, in tests.

use core::cell::UnsafeCell;
use core::fmt::{self, Write as _};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};

pub const DEFAULT_SIZE: usize = 256 * 1024;
pub const MAX_SIZE: usize = 1024 * 1024;
pub const MAX_TEXT: usize = 1024;
pub const MAX_TAG: usize = 16;
const HEADER: usize = 32;
const KIND_RECORD: u8 = 1;
const KIND_PAD: u8 = 2;
/// A record whose writer hasn't committed it yet.
const KIND_WRITING: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    Debug = 0,
    Info = 1,
    Notice = 2,
    Warning = 3,
    Error = 4,
    Panic = 5,
}

impl Level {
    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s {
            "debug" => Self::Debug,
            "info" => Self::Info,
            "notice" => Self::Notice,
            "warning" => Self::Warning,
            "error" => Self::Error,
            "panic" => Self::Panic,
            _ => return None,
        })
    }

    #[cfg_attr(not(aspis_test_build), allow(dead_code))]
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Debug,
            1 => Self::Info,
            2 => Self::Notice,
            3 => Self::Warning,
            4 => Self::Error,
            _ => Self::Panic,
        }
    }
}

#[repr(C, align(8))]
struct Storage(UnsafeCell<[u8; MAX_SIZE]>);
// SAFETY: each writer writes only the bytes it reserved (see the module
// comment), and readers see a record only once its writer committed it.
unsafe impl Sync for Storage {}

static RING: Storage = Storage(UnsafeCell::new([0; MAX_SIZE]));
static SIZE: AtomicUsize = AtomicUsize::new(DEFAULT_SIZE);
/// Bytes ever written; the write position is `HEAD % SIZE`.
static HEAD: AtomicU64 = AtomicU64::new(0);
/// The byte position (same scale as `HEAD`) of the oldest whole record.
static OLDEST: AtomicU64 = AtomicU64::new(0);
static SEQ: AtomicU64 = AtomicU64::new(0);
static THRESHOLD: AtomicU8 = AtomicU8::new(Level::Info as u8);
static TO_UART: AtomicBool = AtomicBool::new(true);
static TO_FB: AtomicBool = AtomicBool::new(true);

/// Sets the ring's size and where records go. Call once, before any
/// record is written that should survive; earlier records are dropped.
pub fn configure(size: usize, threshold: Level, uart: bool, fb: bool) {
    let size = if size.is_power_of_two() && (4096..=MAX_SIZE).contains(&size) {
        size
    } else {
        DEFAULT_SIZE
    };
    SIZE.store(size, Ordering::Relaxed);
    HEAD.store(0, Ordering::Relaxed);
    OLDEST.store(0, Ordering::Relaxed);
    THRESHOLD.store(threshold as u8, Ordering::Relaxed);
    TO_UART.store(uart, Ordering::Relaxed);
    TO_FB.store(fb, Ordering::Relaxed);
}

pub fn size() -> usize {
    SIZE.load(Ordering::Relaxed)
}

fn ring() -> *mut u8 {
    RING.0.get().cast()
}

/// The first word of the record or pad at `at`: its length, kind, level and
/// CPU, as one atomic load, so a reader sees a record whole or not at all.
fn word(at: usize) -> u64 {
    // SAFETY: `at + 8 <= size <= MAX_SIZE`, checked by callers; records and
    // pads start at multiples of 8, and the ring is 8-aligned.
    unsafe { (*(ring().add(at) as *const AtomicU64)).load(Ordering::Acquire) }
}

fn set_word(at: usize, w: u64) {
    // SAFETY: as for `word`; the caller reserved the bytes.
    unsafe { (*(ring().add(at) as *const AtomicU64)).store(w, Ordering::Release) }
}

/// A record's or pad's first word: length, kind, level and CPU.
const fn first_word(len: u64, kind: u8, level: u8, cpu: u16) -> u64 {
    len | (kind as u64) << 32 | (level as u64) << 40 | (cpu as u64) << 48
}

/// Appends a record and returns its sequence number (module docs, ADR
/// 0042, rule 3): the writer reserves its bytes with one atomic update of
/// the head, drops the records they overwrite, marks the record as being
/// written, fills it, and commits it by writing its first word last.
pub fn push(level: Level, tag: &str, text: &str) -> u64 {
    let size = size() as u64;
    let tag = &tag.as_bytes()[..tag.len().min(MAX_TAG)];
    let mut text_len = text.len().min(MAX_TEXT);
    while !text.is_char_boundary(text_len) {
        text_len -= 1;
    }
    let text = &text.as_bytes()[..text_len];
    let need = (HEADER + tag.len() + text.len()).next_multiple_of(8) as u64;

    // Reserve: the record's bytes, after a pad to the ring's end if it
    // doesn't fit before it. Positions are multiples of 8, so a pad has
    // room for its first word.
    let (start, pad) = loop {
        let head = HEAD.load(Ordering::Acquire);
        let pos = head % size;
        let (start, pad) = if pos + need > size {
            (head + (size - pos), Some(pos))
        } else {
            (head, None)
        };
        if HEAD
            .compare_exchange_weak(head, start + need, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            break (start, pad);
        }
    };
    // Drop the records this one overwrites, reading their lengths before
    // anything here is written. The oldest position only moves forward, by
    // compare-and-swap, so a later writer never moves it back.
    loop {
        let oldest = OLDEST.load(Ordering::Acquire);
        let mut o = oldest;
        while o + size < start + need {
            let len = (word((o % size) as usize) & 0xffff_ffff).max(8);
            o += len;
        }
        if o == oldest
            || OLDEST
                .compare_exchange(oldest, o, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            break;
        }
    }

    let at = (start % size) as usize;
    // Marked as being written first, so no reader takes the last lap's
    // bytes here for a record.
    set_word(at, first_word(need, KIND_WRITING, 0, 0));
    if let Some(pos) = pad {
        set_word(pos as usize, first_word(size - pos, KIND_PAD, 0, 0));
    }
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let cpu = crate::sched::percore::index() as u16;
    let mut h = [0u8; HEADER];
    h[8..16].copy_from_slice(&seq.to_le_bytes());
    h[16..24].copy_from_slice(&crate::timer::now().to_le_bytes());
    h[24] = tag.len() as u8;
    h[26..28].copy_from_slice(&(text.len() as u16).to_le_bytes());
    // SAFETY: `at + need <= size <= MAX_SIZE`, and these bytes are this
    // writer's, reserved above.
    unsafe {
        let p = ring().add(at);
        core::ptr::copy_nonoverlapping(h.as_ptr().add(8), p.add(8), HEADER - 8);
        core::ptr::copy_nonoverlapping(tag.as_ptr(), p.add(HEADER), tag.len());
        core::ptr::copy_nonoverlapping(text.as_ptr(), p.add(HEADER + tag.len()), text.len());
    }
    // The commit, with release: a reader that sees it sees the record.
    set_word(at, first_word(need, KIND_RECORD, level as u8, cpu));
    seq
}

/// A record read back from the ring.
#[cfg_attr(not(aspis_test_build), allow(dead_code))]
pub struct Record<'a> {
    pub seq: u64,
    /// The core that wrote it, by its index in the core table.
    pub cpu: u16,
    #[allow(dead_code)]
    pub ticks: u64,
    pub level: Level,
    #[allow(dead_code)]
    pub tag: &'a str,
    pub text: &'a str,
}

/// Calls `f` for every record still in the ring, oldest first.
#[cfg_attr(not(aspis_test_build), allow(dead_code))]
pub fn for_each(mut f: impl FnMut(&Record<'_>)) {
    let size = size() as u64;
    let head = HEAD.load(Ordering::Acquire);
    let mut at = OLDEST.load(Ordering::Acquire);
    while at < head {
        let pos = (at % size) as usize;
        let w = word(pos);
        let len = w & 0xffff_ffff;
        let kind = (w >> 32) as u8;
        // A record still being written ends the walk: what follows it
        // isn't committed in order yet.
        if len < 8 || !matches!(kind, KIND_RECORD | KIND_PAD) {
            break;
        }
        if kind == KIND_RECORD {
            // SAFETY: a whole committed record lies at `pos`, written by
            // `push`; its first word's acquire load ordered its bytes.
            let r = unsafe { core::slice::from_raw_parts(ring().add(pos), len as usize) };
            let tag_len = r[24] as usize;
            let text_len = u16::from_le_bytes([r[26], r[27]]) as usize;
            let rec = Record {
                seq: u64::from_le_bytes(r[8..16].try_into().unwrap()),
                cpu: (w >> 48) as u16,
                ticks: u64::from_le_bytes(r[16..24].try_into().unwrap()),
                level: Level::from_u8((w >> 40) as u8),
                tag: core::str::from_utf8(&r[HEADER..HEADER + tag_len]).unwrap_or("?"),
                text: core::str::from_utf8(&r[HEADER + tag_len..HEADER + tag_len + text_len])
                    .unwrap_or("?"),
            };
            f(&rec);
        }
        at += len;
    }
}

/// A fixed buffer to format one record's text into.
pub struct Line {
    buf: [u8; MAX_TEXT],
    len: usize,
}

impl Line {
    pub const fn new() -> Self {
        Self {
            buf: [0; MAX_TEXT],
            len: 0,
        }
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl fmt::Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let room = MAX_TEXT - self.len;
        let mut n = s.len().min(room);
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// Writes a record to the ring, and to the UART and the framebuffer if its
/// level is at or above the threshold.
pub fn log(level: Level, tag: &str, args: fmt::Arguments<'_>) {
    assert!(
        crate::smp::online_count() <= 1 || crate::smp::lock::in_kernel_state(),
        "a log record written without the kernel lock"
    );
    let mut line = Line::new();
    let _ = line.write_fmt(args);
    let text = line.as_str();
    push(level, tag, text);
    if (level as u8) < THRESHOLD.load(Ordering::Relaxed) {
        return;
    }
    if TO_UART.load(Ordering::Relaxed) {
        crate::uart::write(tag);
        crate::uart::write(": ");
        crate::uart::write(text);
        crate::uart::write("\n");
    }
    if TO_FB.load(Ordering::Relaxed) {
        crate::with_console(|c| {
            let fg = c.fg;
            c.fg = match level {
                Level::Warning | Level::Error | Level::Panic => crate::console::WARNING,
                Level::Debug => crate::console::DIM,
                _ => fg,
            };
            c.write_str(text);
            c.write_str("\n");
            c.fg = fg;
        });
    }
}

#[macro_export]
macro_rules! klog {
    ($level:ident, $tag:expr, $($arg:tt)*) => {
        $crate::log::log($crate::log::Level::$level, $tag, format_args!($($arg)*))
    };
}

#[cfg(aspis_test_build)]
mod tests {
    use super::*;

    crate::kernel_test!(log_ring_keeps_records_in_order, {
        let before = SEQ.load(Ordering::Relaxed);
        let a = push(Level::Info, "test", "first");
        let b = push(Level::Debug, "test", "second");
        assert_eq!(b, a + 1);
        assert!(a >= before);
        let mut seen = 0;
        for_each(|r| {
            if r.seq == a {
                assert_eq!(r.text, "first");
                seen += 1;
            }
            if r.seq == b {
                assert_eq!((r.text, r.level), ("second", Level::Debug));
                seen += 1;
            }
        });
        assert_eq!(seen, 2);
    });

    crate::kernel_test!(log_ring_wraps_and_drops_the_oldest, {
        let size = size();
        const BYTES: [u8; 200] = [b'x'; 200];
        let text = core::str::from_utf8(&BYTES).unwrap();
        let first = push(Level::Info, "wrap", text);
        let mut last = first;
        for _ in 0..(size / 200 + 10) {
            last = push(Level::Info, "wrap", text);
        }
        let (mut count, mut lowest, mut previous) = (0u64, u64::MAX, None);
        for_each(|r| {
            if let Some(p) = previous {
                assert_eq!(
                    r.seq,
                    p + 1,
                    "sequence numbers have no gaps inside the ring"
                );
            }
            previous = Some(r.seq);
            lowest = lowest.min(r.seq);
            count += 1;
        });
        assert!(lowest > first, "the oldest records were overwritten");
        assert_eq!(previous, Some(last));
        assert!(count as usize * 200 <= size);
    });
}
