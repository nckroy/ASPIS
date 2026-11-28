// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Each core's scheduler data and entry stack (kernel specification, "The
//! kernel lock and long operations" and "Starting secondary cores"; ADR
//! 0052, rule 3).
//!
//! Every core has a slot in the per-core window at
//! [`kmem::layout::PERCORE_WINDOW_BASE`], 256 KiB each, by its index in the
//! core table. `mm::init` maps the slots, for each core the device tree
//! names, with pages from the boot allocator ([`map_slots`]). A slot holds,
//! from its base:
//!
//! - an unmapped guard page, so an overflow of the entry stack takes a
//!   translation fault;
//! - the 64 KiB entry stack;
//! - the core's [`PerCore`], right at the stack's top: `TPIDR_EL1` holds
//!   its address, so the EL0 vectors switch to the stack with one `MRS`,
//!   and [`this_core`] finds the data with the same one;
//! - the core's start record, which the secondary entry reads with its MMU
//!   off (`crate::smp::start`);
//! - another unmapped guard page, and the 16 KiB emergency stack, on which
//!   an overflow of the entry stack is reported;
//! - and nothing else: the rest of the slot is unmapped.
//!
//! **An overflow.** The fault on the guard page re-enters the kernel's
//! synchronous vector on the same stack, as any exception at EL1 does, so
//! that vector checks the stack pointer before it stores a frame: within
//! 64 KiB below this core's entry stack, or less than a frame above its
//! base, it is an overflow. The vector then switches to the emergency stack
//! and panics, naming the core, before anything is written below the
//! guard, so the slot below, another core's live data, is never touched
//! (`crate::exceptions`). The SError vector checks the same way. The boot
//! stack, below whose guard the memory is mapped, is reported as before.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use kirq::MAX_CORES;
use kmem::PAGE_SIZE;
use kmem::layout::{PERCORE_SLOT, PERCORE_WINDOW_BASE};
use ksched::batch::Batcher;
use ksched::runq::RunQueues;
use ksched::smp::clh::{Clh, Held, Node};
use ksched::worklist::WorkList;

/// The entry stack's size: 64 KiB, as the boot stack's.
pub const ENTRY_STACK: usize = 64 * 1024;
/// Pages of a core's [`PerCore`].
pub const DATA_PAGES: u64 = core::mem::size_of::<PerCore>().div_ceil(PAGE_SIZE as usize) as u64;
/// Mapped pages of a slot below the emergency stack's guard: the stack,
/// the data and the start record.
pub const MAPPED_PAGES: u64 = ENTRY_STACK as u64 / PAGE_SIZE + DATA_PAGES + 1;
/// The emergency stack's size: 16 KiB, enough for the panic path.
pub const EMERGENCY_STACK: u64 = 16 * 1024;
/// The emergency stack's top, as a number of pages above the core's data
/// (`TPIDR_EL1`), for the vectors' `ADD` (`crate::exceptions`).
pub const EMERGENCY_TOP_PAGES: u64 = DATA_PAGES + 2 + EMERGENCY_STACK / PAGE_SIZE;

const _: () = assert!(PAGE_SIZE + (MAPPED_PAGES + 1) * PAGE_SIZE + EMERGENCY_STACK <= PERCORE_SLOT);
// The vectors' overflow check: `ENTRY_STACK` is 64 KiB, `0x10, lsl #12`.
const _: () = assert!(ENTRY_STACK == 0x10 << 12);
// `ADD`'s immediate, shifted by 12, is 12 bits.
const _: () = assert!(EMERGENCY_TOP_PAGES < 1 << 12);
const _: () = assert!(MAX_CORES == ksched::smp::MAX_CORES && MAX_CORES == kmem::asid::MAX_CORES);

/// Core `i`'s slot.
const fn slot(i: usize) -> u64 {
    PERCORE_WINDOW_BASE + i as u64 * PERCORE_SLOT
}

/// Core `i`'s entry stack's lowest address, right above its guard page.
pub const fn stack_base(i: usize) -> u64 {
    slot(i) + PAGE_SIZE
}

/// Core `i`'s [`PerCore`]: the top of its entry stack, and its `TPIDR_EL1`.
pub const fn data_va(i: usize) -> u64 {
    stack_base(i) + ENTRY_STACK as u64
}

/// Core `i`'s start record's page.
pub const fn record_va(i: usize) -> u64 {
    data_va(i) + DATA_PAGES * PAGE_SIZE
}

/// Core `i`'s guard page.
pub const fn guard(i: usize) -> (u64, u64) {
    (slot(i), slot(i) + PAGE_SIZE)
}

/// Core `i`'s emergency stack's lowest address, above its own guard page.
pub const fn emergency_base(i: usize) -> u64 {
    record_va(i) + 2 * PAGE_SIZE
}

const _: () =
    assert!(emergency_base(0) + EMERGENCY_STACK == data_va(0) + EMERGENCY_TOP_PAGES * PAGE_SIZE);

/// How many slots `mm::init` mapped: the cores the device tree names.
static MAPPED: AtomicUsize = AtomicUsize::new(0);
/// Each core's start record's physical address.
static RECORD_PA: [AtomicU64; MAX_CORES] = [const { AtomicU64::new(0) }; MAX_CORES];
/// Each core's data: set once [`init`] has filled it.
static READY: [core::sync::atomic::AtomicBool; MAX_CORES] =
    [const { core::sync::atomic::AtomicBool::new(false) }; MAX_CORES];

/// Maps the slots of `cores` cores in the kernel's tables, by `mm::init`
/// before the switch: `map(va)` maps a zeroed page from the boot allocator
/// at `va`, read-write, and returns its physical address (kernel
/// specification, "Boot memory").
pub fn map_slots(cores: usize, mut map: impl FnMut(u64) -> u64) {
    let cores = cores.min(MAX_CORES);
    for (i, record) in RECORD_PA.iter().enumerate().take(cores) {
        for p in 0..MAPPED_PAGES {
            let va = stack_base(i) + p * PAGE_SIZE;
            let pa = map(va);
            if va == record_va(i) {
                record.store(pa, Ordering::Relaxed);
            }
        }
        for p in 0..EMERGENCY_STACK / PAGE_SIZE {
            map(emergency_base(i) + p * PAGE_SIZE);
        }
    }
    MAPPED.store(cores, Ordering::Relaxed);
}

/// How many cores have a slot.
pub fn mapped() -> usize {
    MAPPED.load(Ordering::Relaxed)
}

/// Core `i`'s start record: its address in the window, and its physical
/// address.
pub fn record(i: usize) -> (u64, u64) {
    assert!(i < mapped(), "core {i} has no slot");
    (record_va(i), RECORD_PA[i].load(Ordering::Relaxed))
}

/// Which slot a guard-page fault at `far` hit, for the panic message.
pub fn guard_of(far: u64) -> Option<usize> {
    (0..mapped()).find(|&i| (guard(i).0..guard(i).1).contains(&far))
}

/// A core's scheduler data.
#[repr(C)]
pub struct PerCore {
    /// The core's index in the core table.
    pub index: usize,
    /// The thread running on the core, by its object's address, or 0 while
    /// the core idles.
    pub current: u64,
    /// The count at which `current` was dispatched, or its time last
    /// charged.
    pub dispatch: u64,
    /// The core's run queues (ADR 0051, rule 2).
    pub runq: RunQueues,
    /// The roots of the core's release tree (contexts waiting for a refill)
    /// and deadline tree (threads waiting with a deadline), or 0.
    pub release_root: u64,
    pub deadline_root: u64,
    /// The compare value last written, so it is written only when it
    /// changes; 0 before the first. Zero keeps the block in `.bss`.
    pub cval: u64,
    /// The core's work list: the walks of take-backs it started, and the
    /// eventcounts with wakes pending that it first queued (K24).
    pub work: WorkList,
    /// Which source the core's next batch starts from (K24).
    pub batcher: Batcher,
    /// A context whose budget ran out at a commit while its thread went on
    /// running in the kernel: the exit path ends its time slice
    /// (`super::run::commit_current`). 0 for none.
    pub exhausted: u64,
    /// The timer fired since the last exit (`timer::hooks`).
    pub timer_fired: bool,
    /// Work is left for the next batch: releases, deadlines or walk steps
    /// past its bound (K24).
    pub batch_pending: bool,
    /// A batch is running: its time is charged to no context (kernel
    /// specification, "Scheduling contexts and budgets").
    pub in_batch: bool,
    /// The core holds the kernel lock (`crate::smp::lock`).
    pub holds_lock: bool,
    /// The core serves a remote call, with the lock its requester holds
    /// lent to it (`crate::smp::remote`).
    pub serving: bool,
    /// The kernel lock's node the core uses next, and the hold it has.
    pub lock_node: Option<Node>,
    pub held: Option<Held>,
    /// The entry from EL0 in progress while the core waits for the lock:
    /// [`ENTERING_SVC`] for a system call, [`ENTERING_OTHER`] for anything
    /// else, 0 for none. A remote stall of the entering thread reads it
    /// (`crate::smp::remote`); tests read it from other cores.
    pub entering: AtomicU64,
    /// What a remote probe recorded (test builds' `crate::smp::remote`).
    pub probe: Probe,
    /// Counters, for the tests and the log.
    pub stats: Stats,
}

/// [`PerCore::entering`]: a system call, which a stall makes run again.
pub const ENTERING_SVC: u64 = 1;
/// [`PerCore::entering`]: any other entry.
pub const ENTERING_OTHER: u64 = 2;

/// A core's state as a remote probe read it on that core (test builds).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Probe {
    pub done: bool,
    pub daif: u64,
    pub tpidr: u64,
    pub vbar: u64,
    pub cntkctl: u64,
    pub count: u64,
    pub mdscr: u64,
    pub timer_ppi_enabled: bool,
    pub sgis_enabled: bool,
    pub sctlr: u64,
    pub ttbr0: u64,
}

/// A core's scheduling counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Stats {
    /// Switches from one thread to another, or from idle to a thread.
    pub switches: u64,
    /// Entries from EL0.
    pub entries: u64,
    /// Budgets that ran out.
    pub exhausted: u64,
    /// Timeout faults raised.
    pub timeouts: u64,
    /// Refills released from the release tree.
    pub releases: u64,
    /// Deadlines that passed.
    pub expiries: u64,
    /// Exits that ran a batch with work left after it.
    pub batches_left: u64,
    /// Times the core went idle.
    pub idles: u64,
    /// Times an idle core with batch work left gave the lock up between
    /// two batches.
    pub batch_yields: u64,
    /// Batches that ran at least one unit, and the most units one ran.
    pub batches: u64,
    pub batch_max: u64,
    /// Batches that ran units of each source: releases, deadlines, the
    /// work list.
    pub batches_of: [u64; 3],
    /// Steps of take-back walks.
    pub walk_steps: u64,
    /// Units of eventcounts' pending wakes (C14; K24).
    pub ec_units: u64,
    /// Counts spent in batches, charged to no context.
    pub batch_counts: u64,
    /// System calls stopped at a preemption point, to be made again.
    pub restarts: u64,
    /// Times the core would have gone idle with batch work left: always 0.
    pub idle_with_work: u64,
    /// Remote calls the core served (`crate::smp::remote`).
    pub served: u64,
}

impl PerCore {
    const fn new() -> PerCore {
        PerCore {
            index: 0,
            current: 0,
            dispatch: 0,
            runq: RunQueues::new(),
            release_root: 0,
            deadline_root: 0,
            cval: 0,
            work: WorkList::new(),
            batcher: Batcher::new(),
            exhausted: 0,
            timer_fired: false,
            batch_pending: false,
            in_batch: false,
            holds_lock: false,
            serving: false,
            lock_node: None,
            held: None,
            entering: AtomicU64::new(0),
            probe: Probe {
                done: false,
                daif: 0,
                tpidr: 0,
                vbar: 0,
                cntkctl: 0,
                count: 0,
                mdscr: 0,
                timer_ppi_enabled: false,
                sgis_enabled: false,
                sctlr: 0,
                ttbr0: 0,
            },
            stats: Stats {
                switches: 0,
                entries: 0,
                exhausted: 0,
                timeouts: 0,
                releases: 0,
                expiries: 0,
                batches_left: 0,
                idles: 0,
                batch_yields: 0,
                batches: 0,
                batch_max: 0,
                batches_of: [0; 3],
                walk_steps: 0,
                ec_units: 0,
                batch_counts: 0,
                restarts: 0,
                idle_with_work: 0,
                served: 0,
            },
        }
    }
}

/// Fills core `index`'s data in its slot. The boot core runs it for itself
/// in `sched::init`, and for each secondary core before `CPU_ON`, while
/// that core is off.
pub fn init(index: usize) {
    assert!(
        index < mapped(),
        "core {index} has no slot in the per-core window"
    );
    let data = data_va(index) as *mut PerCore;
    let mut d = PerCore::new();
    d.index = index;
    d.lock_node = Clh::node(index);
    // SAFETY: the slot's data pages, which `mm::init` mapped read-write and
    // nothing else uses: the core is the caller, or is off.
    unsafe { data.write(d) };
    READY[index].store(true, Ordering::Release);
}

/// Points `TPIDR_EL1` at this core's data: the boot core's, in
/// `sched::init`. A secondary core's entry sets it before any Rust runs.
pub fn set_tpidr(index: usize) {
    // SAFETY: TPIDR_EL1 is the kernel's own; the vectors read it to find
    // the entry stack, which ends where the data begins.
    unsafe { asm!("msr tpidr_el1, {}", in(reg) data_va(index), options(nostack, preserves_flags)) };
}

/// The address `TPIDR_EL1` holds: this core's data, and the top of its
/// entry stack.
pub fn tpidr() -> u64 {
    let v: u64;
    // SAFETY: reading TPIDR_EL1 has no side effects.
    unsafe { asm!("mrs {}, tpidr_el1", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// This core's data.
///
/// The kernel lock guards every core's data, with IRQs masked, and callers
/// keep the reference only within one scheduler operation, never across a
/// call that takes it again. A core changes its own fields while it serves
/// a remote call, with the lock its requester holds lent to it; the
/// requester waits until it is done.
///
/// The exceptions are a core's own fields that it touches without the
/// lock, before it takes it: `holds_lock`, `lock_node` and `index` in
/// `smp::lock::lock`, and `current` and `entering` on the entry from EL0.
/// Meanwhile the lock's holder may change other fields of the same data
/// ([`core`]). The bytes are disjoint, so no access races; but both sides
/// hold a `&mut` to the whole `PerCore`, which Rust's aliasing rules don't
/// allow, and per-field access would.
#[allow(clippy::mut_from_ref)]
pub fn this_core() -> &'static mut PerCore {
    let p = tpidr() as *mut PerCore;
    assert!(!p.is_null(), "the scheduler runs before sched::init");
    // SAFETY: TPIDR_EL1 points at this core's `PerCore`, set by
    // `set_tpidr` or the secondary entry, in its slot, which is mapped for
    // the kernel's life. See the function's comment for exclusivity.
    unsafe { &mut *p }
}

/// This core's index, or 0 before its data is set up: for the log and the
/// ASID allocator, which run before `sched::init` too.
pub fn index() -> usize {
    match tpidr() {
        0 => 0,
        // SAFETY: as for `this_core`; only the index is read.
        p => unsafe { (*(p as *const PerCore)).index },
    }
}

/// The data of core `index`, under the kernel lock (see [`this_core`]).
#[allow(clippy::mut_from_ref)]
pub fn core(index: usize) -> &'static mut PerCore {
    assert!(
        index < MAX_CORES && READY[index].load(Ordering::Acquire),
        "core {index} has no scheduler data"
    );
    // SAFETY: `init` filled the slot's data, which is mapped for the
    // kernel's life; the kernel lock guards it, as for `this_core`.
    unsafe { &mut *(data_va(index) as *mut PerCore) }
}

/// Core `index`'s [`PerCore::entering`], read from any core without the
/// lock (test builds).
#[cfg(aspis_test_build)]
pub fn entering(index: usize) -> u64 {
    assert!(is_ready(index));
    // SAFETY: the core's data, set up and mapped for the kernel's life;
    // only the atomic field is read, through a shared reference to it.
    unsafe {
        (*(data_va(index) as *const PerCore))
            .entering
            .load(Ordering::Relaxed)
    }
}

/// Whether core `index`'s data is set up.
pub fn is_ready(index: usize) -> bool {
    index < MAX_CORES && READY[index].load(Ordering::Acquire)
}
