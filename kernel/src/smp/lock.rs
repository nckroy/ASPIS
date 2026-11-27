// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The kernel lock (ADR 0052, rule 2; kernel specification, "The kernel
//! lock and long operations"): one CLH queue lock, `ksched::smp::clh`'s, as
//! seL4's big kernel lock.
//!
//! **Who holds it.** A core holds the lock whenever it runs kernel code
//! with the kernel's state in reach. Every entry from EL0 takes it
//! (`crate::sched::entry`), and the exit path releases it at the last
//! moment before the return to EL0, and around the idle loop's `WFI`
//! (`crate::sched::run`). The boot core takes it in `sched::init`, before
//! any other core runs, and holds it through `kernel_main` and the tests,
//! releasing it only where its scheduler returns to EL0 or idles, as every
//! core's does. The lock is never taken twice: a second take panics.
//!
//! **While it spins,** a core serves the remote calls sent to it, and stops
//! if a panic asked every core to stop (`super::remote`; kernel
//! specification, "Cross-core signals and TLB maintenance"). So two cores never wait on each other: the requester holds the
//! lock, and its target serves the request in its spin.
//!
//! **At release,** the cores marked to reschedule ([`mark_resched`]) get
//! one SGI 1 each, coalesced, so a thread made ready there, or a timer
//! entry made there, is seen at once (kernel specification, "Cross-core
//! signals and TLB maintenance").
//!
//! The statics the kernel keeps in `BootCell`s are guarded by this lock:
//! every access after boot is on a path that holds it. The only lock-free
//! paths are the panic path, SGI sends, the per-core interrupt counters and
//! the online flags.

use crate::sched::percore::{self, this_core};
use core::sync::atomic::{AtomicU64, Ordering};
use ksched::smp::clh::Clh;

static KLOCK: Clh = Clh::new();

/// The cores to send SGI 1 to when the lock is released, one bit each.
static RESCHED: AtomicU64 = AtomicU64::new(0);

/// Takes the kernel lock on this core, serving remote calls and the panic
/// stop while it waits.
pub fn lock() {
    let c = this_core();
    assert!(!c.holds_lock, "the kernel lock is taken twice on one core");
    let Some(mut node) = c.lock_node.take() else {
        panic!("core {} has no kernel-lock node", c.index);
    };
    let index = c.index;
    // No reference to the core's data is held across the spin: serving a
    // remote call takes it afresh.
    let held = KLOCK.acquire(&mut node, || super::remote::spin(index));
    #[cfg(aspis_test_build)]
    order::record(index, held.node(), held.predecessor);
    let c = this_core();
    c.lock_node = Some(node);
    c.held = Some(held);
    c.holds_lock = true;
}

/// Releases the kernel lock, then sends the coalesced SGI 1s.
pub fn unlock() {
    let c = this_core();
    assert!(
        c.holds_lock,
        "the kernel lock is released by a core that doesn't hold it"
    );
    let Some(held) = c.held.take() else {
        panic!("core {} holds the kernel lock without a hold", c.index);
    };
    let me = c.index;
    c.holds_lock = false;
    let marked = RESCHED.swap(0, Ordering::Relaxed) & !(1 << me);
    KLOCK.release(held);
    for k in (0..kirq::MAX_CORES).filter(|k| marked & 1 << k != 0) {
        // A core that isn't up yet has nothing to reschedule.
        let _ = crate::irq::send_sgi(crate::irq::Sgi::Reschedule, crate::irq::Target::Core(k));
    }
}

/// Whether this core holds the kernel lock. False before the core's data
/// exists.
pub fn holds_lock() -> bool {
    percore::tpidr() != 0 && this_core().holds_lock
}

/// Whether this core may touch the kernel's state: it holds the lock, or
/// serves a remote call with its requester's lock lent to it.
pub fn in_kernel_state() -> bool {
    percore::tpidr() != 0 && {
        let c = this_core();
        c.holds_lock || c.serving
    }
}

/// Marks core `k` to get SGI 1 when this core releases the lock: a thread
/// was made ready there, or its release or deadline tree changed (kernel
/// specification, "Cross-core signals and TLB maintenance").
pub fn mark_resched(k: usize) {
    if k != percore::index() {
        RESCHED.fetch_or(1 << k, Ordering::Relaxed);
    }
}

/// The order cores took the lock in, for the test of its FIFO order (test
/// builds): each take's node and the node it waited behind.
#[cfg(aspis_test_build)]
pub mod order {
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// How many takes are kept.
    pub const CAPACITY: usize = 4096;

    /// One take of the lock.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Take {
        pub core: usize,
        pub node: usize,
        pub predecessor: usize,
    }

    static ON: AtomicBool = AtomicBool::new(false);
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    static LOG: crate::mm::BootCell<[Take; CAPACITY]> = crate::mm::BootCell::new(
        [Take {
            core: 0,
            node: 0,
            predecessor: 0,
        }; CAPACITY],
    );

    /// Starts recording, from an empty log.
    pub fn start() {
        COUNT.store(0, Ordering::Relaxed);
        ON.store(true, Ordering::Relaxed);
    }

    /// Stops recording.
    pub fn stop() {
        ON.store(false, Ordering::Relaxed);
    }

    /// Records a take, by the core that now holds the lock.
    pub(super) fn record(core: usize, node: usize, predecessor: usize) {
        if !ON.load(Ordering::Relaxed) {
            return;
        }
        let i = COUNT.load(Ordering::Relaxed);
        if i < CAPACITY {
            // SAFETY: the core holds the kernel lock, which orders every
            // write here after the last holder's.
            unsafe {
                LOG.get_mut()[i] = Take {
                    core,
                    node,
                    predecessor,
                }
            };
            COUNT.store(i + 1, Ordering::Relaxed);
        }
    }

    /// The takes recorded, in the order they happened.
    pub fn takes() -> impl Iterator<Item = Take> {
        let n = COUNT.load(Ordering::Relaxed).min(CAPACITY);
        // SAFETY: read under the kernel lock, so no take writes meanwhile;
        // each is copied.
        (0..n).map(|i| unsafe { LOG.get()[i] })
    }
}
