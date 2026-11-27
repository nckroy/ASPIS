// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Remote calls and the panic stop's flag (ADR 0052, rule 4; kernel
//! specification, "Cross-core signals and TLB maintenance").
//!
//! - **One request at a time.** Only the holder of the kernel lock sends
//!   one, so one request is in flight. It writes the operation and its
//!   argument, marks each target pending, sends each SGI 0, and spins until
//!   each target marks itself done, as seL4's `doRemoteMaskOp` does.
//! - **A target serves it where it spins for the lock**: it reaches that
//!   spin from user mode (the interrupt's entry takes the lock), from idle
//!   (`wfi` wakes) or from the kernel's exit (the interrupt is taken right
//!   after `eret`). The SGI handler itself only counts.
//! - **The stop.** The panicking core sets the stop flag, with release,
//!   before it sends SGI 2. Every spin in the kernel, this one, the lock's
//!   and the bring-up wait, and the idle loop poll it and stop, so the stop
//!   reaches a core that waits for the lock the panicking core holds, and a
//!   requester whose target has already halted doesn't wait for ever.
//!
//! Memory order: the operation is written before the pending mark, which is
//! stored with release and taken with acquire, so a target reads the
//! operation the requester wrote; done is stored with release and read with
//! acquire, so the requester sees the target's work.

use super::MAX_CORES;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The shared state of remote calls.
pub struct Remote {
    op: AtomicU64,
    arg: AtomicU64,
    pending: [AtomicBool; MAX_CORES],
    done: [AtomicBool; MAX_CORES],
    stop: AtomicBool,
}

/// How a request ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Every target served it.
    Served,
    /// The panic stop came first.
    Stopped,
}

impl Default for Remote {
    fn default() -> Self {
        Self::new()
    }
}

impl Remote {
    pub const fn new() -> Remote {
        Remote {
            op: AtomicU64::new(0),
            arg: AtomicU64::new(0),
            pending: [const { AtomicBool::new(false) }; MAX_CORES],
            done: [const { AtomicBool::new(false) }; MAX_CORES],
            stop: AtomicBool::new(false),
        }
    }

    /// Sends `op` and `arg` to each core in `targets`, a bit mask, calling
    /// `send` for each (the kernel sends SGI 0), then waits for each, calling
    /// `spin` while it waits. The caller holds the kernel lock, and isn't a
    /// target itself.
    pub fn request(
        &self,
        targets: u64,
        op: u64,
        arg: u64,
        mut send: impl FnMut(usize),
        mut spin: impl FnMut(),
    ) -> Outcome {
        self.op.store(op, Ordering::Relaxed);
        self.arg.store(arg, Ordering::Relaxed);
        let cores = (0..MAX_CORES).filter(|c| targets & (1 << c) != 0);
        for c in cores.clone() {
            self.done[c].store(false, Ordering::Relaxed);
            self.pending[c].store(true, Ordering::Release);
            send(c);
        }
        for c in cores {
            while !self.done[c].load(Ordering::Acquire) {
                if self.stopping() {
                    return Outcome::Stopped;
                }
                spin();
                core::hint::spin_loop();
            }
        }
        Outcome::Served
    }

    /// On core `core`: serves a pending request with `f`, if there is one.
    /// True if it served one.
    pub fn serve(&self, core: usize, f: impl FnOnce(u64, u64)) -> bool {
        if core >= MAX_CORES || !self.pending[core].swap(false, Ordering::Acquire) {
            return false;
        }
        f(
            self.op.load(Ordering::Relaxed),
            self.arg.load(Ordering::Relaxed),
        );
        self.done[core].store(true, Ordering::Release);
        true
    }

    /// Whether a request waits for `core`: for the spin loops.
    pub fn is_pending(&self, core: usize) -> bool {
        core < MAX_CORES && self.pending[core].load(Ordering::Acquire)
    }

    /// The panic path: publishes the stop, before SGI 2 is sent.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    /// Whether a panic has asked every core to stop.
    pub fn stopping(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }
}
