// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The kernel lock: a CLH queue lock (kernel specification, "The kernel lock
//! and long operations"), as seL4's `clh_lock_acquire`.
//!
//! Each core spins on its predecessor's node, not on one shared word, and
//! cores take the lock in the order they swapped into the tail: first come,
//! first served, so no core waits behind a later one (ADR 0052, rule 2).
//!
//! There is one node per core and one spare. A core that takes the lock
//! hands its own node on and adopts its predecessor's, which is free from
//! then on, so the nodes circulate and no node is ever in two places.
//!
//! **Spinning serves requests.** The spin calls a hook on every turn: the
//! kernel serves remote calls there, and the panic stop's flag
//! ([`super::remote::Remote::stopping`]), so a core waiting for the lock
//! still answers both (kernel specification, "Cross-core signals and TLB
//! maintenance").
//!
//! Memory order: a node is set busy before the tail swap, whose release
//! publishes it; the spin reads the predecessor's node with acquire, so it
//! sees everything the predecessor did under the lock; the release stores
//! with release.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::MAX_CORES;

/// The node array: one per core, and the spare.
const NODES: usize = MAX_CORES + 1;

/// A CLH lock for up to [`MAX_CORES`] cores.
pub struct Clh {
    /// Node `i` is busy while its owner holds or waits for the lock.
    busy: [AtomicBool; NODES],
    tail: AtomicUsize,
}

/// A core's node: the index of the node it will set busy next time.
/// Kept in the core's per-core data.
#[derive(Debug, PartialEq, Eq)]
pub struct Node(usize);

/// Proof of holding the lock: the node to release, and the node the
/// predecessor held, for the tests' check of the order.
#[derive(Debug, PartialEq, Eq)]
pub struct Held {
    mine: usize,
    pub predecessor: usize,
}

impl Held {
    /// The node this holder set busy.
    pub fn node(&self) -> usize {
        self.mine
    }
}

impl Default for Clh {
    fn default() -> Self {
        Self::new()
    }
}

impl Clh {
    /// A free lock. The spare node starts as the tail.
    pub const fn new() -> Clh {
        Clh {
            busy: [const { AtomicBool::new(false) }; NODES],
            tail: AtomicUsize::new(MAX_CORES),
        }
    }

    /// Core `core`'s first node: its own index. None past [`MAX_CORES`].
    pub const fn node(core: usize) -> Option<Node> {
        if core < MAX_CORES {
            Some(Node(core))
        } else {
            None
        }
    }

    /// Takes the lock, calling `spin` while it waits.
    pub fn acquire(&self, node: &mut Node, mut spin: impl FnMut()) -> Held {
        let mine = node.0;
        self.busy[mine].store(true, Ordering::Relaxed);
        let prev = self.tail.swap(mine, Ordering::AcqRel);
        while self.busy[prev].load(Ordering::Acquire) {
            spin();
            core::hint::spin_loop();
        }
        // The predecessor's node is free now: it is this core's next one.
        node.0 = prev;
        Held {
            mine,
            predecessor: prev,
        }
    }

    /// Releases the lock.
    pub fn release(&self, held: Held) {
        self.busy[held.mine].store(false, Ordering::Release);
    }

    /// Whether some core holds or waits for the lock: for assertions.
    pub fn is_held(&self) -> bool {
        let t = self.tail.load(Ordering::Acquire);
        self.busy[t].load(Ordering::Acquire)
    }
}
