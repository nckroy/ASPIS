// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The layouts of endpoints, eventcounts, wait sets and a thread's IPC
//! state, and the kernel's views of them through the direct map (kernel
//! specification, "Untyped memory and kernel records", K07 and K33).
//!
//! Retype makes each object from zeroed memory, and zero is each one's idle
//! state: an endpoint with no queue, an eventcount at 0 with no waiters, a
//! wait set with no entries and no waiter, and a thread waiting on nothing,
//! with no IPC buffer and no bound eventcount.
//!
//! **An endpoint** is 64 bytes:
//!
//! | Word | Contents |
//! |---|---|
//! | 0 | Bit 0: the queue holds receivers, not senders (meaningless while it is empty) |
//! | 1 | The root of its queue: threads keyed by priority, highest first, then by arrival (K25) |
//! | 2 | The root of its queued senders' badge tree, keyed by badge, then arrival (K23) |
//! | 3 | The next arrival number, which never wraps |
//! | 4-7 | Kept |
//!
//! **An eventcount** is 64 bytes:
//!
//! | Word | Contents |
//! |---|---|
//! | 0 | The count, which never wraps (ADR 0053, rule 3) |
//! | 1 | The root of its waiters' tree, keyed by target, then by node (K25) |
//! | 2 | Bit 0: a wake is pending; bit 8: on a work list; bits 16-23: that list's core (K24, K31) |
//! | 3-4 | Its links on that work list |
//! | 5-7 | Kept (C13b may use one) |
//!
//! **A wait set** is `2^k` bytes, k from 7 to 12, aligned to its size (K33).
//! Its first half is its slot array: slot 0 the park slot, slot i + 1 the
//! copy of entry i's eventcount, a binding (K07). Its second half starts
//! with a 32-byte header (the waiting thread, the mask of entries linked
//! now, the number of entries, and k), then entry i's 32-byte node at
//! `32 * (i + 1)`. The kernel writes the header's number and k, and each
//! node's owner flags, the first time it reaches the set through a
//! capability ([`init_set`]), since retype leaves them zero. It names a
//! set to `kipc` by its address with k in the low bits ([`ws_name`]).
//!
//! **A node** in an eventcount's waiters' tree is 32 bytes, 32-byte aligned:
//! left, right, the parent with flags, and the target. The parent word's
//! low five bits are free for flags: bit 0 the color (red), bit 1 an entry
//! node rather than a thread's, bits 2-4 k - 7 of an entry's set. So the
//! kernel finds a node's owner from the node alone (`kipc`'s
//! `IpcStore::owner`): a thread's node lies at 0x560 in its 2 KiB object,
//! and an entry's in its set, found by rounding down to `2^k`.
//!
//! **A thread's IPC state** takes the first 192 of its 768 kept bytes, at
//! 0x500 ([`IpcState`]); the rest stays kept for C15 (page wait), C16 (the
//! job's thread list) and C70.

use crate::mm::phys::{DirectMem, Window};
use crate::sched::object::{TCB_SIZE, Tcb};
use core::mem::{offset_of, size_of};
use kmem::untyped::{ENDPOINT_BITS, EVENTCOUNT_BITS, wait_set_entries};

/// Where a thread's IPC state starts.
pub const IPC_STATE: u64 = 0x500;

/// A thread's IPC state, at [`IPC_STATE`] (module docs).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IpcState {
    /// The endpoint it is queued on, 0 for none.
    pub ep: u64,
    /// Its node in that endpoint's queue: left, right, and the parent with
    /// the color in bit 0.
    pub q: [u64; 3],
    /// Its arrival number on that endpoint.
    pub arrival: u64,
    /// Its node in the endpoint's badge tree, as a queued sender.
    pub bq: [u64; 3],
    /// A queued sender's info word, checked when it was sent.
    pub info: u64,
    /// A queued sender's badge: its capability's, or for a fault, the
    /// endpoint copy's.
    pub badge: u64,
    /// Bits 0-1: why it is queued ([`role`]); bit 2: its capability has
    /// the grant right; bits 8-15: its priority when it joined (K25).
    pub flags: u64,
    /// Its bound eventcount's last-seen count (ADR 0053, rule 5).
    pub last: u64,
    /// Its node in an eventcount's waiters' tree, 32-byte aligned: left,
    /// right, the parent with flags, and the target (module docs).
    pub node: [u64; 4],
    /// The eventcount whose tree that node is in, 0 for none.
    pub node_ec: u64,
    /// Its IPC buffer's virtual address, and the physical address of the
    /// page behind it, pinned by the copy in thread slot 7 (K29); 0 for
    /// none.
    pub buf_va: u64,
    pub buf_pa: u64,
    /// Its bound eventcount, whose copy is in thread slot 6, 0 for none.
    pub bound: u64,
    /// The wait set it waits on, 0 for none.
    pub set: u64,
    /// Kept.
    pub spare: [u64; 3],
}

const _: () = assert!(size_of::<IpcState>() == 0xc0);
const _: () = assert!(IPC_STATE + size_of::<IpcState>() as u64 <= TCB_SIZE);
// The node's parent word keeps its flags in the low five bits.
const _: () = assert!((IPC_STATE + offset_of!(IpcState, node) as u64).is_multiple_of(32));

/// Where a thread's eventcount node lies in its object.
pub const THREAD_NODE: u64 = IPC_STATE + offset_of!(IpcState, node) as u64;

/// The queued role in [`IpcState::flags`].
pub mod role {
    pub const MASK: u64 = 3;
    pub const RECV: u64 = 0;
    pub const SEND: u64 = 1;
    pub const CALL: u64 = 2;
    pub const FAULT: u64 = 3;
    /// The sender's capability has the grant right.
    pub const GRANT: u64 = 1 << 2;
    pub const PRIO_SHIFT: u32 = 8;
}

/// The word at physical address `pa`, an object's, through the direct map.
fn word(pa: u64) -> *mut u64 {
    debug_assert!(pa != 0 && pa.is_multiple_of(8));
    DirectMem.va(pa) as *mut u64
}

/// Reads the word at `pa`.
fn read(pa: u64) -> u64 {
    // SAFETY: `pa` is a word of an endpoint, eventcount, wait set or
    // thread, RAM retyped from untyped memory, in the direct map,
    // read-write, which only the kernel touches, under its lock.
    unsafe { core::ptr::read_volatile(word(pa)) }
}

/// Writes the word at `pa`.
fn write(pa: u64, v: u64) {
    // SAFETY: as for `read`.
    unsafe { core::ptr::write_volatile(word(pa), v) }
}

/// Runs `f` on `t`'s IPC state.
pub fn with_ipc<R>(t: Tcb, f: impl FnOnce(&mut IpcState) -> R) -> R {
    debug_assert!(t.0 != 0 && t.0.is_multiple_of(TCB_SIZE));
    let p = DirectMem.va(t.0 + IPC_STATE) as *mut IpcState;
    // SAFETY: the IPC state lies in the thread's kept bytes, inside its
    // 2 KiB object of RAM in the direct map, read-write; only the kernel
    // touches it, under its lock, and the reference lives only for `f`,
    // which doesn't reach this thread's IPC state again.
    f(unsafe { &mut *p })
}

/// A copy of `t`'s IPC state.
pub fn ipc(t: Tcb) -> IpcState {
    with_ipc(t, |s| *s)
}

/// An endpoint's words (module docs).
pub mod ep_word {
    pub const STATE: u64 = 0;
    pub const ROOT: u64 = 8;
    pub const BROOT: u64 = 16;
    pub const NEXT: u64 = 24;
    /// Word 0's bit: the queue holds receivers.
    pub const RECEIVERS: u64 = 1;
}

/// An eventcount's words (module docs).
pub mod ec_word {
    pub const COUNT: u64 = 0;
    pub const ROOT: u64 = 8;
    pub const WORD: u64 = 16;
    pub const WNEXT: u64 = 24;
    pub const WPREV: u64 = 32;
    /// Word 2's bits.
    pub const PENDING: u64 = 1 << 0;
    pub const QUEUED: u64 = 1 << 8;
    pub const CORE_SHIFT: u32 = 16;
    pub const CORE: u64 = 0xff << CORE_SHIFT;
}

const _: () = assert!(ec_word::WPREV + 8 <= 1 << EVENTCOUNT_BITS);
const _: () = assert!(ep_word::NEXT + 8 <= 1 << ENDPOINT_BITS);

/// Reads word `off` of the object at `pa`.
pub fn get(pa: u64, off: u64) -> u64 {
    read(pa + off)
}

/// Writes word `off` of the object at `pa`.
pub fn set(pa: u64, off: u64, v: u64) {
    write(pa + off, v)
}

/// A wait set's header words, from the start of its second half.
pub mod ws_word {
    pub const WAITER: u64 = 0;
    pub const LINKED: u64 = 8;
    pub const ENTRIES: u64 = 16;
    pub const BITS: u64 = 24;
}

/// Where the header of the wait set at `ws`, of `2^bits` bytes, lies.
pub const fn ws_header(ws: u64, bits: u8) -> u64 {
    ws + (1 << (bits - 1))
}

/// Where entry `i`'s node of the wait set at `ws`, of `2^bits` bytes,
/// lies.
pub const fn entry_node(ws: u64, bits: u8, i: usize) -> u64 {
    ws_header(ws, bits) + 32 * (i as u64 + 1)
}

/// A wait set as `kipc` names it: its address, with its size bits in the
/// low seven, which its 128-byte alignment leaves free. So every view of
/// the set finds its header from the name alone.
pub const fn ws_name(ws: u64, bits: u8) -> u64 {
    ws | bits as u64
}

/// The address and size bits of the wait set named `name` ([`ws_name`]).
pub const fn ws_of(name: u64) -> (u64, u8) {
    (name & !0x7f, (name & 0x7f) as u8)
}

/// Writes the header's number of entries and size, and every entry node's
/// owner flags, unless they are written already: the first time the kernel
/// reaches the wait set at `ws`, of `2^bits` bytes, through a capability.
pub fn init_set(ws: u64, bits: u8) {
    let h = ws_header(ws, bits);
    if get(h, ws_word::BITS) == bits as u64 {
        return;
    }
    let n = wait_set_entries(bits) as usize;
    for i in 0..n {
        let node = entry_node(ws, bits, i);
        set(
            node,
            16,
            node_flags::ENTRY | ((bits - 7) as u64) << node_flags::BITS_SHIFT,
        );
    }
    set(h, ws_word::ENTRIES, n as u64);
    set(h, ws_word::BITS, bits as u64);
}

/// The flags in a node's parent word (module docs).
pub mod node_flags {
    pub const RED: u64 = 1 << 0;
    pub const ENTRY: u64 = 1 << 1;
    pub const BITS_SHIFT: u32 = 2;
    pub const BITS: u64 = 7 << BITS_SHIFT;
    /// Every flag bit: the rest of the word is the parent's address.
    pub const ALL: u64 = 0x1f;
}

/// Whose a node is: a thread's, or entry `i` of the wait set at `ws` of
/// `2^bits` bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeOwner {
    Thread(Tcb),
    Entry { ws: u64, bits: u8, i: usize },
}

/// The owner of the node at `n`, from its own flags.
pub fn node_owner(n: u64) -> NodeOwner {
    let p = get(n, 16);
    if p & node_flags::ENTRY == 0 {
        let t = Tcb(n & !(TCB_SIZE - 1));
        debug_assert_eq!(n - t.0, THREAD_NODE, "node {n:#x} isn't a thread's");
        return NodeOwner::Thread(t);
    }
    let bits = ((p & node_flags::BITS) >> node_flags::BITS_SHIFT) as u8 + 7;
    let ws = n & !((1u64 << bits) - 1);
    let i = ((n - ws_header(ws, bits)) / 32 - 1) as usize;
    NodeOwner::Entry { ws, bits, i }
}

/// The node of thread `t`.
pub const fn thread_node(t: Tcb) -> u64 {
    t.0 + THREAD_NODE
}
