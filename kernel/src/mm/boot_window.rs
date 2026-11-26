// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The boot window: page slots in the bootstrap tables' upper half, through
//! which the kernel reaches physical memory before it switches to its own
//! tables (kernel specification, "Address-space layout", "Bootstrap tables
//! and the switch").
//!
//! The bootstrap tables map the kernel's image and nothing else, so the
//! kernel maps here, page by page, exactly what it must reach before the
//! switch: the boot information and the device tree read-only, the UART as
//! device memory, and each page of its new tables read-write as the boot
//! allocator hands it out. Nothing else is ever mapped here: no
//! firmware-reserved memory (ADR 0039, rule 1), and not the seed's page
//! (ADR 0048, rule 2). Linux's early fixmap works the same way.
//!
//! Slots are handed out once, in order, and never reused, so no entry ever
//! changes from one valid descriptor to another, and no TLB maintenance is
//! needed until the switch, which invalidates every TLB entry. After the
//! switch the window is gone: [`close`] marks it so, and any later use
//! panics.

use super::BootCell;
use super::arch;
use super::phys::Window;
use core::sync::atomic::{AtomicBool, Ordering};
use kmem::desc::{self, KernelPerm, MemType};
use kmem::layout::{KERNEL_BASE, KERNEL_MAX_SIZE};
use kmem::{PAGE_SIZE, align_down, align_up};

/// The window's first address: right above the image's 32 MiB, where
/// `_start` links the window's level-3 tables.
pub const BASE: u64 = KERNEL_BASE + KERNEL_MAX_SIZE;

/// The window's page slots.
pub const SLOTS: usize = 512 * crate::entry::WINDOW_TABLES;

/// The most table pages the window can hold for the kernel's new tables.
/// QEMU's `virt` needs about twenty; a fragmented memory map needs more.
const MAX_TABLES: usize = 1024;

/// What the window has mapped so far.
struct State {
    /// The next free slot.
    next: usize,
    /// The physical address of each table page mapped, and its slot.
    tables: [(u64, usize); MAX_TABLES],
    n_tables: usize,
    /// The table page found last: walks touch the same tables again and
    /// again.
    recent: usize,
}

static STATE: BootCell<State> = BootCell::new(State {
    next: 0,
    tables: [(0, 0); MAX_TABLES],
    n_tables: 0,
    recent: 0,
});

/// Set at the switch, after which nothing in the window is mapped.
static CLOSED: AtomicBool = AtomicBool::new(false);

const RO: KernelPerm = KernelPerm {
    write: false,
    exec: false,
};
const RW: KernelPerm = KernelPerm {
    write: true,
    exec: false,
};

fn assert_open() {
    assert!(
        !CLOSED.load(Ordering::Relaxed),
        "the boot window is used after the switch"
    );
}

/// Maps the pages of `[pa, pa + len)` into the next free slots, as `mem`
/// with `perm`, and returns the window address of `pa`, or `None` if the
/// window is full.
fn map(pa: u64, len: u64, mem: MemType, perm: KernelPerm) -> Option<u64> {
    assert_open();
    let first = align_down(pa, PAGE_SIZE);
    let end = align_up(pa.checked_add(len.max(1))?, PAGE_SIZE)?;
    let pages = ((end - first) / PAGE_SIZE) as usize;
    // SAFETY: one CPU, before the switch; the reference ends here.
    let st = unsafe { STATE.get_mut() };
    if st.next + pages > SLOTS {
        return None;
    }
    let slot = st.next;
    st.next += pages;
    let tables = crate::entry::window_tables() as *mut u64;
    for i in 0..pages {
        let page = first + (i as u64) * PAGE_SIZE;
        let d = desc::kernel_leaf(page, 3, mem, perm)
            .unwrap_or_else(|e| panic!("can't map {page:#x} in the boot window: {e:?}"));
        // SAFETY: the window's level-3 tables are `SLOTS` entries one after
        // another in the image's `.bss`, mapped read-write; this slot was
        // invalid, so no TLB holds it.
        unsafe { core::ptr::write_volatile(tables.add(slot + i), d) };
    }
    // The entries reach the walker, and this core uses them from here on.
    arch::dsb_ishst();
    arch::isb();
    Some(BASE + (slot as u64) * PAGE_SIZE + (pa - first))
}

/// Maps `[pa, pa + len)` read-only, never executable, for the boot
/// information and the device tree, which the memory map keeps.
pub fn map_ro(pa: u64, len: u64) -> Option<u64> {
    map(pa, len, MemType::Normal, RO)
}

/// Maps `[pa, pa + len)` as device memory, read-write, never executable,
/// for the UART.
pub fn map_device(pa: u64, len: u64) -> Option<u64> {
    map(pa, len, MemType::Device, RW)
}

/// Maps `pa`, a page the boot allocator just handed out for one of the
/// kernel's new tables, read-write, and returns its window address. The
/// page is reached through [`BootWindow`] from then on.
pub fn map_table(pa: u64) -> u64 {
    let Some(va) = map(pa, PAGE_SIZE, MemType::Normal, RW) else {
        panic!("the boot window is full");
    };
    // SAFETY: one CPU, before the switch; the reference ends here.
    let st = unsafe { STATE.get_mut() };
    assert!(
        st.n_tables < MAX_TABLES,
        "the kernel's tables need more than {MAX_TABLES} pages"
    );
    st.tables[st.n_tables] = (pa, ((va - BASE) / PAGE_SIZE) as usize);
    st.n_tables += 1;
    va
}

/// Marks the window gone, at the switch to the kernel's own tables.
pub fn close() {
    CLOSED.store(true, Ordering::Relaxed);
}

/// The kernel's new tables, as the boot window reaches them before the
/// switch. Only pages [`map_table`] mapped are reachable.
pub struct BootWindow;

impl Window for BootWindow {
    fn va(&self, pa: u64) -> u64 {
        assert_open();
        let page = align_down(pa, PAGE_SIZE);
        // SAFETY: one CPU, before the switch; the reference ends here.
        let st = unsafe { STATE.get_mut() };
        let found = if st.recent < st.n_tables && st.tables[st.recent].0 == page {
            Some(st.recent)
        } else {
            st.tables[..st.n_tables]
                .iter()
                .position(|&(p, _)| p == page)
        };
        let Some(i) = found else {
            panic!("{pa:#x} isn't a table page in the boot window");
        };
        st.recent = i;
        BASE + (st.tables[i].1 as u64) * PAGE_SIZE + (pa - page)
    }
}
