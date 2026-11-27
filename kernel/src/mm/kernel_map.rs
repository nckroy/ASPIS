// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The kernel's own tables, for its half of the address space (ADR 0048,
//! rules 4 and 6; kernel specification, "Address-space layout"):
//!
//! - the image, by section: text read-only and executable, read-only data
//!   read-only, data and `.bss` read-write, everything but text PXN, and
//!   the boot stack's guard page unmapped;
//! - the direct map: usable RAM read-write, and the kept ranges (the kernel
//!   image, the initial image and the boot information) read-only, never
//!   executable;
//! - the device window: the UART, then the boot framebuffer;
//! - the per-core window: each core's entry stack and scheduler data, page
//!   by page, above an unmapped guard (C12; `crate::sched::percore`).
//!
//! Every leaf is global and UXN. The encoders in [`kmem::desc`] enforce
//! W^X, so nothing here can make a writable, executable mapping.
//!
//! The tables are built after the stub has relocated the image, so read-only
//! protection starts after relocation (ADR 0035, rule 3).

use kmem::desc::{self, KernelPerm, LeafError, MemType};
use kmem::layout::{DEVICE_WINDOW_BASE, DEVICE_WINDOW_SIZE, DIRECT_MAP_BASE};
use kmem::memmap::Classified;
use kmem::table::{FrameSource, MapError, PhysMem, Tables};
use kmem::{BLOCK_2M, PAGE_SIZE, align_down, align_up};

unsafe extern "C" {
    // Linker symbols from `link.ld`; only their addresses matter.
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
    static __data_end: u8;
    static __stack_guard_start: u8;
    static __stack_guard_end: u8;
}

/// The image's parts, as `[start, end)` virtual addresses.
#[derive(Clone, Copy)]
pub struct ImageLayout {
    pub text: (u64, u64),
    pub rodata: (u64, u64),
    pub data: (u64, u64),
    /// The boot stack's guard page, which no table maps.
    pub guard: (u64, u64),
}

/// Where `link.ld` put the image's parts.
pub fn image_layout() -> ImageLayout {
    let a = |p: *const u8| p as u64;
    ImageLayout {
        text: (a(&raw const __text_start), a(&raw const __text_end)),
        rodata: (a(&raw const __rodata_start), a(&raw const __rodata_end)),
        data: (a(&raw const __data_start), a(&raw const __data_end)),
        guard: (
            a(&raw const __stack_guard_start),
            a(&raw const __stack_guard_end),
        ),
    }
}

const RX: KernelPerm = KernelPerm {
    write: false,
    exec: true,
};
const RO: KernelPerm = KernelPerm {
    write: false,
    exec: false,
};
const RW: KernelPerm = KernelPerm {
    write: true,
    exec: false,
};

/// Maps `[va, va + len)` to `[pa, pa + len)` as `mem` with `perm`.
fn map(
    t: &Tables<'_, impl PhysMem>,
    src: &mut impl FrameSource,
    (va, pa, len): (u64, u64, u64),
    mem: MemType,
    perm: KernelPerm,
) -> Result<(), MapError> {
    let mut leaf =
        |pa: u64, level: u8| -> Result<u64, LeafError> { desc::kernel_leaf(pa, level, mem, perm) };
    t.map(va, pa, len, &mut leaf, src)
}

/// Maps the image by section. `kernel_pa` gives an image address's
/// physical address.
pub fn map_image(
    t: &Tables<'_, impl PhysMem>,
    src: &mut impl FrameSource,
    kernel_pa: impl Fn(u64) -> u64,
) -> Result<(), MapError> {
    let l = image_layout();
    let part = |(s, e): (u64, u64)| (s, kernel_pa(s), e - s);
    map(t, src, part(l.text), MemType::Normal, RX)?;
    map(t, src, part(l.rodata), MemType::Normal, RO)?;
    // Data and .bss, around the guard page.
    map(t, src, part((l.data.0, l.guard.0)), MemType::Normal, RW)?;
    map(t, src, part((l.guard.1, l.data.1)), MemType::Normal, RW)
}

/// Maps one page at `va` to `pa`, read-write and never executable: a page
/// of the per-core window (C12).
pub fn map_page_rw(
    t: &Tables<'_, impl PhysMem>,
    src: &mut impl FrameSource,
    va: u64,
    pa: u64,
) -> Result<(), MapError> {
    map(t, src, (va, pa, PAGE_SIZE), MemType::Normal, RW)
}

/// Maps the direct map: usable RAM read-write, the kept ranges read-only.
/// Neither is ever executable.
pub fn map_direct(
    t: &Tables<'_, impl PhysMem>,
    src: &mut impl FrameSource,
    c: &Classified,
) -> Result<(), MapError> {
    for (s, e) in c.direct_map_rw() {
        map(t, src, (DIRECT_MAP_BASE + s, s, e - s), MemType::Normal, RW)?;
    }
    for (s, e) in c.direct_map_ro() {
        map(t, src, (DIRECT_MAP_BASE + s, s, e - s), MemType::Normal, RO)?;
    }
    Ok(())
}

/// The device window's next free address. Mappings are handed out in
/// order, and each keeps its physical address's offset within 2 MiB, so
/// that blocks can be used.
pub struct DeviceWindow {
    next: u64,
}

impl DeviceWindow {
    pub const fn new() -> Self {
        Self {
            next: DEVICE_WINDOW_BASE,
        }
    }

    /// Maps the pages that hold `[pa, pa + size)` read-write and never
    /// executable, as `mem`, and returns the virtual address of `pa`.
    pub fn map(
        &mut self,
        t: &Tables<'_, impl PhysMem>,
        src: &mut impl FrameSource,
        (pa, size): (u64, u64),
        mem: MemType,
    ) -> Result<u64, MapError> {
        let start = align_down(pa, PAGE_SIZE);
        let end = pa
            .checked_add(size.max(1))
            .and_then(|e| align_up(e, PAGE_SIZE))
            .ok_or(MapError::OutOfRange)?;
        let va = align_up(self.next, BLOCK_2M)
            .and_then(|v| v.checked_add(start & (BLOCK_2M - 1)))
            .ok_or(MapError::OutOfRange)?;
        let next = va.checked_add(end - start).ok_or(MapError::OutOfRange)?;
        if next > DEVICE_WINDOW_BASE + DEVICE_WINDOW_SIZE {
            return Err(MapError::OutOfRange);
        }
        map(t, src, (va, start, end - start), mem, RW)?;
        self.next = next;
        Ok(va + (pa - start))
    }
}
