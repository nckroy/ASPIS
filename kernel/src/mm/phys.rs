// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! How the kernel reaches physical memory: through the boot window before
//! the switch to its own tables ([`super::boot_window`]), and through the
//! direct map after it (ADR 0048, rule 4).

use core::sync::atomic::{AtomicU64, Ordering};
use kmem::layout::{DIRECT_MAP_BASE, DIRECT_MAP_PA_LIMIT};
use kmem::table::PhysMem;

/// Physical memory as the kernel reaches it through one mapping.
pub trait Window {
    /// The virtual address of physical address `pa`.
    fn va(&self, pa: u64) -> u64;
}

/// Physical memory through the direct map, after the switch. It reaches
/// usable RAM read-write and the kept ranges read-only, and nothing else
/// (kernel specification, "Address-space layout").
///
/// The boot code doesn't use it, since the kernel's tables are built before
/// the switch; the tests do, and so will user address spaces.
#[cfg_attr(not(aspis_test_build), allow(dead_code))]
pub struct DirectMem;

impl Window for DirectMem {
    fn va(&self, pa: u64) -> u64 {
        assert!(
            pa < DIRECT_MAP_PA_LIMIT,
            "{pa:#x} is beyond the direct map's reach"
        );
        DIRECT_MAP_BASE + pa
    }
}

/// Translation tables are read and written one descriptor at a time, with
/// single 64-bit volatile accesses, so a walker never sees a torn
/// descriptor. Tables are normal write-back memory, and walks are
/// cacheable, so no cache maintenance is needed (kernel specification,
/// "Cross-core signals and TLB maintenance").
macro_rules! phys_mem {
    ($t:ty) => {
        impl PhysMem for $t {
            fn read(&self, table: u64, i: usize) -> u64 {
                let at = self.va(table + 8 * i as u64);
                // SAFETY: `table` is a translation table the kernel made,
                // which the window maps as normal memory, and `i` is below
                // 512.
                unsafe { core::ptr::read_volatile(at as *const u64) }
            }

            fn write(&self, table: u64, i: usize, v: u64) {
                let at = self.va(table + 8 * i as u64);
                // SAFETY: as for `read`; the kernel owns the table.
                unsafe { core::ptr::write_volatile(at as *mut u64, v) }
            }
        }
    };
}

phys_mem!(super::boot_window::BootWindow);
phys_mem!(DirectMem);

/// The kernel image's physical base, from the boot information's kernel
/// placement (ADR 0041, rule 3).
static KERNEL_PHYS: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" {
    static __kernel_start: u8;
}

/// The kernel image's virtual base, which `link.ld` fixes.
pub fn kernel_start() -> u64 {
    (&raw const __kernel_start) as u64
}

/// Records where the stub loaded the image.
pub fn set_kernel_phys(pa: u64) {
    KERNEL_PHYS.store(pa, Ordering::Relaxed);
}

/// The physical address of `va`, an address in the kernel's image.
pub fn kernel_pa(va: u64) -> u64 {
    let start = kernel_start();
    assert!(
        va >= start && va - start < kmem::layout::KERNEL_MAX_SIZE,
        "{va:#x} is outside the kernel's image"
    );
    va - start + KERNEL_PHYS.load(Ordering::Relaxed)
}
