// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The PL011 UART the kernel's console also writes to (ADR 0009, rule 3).
//! It is found in the device tree; the firmware has already set it up.
//!
//! The kernel first writes to it through the bootstrap tables' boot window
//! ([`init`]). Once the kernel has its own tables, the UART is mapped in the
//! device window, and [`rebase`] moves the console there as soon as the
//! kernel has switched to them.

use core::sync::atomic::{AtomicUsize, Ordering};

/// The UART's base address, in the boot window until [`rebase`], then in
/// the device window; zero until found.
static BASE: AtomicUsize = AtomicUsize::new(0);

const DR: usize = 0x00;
const FR: usize = 0x18;
const FR_TXFF: u32 = 1 << 5;

/// The `(base, size)` of the PL011 the kernel drives: the one
/// `/chosen/stdout-path` names, else the first in the device tree. `None`
/// if there is none. An error if there is one whose physical address the
/// kernel can't read for certain: it must neither write to a wrong address
/// nor give its UART away ([`crate::mm::devices`]).
pub fn find(fdt: &fdt::Fdt<'_>) -> Result<Option<(u64, u64)>, crate::mm::FindError> {
    let chosen = fdt.chosen().stdout().filter(|n| {
        n.compatible()
            .is_some_and(|c| c.all().any(|s| s == "arm,pl011"))
    });
    let Some(node) = chosen.or_else(|| fdt.find_compatible(&["arm,pl011"])) else {
        return Ok(None);
    };
    const WHAT: &str = "the UART";
    let Some(reg) = crate::mm::physical_reg(fdt, node, WHAT)?.next() else {
        return Err(crate::mm::FindError::NoReg(WHAT));
    };
    let base = reg.starting_address as u64;
    Ok((base != 0).then_some((base, reg.size.unwrap_or(4096) as u64)))
}

/// Starts writing to the UART, which `map` maps as device memory and
/// returns the address of. Does nothing if there is no UART the kernel can
/// drive.
pub fn init(fdt: &fdt::Fdt<'_>, map: impl FnOnce(u64, u64) -> Option<u64>) {
    if let Ok(Some((base, size))) = find(fdt)
        && let Some(va) = map(base, size)
    {
        BASE.store(va as usize, Ordering::Release);
    }
}

/// Moves the console to the UART's address in the device window, which the
/// kernel's own tables map as device memory.
pub fn rebase(va: u64) {
    BASE.store(va as usize, Ordering::Release);
}

fn put(base: usize, byte: u8) {
    // SAFETY: `base` is a PL011 found in the device tree, mapped as device
    // memory: in the boot window until `rebase`, then in the device window.
    unsafe {
        while core::ptr::read_volatile((base + FR) as *const u32) & FR_TXFF != 0 {
            core::hint::spin_loop();
        }
        core::ptr::write_volatile((base + DR) as *mut u32, byte as u32);
    }
}

/// Writes text, turning `\n` into `\r\n`. Does nothing until [`init`].
pub fn write(s: &str) {
    let base = BASE.load(Ordering::Acquire);
    if base == 0 {
        return;
    }
    for b in s.bytes() {
        if b == b'\n' {
            put(base, b'\r');
        }
        put(base, b);
    }
}
