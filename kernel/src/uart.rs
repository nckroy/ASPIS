// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The PL011 UART the kernel's console also writes to (ADR 0009, rule 3).
//! It is found in the device tree; the firmware has already set it up.

use core::sync::atomic::{AtomicUsize, Ordering};

/// The UART's base address, through the early identity map; zero until found.
static BASE: AtomicUsize = AtomicUsize::new(0);

const DR: usize = 0x00;
const FR: usize = 0x18;
const FR_TXFF: u32 = 1 << 5;

/// Finds the first PL011 in the device tree, preferring the one
/// `/chosen/stdout-path` names.
pub fn init(fdt: &fdt::Fdt<'_>) -> Option<usize> {
    let chosen = fdt.chosen().stdout().filter(|n| {
        n.compatible()
            .is_some_and(|c| c.all().any(|s| s == "arm,pl011"))
    });
    let node = chosen.or_else(|| fdt.find_compatible(&["arm,pl011"]))?;
    let base = node.reg()?.next()?.starting_address as usize;
    // The early identity map covers the first 4 GiB only.
    if base == 0 || base >= 1 << 32 {
        return None;
    }
    BASE.store(base, Ordering::Release);
    Some(base)
}

fn put(base: usize, byte: u8) {
    // SAFETY: `base` is a PL011 found in the device tree, mapped as device
    // memory by the early tables.
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
