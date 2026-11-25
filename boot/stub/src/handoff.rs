// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Entering the kernel in the state ADR 0041, rule 1 fixes: EL1, MMU and
//! data cache off, everything the kernel will read cleaned to the point of
//! coherency, exceptions masked, `x0` holding the boot information's
//! physical address and `x1` to `x3` zero.

use core::arch::{asm, global_asm};

/// The exception level the firmware runs the stub at.
pub fn current_el() -> u32 {
    let el: u64;
    // SAFETY: reading CurrentEL has no side effects.
    unsafe { asm!("mrs {}, CurrentEL", out(reg) el, options(nomem, nostack)) };
    ((el >> 2) & 3) as u32
}

/// Cleans and invalidates `[start, start + len)` to the point of coherency,
/// so the kernel, which starts with the caches off, sees what the stub wrote,
/// and no dirty line can later overwrite what the kernel writes uncached.
pub fn clean_invalidate(start: usize, len: usize) {
    let ctr: u64;
    // SAFETY: reading CTR_EL0 has no side effects.
    unsafe { asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack)) };
    let line = 4usize << ((ctr >> 16) & 0xf);
    let mut addr = start & !(line - 1);
    while addr < start + len {
        // SAFETY: `addr` lies in memory the stub owns; DC CIVAC only
        // affects caches.
        unsafe { asm!("dc civac, {}", in(reg) addr, options(nostack)) };
        addr += line;
    }
    // SAFETY: barriers only.
    unsafe { asm!("dsb sy", "isb", options(nostack)) };
}

unsafe extern "C" {
    fn aspis_enter_kernel(entry: u64, boot_info: u64, el: u64) -> !;
}

/// Turns the MMU and caches off and jumps to the kernel. Must be called
/// after `ExitBootServices`, with the stub's own code identity-mapped, as
/// UEFI guarantees.
///
/// # Safety
///
/// `entry` must be the kernel's physical entry point, loaded and relocated,
/// and `boot_info` valid boot information, both cleaned to the PoC.
pub unsafe fn enter_kernel(entry: u64, boot_info: u64) -> ! {
    // SAFETY: the caller's contract.
    unsafe { aspis_enter_kernel(entry, boot_info, current_el() as u64) }
}

// x0 = physical entry, x1 = boot information, x2 = the current EL.
global_asm!(
    ".global aspis_enter_kernel",
    ".balign 64",
    "aspis_enter_kernel:",
    "    msr daifset, #0xf",
    "    mov x19, x0",
    "    mov x20, x1",
    "    cmp x2, #2",
    "    b.eq 2f",
    // EL1: turn off the MMU and both caches, then branch.
    "    mrs x3, sctlr_el1",
    "    bic x3, x3, #1",
    "    bic x3, x3, #4",
    "    bic x3, x3, #0x1000",
    "    msr sctlr_el1, x3",
    "    isb",
    "    ic iallu",
    "    tlbi vmalle1",
    "    dsb nsh",
    "    isb",
    // Enter through an exception return, so PSTATE is known: EL1h, which
    // uses SP_EL1, with DAIF masked (ADR 0041, rule 1).
    "    mov x3, #0x3c5",
    "    msr spsr_el1, x3",
    "    msr elr_el1, x19",
    "    mov x0, x20",
    "    mov x1, xzr",
    "    mov x2, xzr",
    "    mov x3, xzr",
    "    isb",
    "    eret",
    // EL2: turn off EL2's MMU and caches, make EL1 AArch64 with no traps
    // the kernel would trip over, and drop to EL1h with DAIF masked.
    "2:",
    "    mrs x3, sctlr_el2",
    "    bic x3, x3, #1",
    "    bic x3, x3, #4",
    "    bic x3, x3, #0x1000",
    "    msr sctlr_el2, x3",
    "    isb",
    "    ic iallu",
    "    tlbi alle2",
    "    dsb nsh",
    "    isb",
    // HCR_EL2: RW (EL1 is AArch64), nothing else; this also clears E2H.
    "    movz x3, #0x8000, lsl #16",
    "    msr hcr_el2, x3",
    // The layout of the registers below depends on HCR_EL2.E2H.
    "    isb",
    // EL1 may use the physical counter and timer.
    "    mov x3, #3",
    "    msr cnthctl_el2, x3",
    "    msr cntvoff_el2, xzr",
    // CPTR_EL2: only its RES1 bits, so FP, SIMD and SVE don't trap to EL2.
    // Bit 12 (TSM) is RES1 without SME and traps SME with it: clear it
    // when the CPU has SME.
    "    mov x3, #0x32ff",
    "    mrs x4, id_aa64pfr1_el1",
    "    ubfx x4, x4, #24, #4",
    "    cbz x4, 3f",
    "    bic x3, x3, #0x1000",
    "3:",
    "    msr cptr_el2, x3",
    "    msr hstr_el2, xzr",
    "    msr vttbr_el2, xzr",
    // SCTLR_EL1: the RES1 bits, MMU and caches off.
    "    movz x3, #0x0800",
    "    movk x3, #0x30d0, lsl #16",
    "    msr sctlr_el1, x3",
    // EL1h, DAIF masked.
    "    mov x3, #0x3c5",
    "    msr spsr_el2, x3",
    "    msr elr_el2, x19",
    "    mov x0, x20",
    "    mov x1, xzr",
    "    mov x2, xzr",
    "    mov x3, xzr",
    "    isb",
    "    eret",
);
