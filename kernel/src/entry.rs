// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The kernel's first instructions.
//!
//! The stub enters `_start` at the kernel's physical address, at EL1, with
//! the MMU and data cache off, exceptions masked and `x0` holding the boot
//! information's physical address (ADR 0041, rule 1). The kernel turns on
//! the MMU itself (C05): this code builds a minimal set of page tables,
//! enables translation, and jumps to [`crate::kernel_main`] at its virtual
//! address in the upper half.
//!
//! The early tables, which C10 replaces with the kernel's real memory
//! management:
//!
//! - TTBR0 identity-maps the first 4 GiB of physical memory with 1 GiB
//!   blocks: the first gigabyte as device memory (the UART and other MMIO
//!   on QEMU `virt`), the rest as normal memory (RAM, the framebuffer, the
//!   boot information, the device tree and the initial image).
//! - TTBR1 maps 32 MiB from the kernel's virtual base to its physical base
//!   with 2 MiB blocks.
//!
//! Everything here is position-independent: it runs before the MMU is on,
//! at the physical address, and reads only PC-relative addresses until it
//! loads the two absolute pointers in `BOOT_POINTERS`, which the stub has
//! relocated.

use core::arch::global_asm;

/// The early translation tables and the boot stack, in `.bss`, which the
/// stub zeroed and cleaned to the point of coherency.
#[repr(C, align(4096))]
pub struct Table([u64; 512]);

#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.boot_pt")]
static mut BOOT_PT_L0_LOW: Table = Table([0; 512]);
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.boot_pt")]
static mut BOOT_PT_L1_LOW: Table = Table([0; 512]);
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.boot_pt")]
static mut BOOT_PT_L0_HIGH: Table = Table([0; 512]);
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.boot_pt")]
static mut BOOT_PT_L1_HIGH: Table = Table([0; 512]);
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.boot_pt")]
static mut BOOT_PT_L2_HIGH: Table = Table([0; 512]);

#[repr(C, align(16))]
pub struct Stack([u8; 64 * 1024]);

#[unsafe(no_mangle)]
static mut BOOT_STACK: Stack = Stack([0; 64 * 1024]);

global_asm!(
    // The virtual addresses the early code jumps to, relocated by the stub.
    ".section .data.boot_pointers, \"aw\"",
    ".balign 8",
    "BOOT_POINTERS:",
    "    .quad kernel_main",
    "    .quad BOOT_STACK + 65536",
    "",
    ".section .text.boot, \"ax\"",
    ".global _start",
    "_start:",
    "    mov x19, x0",
    // FP and SIMD: Rust code may use them.
    "    mov x1, #(3 << 20)",
    "    msr cpacr_el1, x1",
    "    isb",
    // Physical addresses, PC-relative.
    "    adrp x20, __kernel_start",
    "    adrp x2, BOOT_PT_L0_LOW",
    "    adrp x3, BOOT_PT_L1_LOW",
    "    adrp x4, BOOT_PT_L0_HIGH",
    "    adrp x5, BOOT_PT_L1_HIGH",
    "    adrp x6, BOOT_PT_L2_HIGH",
    // TTBR0: L0[0] -> L1_LOW.
    "    orr x7, x3, #3",
    "    str x7, [x2]",
    // L1_LOW[0]: 0 GiB, device-nGnRE, AF, PXN, UXN.
    "    movz x7, #0x0401",
    "    movk x7, #0x0060, lsl #48",
    "    str x7, [x3]",
    // L1_LOW[1..4]: 1, 2, 3 GiB, normal write-back, inner shareable, AF, UXN.
    "    movz x8, #0x0705",
    "    movk x8, #0x0040, lsl #48",
    "    movz x9, #0x4000, lsl #16",
    "    orr x10, x9, x8",
    "    str x10, [x3, #8]",
    "    movz x9, #0x8000, lsl #16",
    "    orr x10, x9, x8",
    "    str x10, [x3, #16]",
    "    movz x9, #0xc000, lsl #16",
    "    orr x10, x9, x8",
    "    str x10, [x3, #24]",
    // TTBR1: L0_HIGH[256] -> L1_HIGH, L1_HIGH[0] -> L2_HIGH, for the base
    // 0xffff_8000_0000_0000 that link.ld fixes.
    "    orr x7, x5, #3",
    "    str x7, [x4, #(256 * 8)]",
    "    orr x7, x6, #3",
    "    str x7, [x5]",
    // L2_HIGH[0..16]: 2 MiB blocks from the kernel's physical base.
    "    mov x11, #0",
    "1:",
    "    add x10, x20, x11, lsl #21",
    "    orr x10, x10, x8",
    "    str x10, [x6, x11, lsl #3]",
    "    add x11, x11, #1",
    "    cmp x11, #16",
    "    b.lo 1b",
    // MAIR: attr0 device-nGnRE, attr1 normal write-back, attr2 non-cacheable.
    "    movz x7, #0xff04",
    "    movk x7, #0x0044, lsl #16",
    "    msr mair_el1, x7",
    // TCR: 48-bit halves, 4 KiB granules, write-back walks, inner
    // shareable; IPS from the CPU's physical address range, at most 48 bits.
    "    mrs x7, id_aa64mmfr0_el1",
    "    and x7, x7, #0xf",
    "    mov x9, #5",
    "    cmp x7, x9",
    "    csel x7, x7, x9, ls",
    "    lsl x7, x7, #32",
    "    movz x9, #0x3510",
    "    movk x9, #0xb510, lsl #16",
    "    orr x7, x7, x9",
    "    msr tcr_el1, x7",
    "    msr ttbr0_el1, x2",
    "    msr ttbr1_el1, x4",
    "    isb",
    "    tlbi vmalle1",
    "    dsb nsh",
    "    isb",
    // SCTLR: the RES1 bits, M, C, SA and I.
    "    movz x7, #0x180d",
    "    movk x7, #0x30d0, lsl #16",
    "    msr sctlr_el1, x7",
    "    isb",
    // Still at the physical address, now through the identity map.
    "    adrp x7, BOOT_POINTERS",
    "    add x7, x7, :lo12:BOOT_POINTERS",
    "    ldr x8, [x7]",
    "    ldr x9, [x7, #8]",
    "    mov sp, x9",
    "    mov x0, x19",
    "    br x8",
);
