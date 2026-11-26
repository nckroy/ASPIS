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
//! These are the bootstrap tables. They run the kernel only until
//! [`crate::mm::init`] has built the kernel's own tables and switched to them
//! (kernel specification, "Address-space layout", "Bootstrap tables and the
//! switch"). They map the kernel's image and nothing else, so even before the
//! switch the kernel never maps firmware-reserved memory, such as the UEFI
//! runtime regions (ADR 0039, rule 1), or the seed's page (ADR 0048,
//! rule 2):
//!
//! - The kernel's first 2 MiB are mapped by page, in one level-3 table that
//!   both halves share: text read-only and executable at EL1, the rest of
//!   the image read-write and PXN, and nothing past the image's end.
//! - TTBR0 identity-maps that level-3 table only. `_start` turns the MMU on
//!   there, and the switch's trampoline runs there.
//! - TTBR1 maps the image from the kernel's virtual base to its physical
//!   base: the shared level-3 table, then 2 MiB blocks, read-write and PXN,
//!   and the image's last part by page, in a second level-3 table, so that
//!   nothing past the image's end is mapped.
//! - TTBR1 also holds the boot window: [`WINDOW_TABLES`] level-3 tables right
//!   above the image's 32 MiB, empty at first. Before the switch the kernel
//!   maps there, page by page, exactly what it must reach: the boot
//!   information, the device tree, the UART and the pages of its new tables
//!   (`mm::boot_window`).
//!
//! So the bootstrap tables are W^X too, and `SCTLR_EL1.WXN` is set from the
//! start: no mapping is ever writable and executable (ADR 0048, rule 6).
//! Every leaf is UXN. `link.ld` asserts that text fits in 2 MiB and the
//! image in 32 MiB.
//!
//! Everything here is position-independent: it runs before the MMU is on,
//! at the physical address, and reads only PC-relative addresses. It loads
//! the two absolute pointers in `BOOT_POINTERS`, which the stub has
//! relocated and cleaned to the point of coherency, before it turns the MMU
//! on, so the identity map needs nothing but text.

use core::arch::global_asm;

/// A translation table. The bootstrap tables are in `.bss`, which the stub
/// zeroed and cleaned to the point of coherency.
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
static mut BOOT_PT_L2_LOW: Table = Table([0; 512]);
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.boot_pt")]
static mut BOOT_PT_L3_KERNEL: Table = Table([0; 512]);
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.boot_pt")]
static mut BOOT_PT_L0_HIGH: Table = Table([0; 512]);
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.boot_pt")]
static mut BOOT_PT_L1_HIGH: Table = Table([0; 512]);
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.boot_pt")]
static mut BOOT_PT_L2_HIGH: Table = Table([0; 512]);
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.boot_pt")]
static mut BOOT_PT_L3_TAIL: Table = Table([0; 512]);

/// The boot window's level-3 tables, each 2 MiB of virtual addresses.
pub const WINDOW_TABLES: usize = 4;

/// The boot window's level-3 tables, one after another. `_start` links them
/// into TTBR1 at [`kmem::layout::KERNEL_BASE`] + 32 MiB; `mm::boot_window`
/// fills them.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.boot_pt")]
static mut BOOT_PT_WINDOW: [Table; WINDOW_TABLES] = [const { Table([0; 512]) }; WINDOW_TABLES];

/// The address of the boot window's first level-3 table, in the kernel's
/// image; the others follow it.
pub fn window_tables() -> u64 {
    (&raw const BOOT_PT_WINDOW) as u64
}

/// An empty table. `TTBR0_EL1` holds it, with ASID 0, whenever no user
/// address space is active, and the switch points `TTBR1_EL1` at it while it
/// invalidates the TLB (kernel specification, "Address-space layout").
/// It is read-only data, which the kernel's tables map read-only, so nothing
/// can write it: not even the exception frames of a stack overflow, which
/// land below the guard page, in the dead bootstrap tables.
#[unsafe(link_section = ".rodata.zero_table")]
static ZERO_TABLE: Table = Table([0; 512]);

/// The bootstrap tables' level-0 tables, for `TTBR0_EL1` and `TTBR1_EL1`,
/// as addresses in the kernel's image: for the test that checks they were
/// W^X.
#[cfg(aspis_test_build)]
pub fn bootstrap_roots() -> (u64, u64) {
    (
        (&raw const BOOT_PT_L0_LOW) as u64,
        (&raw const BOOT_PT_L0_HIGH) as u64,
    )
}

/// The address of [`ZERO_TABLE`], in the kernel's image.
pub fn zero_table() -> u64 {
    (&raw const ZERO_TABLE) as u64
}

/// The boot stack's size.
pub const BOOT_STACK_SIZE: usize = 64 * 1024;

/// The boot core's stack, in a page-aligned section of its own that
/// `link.ld` places right above an unmapped guard page.
#[repr(C, align(4096))]
pub struct Stack([u8; BOOT_STACK_SIZE]);

#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.stack")]
static mut BOOT_STACK: Stack = Stack([0; BOOT_STACK_SIZE]);

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
    "    msr spsel, #1",
    "    mov x19, x0",
    // FP and SIMD: Rust code may use them.
    "    mov x1, #(3 << 20)",
    "    msr cpacr_el1, x1",
    "    isb",
    // The two pointers, read now, with the MMU off, from memory the stub
    // cleaned to the point of coherency: x24 is kernel_main, x25 the stack.
    "    adrp x7, BOOT_POINTERS",
    "    add x7, x7, :lo12:BOOT_POINTERS",
    "    ldr x24, [x7]",
    "    ldr x25, [x7, #8]",
    // Physical addresses, PC-relative. x20 is the kernel's physical base,
    // which the stub aligned to 2 MiB, x23 the size of its text, which
    // link.ld page-aligns and keeps within 2 MiB, and x28 the size of the
    // whole image, which link.ld page-aligns and keeps within 32 MiB.
    "    adrp x20, __kernel_start",
    "    adrp x2, BOOT_PT_L0_LOW",
    "    adrp x3, BOOT_PT_L1_LOW",
    "    adrp x4, BOOT_PT_L0_HIGH",
    "    adrp x5, BOOT_PT_L1_HIGH",
    "    adrp x6, BOOT_PT_L2_HIGH",
    "    adrp x21, BOOT_PT_L2_LOW",
    "    adrp x22, BOOT_PT_L3_KERNEL",
    "    adrp x26, BOOT_PT_L3_TAIL",
    "    adrp x27, BOOT_PT_WINDOW",
    "    adrp x23, __text_end",
    "    sub x23, x23, x20",
    "    adrp x28, __kernel_end",
    "    sub x28, x28, x20",
    // TTBR0 has 48 bits: a kernel above them can't be identity-mapped.
    "    lsr x10, x20, #48",
    "    cbnz x10, 9f",
    // x8: a block of normal write-back memory, inner shareable, AF,
    // read-write, PXN and UXN.
    "    movz x8, #0x0705",
    "    movk x8, #0x0060, lsl #48",
    // TTBR0: L0_LOW -> L1_LOW -> L2_LOW -> L3_KERNEL, at the indices of the
    // kernel's physical base. Nothing else is mapped.
    "    ubfx x10, x20, #39, #9",
    "    orr x7, x3, #3",
    "    str x7, [x2, x10, lsl #3]",
    "    ubfx x10, x20, #30, #9",
    "    orr x7, x21, #3",
    "    str x7, [x3, x10, lsl #3]",
    "    ubfx x10, x20, #21, #9",
    "    orr x7, x22, #3",
    "    str x7, [x21, x10, lsl #3]",
    // L3_KERNEL[i]: page i of the kernel's first 2 MiB, normal memory, AF,
    // UXN. Text is read-only and executable at EL1 (AP = 10, PXN = 0); the
    // rest of the image is read-write and PXN; past the image's end the
    // entries stay invalid. The identity map and the high map share this
    // table, so both are W^X (ADR 0048, rule 6).
    "    movz x15, #0x0787",
    "    movk x15, #0x0040, lsl #48",
    "    movz x16, #0x0707",
    "    movk x16, #0x0060, lsl #48",
    "    mov x11, #0",
    "3:",
    "    lsl x10, x11, #12",
    "    cmp x10, x28",
    "    b.hs 4f",
    "    cmp x10, x23",
    "    csel x9, x15, x16, lo",
    "    add x10, x10, x20",
    "    orr x10, x10, x9",
    "    str x10, [x22, x11, lsl #3]",
    "    add x11, x11, #1",
    "    cmp x11, #512",
    "    b.lo 3b",
    "4:",
    // TTBR1: L0_HIGH[256] -> L1_HIGH, L1_HIGH[0] -> L2_HIGH, for the base
    // 0xffff_8000_0000_0000 that link.ld fixes.
    "    orr x7, x5, #3",
    "    str x7, [x4, #(256 * 8)]",
    "    orr x7, x6, #3",
    "    str x7, [x5]",
    // L2_HIGH[0] -> L3_KERNEL. L2_HIGH[c], for c from 1 while 2 MiB chunk c
    // starts inside the image: a 2 MiB block, read-write, PXN, UXN, if the
    // chunk lies wholly inside it; else L3_TAIL, whose pages inside the
    // image are read-write, PXN, UXN, and the rest invalid.
    "    orr x7, x22, #3",
    "    str x7, [x6]",
    "    mov x13, #0x200000",
    "    mov x11, #1",
    "5:",
    "    lsl x10, x11, #21",
    "    cmp x10, x28",
    "    b.hs 7f",
    "    add x12, x10, x13",
    "    cmp x12, x28",
    "    b.hi 6f",
    "    add x12, x20, x10",
    "    orr x12, x12, x8",
    "    str x12, [x6, x11, lsl #3]",
    "    add x11, x11, #1",
    "    cmp x11, #16",
    "    b.lo 5b",
    "    b 7f",
    "6:",
    "    orr x7, x26, #3",
    "    str x7, [x6, x11, lsl #3]",
    "    mov x14, #0",
    "8:",
    "    add x12, x10, x14, lsl #12",
    "    cmp x12, x28",
    "    b.hs 7f",
    "    add x12, x12, x20",
    "    orr x12, x12, x16",
    "    str x12, [x26, x14, lsl #3]",
    "    add x14, x14, #1",
    "    b 8b",
    "7:",
    // L2_HIGH[16 + i] -> BOOT_PT_WINDOW[i]: the boot window, right above the
    // image's 32 MiB, empty until the kernel maps into it.
    "    mov x11, #16",
    "10:",
    "    orr x7, x27, #3",
    "    str x7, [x6, x11, lsl #3]",
    "    add x27, x27, #4096",
    "    add x11, x11, #1",
    "    cmp x11, #(16 + {window_tables})",
    "    b.lo 10b",
    // The tables were written with the MMU off, straight to memory, but the
    // walker will read them through the cache. Invalidate any line of them
    // the cache may hold from before, as Linux's head.S does.
    "    mrs x12, ctr_el0",
    "    ubfx x12, x12, #16, #4",
    "    mov x13, #4",
    "    lsl x12, x13, x12",
    "    adrp x13, __boot_pt_start",
    "    add x13, x13, :lo12:__boot_pt_start",
    "    adrp x14, __boot_pt_end",
    "    add x14, x14, :lo12:__boot_pt_end",
    "    sub x15, x12, #1",
    "    bic x13, x13, x15",
    "11:",
    "    dc ivac, x13",
    "    add x13, x13, x12",
    "    cmp x13, x14",
    "    b.lo 11b",
    "    dsb sy",
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
    // SCTLR: the RES1 bits, M, C, SA, I and WXN, so the hardware treats
    // any writable mapping as execute-never from the first instruction.
    "    movz x7, #0x180d",
    "    movk x7, #0x30d8, lsl #16",
    "    msr sctlr_el1, x7",
    "    isb",
    // Still at the physical address, now through the identity map.
    "    mov sp, x25",
    "    mov x0, x19",
    "    br x24",
    // The kernel is where TTBR0 can't reach. With the MMU off nothing can
    // be printed, so wait forever.
    "9:",
    "    wfe",
    "    b 9b",
    window_tables = const WINDOW_TABLES,
);
