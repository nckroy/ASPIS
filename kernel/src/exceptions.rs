// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Exception vectors. Every vector saves x0 to x30 in a 32-word frame on
//! the stack.
//!
//! - **An IRQ taken at EL1 with `SP_EL1`** goes to [`crate::irq::handle`]
//!   and returns (C13a; kernel specification, "The kernel's interrupt
//!   controller"). The kernel takes one only inside its two assembly
//!   windows, [`crate::irq::window`] and [`crate::irq::wait`].
//! - **Every other exception** is unexpected until there are threads (C12),
//!   and is reported and ends in a panic, which reaches the UART and the
//!   framebuffer (ADR 0009, rule 5; ADR 0042, rule 7): IRQs from EL1 with
//!   `SP_EL0` and from EL0 (C12 adds the user entry path), every FIQ (the
//!   kernel never unmasks FIQs), and every SError. A synchronous abort
//!   taken at EL1 stays a panic after C12: the kernel never takes a page
//!   fault (ADR 0048, rule 5).

use core::arch::global_asm;

#[repr(C)]
pub struct Frame {
    pub x: [u64; 31],
    pub _pad: u64,
}

global_asm!(
    ".macro VECTOR idx",
    ".balign 128",
    "    sub sp, sp, #(32 * 8)",
    "    stp x0, x1, [sp, #(0 * 16)]",
    "    stp x2, x3, [sp, #(1 * 16)]",
    "    stp x4, x5, [sp, #(2 * 16)]",
    "    stp x6, x7, [sp, #(3 * 16)]",
    "    stp x8, x9, [sp, #(4 * 16)]",
    "    stp x10, x11, [sp, #(5 * 16)]",
    "    stp x12, x13, [sp, #(6 * 16)]",
    "    stp x14, x15, [sp, #(7 * 16)]",
    "    stp x16, x17, [sp, #(8 * 16)]",
    "    stp x18, x19, [sp, #(9 * 16)]",
    "    stp x20, x21, [sp, #(10 * 16)]",
    "    stp x22, x23, [sp, #(11 * 16)]",
    "    stp x24, x25, [sp, #(12 * 16)]",
    "    stp x26, x27, [sp, #(13 * 16)]",
    "    stp x28, x29, [sp, #(14 * 16)]",
    "    str x30, [sp, #(15 * 16)]",
    "    mov x0, sp",
    "    mov x1, #\\idx",
    "    b aspis_exception_common",
    ".endm",
    "",
    ".section .text.vectors, \"ax\"",
    ".balign 2048",
    ".global aspis_vectors",
    "aspis_vectors:",
    "    VECTOR 0",
    "    VECTOR 1",
    "    VECTOR 2",
    "    VECTOR 3",
    "    VECTOR 4",
    "    VECTOR 5",
    "    VECTOR 6",
    "    VECTOR 7",
    "    VECTOR 8",
    "    VECTOR 9",
    "    VECTOR 10",
    "    VECTOR 11",
    "    VECTOR 12",
    "    VECTOR 13",
    "    VECTOR 14",
    "    VECTOR 15",
    "",
    "aspis_exception_common:",
    // Vector 5: an IRQ at EL1 with SP_EL1.
    "    cmp x1, #5",
    "    b.eq aspis_irq_common",
    "    mrs x2, esr_el1",
    "    mrs x3, elr_el1",
    "    mrs x4, far_el1",
    "    b aspis_exception",
    "",
    // The IRQ path. ELR_EL1 and SPSR_EL1 are kept in x21 and x22, which
    // the Rust handler preserves as callee-saved; their old values are in
    // the frame. Every register is restored from the frame, and the stack
    // is as the vector found it.
    "aspis_irq_common:",
    "    mrs x21, elr_el1",
    "    mrs x22, spsr_el1",
    "    mov x0, sp",
    "    bl aspis_irq",
    "    msr elr_el1, x21",
    "    msr spsr_el1, x22",
    "    ldp x0, x1, [sp, #(0 * 16)]",
    "    ldp x2, x3, [sp, #(1 * 16)]",
    "    ldp x4, x5, [sp, #(2 * 16)]",
    "    ldp x6, x7, [sp, #(3 * 16)]",
    "    ldp x8, x9, [sp, #(4 * 16)]",
    "    ldp x10, x11, [sp, #(5 * 16)]",
    "    ldp x12, x13, [sp, #(6 * 16)]",
    "    ldp x14, x15, [sp, #(7 * 16)]",
    "    ldp x16, x17, [sp, #(8 * 16)]",
    "    ldp x18, x19, [sp, #(9 * 16)]",
    "    ldp x20, x21, [sp, #(10 * 16)]",
    "    ldp x22, x23, [sp, #(11 * 16)]",
    "    ldp x24, x25, [sp, #(12 * 16)]",
    "    ldp x26, x27, [sp, #(13 * 16)]",
    "    ldp x28, x29, [sp, #(14 * 16)]",
    "    ldr x30, [sp, #(15 * 16)]",
    "    add sp, sp, #(32 * 8)",
    "    eret",
);

unsafe extern "C" {
    static aspis_vectors: u8;
    // The boot stack's guard page, from `link.ld`.
    static __stack_guard_start: u8;
    static __stack_guard_end: u8;
}

/// Points VBAR_EL1 at the vectors.
pub fn install() {
    // SAFETY: the vector table is 2 KiB aligned code in the kernel image.
    unsafe {
        core::arch::asm!(
            "msr vbar_el1, {}",
            "isb",
            in(reg) &raw const aspis_vectors,
            options(nostack)
        );
    }
}

/// The IRQ vector's handler. The frame is the interrupted context's
/// registers; C12 makes it a thread's saved context for an IRQ from EL0.
#[unsafe(no_mangle)]
extern "C" fn aspis_irq(_frame: &mut Frame) {
    crate::irq::handle();
}

const KINDS: [&str; 4] = ["synchronous", "IRQ", "FIQ", "SError"];
const FROM: [&str; 4] = ["EL1 with SP_EL0", "EL1", "EL0 (AArch64)", "EL0 (AArch32)"];

#[unsafe(no_mangle)]
extern "C" fn aspis_exception(frame: &Frame, idx: u64, esr: u64, elr: u64, far: u64) -> ! {
    let kind = KINDS[(idx % 4) as usize];
    let from = FROM[(idx / 4 % 4) as usize];
    // A data abort at EL1 on the boot stack's guard page, which the
    // kernel's tables leave unmapped: the stack overflowed.
    let guard = (&raw const __stack_guard_start) as u64..(&raw const __stack_guard_end) as u64;
    if esr >> 26 == 0x25 && guard.contains(&far) {
        panic!("kernel stack overflow: FAR {far:#x}, ELR {elr:#x}");
    }
    panic!(
        "unexpected {kind} exception from {from}: ESR {esr:#x} (class {:#x}), ELR {elr:#x}, FAR {far:#x}, x0 {:#x}, x30 {:#x}",
        esr >> 26,
        frame.x[0],
        frame.x[30]
    );
}
