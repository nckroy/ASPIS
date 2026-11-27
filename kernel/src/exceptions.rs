// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Exception vectors.
//!
//! - **An IRQ taken at EL1 with `SP_EL1`** saves x0 to x30 in a 32-word
//!   frame on the stack, goes to [`crate::irq::handle`] and returns (C13a;
//!   kernel specification, "The kernel's interrupt controller"). The kernel
//!   takes one only inside its two assembly windows, [`crate::irq::window`]
//!   and [`crate::irq::wait`], which the C11 and C13a tests use.
//! - **Every exception from EL0 in AArch64** (C12) is the kernel entry from
//!   a thread, as seL4's AArch64 entry: `SP_EL1` points at the running
//!   thread's saved context, so the vector stores x0 to x30 straight into
//!   it, and the common path stores `SP_EL0`, `ELR_EL1`, `SPSR_EL1`,
//!   `TPIDR_EL0`, and the FP and SIMD registers, eagerly at every entry
//!   (C78 may make it lazy). It then switches to the core's entry stack,
//!   whose top `TPIDR_EL1` holds, and calls `aspis_user_entry`
//!   ([`crate::sched::entry`]). The way back, `aspis_user_restore`, loads
//!   them all again from the thread's object, points `SP_EL1` at its saved
//!   context and returns with `ERET`. It masks SErrors before `SP_EL1`
//!   moves to the thread's object, so an SError is never taken onto it;
//!   `ERET` unmasks them again for EL0. On the way in, taking the exception
//!   masks them, and the common path unmasks them only once `sp` is the
//!   entry stack (K77). Those are the only two windows
//!   in which the kernel runs with SErrors masked.
//! - **Every other exception** is reported and ends in a panic, which
//!   reaches the UART and the framebuffer (ADR 0009, rule 5; ADR 0042,
//!   rule 7): anything taken at EL1 with `SP_EL0`, an FIQ or SError at EL1,
//!   anything from EL0 in AArch32, which no thread can enter, and every
//!   synchronous exception at EL1. The kernel never takes a page fault (ADR
//!   0048, rule 5).
//! - **An entry-stack overflow** (C12). The synchronous and SError vectors
//!   at EL1 with `SP_EL1` check the stack pointer before they store a frame
//!   on it, since an overflow's fault on the guard page is taken on the
//!   same stack. A stack pointer within 64 KiB below this core's entry
//!   stack, or less than a frame above its base, is an overflow: the vector
//!   switches to the core's emergency stack and panics, naming the core,
//!   having written nothing below the guard (`crate::sched::percore`). The
//!   check borrows `TPIDR_EL0` for x0: in the kernel it holds nothing, since
//!   every entry from EL0 saved the thread's, and the way back loads it
//!   again; and both vectors end in a panic. The IRQ vector, whose handler
//!   returns, doesn't check.

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
    // The synchronous and SError vectors at EL1 with SP_EL1: the overflow
    // check (module docs), then VECTOR's body. x0 = SP - TPIDR_EL1 + 128
    // KiB - 256 = SP - (stack base) + 64 KiB - 256, which is below 64 KiB
    // exactly when SP is within 64 KiB below the base, or less than a
    // frame above it. On the boot stack, or before TPIDR_EL1 is set, it is
    // far larger. 28 instructions, within the vector's 32.
    ".macro CHECKED_VECTOR idx",
    ".balign 128",
    "    msr tpidr_el0, x0",
    "    mrs x0, tpidr_el1",
    "    sub x0, sp, x0",
    "    add x0, x0, #0x20, lsl #12",
    "    sub x0, x0, #(32 * 8)",
    "    cmp x0, #0x10, lsl #12",
    "    mrs x0, tpidr_el0",
    "    b.lo aspis_entry_stack_overflow",
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
    // An exception from EL0: SP_EL1 is the thread's saved context (module
    // docs). 18 instructions, within the vector's 32.
    ".macro USER_VECTOR kind",
    ".balign 128",
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
    "    mov x0, #\\kind",
    "    b aspis_user_common",
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
    "    CHECKED_VECTOR 4",
    "    VECTOR 5",
    "    VECTOR 6",
    "    CHECKED_VECTOR 7",
    // From EL0 in AArch64: synchronous, IRQ, FIQ, SError.
    "    USER_VECTOR 0",
    "    USER_VECTOR 1",
    "    USER_VECTOR 2",
    "    USER_VECTOR 3",
    "    VECTOR 12",
    "    VECTOR 13",
    "    VECTOR 14",
    "    VECTOR 15",
    "",
    // The rest of the entry from EL0. x0 is the kind; x1 to x3 are free,
    // since the vector saved them. The offsets are the saved context's:
    // `SP_EL0` at 248, `ELR_EL1` 256, `SPSR_EL1` 264, `TPIDR_EL0` 272, and
    // the FP and SIMD state 288 bytes on (`crate::sched::object`).
    "aspis_user_common:",
    "    mrs x1, sp_el0",
    "    mrs x2, elr_el1",
    "    stp x1, x2, [sp, #248]",
    "    mrs x1, spsr_el1",
    "    mrs x2, tpidr_el0",
    "    stp x1, x2, [sp, #264]",
    "    add x1, sp, #288",
    "    stp q0, q1, [x1, #(0 * 32)]",
    "    stp q2, q3, [x1, #(1 * 32)]",
    "    stp q4, q5, [x1, #(2 * 32)]",
    "    stp q6, q7, [x1, #(3 * 32)]",
    "    stp q8, q9, [x1, #(4 * 32)]",
    "    stp q10, q11, [x1, #(5 * 32)]",
    "    stp q12, q13, [x1, #(6 * 32)]",
    "    stp q14, q15, [x1, #(7 * 32)]",
    "    stp q16, q17, [x1, #(8 * 32)]",
    "    stp q18, q19, [x1, #(9 * 32)]",
    "    stp q20, q21, [x1, #(10 * 32)]",
    "    stp q22, q23, [x1, #(11 * 32)]",
    "    stp q24, q25, [x1, #(12 * 32)]",
    "    stp q26, q27, [x1, #(13 * 32)]",
    "    stp q28, q29, [x1, #(14 * 32)]",
    "    stp q30, q31, [x1, #(15 * 32)]",
    "    mrs x2, fpcr",
    "    mrs x3, fpsr",
    "    add x1, x1, #512",
    "    stp x2, x3, [x1]",
    // The kernel's Rust may use FP: it runs with the default FPCR, not the
    // thread's trap enables, flush-to-zero or rounding mode.
    "    msr fpcr, xzr",
    "    mrs x1, esr_el1",
    "    mrs x2, far_el1",
    // The core's entry stack; its data begins where the stack ends. Taking
    // the exception masked SErrors; now that `sp` is a kernel stack, an
    // SError may be taken in the kernel again (K77).
    "    mrs x3, tpidr_el1",
    "    mov sp, x3",
    "    msr daifclr, #4",
    "    mov x29, #0",
    "    mov x30, #0",
    "    bl aspis_user_entry",
    "    brk #0",
    "",
    // aspis_user_restore(ctx): returns to EL0 with the context at `ctx`.
    ".global aspis_user_restore",
    "aspis_user_restore:",
    "    msr daifset, #4",
    "    add x1, x0, #288",
    "    ldp q0, q1, [x1, #(0 * 32)]",
    "    ldp q2, q3, [x1, #(1 * 32)]",
    "    ldp q4, q5, [x1, #(2 * 32)]",
    "    ldp q6, q7, [x1, #(3 * 32)]",
    "    ldp q8, q9, [x1, #(4 * 32)]",
    "    ldp q10, q11, [x1, #(5 * 32)]",
    "    ldp q12, q13, [x1, #(6 * 32)]",
    "    ldp q14, q15, [x1, #(7 * 32)]",
    "    ldp q16, q17, [x1, #(8 * 32)]",
    "    ldp q18, q19, [x1, #(9 * 32)]",
    "    ldp q20, q21, [x1, #(10 * 32)]",
    "    ldp q22, q23, [x1, #(11 * 32)]",
    "    ldp q24, q25, [x1, #(12 * 32)]",
    "    ldp q26, q27, [x1, #(13 * 32)]",
    "    ldp q28, q29, [x1, #(14 * 32)]",
    "    ldp q30, q31, [x1, #(15 * 32)]",
    "    add x1, x1, #512",
    "    ldp x2, x3, [x1]",
    "    msr fpcr, x2",
    "    msr fpsr, x3",
    "    ldp x1, x2, [x0, #248]",
    "    msr sp_el0, x1",
    "    msr elr_el1, x2",
    "    ldp x1, x2, [x0, #264]",
    "    msr spsr_el1, x1",
    "    msr tpidr_el0, x2",
    "    mov sp, x0",
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
    "    ldp x0, x1, [sp, #(0 * 16)]",
    "    eret",
    // No straight-line speculation past the ERET, as Linux does
    // (`sb`, where FEAT_SB isn't assumed). The BHB mitigation stays MH's.
    "    dsb nsh",
    "    isb",
    "",
    // An entry-stack overflow: the emergency stack, at TPIDR_EL1 plus
    // `percore::EMERGENCY_TOP_PAGES` pages, then the report. Nothing
    // returns here.
    "aspis_entry_stack_overflow:",
    "    mov x3, sp",
    "    mrs x4, tpidr_el1",
    "    add x4, x4, #{top}, lsl #12",
    "    mov sp, x4",
    "    mrs x0, esr_el1",
    "    mrs x1, elr_el1",
    "    mrs x2, far_el1",
    "    mov x29, #0",
    "    bl aspis_stack_overflow",
    "    brk #0",
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
    top = const crate::sched::percore::EMERGENCY_TOP_PAGES,
);

unsafe extern "C" {
    static aspis_vectors: u8;
    // The boot stack's guard page, from `link.ld`.
    static __stack_guard_start: u8;
    static __stack_guard_end: u8;
}

/// Points VBAR_EL1 at the vectors, and clears `TPIDR_EL1`, which the
/// firmware may have left set, so the scheduler can tell that no core's
/// data is set up yet ([`crate::sched::percore`]).
pub fn install() {
    // SAFETY: the vector table is 2 KiB aligned code in the kernel image;
    // TPIDR_EL1 is the kernel's own, and nothing reads it before
    // `sched::init` sets it.
    unsafe {
        core::arch::asm!(
            "msr vbar_el1, {}",
            "msr tpidr_el1, xzr",
            "isb",
            in(reg) &raw const aspis_vectors,
            options(nostack)
        );
    }
}

/// The IRQ vector's handler. The frame is the interrupted context's
/// registers. An IRQ from EL0 takes the user vectors instead
/// (`crate::sched::entry`).
#[unsafe(no_mangle)]
extern "C" fn aspis_irq(_frame: &mut Frame) {
    crate::irq::handle();
}

const KINDS: [&str; 4] = ["synchronous", "IRQ", "FIQ", "SError"];
const FROM: [&str; 4] = ["EL1 with SP_EL0", "EL1", "EL0 (AArch64)", "EL0 (AArch32)"];

/// An entry-stack overflow, which the synchronous or SError vector found
/// (module docs), on the core's emergency stack. `sp` is the stack pointer
/// it found.
#[unsafe(no_mangle)]
extern "C" fn aspis_stack_overflow(esr: u64, elr: u64, far: u64, sp: u64) -> ! {
    panic!(
        "core {}'s entry stack overflowed: SP {sp:#x}, FAR {far:#x}, ELR {elr:#x}, ESR {esr:#x}",
        crate::sched::percore::index()
    );
}

#[unsafe(no_mangle)]
extern "C" fn aspis_exception(frame: &Frame, idx: u64, esr: u64, elr: u64, far: u64) -> ! {
    let kind = KINDS[(idx % 4) as usize];
    let from = FROM[(idx / 4 % 4) as usize];
    if idx % 4 == 3 {
        // An SError taken in the kernel: reported, then a panic (K77).
        panic!("SError from {from}: ESR {esr:#x}, ELR {elr:#x}");
    }
    // A data abort at EL1 on the boot stack's guard page, which the
    // kernel's tables leave unmapped: the stack overflowed.
    let guard = (&raw const __stack_guard_start) as u64..(&raw const __stack_guard_end) as u64;
    if esr >> 26 == 0x25 && guard.contains(&far) {
        panic!("kernel stack overflow: FAR {far:#x}, ELR {elr:#x}");
    }
    // Or on a core's entry-stack guard, in the per-core window, other than
    // by an overflow, which the vector reports ([`aspis_stack_overflow`]):
    // a stray access there (C12).
    if esr >> 26 == 0x25
        && let Some(core) = crate::sched::percore::guard_of(far)
    {
        panic!("access to core {core}'s entry-stack guard: FAR {far:#x}, ELR {elr:#x}");
    }
    panic!(
        "unexpected {kind} exception from {from}: ESR {esr:#x} (class {:#x}), ELR {elr:#x}, FAR {far:#x}, x0 {:#x}, x30 {:#x}",
        esr >> 26,
        frame.x[0],
        frame.x[30]
    );
}
