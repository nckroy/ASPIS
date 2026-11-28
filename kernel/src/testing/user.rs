// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The EL0 programs the in-QEMU tests run (test builds only).
//!
//! They are assembled into one position-independent blob in read-only
//! data, which the kernel never executes: a test copies the blob into a
//! frame and maps it read-only and executable in the thread's address space
//! (`crate::sched::testkit`). The blob starts with a marker that `cargo
//! xtask check-production` looks for, so production images can't hold it.
//! Each program reaches the kernel only through the test trap
//! ([`super::trap`]), takes its arguments in x0 to x7, as the test writes
//! them, and needs no stack. The IPC programs use K28's registers
//! (`kipc::msg::regs`).

use core::arch::global_asm;

/// The fp program's lines for each of v0 to v31: `fill` sets the register
/// to x3, and `check` compares both its halves with x3; each then adds 1 to
/// x3.
macro_rules! each_v {
    (fill) => {
        each_v!(@ fill 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31)
    };
    (check) => {
        each_v!(@ check 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31)
    };
    (@ fill $($r:literal)*) => {
        concat!($("    dup v", $r, ".2d, x3\n    add x3, x3, #1\n",)*)
    };
    (@ check $($r:literal)*) => {
        concat!($(
            "    mov x5, v", $r, ".d[0]\n    cmp x5, x3\n    b.ne 9f\n",
            "    mov x5, v", $r, ".d[1]\n    cmp x5, x3\n    b.ne 9f\n",
            "    add x3, x3, #1\n",
        )*)
    };
}

global_asm!(
    ".section .rodata.aspis_user_tests, \"a\"",
    ".balign 16",
    ".global aspis_user_blob",
    "aspis_user_blob:",
    ".ascii \"ASPIS-USER-TESTS\"",
    // The test trap (`super::trap`): the call's number in x8.
    ".macro TRAP num",
    "    mov x8, #\\num",
    "    svc #0x7e57",
    ".endm",
    "",
    // report_end(x0): reports x0, then ends.
    ".global aspis_user_report_end",
    "aspis_user_report_end:",
    "    TRAP 2",
    "    TRAP 0",
    "    b .",
    "",
    // spin_report(x0, x1): forever: spins x1 times, then reports x0.
    ".global aspis_user_spin_report",
    "aspis_user_spin_report:",
    "    mov x19, x0",
    "1:  mov x2, x1",
    "2:  subs x2, x2, #1",
    "    b.ne 2b",
    "    mov x0, x19",
    "    TRAP 2",
    "    b 1b",
    "",
    // yield_report(x0): forever: reports x0, then yields.
    ".global aspis_user_yield_report",
    "aspis_user_yield_report:",
    "    mov x19, x0",
    "1:  mov x0, x19",
    "    TRAP 2",
    "    TRAP 1",
    "    b 1b",
    "",
    // sleep_report(x0): sleeps until the deadline x0, reports the result,
    // then ends.
    ".global aspis_user_sleep_report",
    "aspis_user_sleep_report:",
    "    TRAP 3",
    "    TRAP 2",
    "    TRAP 0",
    "    b .",
    "",
    // spin(): forever.
    ".global aspis_user_spin",
    "aspis_user_spin:",
    "    b .",
    "",
    // fp(x0, x1, x2): fills v0 to v31 with x0, x0 + 1, ..., then x1 times
    // spins x2 times and checks every register still holds its value;
    // reports 1, or 0xbad at the first that doesn't, then ends.
    ".global aspis_user_fp",
    "aspis_user_fp:",
    "    mov x3, x0",
    each_v!(fill),
    "1:  mov x4, x2",
    "2:  subs x4, x4, #1",
    "    b.ne 2b",
    "    mov x3, x0",
    each_v!(check),
    "    subs x1, x1, #1",
    "    b.ne 1b",
    "    mov x0, #1",
    "    b 8f",
    "9:  mov x0, #0xbad",
    "8:  TRAP 2",
    "    TRAP 0",
    "    b .",
    "",
    // tpidr(x0, x1): writes x0 to TPIDR_EL0, spins x1 times, reports
    // TPIDR_EL0, then x19 and x30 as the test wrote them, then ends.
    ".global aspis_user_tpidr",
    "aspis_user_tpidr:",
    "    msr tpidr_el0, x0",
    "1:  subs x1, x1, #1",
    "    b.ne 1b",
    "    mrs x0, tpidr_el0",
    "    TRAP 2",
    "    mov x0, x19",
    "    TRAP 2",
    "    mov x0, x30",
    "    TRAP 2",
    "    TRAP 0",
    "    b .",
    "",
    // counts(): reports the virtual count and the frequency, which EL0 may
    // read (K19), then reads the physical count, which traps.
    ".global aspis_user_counts",
    "aspis_user_counts:",
    "    mrs x0, cntvct_el0",
    "    TRAP 2",
    "    mrs x0, cntfrq_el0",
    "    TRAP 2",
    "    mrs x0, cntpct_el0",
    "    TRAP 2",
    "    TRAP 0",
    "    b .",
    "",
    // brk(): a breakpoint, a debug fault (K70).
    ".global aspis_user_brk",
    "aspis_user_brk:",
    "    brk #1",
    "    b .",
    "",
    // svc_unknown(): a system call the kernel doesn't know, then, if its
    // handler resumes it, reports 0x51 and ends.
    ".global aspis_user_svc_unknown",
    "aspis_user_svc_unknown:",
    "    svc #1",
    "    mov x0, #0x51",
    "    TRAP 2",
    "    TRAP 0",
    "    b .",
    "",
    // load(x0): loads from the address x0, reports the value, then ends.
    ".global aspis_user_load",
    "aspis_user_load:",
    "    ldr x0, [x0]",
    "    TRAP 2",
    "    TRAP 0",
    "    b .",
    "",
    // udf(): an undefined instruction, a user exception with no fault
    // address; if its handler resumes it past the instruction, reports
    // 0xdf and ends.
    ".global aspis_user_udf",
    "aspis_user_udf:",
    "    udf #0",
    "    mov x0, #0xdf",
    "    TRAP 2",
    "    TRAP 0",
    "    b .",
    "",
    // serve(x0 endpoint, x1 spins, x2 reply object): forever: receives on
    // x0 with x2; on a call, checks the receive's status in x0 is ok,
    // reports its first word, spins x1 times, then replies with a one-word
    // message, the word plus 1, and receives again. A status other than ok
    // reports 0xbad and spins.
    ".global aspis_user_serve",
    "aspis_user_serve:",
    "    mov x19, x0",
    "    mov x20, x1",
    "    mov x22, x2",
    "    mov x6, x22",
    "    mov x7, #0",
    "    TRAP 5",
    "1:  cbnz x0, 9f",
    "    mov x21, x2",
    "    mov x0, x2",
    "    TRAP 2",
    "    mov x2, x20",
    "2:  subs x2, x2, #1",
    "    b.hi 2b",
    "    mov x0, x19",
    "    mov x1, #8",
    "    add x2, x21, #1",
    "    mov x6, x22",
    "    mov x7, #0",
    "    TRAP 10",
    "    b 1b",
    "9:  mov x0, #0xbad",
    "    TRAP 2",
    "    b .",
    "",
    // call_report(x0 endpoint, x1 deadline, x2 word): calls with a one-word
    // message, reports the call's status, then the reply's first word,
    // then ends.
    ".global aspis_user_call_report",
    "aspis_user_call_report:",
    "    mov x7, x1",
    "    mov x1, #8",
    "    TRAP 4",
    "    mov x19, x2",
    "    TRAP 2",
    "    mov x0, x19",
    "    TRAP 2",
    "    TRAP 0",
    "    b .",
    "",
    // call_count(x0 endpoint, x1 calls): calls x1 times with the words 1,
    // 2, ..., each a one-word message, and checks each reply is the word
    // plus 1; reports the calls made, or 0xbad at the first wrong reply,
    // then ends.
    ".global aspis_user_call_count",
    "aspis_user_call_count:",
    "    mov x19, x0",
    "    mov x20, x1",
    "    mov x21, #0",
    "1:  add x21, x21, #1",
    "    mov x0, x19",
    "    mov x1, #8",
    "    mov x2, x21",
    "    mov x7, #0",
    "    TRAP 4",
    "    cbnz x0, 9f",
    "    add x3, x21, #1",
    "    cmp x2, x3",
    "    b.ne 9f",
    "    cmp x21, x20",
    "    b.lo 1b",
    "    mov x0, x21",
    "    b 8f",
    "9:  mov x0, #0xbad",
    "8:  TRAP 2",
    "    TRAP 0",
    "    b .",
    "",
    // trap_report(x0, x1, x2 arguments, x3 the call's number, x6, x7):
    // makes trap call x3, reports its x0, then ends.
    ".global aspis_user_trap_report",
    "aspis_user_trap_report:",
    "    mov x8, x3",
    "    svc #0x7e57",
    "    TRAP 2",
    "    TRAP 0",
    "    b .",
    "",
    // trap_value_report(x0 to x3 arguments, x5 the call's number, x7):
    // makes trap call x5, reports its x0, then its x1 (a count or a mask),
    // then ends. For the eventcount and wait-set calls, which take x0 to
    // x3 and x7 (C14).
    ".global aspis_user_trap_value_report",
    "aspis_user_trap_value_report:",
    "    mov x8, x5",
    "    svc #0x7e57",
    "    mov x19, x1",
    "    TRAP 2",
    "    mov x0, x19",
    "    TRAP 2",
    "    TRAP 0",
    "    b .",
    "",
    // revoke_report(x0 address): revokes the capability at x0, reports the
    // result, then ends.
    ".global aspis_user_revoke_report",
    "aspis_user_revoke_report:",
    "    TRAP 7",
    "    TRAP 2",
    "    TRAP 0",
    "    b .",
    "",
    // count_report(x0 unused, x1 spins): forever: counts from 1, reports
    // the count, then spins x1 times. A report lost or made twice shows as
    // a gap or a repeat.
    ".global aspis_user_count_report",
    "aspis_user_count_report:",
    "    mov x19, #0",
    "    mov x20, x1",
    "1:  add x19, x19, #1",
    "    mov x0, x19",
    "    TRAP 2",
    "    mov x2, x20",
    "2:  subs x2, x2, #1",
    "    b.hi 2b",
    "    b 1b",
    "",
    // load_loop(x0 address, x1 spins): forever: loads from x0, reports the
    // value, then spins x1 times.
    ".global aspis_user_load_loop",
    "aspis_user_load_loop:",
    "    mov x19, x0",
    "    mov x20, x1",
    "1:  ldr x0, [x19]",
    "    TRAP 2",
    "    mov x2, x20",
    "2:  subs x2, x2, #1",
    "    b.hi 2b",
    "    b 1b",
    "",
    ".global aspis_user_blob_end",
    "aspis_user_blob_end:",
);

unsafe extern "C" {
    static aspis_user_blob: u8;
    static aspis_user_blob_end: u8;
    static aspis_user_report_end: u8;
    static aspis_user_spin_report: u8;
    static aspis_user_yield_report: u8;
    static aspis_user_sleep_report: u8;
    static aspis_user_spin: u8;
    static aspis_user_fp: u8;
    static aspis_user_tpidr: u8;
    static aspis_user_counts: u8;
    static aspis_user_brk: u8;
    static aspis_user_svc_unknown: u8;
    static aspis_user_load: u8;
    static aspis_user_udf: u8;
    static aspis_user_serve: u8;
    static aspis_user_call_report: u8;
    static aspis_user_call_count: u8;
    static aspis_user_trap_report: u8;
    static aspis_user_trap_value_report: u8;
    static aspis_user_revoke_report: u8;
    static aspis_user_count_report: u8;
    static aspis_user_load_loop: u8;
}

/// An EL0 test program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Program {
    /// Reports x0, then ends.
    ReportEnd,
    /// Forever spins x1 times, then reports x0.
    SpinReport,
    /// Forever reports x0, then yields.
    YieldReport,
    /// Sleeps until the deadline x0, reports the result, ends.
    SleepReport,
    /// Spins forever.
    Spin,
    /// Checks its FP and SIMD registers across preemptions (x0 pattern, x1
    /// rounds, x2 spins per round); reports 1, or 0xbad.
    Fp,
    /// Writes TPIDR_EL0 (x0), spins (x1), reports it, then x19 and x30.
    Tpidr,
    /// Reports the virtual count and frequency, then reads the physical
    /// count, which traps.
    Counts,
    /// A breakpoint.
    Brk,
    /// An unknown system call, then reports 0x51 and ends.
    SvcUnknown,
    /// Loads from x0, reports the value, ends.
    Load,
    /// An undefined instruction; resumed past it, reports 0xdf and ends.
    Udf,
    /// A server's loop on the endpoint at x0 with the reply object at x2,
    /// spinning x1 times on each call; reports each caller's first word,
    /// and replies with it plus 1. A receive whose status isn't ok reports
    /// 0xbad.
    Serve,
    /// Calls the endpoint at x0, with deadline x1 and word x2; reports the
    /// status, then the reply's first word, then ends.
    CallReport,
    /// Calls the endpoint at x0 x1 times, checking each reply; reports the
    /// calls made, or 0xbad, then ends.
    CallCount,
    /// Makes trap call x3 with x0 to x2, x6 and x7 as the test wrote them;
    /// reports its x0, then ends.
    TrapReport,
    /// Makes trap call x5 with x0 to x3 and x7 as the test wrote them;
    /// reports its x0, then its x1, then ends.
    TrapValueReport,
    /// Revokes the capability at x0, reports the result, ends.
    RevokeReport,
    /// Forever counts from 1, reports the count, and spins x1 times.
    CountReport,
    /// Forever loads from x0, reports the value, and spins x1 times.
    LoadLoop,
}

/// The blob, the marker included.
pub fn blob() -> &'static [u8] {
    let start = &raw const aspis_user_blob;
    let end = &raw const aspis_user_blob_end;
    // SAFETY: the linker placed the blob, contiguous, between the two
    // symbols, in read-only data.
    unsafe { core::slice::from_raw_parts(start, end as usize - start as usize) }
}

impl Program {
    /// The program's offset in the blob.
    pub fn offset(self) -> u64 {
        let p = match self {
            Program::ReportEnd => &raw const aspis_user_report_end,
            Program::SpinReport => &raw const aspis_user_spin_report,
            Program::YieldReport => &raw const aspis_user_yield_report,
            Program::SleepReport => &raw const aspis_user_sleep_report,
            Program::Spin => &raw const aspis_user_spin,
            Program::Fp => &raw const aspis_user_fp,
            Program::Tpidr => &raw const aspis_user_tpidr,
            Program::Counts => &raw const aspis_user_counts,
            Program::Brk => &raw const aspis_user_brk,
            Program::SvcUnknown => &raw const aspis_user_svc_unknown,
            Program::Load => &raw const aspis_user_load,
            Program::Udf => &raw const aspis_user_udf,
            Program::Serve => &raw const aspis_user_serve,
            Program::CallReport => &raw const aspis_user_call_report,
            Program::CallCount => &raw const aspis_user_call_count,
            Program::TrapReport => &raw const aspis_user_trap_report,
            Program::TrapValueReport => &raw const aspis_user_trap_value_report,
            Program::RevokeReport => &raw const aspis_user_revoke_report,
            Program::CountReport => &raw const aspis_user_count_report,
            Program::LoadLoop => &raw const aspis_user_load_loop,
        };
        p as u64 - (&raw const aspis_user_blob) as u64
    }
}
