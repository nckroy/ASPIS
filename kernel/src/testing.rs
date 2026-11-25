// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! In-QEMU tests, compiled only into test builds (ADR 0036, rules 5 and 6).
//!
//! Tests register themselves in the `.aspis_tests` linker section, which
//! works on stable Rust. The runner reports each result on the UART, one
//! line each, and ends QEMU through semihosting with an exit status. The
//! host-side runner (`cargo xtask test`) reads the lines and the status.

use crate::uart;

pub struct TestCase {
    pub name: &'static str,
    pub run: fn(),
}

/// Marks a test build; CI checks that production images never contain it
/// (ADR 0036, rule 8).
#[used]
#[unsafe(link_section = ".aspis_test_marker")]
static TEST_BUILD_MARKER: [u8; 16] = *b"ASPIS-TEST-BUILD";

#[macro_export]
macro_rules! kernel_test {
    ($name:ident, $body:block) => {
        #[allow(non_upper_case_globals)]
        const _: () = {
            fn $name() $body
            #[used]
            #[unsafe(link_section = ".aspis_tests")]
            static CASE: $crate::testing::TestCase = $crate::testing::TestCase {
                name: stringify!($name),
                run: $name,
            };
        };
    };
}

unsafe extern "C" {
    // Linker symbols; only their addresses matter.
    static __tests_start: u8;
    static __tests_end: u8;
}

fn cases() -> &'static [TestCase] {
    // SAFETY: the linker script gathers every `TestCase` between the two
    // symbols, contiguously.
    unsafe {
        let start = (&raw const __tests_start).cast::<TestCase>();
        let end = (&raw const __tests_end).cast::<TestCase>();
        let n = (end as usize - start as usize) / core::mem::size_of::<TestCase>();
        core::slice::from_raw_parts(start, n)
    }
}

/// The name of the test running now, for the panic path.
pub static mut CURRENT: Option<&'static str> = None;

/// Runs every test. A failing test panics; the panic path reports it and
/// exits with a failure status.
pub fn run() {
    let cases = cases();
    let mut line = crate::log::Line::new();
    let _ = core::fmt::write(&mut line, format_args!("running {} tests\n", cases.len()));
    uart::write(line.as_str());
    for case in cases {
        // SAFETY: one CPU, no concurrency.
        unsafe { CURRENT = Some(case.name) };
        (case.run)();
        uart::write("test ");
        uart::write(case.name);
        uart::write(" ... ok\n");
    }
    // SAFETY: as above.
    unsafe { CURRENT = None };
    let mut line = crate::log::Line::new();
    let _ = core::fmt::write(
        &mut line,
        format_args!("test result: ok. {} passed; 0 failed\n", cases.len()),
    );
    uart::write(line.as_str());
}

/// Ends QEMU with `code` as its exit status, through semihosting
/// `SYS_EXIT` (TCG only). Test builds only.
pub fn exit(code: u32) -> ! {
    let block: [u64; 2] = [0x2_0026, code as u64]; // ADP_Stopped_ApplicationExit
    // SAFETY: a semihosting call; QEMU ends the run.
    unsafe {
        core::arch::asm!("hlt #0xf000", in("w0") 0x18u32, in("x1") &block, options(nostack));
    }
    crate::halt()
}
