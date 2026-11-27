// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! In-QEMU tests, compiled only into test builds (ADR 0036, rules 5 and 6).
//!
//! Tests register themselves in the `.aspis_tests` linker section, which
//! works on stable Rust. The runner reports each result on the UART, one
//! line each, and ends QEMU through semihosting with an exit status. The
//! host-side runner (`cargo xtask test`) reads the lines and the status.
//!
//! From C12, tests run EL0 threads through [`driver::run_until`], which
//! switches from the boot stack into the scheduler and back. Their programs
//! ([`user`]) reach the kernel through the test trap ([`trap`]), and report
//! values into [`report`]'s log.

pub mod driver;
pub mod report;
pub mod trap;
pub mod user;

use crate::uart;

pub struct TestCase {
    pub name: &'static str,
    pub run: fn(),
    pub phase: Phase,
}

/// When a test runs (C12): with the boot core alone, before the other cores
/// start, or with every core up. The boot core runs both, and holds the
/// kernel lock throughout, as it does for any kernel code; its scheduler
/// releases it while threads run or the core idles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    BootCore,
    AllCores,
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
                phase: $crate::testing::Phase::BootCore,
            };
        };
    };
}

/// A test that runs once every core is up (C12).
#[macro_export]
macro_rules! kernel_smp_test {
    ($name:ident, $body:block) => {
        #[allow(non_upper_case_globals)]
        const _: () = {
            fn $name() $body
            #[used]
            #[unsafe(link_section = ".aspis_tests")]
            static CASE: $crate::testing::TestCase = $crate::testing::TestCase {
                name: stringify!($name),
                run: $name,
                phase: $crate::testing::Phase::AllCores,
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

/// `test.only=TEXT`: run only the tests whose names contain TEXT, for
/// quicker runs while developing. Unset runs them all.
static ONLY: core::sync::atomic::AtomicPtr<u8> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
static ONLY_LEN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Records `test.only`'s value, from the kernel's command line.
pub fn set_only(text: &'static str) {
    use core::sync::atomic::Ordering::Relaxed;
    ONLY_LEN.store(text.len(), Relaxed);
    ONLY.store(text.as_ptr().cast_mut(), Relaxed);
}

fn only() -> Option<&'static str> {
    use core::sync::atomic::Ordering::Relaxed;
    let p = ONLY.load(Relaxed);
    if p.is_null() {
        return None;
    }
    // SAFETY: `set_only` stored a `&'static str`'s pointer and length.
    Some(unsafe {
        core::str::from_utf8_unchecked(core::slice::from_raw_parts(p, ONLY_LEN.load(Relaxed)))
    })
}

/// Runs every test of `phase`. A failing test panics; the panic path
/// reports it and exits with a failure status. The phases share one count:
/// the first prints "running", the last the result.
pub fn run(phase: Phase) {
    let cases = cases();
    let chosen = |c: &&TestCase| only().is_none_or(|o| c.name.contains(o));
    if phase == Phase::BootCore {
        let n = cases.iter().filter(chosen).count();
        let mut line = crate::log::Line::new();
        let _ = core::fmt::write(&mut line, format_args!("running {n} tests\n"));
        uart::write(line.as_str());
    }
    for case in cases.iter().filter(chosen).filter(|c| c.phase == phase) {
        // SAFETY: the boot core's runner is its only writer, under the
        // kernel lock; the panic path only reads it.
        unsafe { CURRENT = Some(case.name) };
        (case.run)();
        uart::write("test ");
        uart::write(case.name);
        uart::write(" ... ok\n");
    }
    // SAFETY: as above.
    unsafe { CURRENT = None };
    if phase == Phase::AllCores {
        let n = cases.iter().filter(chosen).count();
        let mut line = crate::log::Line::new();
        let _ = core::fmt::write(
            &mut line,
            format_args!("test result: ok. {n} passed; 0 failed\n"),
        );
        uart::write(line.as_str());
    }
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
