// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The ASPIS kernel, at milestone M1 ("first light"): it boots, turns on
//! the MMU, finds the UART in the device tree, draws its console as text on
//! the boot framebuffer from the first message, keeps a log ring, and
//! reports a panic on both (ADRs 0009, 0041 and 0042).
//!
//! The root server, and everything that runs on top of the kernel, come in
//! later milestones (M2 and M3).

#![no_std]
#![no_main]

mod console;
mod entry;
mod exceptions;
mod log;
mod settings;
#[cfg(aspis_test_build)]
mod testing;
mod uart;

use bootinfo::{BootInfo, MemoryType, initfs_check, start};
use console::{Console, FbState};
use core::cell::UnsafeCell;
use core::fmt::Write as _;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

const VERSION: &str = env!("CARGO_PKG_VERSION");

struct ConsoleSlot(UnsafeCell<Option<Console>>);
// SAFETY: M1 runs one CPU with exceptions masked.
unsafe impl Sync for ConsoleSlot {}
static CONSOLE: ConsoleSlot = ConsoleSlot(UnsafeCell::new(None));

/// Runs `f` on the framebuffer console, if there is one and the kernel
/// still draws on it (ADR 0009, rule 4; ADR 0042, rule 6).
pub fn with_console(f: impl FnOnce(&mut Console)) {
    if console::state() != FbState::Kernel {
        return;
    }
    // SAFETY: one CPU, and no reentry except from the panic path, which
    // doesn't come back.
    if let Some(c) = unsafe { (*CONSOLE.0.get()).as_mut() } {
        f(c);
    }
}

/// Set when `test.panic` asked for a panic, so the panic path halts and
/// leaves the report on screen instead of ending the run.
static FORCED_PANIC: AtomicBool = AtomicBool::new(false);

pub fn halt() -> ! {
    loop {
        // SAFETY: waiting for an event, with exceptions masked.
        unsafe { core::arch::asm!("wfe", options(nomem, nostack)) };
    }
}

/// The boot information at `phys`, through the early identity map.
///
/// # Safety
///
/// `phys` must be where the stub put the boot information.
unsafe fn boot_info(phys: u64) -> Option<BootInfo<'static>> {
    if phys == 0 || phys >= 1 << 32 {
        return None;
    }
    // SAFETY: the header's first 32 bytes are readable; its total length
    // says how many more are.
    let header = unsafe { core::slice::from_raw_parts(phys as *const u8, bootinfo::HEADER_LEN) };
    let total = u32::from_le_bytes(header[16..20].try_into().ok()?) as usize;
    if !(bootinfo::HEADER_LEN..=1 << 20).contains(&total) {
        return None;
    }
    // SAFETY: as above.
    let all = unsafe { core::slice::from_raw_parts(phys as *const u8, total) };
    BootInfo::parse(all).ok()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(boot_info_phys: u64) -> ! {
    exceptions::install();
    // SAFETY: the stub passes the boot information's address in x0.
    let Some(info) = (unsafe { boot_info(boot_info_phys) }) else {
        // Nowhere to report it yet: no UART is known without the boot
        // information's device tree.
        halt()
    };

    // The UART, from the device tree.
    // SAFETY: the stub copied the device tree into memory it reserved.
    let fdt = info
        .device_tree()
        .and_then(|(addr, _)| unsafe { fdt::Fdt::from_ptr(addr as *const u8) }.ok());
    if let Some(f) = &fdt {
        uart::init(f);
    }

    // The kernel arguments (ADR 0041, rule 5).
    let mut notes: [Option<settings::Note<'static>>; 16] = [None; 16];
    let mut n_notes = 0;
    let s = settings::read(info.command_line(), |note| {
        if n_notes < notes.len() {
            notes[n_notes] = Some(note);
            n_notes += 1;
        }
    });
    log::configure(s.log_size, s.log_level, s.console_uart, s.console_fb);
    if s.test_panic {
        FORCED_PANIC.store(true, Ordering::Relaxed);
    }

    // The console, from the first message (ADR 0009, rule 1).
    // There is a console whenever there is a framebuffer, so a panic can
    // reach it even with `console=uart` (ADR 0042, rule 7). The kernel
    // draws its log there only if `console` includes `fb`.
    if let Some(fb) = info.framebuffer() {
        // SAFETY: one CPU; nothing else holds the slot yet.
        unsafe { *CONSOLE.0.get() = Console::new(fb, s.cell) };
    }
    if s.console_fb {
        let mut title = log::Line::new();
        let _ = write!(title, "ASPIS {VERSION}");
        with_console(|c| {
            c.clear();
            c.title(title.as_str(), "first light");
            c.logo();
        });
    }

    klog!(Notice, "kernel", "ASPIS {VERSION}: first light");
    report_boot(&info, &s, fdt.is_some());
    for note in notes.iter().flatten() {
        match *note {
            settings::Note::Error { offset } => klog!(
                Warning,
                "args",
                "the kernel arguments have an error at byte {offset}; only those before it count"
            ),
            settings::Note::Repeated(k) => klog!(
                Notice,
                "args",
                "{k} appears more than once; the last one counts"
            ),
            settings::Note::BadValue(k) => klog!(
                Warning,
                "args",
                "{k} has a value the kernel doesn't accept; ignored"
            ),
            settings::Note::ForRootServer(k) => klog!(Info, "args", "{k} is for the root server"),
            settings::Note::Ignored(k) => klog!(Notice, "args", "unknown argument {k}, ignored"),
        }
    }

    #[cfg(aspis_test_build)]
    if !s.test_panic {
        testing::run();
        testing::exit(0);
    }

    if s.test_panic {
        panic!("forced by test.panic, to show the panic path");
    }

    klog!(
        Info,
        "kernel",
        "M1 ends here. The root server and the node's servers come in M2 and M3. Idling."
    );
    halt()
}

fn report_boot(info: &BootInfo<'_>, s: &settings::Settings, have_dt: bool) {
    if let Some(stub) = info.stub() {
        let how = match stub.start {
            start::GRUB_LINUX => "GRUB linux",
            start::CHAINLOADER_OR_DIRECT => "chainloader or direct boot",
            _ => "unknown",
        };
        klog!(
            Info,
            "boot",
            "stub {}.{}, started by {how}, entered at EL{}; firmware {} {:#x}",
            stub.version >> 16,
            stub.version & 0xffff,
            stub.entered_el,
            stub.vendor(),
            stub.firmware_revision
        );
    }
    let k = info.kernel_placement();
    klog!(
        Info,
        "boot",
        "kernel at physical {:#x}, virtual {:#x}, {} KiB",
        k.physical_base,
        k.virtual_base,
        k.size / 1024
    );
    let (mut usable, mut ranges) = (0u64, 0usize);
    for r in info.memory_map().iter() {
        ranges += 1;
        if r.memory_type() == Some(MemoryType::Usable) {
            usable += r.pages * bootinfo::PAGE_SIZE;
        }
    }
    klog!(
        Info,
        "boot",
        "memory map: {ranges} ranges, {} MiB usable",
        usable >> 20
    );
    match info.initial_image() {
        Some(i) => klog!(
            Info,
            "boot",
            "initial image: {} KiB at {:#x}, SHA-512 {:02x}{:02x}{:02x}{:02x}..., {}",
            i.size / 1024,
            i.base,
            i.digest[0],
            i.digest[1],
            i.digest[2],
            i.digest[3],
            match i.check {
                initfs_check::MATCHED => "matches aspis.efi",
                initfs_check::WAIVED => "check waived by a test build",
                _ => "unknown check result",
            }
        ),
        None => klog!(Warning, "boot", "no initial image"),
    }
    match info.seed() {
        // ADR 0041, rule 4: the kernel never reads the seed's page.
        Some(seed) => klog!(
            Info,
            "boot",
            "seed: {} bytes from the firmware at {:#x}, not read; held for the entropy service",
            seed.length,
            seed.address
        ),
        None => klog!(Notice, "boot", "no seed from the firmware"),
    }
    klog!(
        Info,
        "boot",
        "device tree: {}; ACPI: {}",
        if have_dt { "yes" } else { "no" },
        if info.acpi_rsdp().is_some() {
            "yes"
        } else {
            "no"
        }
    );
    match info.framebuffer() {
        Some(fb) => {
            let mut cell = (0, 0);
            let mut grid = (0, 0);
            with_console(|c| {
                cell = c.cell();
                grid = c.grid();
            });
            klog!(
                Info,
                "console",
                "framebuffer {}x{}, cells {}x{}, {}x{} characters",
                fb.width,
                fb.height,
                cell.0,
                cell.1,
                grid.0,
                grid.1
            );
        }
        None => klog!(
            Notice,
            "console",
            "no linear framebuffer: the console uses the UART only"
        ),
    }
    klog!(
        Info,
        "log",
        "log ring of {} KiB; console threshold {:?}",
        log::size() / 1024,
        s.log_level
    );
}

static PANICKING: AtomicBool = AtomicBool::new(false);

/// The panic path (ADR 0009, rule 5; ADR 0042, rule 7): always the UART,
/// the framebuffer unless it is retired, and the ring. It takes no lock.
#[panic_handler]
fn panic(p: &PanicInfo<'_>) -> ! {
    // SAFETY: masking exceptions.
    unsafe { core::arch::asm!("msr daifset, #0xf", options(nomem, nostack)) };
    if PANICKING.swap(true, Ordering::Relaxed) {
        uart::write("\npanic while panicking\n");
        halt()
    }
    let mut line = log::Line::new();
    let _ = write!(line, "{}", p.message());
    if let Some(loc) = p.location() {
        let _ = write!(line, " ({}:{})", loc.file(), loc.line());
    }
    #[cfg(aspis_test_build)]
    // SAFETY: one CPU.
    if let Some(t) = unsafe { testing::CURRENT } {
        uart::write("test ");
        uart::write(t);
        uart::write(" ... FAILED\n");
    }
    uart::write("\nKERNEL PANIC: ");
    uart::write(line.as_str());
    uart::write("\n");
    log::push(log::Level::Panic, "panic", line.as_str());

    if console::state() != FbState::Retired {
        // SAFETY: the panic path doesn't return, so this is the only user.
        if let Some(c) = unsafe { (*CONSOLE.0.get()).as_mut() } {
            c.clear_text_area(console::PANIC_BG);
            c.fg = console::TEXT;
            c.write_str("KERNEL PANIC\n\n");
            c.write_str(line.as_str());
            c.write_str("\n\nThe node has stopped. The report is also on the serial console.");
        }
    }

    #[cfg(aspis_test_build)]
    if !FORCED_PANIC.load(Ordering::Relaxed) {
        testing::exit(101);
    }
    halt()
}

#[cfg(aspis_test_build)]
mod tests {
    use super::*;

    crate::kernel_test!(framebuffer_states_only_go_forward, {
        // The real state stays Kernel: test the rule on the transitions
        // without disturbing it, by checking that going back is refused.
        assert_eq!(console::state(), FbState::Kernel);
        assert!(console::advance(FbState::Kernel).is_err());
    });

    crate::kernel_test!(virtual_count_has_no_offset, {
        // The kernel's clock is the virtual count (ADR 0051, rule 4). When
        // the stub is entered at EL2 it zeroes CNTVOFF_EL2 and lets EL1 read
        // the physical counter, so the virtual count read between two
        // physical reads must fall between them. Tests run under QEMU's TCG,
        // with no hypervisor of their own to set an offset.
        fn read(physical: bool) -> u64 {
            let t: u64;
            // SAFETY: reading a counter has no side effects; the ISB keeps
            // the read in program order.
            unsafe {
                if physical {
                    core::arch::asm!("isb", "mrs {}, cntpct_el0", out(reg) t, options(nomem, nostack));
                } else {
                    core::arch::asm!("isb", "mrs {}, cntvct_el0", out(reg) t, options(nomem, nostack));
                }
            }
            t
        }
        let before = read(true);
        let virtual_count = read(false);
        let after = read(true);
        assert!(
            before <= virtual_count && virtual_count <= after,
            "virtual count {virtual_count} outside [{before}, {after}]: CNTVOFF_EL2 isn't zero"
        );
    });

    crate::kernel_test!(arguments_after_an_error_are_ignored, {
        let s = settings::read(b"log.level=debug Bad=1 log.level=error", |_| {});
        assert_eq!(s.log_level, log::Level::Debug);
        let s = settings::read(b"console=uart console.cell=24 log.size=64K", |_| {});
        assert!(s.console_uart && !s.console_fb);
        assert_eq!((s.cell, s.log_size), (Some(24), 64 * 1024));
    });
}
