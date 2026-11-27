// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The scheduler's boot objects and the boot core's setup (kernel
//! specification, "What the root server receives"; ADR 0048, rule 2;
//! "Priorities and bands", the first thread).
//!
//! `mm::seal` takes three boot pages for them before it seals the boot
//! allocator ([`Pages`]), and `cap::boot` keeps their originals, so none is
//! ever destroyed:
//!
//! - **the scheduling-control CNode**, one page of 128 slots, named by root
//!   slot 4. Slot n holds core n's scheduling control, a root of the
//!   derivation tree, for each core that is online: the boot core's at
//!   [`init`], each other core's once PSCI has brought it up ("Scheduling contexts and budgets").
//! - **the first thread**, named by root slot 2: as seL4's
//!   `create_initial_thread`, it has priority and maximum controlled
//!   priority 255, so the root server can give every other thread any
//!   priority (ADR 0051, rule 2). It is suspended, with no root CNode,
//!   address space or registers set: C17 loads the root server's image and
//!   C19 starts it.
//! - **its scheduling context**, one page, named by root slot 5: bound to
//!   the first thread, on the boot core, round-robin with seL4's default
//!   boot time slice of 5 ms. So it takes the whole of the boot core's share
//!   (K13), which the root server reconfigures as its boot manifest divides
//!   the core.
//!
//! [`init`] runs after `timer::init`: the boot core's per-core data, its
//! EL0 hygiene ([`init_cpu`]), SError unmasked ([`unmask_serror`], K77),
//! the kernel lock, which the boot core holds from then on, and the objects
//! above. Each secondary core runs [`init_cpu`] and [`unmask_serror`] for
//! itself (`crate::smp::start`).

use super::object::Tcb;
use super::{context, percore, thread};
use crate::cap::boot as cboot;
use crate::cap::{self, DirectSlots};
use kcap::SlotRef;
use kcap::cap::Cap;
use kcap::mdb;

/// The first thread's priority and maximum controlled priority.
pub const FIRST_THREAD_PRIORITY: u8 = 255;
/// Its context's budget and period: seL4's `BOOT_THREAD_TIME_SLICE`.
pub const FIRST_CONTEXT_US: u64 = 5_000;

/// The boot pages `mm::seal` takes for the scheduler.
#[derive(Clone, Copy, Debug)]
pub struct Pages {
    pub control: u64,
    pub thread: u64,
    pub context: u64,
}

/// `ID_AA64DFR0_EL1`.
fn id_aa64dfr0() -> u64 {
    let v: u64;
    // SAFETY: reading an ID register has no side effects.
    unsafe {
        core::arch::asm!("mrs {}, id_aa64dfr0_el1", out(reg) v, options(nomem, nostack, preserves_flags))
    };
    v
}

/// Whether the core has a PMU: `ID_AA64DFR0_EL1.PMUVer` is neither 0 (none)
/// nor 0xF (an implementation defined one).
pub fn has_pmu() -> bool {
    !matches!((id_aa64dfr0() >> 8) & 0xf, 0 | 0xf)
}

/// This core's EL0 hygiene (kernel specification, "Fault delivery"; K70): `TPIDRRO_EL0` 0, so no
/// thread sees another's value; `PMUSERENR_EL0` 0 where there is a PMU, so
/// EL0 can't reach it; `MDSCR_EL1` 0, so no debug event reaches EL0 (K70).
/// `CNTKCTL_EL1` is `timer::init_cpu`'s (K19), and `CPACR_EL1` the entry's:
/// FP and SIMD on, SVE and SME trapped.
pub fn init_cpu() {
    // SAFETY: EL1 system registers that only the kernel uses; zeroing them
    // takes EL0's access to user read-only TLS, the PMU and self-hosted
    // debug away.
    unsafe {
        core::arch::asm!(
            "msr tpidrro_el0, xzr",
            "msr mdscr_el1, xzr",
            "isb",
            options(nostack, preserves_flags)
        )
    };
    if has_pmu() {
        // SAFETY: as above; the register exists where there is a PMU.
        unsafe {
            core::arch::asm!(
                "msr pmuserenr_el0, xzr",
                "isb",
                options(nostack, preserves_flags)
            )
        };
    }
}

/// Unmasks SError on this core (K77). Its vectors, its stack and its
/// per-core data are set, so an SError taken in the kernel from here on is
/// reported, and the kernel panics; one taken from EL0 too (C20 and C78
/// revisit that one). The only windows with SErrors masked are the
/// exception entry from EL0 before `sp` is the entry stack, and the way
/// back from where `sp` points at the thread (`crate::exceptions`).
pub fn unmask_serror() {
    // SAFETY: PSTATE.A only; the SError vectors at EL1 run on a kernel
    // stack.
    unsafe { core::arch::asm!("msr daifclr, #4", options(nomem, nostack, preserves_flags)) };
}

/// `DAIF` now, for tests.
#[cfg(aspis_test_build)]
pub fn daif() -> u64 {
    let v: u64;
    // SAFETY: reading DAIF has no side effects.
    unsafe {
        core::arch::asm!("mrs {}, daif", out(reg) v, options(nomem, nostack, preserves_flags))
    };
    v
}

/// `DAIF.A`: SErrors masked.
#[cfg(aspis_test_build)]
pub const DAIF_A: u64 = 1 << 8;

/// `MDSCR_EL1` and `PMUSERENR_EL0` now, for tests.
#[cfg(aspis_test_build)]
pub fn debug_controls() -> (u64, Option<u64>) {
    let m: u64;
    // SAFETY: reading the register has no side effects.
    unsafe {
        core::arch::asm!("mrs {}, mdscr_el1", out(reg) m, options(nomem, nostack, preserves_flags))
    };
    let p = has_pmu().then(|| {
        let p: u64;
        // SAFETY: as above; the register exists where there is a PMU.
        unsafe { core::arch::asm!("mrs {}, pmuserenr_el0", out(reg) p, options(nomem, nostack, preserves_flags)) };
        p
    });
    (m, p)
}

/// The boot core's index in the core table.
fn boot_core() -> usize {
    match crate::irq::get() {
        Some(i) => i.cores().boot(),
        None => panic!("sched::init before irq::init"),
    }
}

/// Sets up the boot core and the scheduler's boot objects (module docs).
pub fn init() {
    let core = boot_core();
    percore::init(core);
    percore::set_tpidr(core);
    init_cpu();
    unmask_serror();
    // The boot core holds the kernel lock from here on, wherever it runs
    // kernel code (`crate::smp::lock`).
    crate::smp::start::boot_core_online(core);
    crate::smp::lock::lock();
    // The boot core's scheduling control, a root of the tree.
    add_control(core);
    let ctl = control_slot(core);
    // The first thread's priorities. It is the authority for every other
    // thread's, and itself: retype made it with 0 and 0.
    let t = Tcb(first_thread());
    t.update(|s| {
        s.priority = FIRST_THREAD_PRIORITY;
        s.mcp = FIRST_THREAD_PRIORITY;
        s.core = core as u8;
    });
    let ts = cboot::root_slot(cboot::FIRST_THREAD);
    let cs = cboot::root_slot(cboot::FIRST_CONTEXT);
    if let Err(e) = context::configure(ctl, cs, FIRST_CONTEXT_US, FIRST_CONTEXT_US, 0, 0) {
        panic!("can't configure the first thread's context: {e:?}");
    }
    if let Err(e) = thread::bind_context(ts, cs) {
        panic!("can't bind the first thread's context: {e:?}");
    }
    crate::klog!(
        Info,
        "sched",
        "first thread at priority {FIRST_THREAD_PRIORITY}, suspended, on a {} ms round-robin context on core {core}",
        FIRST_CONTEXT_US / 1000
    );
}

/// Puts core `core`'s scheduling control in its slot, a root of the
/// derivation tree: the boot core's in [`init`], and each other core's once
/// it is online (kernel specification, "Scheduling contexts and budgets").
pub fn add_control(core: usize) {
    mdb::insert_root(
        &mut DirectSlots,
        control_slot(core),
        Cap::SchedControl { core: core as u8 },
    );
}

/// The scheduling-control CNode's slot for core `core`.
pub fn control_slot(core: usize) -> SlotRef {
    match cap::cap(cboot::original(cboot::ORIGINAL_SCHED_CONTROL)) {
        Cap::CNode { ptr, .. } => SlotRef(ptr).offset(core as u64),
        c => panic!("the scheduling-control CNode's original is {c:x?}"),
    }
}

/// The first thread's object.
pub fn first_thread() -> u64 {
    match cap::cap(cboot::original(cboot::ORIGINAL_FIRST_THREAD)) {
        Cap::Thread { ptr, .. } => ptr,
        c => panic!("the first thread's original is {c:x?}"),
    }
}
