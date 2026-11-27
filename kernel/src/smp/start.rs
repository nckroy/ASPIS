// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Bringing the secondary cores up through PSCI `CPU_ON` (ADR 0052, rule 1;
//! kernel specification, "Starting secondary cores").
//!
//! **What a core starts with.** Before the seal, `mm::init` maps each
//! core's slot in the per-core window (`crate::sched::percore`) and takes
//! four zeroed pages for an identity map ([`take_identity_pages`]). At
//! bring-up the boot core fills a start record in each core's slot and
//! cleans it to the point of coherency, and calls `CPU_ON` with the core's
//! affinity, the physical address of [`aspis_secondary_entry`], and the
//! record's physical address as the context ID.
//!
//! **The entry,** position-independent code in one page of its own
//! (`.text.secondary`):
//!
//! 1. At EL2, as under QEMU's `virtualization=on` or EL2 firmware, it sets
//!    EL1 up as the stub does on the boot core (`boot/stub/src/handoff.rs`,
//!    copied, so the stub's reproducible build is untouched): EL2's MMU off,
//!    EL1 AArch64, the counter with no offset (`CNTVOFF_EL2` = 0, so every
//!    core's virtual count agrees, ADR 0051, rule 4), `ICC_SRE_EL2.Enable`,
//!    and no traps; then it drops to EL1h with DAIF masked.
//! 2. At EL1, with the MMU off, it reads the whole record, sets the boot
//!    core's `MAIR_EL1`, `TCR_EL1` and `TTBR1_EL1`, and `TTBR0_EL1` to the
//!    identity map, which maps only the entry's page, read-only and
//!    executable at EL1; then turns the MMU on with the boot core's
//!    `SCTLR_EL1`, and branches to its upper-half address.
//! 3. There it points `TTBR0_EL1` at the empty table with ASID 0, drops the
//!    identity map's TLB entries, sets `sp` and `TPIDR_EL1` to its slot's
//!    data, and `VBAR_EL1`, and calls [`aspis_secondary_main`].
//!
//! **Then, in Rust:** first the core claims its start, before it touches
//! anything: a core the boot core has given up on parks at once, never
//! online, so nothing it could do in its setup, a panic included, reaches
//! a node that runs without it. Then PAN, the core's GIC interface (Group 1
//! SGIs, stale SGIs cleared), its timer, its EL0 hygiene, SError unmasked
//! (K77), and the online flag, which it sets before it takes the kernel
//! lock: the boot core holds the lock while it waits for the flag.
//! Then it takes the lock and enters its scheduler, which idles until a
//! thread is ready on its run queue.
//!
//! **The boot core** waits at most a second of the count for each core to
//! claim its start, logs each failure with PSCI's code and goes on (a core
//! that starts after the boot core gave up on it parks, never online). A
//! core that has claimed its start is waited for until it is online: its
//! setup's own waits are bounded, and end in a panic, which the boot core's
//! wait serves. Then the boot core gives each online core its scheduling
//! control, and logs how many came up.

use crate::sched::percore;
use core::arch::global_asm;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use kirq::MAX_CORES;
use kirq::affinity::Affinity;
use kmem::PAGE_SIZE;
use ksched::smp::psci;

/// The identity map's four tables, levels 0 to 3: physical addresses.
static IDMAP: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

/// Each core's state: [`OFF`], [`STARTING`] (it claimed its start and is
/// setting itself up), [`ONLINE`] (its interface, timer and data are set,
/// and it takes the kernel lock from then on) or [`GIVEN_UP`] (the boot
/// core stopped waiting for it). Lock-free: a starting core and the boot
/// core settle a late core's state by compare-and-swap from [`OFF`], so a
/// core the boot core gave up on never sets anything up, and one that
/// claimed its start is never given up.
static STATE: [AtomicU8; MAX_CORES] = [const { AtomicU8::new(OFF) }; MAX_CORES];
const OFF: u8 = 0;
const ONLINE: u8 = 1;
const GIVEN_UP: u8 = 2;
const STARTING: u8 = 3;

/// Takes the identity map's four pages, zeroed, in `mm::init`.
pub fn take_identity_pages(mut page: impl FnMut() -> u64) {
    for t in &IDMAP {
        t.store(page(), Ordering::Relaxed);
    }
}

/// Whether core `i` is online.
pub fn is_online(i: usize) -> bool {
    i < MAX_CORES && STATE[i].load(Ordering::Acquire) == ONLINE
}

/// The online cores, one bit each.
pub fn online_mask() -> u64 {
    (0..MAX_CORES)
        .filter(|&i| is_online(i))
        .fold(0, |m, i| m | 1 << i)
}

/// How many cores are online.
pub fn online_count() -> usize {
    online_mask().count_ones() as usize
}

/// Marks the boot core online, in `sched::init`.
pub fn boot_core_online(i: usize) {
    STATE[i].store(ONLINE, Ordering::Release);
}

/// A core's start record, as the entry reads it (offsets in the asm).
#[repr(C)]
struct Record {
    mair: u64,
    tcr: u64,
    ttbr0: u64,
    ttbr1: u64,
    sctlr: u64,
    entry: u64,
    data: u64,
    zero_table: u64,
    index: u64,
}

global_asm!(
    ".section .text.secondary, \"ax\"",
    ".balign 4096",
    ".global aspis_secondary_entry",
    "aspis_secondary_entry:",
    "    msr daifset, #0xf",
    "    mov x19, x0",
    "    mrs x1, CurrentEL",
    "    ubfx x1, x1, #2, #2",
    "    cmp x1, #2",
    "    b.ne 1f",
    // EL2, as the stub's handoff sets it on the boot core: EL2's MMU and
    // caches off; EL1 AArch64 (HCR_EL2.RW, which also clears E2H); the
    // physical counter and timer open to EL1, and no offset on the virtual
    // count; EL1's GICv3 interface enabled where there is one; no FP, SIMD
    // or SVE traps; no stage 2. Then EL1h with DAIF masked.
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
    "    movz x3, #0x8000, lsl #16",
    "    msr hcr_el2, x3",
    "    isb",
    "    mov x3, #3",
    "    msr cnthctl_el2, x3",
    "    msr cntvoff_el2, xzr",
    "    mrs x4, id_aa64pfr0_el1",
    "    ubfx x4, x4, #24, #4",
    "    cbz x4, 4f",
    "    mrs x4, s3_4_c12_c9_5",
    "    orr x4, x4, #1",
    "    orr x4, x4, #8",
    "    msr s3_4_c12_c9_5, x4",
    "    isb",
    "    mrs x4, s3_4_c12_c9_5",
    "    tbz x4, #0, 4f",
    "    msr s3_4_c12_c11_0, xzr",
    "4:",
    "    mov x3, #0x32ff",
    "    mrs x4, id_aa64pfr1_el1",
    "    ubfx x4, x4, #24, #4",
    "    cbz x4, 3f",
    "    bic x3, x3, #0x1000",
    "3:",
    "    msr cptr_el2, x3",
    "    msr hstr_el2, xzr",
    "    msr vttbr_el2, xzr",
    "    movz x3, #0x0800",
    "    movk x3, #0x30d0, lsl #16",
    "    msr sctlr_el1, x3",
    "    mov x3, #0x3c5",
    "    msr spsr_el2, x3",
    "    adr x3, 1f",
    "    msr elr_el2, x3",
    "    isb",
    "    eret",
    // EL1, MMU off: FP and SIMD on, then the record, read in full before
    // the MMU is on, since the identity map holds only this page.
    "1:",
    "    msr spsel, #1",
    "    mov x1, #(3 << 20)",
    "    msr cpacr_el1, x1",
    "    isb",
    "    ldp x1, x2, [x19, #0]",
    "    ldp x3, x4, [x19, #16]",
    "    ldp x20, x21, [x19, #32]",
    "    ldp x22, x23, [x19, #48]",
    "    ldr x24, [x19, #64]",
    "    msr mair_el1, x1",
    "    msr tcr_el1, x2",
    "    msr ttbr0_el1, x3",
    "    msr ttbr1_el1, x4",
    "    isb",
    "    tlbi vmalle1",
    "    dsb nsh",
    "    isb",
    "    msr sctlr_el1, x20",
    "    isb",
    "    br x21",
    ".global aspis_secondary_entry_end",
    "aspis_secondary_entry_end:",
    "",
    // The upper half: the identity map goes, then the core's stack, data
    // and vectors.
    ".section .text.aspis_secondary_virtual, \"ax\"",
    ".global aspis_secondary_virtual",
    "aspis_secondary_virtual:",
    "    msr ttbr0_el1, x23",
    "    isb",
    "    tlbi vmalle1",
    "    dsb nsh",
    "    isb",
    "    mov sp, x22",
    "    msr tpidr_el1, x22",
    "    adrp x1, aspis_vectors",
    "    add x1, x1, :lo12:aspis_vectors",
    "    msr vbar_el1, x1",
    "    isb",
    "    mov x0, x24",
    "    mov x29, #0",
    "    mov x30, #0",
    "    bl aspis_secondary_main",
    "    brk #0",
);

unsafe extern "C" {
    // Code labels; only their addresses are used.
    static aspis_secondary_entry: u8;
    static aspis_secondary_entry_end: u8;
    static aspis_secondary_virtual: u8;
}

/// A secondary core's first Rust, on its entry stack (module docs).
#[unsafe(no_mangle)]
extern "C" fn aspis_secondary_main(index: u64) -> ! {
    let i = index as usize;
    if STATE[i]
        .compare_exchange(OFF, STARTING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        // The boot core gave up on this core: it stays off, parked with
        // every interrupt masked, and touches nothing.
        park();
    }
    if crate::mm::arch::has_pan() {
        crate::mm::arch::set_pan();
    }
    let Some(irq) = crate::irq::get() else {
        panic!("core {i} started before the interrupt controller was set up");
    };
    // Nothing here writes a log record before the core holds the kernel
    // lock: what the interface's setup found is logged after `lock`.
    let found = irq.init_cpu(i);
    crate::timer::init_cpu();
    crate::sched::boot::init_cpu();
    crate::sched::boot::unmask_serror();
    STATE[i].store(ONLINE, Ordering::Release);
    super::lock::lock();
    crate::irq::log_cpu_init(i, found);
    crate::sched::run::exit()
}

/// Parks a core the boot core gave up on: every interrupt masked, waiting
/// forever.
fn park() -> ! {
    // SAFETY: masks every exception on this core, which holds nothing.
    unsafe { core::arch::asm!("msr daifset, #0xf", options(nomem, nostack)) };
    loop {
        // SAFETY: waits for an event; nothing is taken while masked.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)) };
    }
}

/// The entry's page: physical address, and the identity map built for it.
fn build_identity_map() -> u64 {
    let entry = (&raw const aspis_secondary_entry) as u64;
    let end = (&raw const aspis_secondary_entry_end) as u64;
    assert!(
        entry.is_multiple_of(PAGE_SIZE) && end - entry <= PAGE_SIZE,
        "the secondary entry doesn't fit one page"
    );
    let pa = crate::mm::phys::kernel_pa(entry);
    let t: [u64; 4] = core::array::from_fn(|i| IDMAP[i].load(Ordering::Relaxed));
    assert!(t.iter().all(|&p| p != 0), "the identity map has no pages");
    let va = |p: u64| match kmem::layout::direct_va(p) {
        Some(v) => v as *mut u64,
        None => panic!("identity table {p:#x} is beyond the direct map"),
    };
    let idx = |shift: u32| ((pa >> shift) & 511) as usize;
    // A table descriptor; and the page: normal write-back memory (attr 1),
    // inner shareable, AF, read-only at EL1 (AP = 10), executable at EL1,
    // UXN, non-global under ASID 0, so it is dropped with that ASID.
    const TABLE: u64 = 0b11;
    const PAGE: u64 = 0b11 | 1 << 2 | 0b10 << 6 | 0b11 << 8 | 1 << 10 | 1 << 11 | 1 << 54;
    // SAFETY: four zeroed pages from the boot allocator, in the direct
    // map, which nothing else uses; each index is below 512.
    unsafe {
        va(t[0]).add(idx(39)).write_volatile(t[1] | TABLE);
        va(t[1]).add(idx(30)).write_volatile(t[2] | TABLE);
        va(t[2]).add(idx(21)).write_volatile(t[3] | TABLE);
        va(t[3]).add(idx(12)).write_volatile(pa | PAGE);
    }
    for p in t {
        // SAFETY: a page of the direct map; cleaning changes no data.
        unsafe { crate::mm::arch::clean_invalidate(va(p) as u64, PAGE_SIZE) };
    }
    t[0]
}

/// Fills core `i`'s start record, cleaned to the point of coherency for its
/// MMU-off reads, and returns its physical address.
fn fill_record(i: usize, idmap: u64) -> u64 {
    use crate::mm::arch;
    let (va, pa) = percore::record(i);
    let r = Record {
        mair: arch::mair(),
        tcr: arch::tcr(),
        ttbr0: idmap,
        ttbr1: arch::ttbr1(),
        sctlr: arch::sctlr(),
        entry: (&raw const aspis_secondary_virtual) as u64,
        data: percore::data_va(i),
        zero_table: crate::mm::phys::kernel_pa(crate::entry::zero_table()),
        index: i as u64,
    };
    // SAFETY: the record's page in core `i`'s slot, mapped read-write;
    // the core is off, so nothing else reads it.
    unsafe { (va as *mut Record).write_volatile(r) };
    // SAFETY: as above; cleaning changes no data.
    unsafe { arch::clean_invalidate(va, PAGE_SIZE) };
    pa
}

/// Which cores the device tree starts through PSCI: `enable-method` is
/// "psci", one bit per core-table index.
fn psci_cores(irq: &crate::irq::Irq) -> u64 {
    let Some(fdt) = crate::mm::device_tree() else {
        return 0;
    };
    let Some(cpus) = fdt.find_node("/cpus") else {
        return 0;
    };
    let cells = cpus
        .property("#address-cells")
        .and_then(|p| kirq::dt::be_u32(p.value))
        .unwrap_or(2);
    let mut mask = 0;
    for n in cpus.children().filter(|n| crate::irq::is_cpu(n)) {
        let psci = psci::enabled_by_psci(n.property("enable-method").map(|p| p.value));
        let index = n
            .property("reg")
            .and_then(|p| kirq::dt::cpu_affinity(p.value, cells))
            .and_then(|a| irq.cores().index_of(a));
        match (psci, index) {
            (true, Some(i)) => mask |= 1 << i,
            (false, Some(i)) if i != irq.cores().boot() => crate::klog!(
                Notice,
                "smp",
                "core {i} ({}) isn't started through PSCI: it stays off",
                n.name
            ),
            _ => {}
        }
    }
    mask
}

/// The longest wait for a core to claim its start: a second of the count.
fn online_wait() -> u64 {
    crate::timer::frequency()
}

/// The longest wait for a core that claimed its start to come online: ten
/// seconds of the count. Its setup's own waits end sooner, in a panic, so
/// this only bounds a core that hangs outright.
fn setup_wait() -> u64 {
    10 * crate::timer::frequency()
}

/// Brings up every other core the device tree names, through PSCI (module
/// docs). On the boot core, which holds the kernel lock, after the phase-1
/// tests in a test build.
pub fn start_secondaries() {
    let Some(irq) = crate::irq::get() else {
        panic!("smp::start_secondaries before irq::init");
    };
    let cores = irq.cores();
    let me = cores.boot();
    let total = cores.len().min(percore::mapped());
    let Some(p) = super::psci() else {
        crate::klog!(
            Info,
            "smp",
            "1 of {} {} online: no usable PSCI",
            cores.len(),
            if cores.len() == 1 { "core" } else { "cores" }
        );
        return;
    };
    let with_psci = psci_cores(irq);
    let idmap = if total > 1 { build_identity_map() } else { 0 };
    let entry = crate::mm::phys::kernel_pa((&raw const aspis_secondary_entry) as u64);
    for i in (0..total).filter(|&i| i != me && with_psci & 1 << i != 0) {
        percore::init(i);
        let record = fill_record(i, idmap);
        let a: Affinity = cores.affinity(i);
        let r = super::psci::call(p.conduit, psci::CPU_ON, a.mpidr(), entry, record);
        match psci::Status::decode(r) {
            psci::Status::Success => {}
            e => {
                crate::klog!(Warning, "smp", "core {i}: CPU_ON failed: {e:?}");
                continue;
            }
        }
        let start = crate::timer::now();
        while !is_online(i) {
            if super::remote::stopping() {
                crate::irq::stop_this_core();
            }
            let waited = crate::timer::now() - start;
            // A core that hasn't claimed its start within a second is given
            // up, and parks if it starts later. One that has is waited for:
            // it comes online, or panics, which this loop serves.
            if waited > online_wait()
                && STATE[i]
                    .compare_exchange(OFF, GIVEN_UP, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                crate::klog!(
                    Warning,
                    "smp",
                    "core {i} didn't start within a second of CPU_ON"
                );
                break;
            }
            if waited > setup_wait() {
                panic!("core {i} started, but didn't come online within ten seconds");
            }
            core::hint::spin_loop();
        }
    }
    for i in (0..total).filter(|&i| i != me && is_online(i)) {
        crate::sched::boot::add_control(i);
    }
    crate::klog!(
        Info,
        "smp",
        "{} of {} cores online",
        online_count(),
        cores.len()
    );
}
