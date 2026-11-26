// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The instructions memory management needs: system registers, barriers,
//! TLB and cache maintenance, address translation, and the trampoline that
//! replaces `TTBR1_EL1`. This is the only `asm!` in `mm`.
//!
//! The sequences follow the kernel specification, "Address-space layout"
//! and "Cross-core signals and TLB maintenance". TLB maintenance is the
//! broadcast inner-shareable kind (ADR 0052, rule 4).

use core::arch::{asm, global_asm};

/// `TCR_EL1.EPD0`: no walks through `TTBR0_EL1`. The kernel keeps it 0.
pub const TCR_EPD0: u64 = 1 << 7;
/// `TCR_EL1.A1`: the ASID comes from `TTBR1_EL1`. The kernel keeps it 0.
pub const TCR_A1: u64 = 1 << 22;
/// `TCR_EL1.AS`: 16-bit ASIDs.
pub const TCR_AS: u64 = 1 << 36;
/// `SCTLR_EL1.WXN`: every writable mapping is execute-never.
pub const SCTLR_WXN: u64 = 1 << 19;
/// `SCTLR_EL1.SPAN`: when clear, every exception taken to EL1 sets PAN.
pub const SCTLR_SPAN: u64 = 1 << 23;
/// `PSTATE.PAN`, as the `PAN` system register holds it.
pub const PSTATE_PAN: u64 = 1 << 22;
/// `PAR_EL1.F`: the translation faulted.
#[cfg_attr(not(aspis_test_build), allow(dead_code))]
pub const PAR_F: u64 = 1;

macro_rules! read_sysreg {
    ($name:ident, $reg:literal) => {
        #[allow(dead_code)]
        pub fn $name() -> u64 {
            let v: u64;
            // SAFETY: reading this system register at EL1 has no side
            // effects.
            unsafe { asm!(concat!("mrs {}, ", $reg), out(reg) v, options(nomem, nostack, preserves_flags)) };
            v
        }
    };
}

read_sysreg!(id_aa64mmfr0, "id_aa64mmfr0_el1");
read_sysreg!(id_aa64mmfr1, "id_aa64mmfr1_el1");
read_sysreg!(dczid, "dczid_el0");
read_sysreg!(ctr, "ctr_el0");
read_sysreg!(tcr, "tcr_el1");
read_sysreg!(sctlr, "sctlr_el1");
read_sysreg!(ttbr0, "ttbr0_el1");
read_sysreg!(ttbr1, "ttbr1_el1");
// PSTATE.PAN, through its generic encoding, so no `.arch` directive is
// needed for the A72, which lacks it (the kernel reads it only where
// `ID_AA64MMFR1_EL1.PAN` says it exists).
read_sysreg!(pan, "s3_0_c4_c2_3");

/// Whether the processor implements PAN (`ID_AA64MMFR1_EL1.PAN` isn't 0).
pub fn has_pan() -> bool {
    (id_aa64mmfr1() >> 20) & 0xf != 0
}

/// The ASID width in bits: 16 where `ID_AA64MMFR0_EL1.ASIDBits` is
/// `0b0010`, else 8.
pub fn asid_bits() -> u8 {
    if (id_aa64mmfr0() >> 4) & 0xf == 0b0010 {
        16
    } else {
        8
    }
}

/// Makes every earlier store visible to the table walkers of every core in
/// the inner-shareable domain.
pub fn dsb_ishst() {
    // SAFETY: a barrier.
    unsafe { asm!("dsb ishst", options(nostack, preserves_flags)) };
}

/// Waits until every earlier memory access and TLB maintenance instruction
/// has completed in the inner-shareable domain (`DSB ISH`).
pub fn dsb_ish() {
    // SAFETY: a barrier.
    unsafe { asm!("dsb ish", options(nostack, preserves_flags)) };
}

/// Makes this core's later instructions see the effect of earlier system
/// register writes and completed TLB maintenance (`ISB`).
pub fn isb() {
    // SAFETY: a barrier.
    unsafe { asm!("isb", options(nostack, preserves_flags)) };
}

/// Invalidates, on every core in the inner-shareable domain, the TLB
/// entries for user address `va` tagged with `asid`, at every level
/// (`TLBI VAE1IS`). The caller follows it with `DSB ISH` and `ISB`.
pub fn tlbi_vae1is(asid: u16, va: u64) {
    let arg = (asid as u64) << 48 | (va >> 12) & 0x0000_0fff_ffff_ffff;
    // SAFETY: TLB maintenance only drops cached translations, which the
    // walker refills from the tables.
    unsafe { asm!("tlbi vae1is, {}", in(reg) arg, options(nostack, preserves_flags)) };
}

/// Invalidates, on every core in the inner-shareable domain, every
/// non-global TLB entry tagged with `asid` (`TLBI ASIDE1IS`). The caller
/// follows it with `DSB ISH` and `ISB`.
pub fn tlbi_aside1is(asid: u16) {
    let arg = (asid as u64) << 48;
    // SAFETY: as for `tlbi_vae1is`.
    unsafe { asm!("tlbi aside1is, {}", in(reg) arg, options(nostack, preserves_flags)) };
}

/// Invalidates every EL1&0 TLB entry on every core in the inner-shareable
/// domain, then waits for it and synchronizes this core (`TLBI VMALLE1IS`,
/// `DSB ISH`, `ISB`): for an ASID rollover.
pub fn flush_all() {
    // SAFETY: as for `tlbi_vae1is`.
    unsafe {
        asm!(
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack, preserves_flags)
        )
    };
}

/// Points `TTBR0_EL1` at the level-0 table at physical address `root`,
/// tagged with `asid`, then `ISB` (kernel specification, "Address-space
/// layout", "ASIDs").
///
/// # Safety
///
/// `root` must be an address space's level-0 table, or the empty table
/// with ASID 0, and every store to the tables must be visible to the walker
/// (`DSB ISHST`). The kernel never runs from the lower half, so the switch
/// changes nothing the kernel itself uses.
pub unsafe fn set_ttbr0(root: u64, asid: u16) {
    let v = (asid as u64) << 48 | root & 0x0000_ffff_ffff_f000;
    // SAFETY: as the caller promises.
    unsafe {
        asm!(
            "msr ttbr0_el1, {}",
            "isb",
            in(reg) v,
            options(nostack, preserves_flags)
        )
    };
}

/// Translates `va` as an EL1 read with the current tables (`AT S1E1R`),
/// and returns `PAR_EL1`: bit 0 set means the translation faulted;
/// otherwise bits 47:12 hold the physical page.
#[cfg_attr(not(aspis_test_build), allow(dead_code))]
pub fn at_s1e1r(va: u64) -> u64 {
    let par: u64;
    // SAFETY: address translation only reads the tables and writes
    // PAR_EL1, which nothing else uses; it never faults.
    unsafe {
        asm!(
            "at s1e1r, {va}",
            "isb",
            "mrs {par}, par_el1",
            va = in(reg) va,
            par = out(reg) par,
            options(nostack, preserves_flags)
        );
    }
    par
}

/// Translates `va` as an EL0 read with the current tables (`AT S1E0R`),
/// and returns `PAR_EL1`, as [`at_s1e1r`] does. PAN doesn't apply.
#[cfg_attr(not(aspis_test_build), allow(dead_code))]
pub fn at_s1e0r(va: u64) -> u64 {
    let par: u64;
    // SAFETY: as for `at_s1e1r`.
    unsafe {
        asm!(
            "at s1e0r, {va}",
            "isb",
            "mrs {par}, par_el1",
            va = in(reg) va,
            par = out(reg) par,
            options(nostack, preserves_flags)
        );
    }
    par
}

/// Translates `va` as an EL1 read that honors PAN (`AT S1E1RP`, FEAT_PAN2),
/// and returns `PAR_EL1`, as [`at_s1e1r`] does. It is written by its
/// generic encoding, `SYS #0, C7, C9, #0`, so no `.arch` directive is
/// needed. Only for a processor where `ID_AA64MMFR1_EL1.PAN` is 2 or more.
#[cfg_attr(not(aspis_test_build), allow(dead_code))]
pub fn at_s1e1rp(va: u64) -> u64 {
    let par: u64;
    // SAFETY: as for `at_s1e1r`; the caller checked FEAT_PAN2.
    unsafe {
        asm!(
            "sys #0, c7, c9, #0, {va}",
            "isb",
            "mrs {par}, par_el1",
            va = in(reg) va,
            par = out(reg) par,
            options(nostack, preserves_flags)
        );
    }
    par
}

/// Loads the 64-bit word at user address `va` as EL0 would (`LDTR`), for
/// tests only: it reads through the TLB, so a test can tell whether a stale
/// translation survived an unmap. PAN doesn't apply to it. The kernel
/// itself never dereferences a user address (ADR 0048, rule 5).
///
/// # Safety
///
/// `va` must be 8-byte aligned and mapped readable at EL0 in the active
/// address space; otherwise the load faults and the kernel panics.
#[cfg(aspis_test_build)]
pub unsafe fn ldtr_u64(va: u64) -> u64 {
    let v: u64;
    // SAFETY: as the caller promises.
    unsafe {
        asm!(
            "ldtr {v}, [{va}]",
            va = in(reg) va,
            v = out(reg) v,
            options(nostack, preserves_flags, readonly)
        );
    }
    v
}

/// Zeroes `[va, va + len)`, which must be page-aligned, mapped, normal
/// memory: with `DC ZVA` where `DCZID_EL0` allows it, else with stores.
///
/// # Safety
///
/// The range must be writable through the current tables, normal memory,
/// and hold nothing anyone still uses.
pub unsafe fn zero(va: u64, len: u64) {
    let dczid = dczid();
    // DZP, bit 4: DC ZVA is prohibited. BS, bits 3:0: log2 of the block in
    // words.
    let block = 4u64 << (dczid & 0xf);
    if dczid & (1 << 4) == 0 && va.is_multiple_of(block) && len.is_multiple_of(block) {
        let mut at = va;
        while at < va + len {
            // SAFETY: the caller's range; DC ZVA writes one block of it.
            unsafe { asm!("dc zva, {}", in(reg) at, options(nostack, preserves_flags)) };
            at += block;
        }
    } else {
        // SAFETY: the caller's range.
        unsafe { core::ptr::write_bytes(va as *mut u8, 0, len as usize) };
    }
}

/// Cleans and invalidates `[va, va + len)` to the point of coherency by
/// address (`DC CIVAC`), then `DSB SY`: for memory whose cacheability
/// changes, such as the framebuffer at the switch.
///
/// # Safety
///
/// The range must be mapped.
pub unsafe fn clean_invalidate(va: u64, len: u64) {
    // CTR_EL0.DminLine, bits 19:16: log2 of the smallest line in words.
    let line = 4u64 << ((ctr() >> 16) & 0xf);
    let mut at = va & !(line - 1);
    while at < va + len {
        // SAFETY: the caller's range is mapped; DC CIVAC changes no data.
        unsafe { asm!("dc civac, {}", in(reg) at, options(nostack, preserves_flags)) };
        at += line;
    }
    // SAFETY: a barrier.
    unsafe { asm!("dsb sy", options(nostack, preserves_flags)) };
}

/// `CTR_EL0.IDC`: data-cache cleaning to the point of unification isn't
/// needed for instruction-to-data coherence.
const CTR_IDC: u64 = 1 << 28;
/// `CTR_EL0.DIC`: instruction-cache invalidation to the point of
/// unification isn't needed for instruction-to-data coherence.
const CTR_DIC: u64 = 1 << 29;
/// Above this many bytes, the I-cache is invalidated whole (`IC IALLUIS`)
/// rather than line by line.
const IC_BY_LINE_MAX: u64 = 64 * 1024;

/// Makes the instructions in `[va, va + len)` coherent with what data
/// stores wrote there, for every core's instruction fetches (Arm ARM,
/// "Instruction cache maintenance", the sequence for self-modifying code):
///
/// 1. unless `CTR_EL0.IDC` is set, `DC CVAU` each data-cache line, so the
///    stores reach the point of unification;
/// 2. `DSB ISH`;
/// 3. unless `CTR_EL0.DIC` is set, `IC IVAU` each instruction-cache line, or
///    `IC IALLUIS` for a large range, so no core fetches stale
///    instructions;
/// 4. `DSB ISH`, then `ISB`.
///
/// It is for memory about to be mapped executable for EL0: memory that
/// held other code before it was reset and retyped, or that the kernel or
/// the stub wrote with data stores (kernel specification, "Cross-core
/// signals and TLB maintenance"). The instruction caches the kernel's
/// targets have are physically indexed, so maintenance through the direct
/// map reaches every alias.
///
/// # Safety
///
/// The range must be mapped, as normal memory, in the current tables.
pub unsafe fn sync_icache(va: u64, len: u64) {
    let ctr = ctr();
    if ctr & CTR_IDC == 0 {
        // DminLine, bits 19:16: log2 of the smallest line in words.
        let line = 4u64 << ((ctr >> 16) & 0xf);
        let mut at = va & !(line - 1);
        while at < va + len {
            // SAFETY: the caller's range is mapped; DC CVAU changes no data.
            unsafe { asm!("dc cvau, {}", in(reg) at, options(nostack, preserves_flags)) };
            at += line;
        }
    }
    dsb_ish();
    if ctr & CTR_DIC == 0 {
        if len > IC_BY_LINE_MAX {
            // SAFETY: invalidating instruction caches changes no data.
            unsafe { asm!("ic ialluis", options(nostack, preserves_flags)) };
        } else {
            // IminLine, bits 3:0: log2 of the smallest line in words.
            let line = 4u64 << (ctr & 0xf);
            let mut at = va & !(line - 1);
            while at < va + len {
                // SAFETY: as above; the range is mapped.
                unsafe { asm!("ic ivau, {}", in(reg) at, options(nostack, preserves_flags)) };
                at += line;
            }
        }
    }
    dsb_ish();
    isb();
}

global_asm!(
    // The trampoline that replaces TTBR1_EL1, as Linux's
    // idmap_cpu_replace_ttbr1 does. The kernel calls it at its physical
    // address, through the bootstrap identity map, because the upper half
    // is unmapped while it runs. x0 is the new level-0 table, x1 the empty
    // one. It touches no memory and no stack, and returns through x30 to
    // the caller's upper-half address, which the new tables map as the old
    // ones did.
    //
    // TTBR1 holds the empty table while every TLB entry is invalidated, so
    // no TLB ever holds entries from both sets of tables: that is
    // break-before-make for the whole half (Arm ARM D8.13), and a change of
    // block size or attributes can't conflict.
    ".pushsection .text.boot, \"ax\"",
    ".balign 4",
    ".global aspis_replace_ttbr1",
    "aspis_replace_ttbr1:",
    "    dsb ishst",
    "    msr ttbr1_el1, x1",
    "    isb",
    "    tlbi vmalle1is",
    "    dsb ish",
    "    isb",
    "    msr ttbr1_el1, x0",
    "    isb",
    "    ret",
    ".popsection",
);

unsafe extern "C" {
    // Only its address is used.
    static aspis_replace_ttbr1: u8;
}

/// The trampoline's address in the kernel's image.
pub fn trampoline() -> u64 {
    (&raw const aspis_replace_ttbr1) as u64
}

/// Points `TTBR1_EL1` at `root`, through the trampoline at physical
/// address `tramp_pa`. `empty` is the physical address of an empty table.
///
/// # Safety
///
/// The bootstrap identity map must be live and map `tramp_pa` executable.
/// `root` must map everything the kernel uses from here on (its image,
/// stack and statics) at the same virtual addresses, and every store to it
/// must be complete. Exceptions must be masked.
pub unsafe fn replace_ttbr1(tramp_pa: u64, root: u64, empty: u64) {
    // SAFETY: as the caller promises. The trampoline clobbers only x30,
    // which `blr` sets, and touches no memory but the system registers.
    unsafe {
        asm!(
            "blr {tramp}",
            tramp = in(reg) tramp_pa,
            in("x0") root,
            in("x1") empty,
            out("x30") _,
            options(nostack)
        );
    }
}

/// Retires the bootstrap identity map and sets the final controls (kernel
/// specification, "Address-space layout", "Registers"):
///
/// - `TCR_EL1.AS` for 16-bit ASIDs, `A1` and `EPD0` clear;
/// - `TTBR0_EL1` = the empty table with ASID 0;
/// - `SCTLR_EL1.WXN`, and `SPAN` cleared where there is PAN;
/// - every TLB entry invalidated, since TCR and WXN may be held in it;
/// - `PSTATE.PAN` set where there is PAN.
///
/// # Safety
///
/// Nothing may use a lower-half address afterwards: the kernel must already
/// run, and reach everything, through `TTBR1_EL1`. `empty` must be the
/// physical address of an empty table.
pub unsafe fn retire_identity(empty: u64, asid16: bool, pan: bool) {
    let mut tcr = tcr() & !(TCR_EPD0 | TCR_A1 | TCR_AS);
    if asid16 {
        tcr |= TCR_AS;
    }
    let mut sctlr = sctlr() | SCTLR_WXN;
    if pan {
        sctlr &= !SCTLR_SPAN;
    }
    // SAFETY: as the caller promises; the kernel runs from the upper half,
    // which none of these changes.
    unsafe {
        asm!(
            "msr tcr_el1, {tcr}",
            "isb",
            "msr ttbr0_el1, {empty}",
            "isb",
            "msr sctlr_el1, {sctlr}",
            "isb",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            tcr = in(reg) tcr,
            empty = in(reg) empty,
            sctlr = in(reg) sctlr,
            options(nostack, preserves_flags)
        );
        if pan {
            // The kernel never clears PAN again (ADR 0048, rule 6).
            asm!(
                "msr s3_0_c4_c2_3, {}",
                "isb",
                in(reg) PSTATE_PAN,
                options(nostack, preserves_flags)
            );
        }
    }
}
