// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The system registers and barriers the interrupt code needs, and volatile
//! access to the GIC's frames. This and the windows in the parent module
//! are the only `asm!` in `irq`.
//!
//! The GICv3 CPU interface's registers are named by their generic
//! encodings, `S3_<op1>_C<n>_C<m>_<op2>`, so no `.arch` directive is
//! needed for a CPU, such as the Cortex-A72, whose GIC is a GICv2.

use core::arch::asm;

macro_rules! read_sysreg {
    ($(#[$m:meta])* $name:ident, $reg:literal) => {
        $(#[$m])*
        #[allow(dead_code)]
        pub fn $name() -> u64 {
            let v: u64;
            // SAFETY: reading this system register at EL1 has no side
            // effects; the caller checked that it exists.
            unsafe { asm!(concat!("mrs {}, ", $reg), out(reg) v, options(nomem, nostack, preserves_flags)) };
            v
        }
    };
}

macro_rules! write_sysreg {
    ($(#[$m:meta])* $name:ident, $reg:literal) => {
        $(#[$m])*
        ///
        /// # Safety
        ///
        /// The register must exist, and the value must keep the kernel's
        /// interrupt state as the kernel specification's "The kernel's
        /// interrupt controller" describes it.
        #[allow(dead_code)]
        pub unsafe fn $name(v: u64) {
            // SAFETY: as the caller promises.
            unsafe { asm!(concat!("msr ", $reg, ", {}"), in(reg) v, options(nostack, preserves_flags)) };
        }
    };
}

read_sysreg!(
    /// `MPIDR_EL1`: this core's affinity.
    mpidr,
    "mpidr_el1"
);
read_sysreg!(
    /// `ID_AA64PFR0_EL1`: its GIC field says whether the GICv3 system
    /// registers exist.
    id_aa64pfr0,
    "id_aa64pfr0_el1"
);
read_sysreg!(
    /// `ISR_EL1`: the interrupts pending at this core, masked or not.
    isr,
    "isr_el1"
);
read_sysreg!(
    /// `DAIF`: the exception masks.
    daif,
    "daif"
);

read_sysreg!(icc_sre, "s3_0_c12_c12_5");
write_sysreg!(
    /// `ICC_SRE_EL1`.
    set_icc_sre,
    "s3_0_c12_c12_5"
);
read_sysreg!(icc_pmr, "s3_0_c4_c6_0");
write_sysreg!(
    /// `ICC_PMR_EL1`.
    set_icc_pmr,
    "s3_0_c4_c6_0"
);
read_sysreg!(icc_bpr1, "s3_0_c12_c12_3");
write_sysreg!(
    /// `ICC_BPR1_EL1`.
    set_icc_bpr1,
    "s3_0_c12_c12_3"
);
read_sysreg!(icc_ctlr, "s3_0_c12_c12_4");
write_sysreg!(
    /// `ICC_CTLR_EL1`.
    set_icc_ctlr,
    "s3_0_c12_c12_4"
);
read_sysreg!(icc_igrpen1, "s3_0_c12_c12_7");
write_sysreg!(
    /// `ICC_IGRPEN1_EL1`.
    set_icc_igrpen1,
    "s3_0_c12_c12_7"
);
read_sysreg!(icc_rpr, "s3_0_c12_c11_3");
write_sysreg!(
    /// `ICC_EOIR1_EL1`: ends the interrupt an acknowledge returned.
    set_icc_eoir1,
    "s3_0_c12_c12_1"
);
write_sysreg!(
    /// `ICC_SGI1R_EL1`: sends a Group 1 SGI.
    set_icc_sgi1r,
    "s3_0_c12_c11_5"
);

/// Reads `ICC_AP1R<n>_EL1`, for `n` below 4.
pub fn icc_ap1r(n: usize) -> u64 {
    match n {
        0 => icc_ap1r0(),
        1 => icc_ap1r1(),
        2 => icc_ap1r2(),
        _ => icc_ap1r3(),
    }
}
read_sysreg!(icc_ap1r0, "s3_0_c12_c9_0");
read_sysreg!(icc_ap1r1, "s3_0_c12_c9_1");
read_sysreg!(icc_ap1r2, "s3_0_c12_c9_2");
read_sysreg!(icc_ap1r3, "s3_0_c12_c9_3");

/// Clears `ICC_AP1R<n>_EL1`, for `n` below 4, as Linux's
/// `gic_cpu_sys_reg_init` does, so that no priority firmware left active
/// blocks the kernel's interrupts. Writing 0 is always allowed.
///
/// # Safety
///
/// `n` must be below [`kirq::regs::icc::ap1r_count`] for this CPU
/// interface, and no interrupt may be active at this core.
pub unsafe fn clear_icc_ap1r(n: usize) {
    // SAFETY: as the caller promises.
    unsafe {
        match n {
            0 => asm!("msr s3_0_c12_c9_0, xzr", options(nostack, preserves_flags)),
            1 => asm!("msr s3_0_c12_c9_1, xzr", options(nostack, preserves_flags)),
            2 => asm!("msr s3_0_c12_c9_2, xzr", options(nostack, preserves_flags)),
            _ => asm!("msr s3_0_c12_c9_3, xzr", options(nostack, preserves_flags)),
        }
    }
}

/// Acknowledges the highest-priority pending Group 1 interrupt
/// (`ICC_IAR1_EL1`), then `DSB SY`, as Linux's `gic_read_iar` does, so the
/// acknowledge is ordered before the handler's memory accesses.
///
/// # Safety
///
/// The caller must end the interrupt it returns, unless it is special.
pub unsafe fn icc_iar1() -> u64 {
    let v: u64;
    // SAFETY: as the caller promises.
    unsafe {
        asm!(
            "mrs {}, s3_0_c12_c12_0",
            "dsb sy",
            out(reg) v,
            options(nostack, preserves_flags)
        )
    };
    v
}

/// Makes this core's later instructions see earlier system-register writes
/// (`ISB`).
pub fn isb() {
    // SAFETY: a barrier.
    unsafe { asm!("isb", options(nostack, preserves_flags)) };
}

/// Makes every earlier store visible in the inner-shareable domain before
/// any later one (`DSB ISHST`): before an SGI, so the core that takes it
/// sees what the sender wrote.
pub fn dsb_ishst() {
    // SAFETY: a barrier.
    unsafe { asm!("dsb ishst", options(nostack, preserves_flags)) };
}

/// Orders every earlier memory access before every later one, in the
/// inner-shareable domain (`DMB ISH`): after a GICv2 acknowledge, so the
/// handler reads what an SGI's sender wrote. Not `nomem`, so the compiler
/// keeps memory accesses on their side of it too.
pub fn dmb_ish() {
    // SAFETY: a barrier.
    unsafe { asm!("dmb ish", options(nostack, preserves_flags)) };
}

/// A frame of the GIC, in the device window: its virtual address and size.
#[derive(Clone, Copy, Debug)]
pub struct Mmio {
    va: u64,
    size: usize,
}

impl Mmio {
    /// The frame at `va`, `size` bytes.
    ///
    /// # Safety
    ///
    /// `[va, va + size)` must be mapped as device memory, read-write, and be
    /// a frame of the GIC, for as long as the kernel runs.
    pub const unsafe fn new(va: u64, size: usize) -> Mmio {
        Mmio { va, size }
    }

    /// The part of the frame from `offset` on, such as a redistributor's
    /// `SGI_base` frame.
    pub fn at(self, offset: usize) -> Mmio {
        assert!(offset <= self.size, "a GIC offset beyond its frame");
        Mmio {
            va: self.va + offset as u64,
            size: self.size - offset,
        }
    }

    fn addr(self, offset: usize, len: usize) -> u64 {
        // A register beyond the frame is a kernel bug: never touch memory
        // the frame doesn't map.
        assert!(
            offset.is_multiple_of(len) && offset + len <= self.size,
            "a GIC register beyond its frame"
        );
        self.va + offset as u64
    }

    /// The virtual address of the register at `offset`, for the panic
    /// path's single store.
    pub fn va(self, offset: usize) -> u64 {
        self.addr(offset, 4)
    }

    pub fn read32(self, offset: usize) -> u32 {
        // SAFETY: an aligned register inside the frame, mapped as device
        // memory (`new`'s contract).
        unsafe { core::ptr::read_volatile(self.addr(offset, 4) as *const u32) }
    }

    pub fn write32(self, offset: usize, v: u32) {
        // SAFETY: as for `read32`.
        unsafe { core::ptr::write_volatile(self.addr(offset, 4) as *mut u32, v) }
    }

    pub fn read64(self, offset: usize) -> u64 {
        // SAFETY: as for `read32`; the GICv3's 64-bit registers take
        // 64-bit accesses.
        unsafe { core::ptr::read_volatile(self.addr(offset, 8) as *const u64) }
    }

    pub fn write64(self, offset: usize, v: u64) {
        // SAFETY: as for `read64`.
        unsafe { core::ptr::write_volatile(self.addr(offset, 8) as *mut u64, v) }
    }
}
