// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Dividing the boot information's memory map (ADR 0041, rule 3) into what
//! the kernel keeps, what the direct map covers, and what becomes untyped
//! and device untyped memory (ADR 0048, rules 1, 2 and 4; kernel
//! specification, "Boot memory").
//!
//! The rules:
//!
//! - Usable ranges are rounded inward to pages; every other type outward.
//! - Where ranges overlap, the more restrictive type wins, in this order:
//!   excluded (firmware-reserved, ACPI, unusable and unknown types); the
//!   seed; the framebuffer; the kept ranges (kernel image, initial image and
//!   boot information); MMIO; usable.
//! - Kept ranges are kept whole, slack pages included. The panic symbol
//!   table, which the stub places inside the kernel image's range, is kept
//!   with it.
//! - Usable RAM at or above [`DIRECT_MAP_PA_LIMIT`] can't be direct-mapped,
//!   so it isn't used. [`Classified::above_direct_limit`] counts it.
//! - Device untyped memory is the complement of every range that isn't
//!   MMIO, up to the physical address size, as in seL4, less the devices the
//!   kernel drives itself: the UART and every frame of the interrupt
//!   controller.

use crate::layout::DIRECT_MAP_PA_LIMIT;
use crate::ranges::{Full, RangeSet};
use crate::{PAGE_SIZE, align_down, align_up};

/// The most ranges one class may hold. The stub's memory map has at most a
/// few hundred entries; seven sets of this size take 28 KiB.
pub const CLASS_RANGES: usize = 256;

/// One class of the memory map.
pub type ClassSet = RangeSet<CLASS_RANGES>;

/// What the kernel makes of a memory-map range. The kernel maps
/// `bootinfo::MemoryType`, and unknown values, into these, so this crate
/// doesn't depend on the boot ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionKind {
    /// RAM the firmware left free.
    Usable,
    /// The kernel's image, with the panic symbol table inside the range.
    KernelImage,
    /// The initial image (ADR 0037).
    InitialImage,
    /// The boot information and the device tree copy it points to.
    BootInformation,
    /// The boot framebuffer (ADR 0042, rule 6).
    Framebuffer,
    /// The seed's page, which the kernel never maps (ADR 0041, rule 4).
    Seed,
    /// Memory-mapped I/O.
    Mmio,
    /// Firmware-reserved (UEFI runtime included, ADR 0039), ACPI reclaimable
    /// and non-volatile, unusable, and any type the kernel doesn't know.
    /// Never mapped, never given out.
    Excluded,
}

/// One memory-map range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub base: u64,
    /// The length in 4 KiB pages, as the boot information gives it.
    pub pages: u64,
    pub kind: RegionKind,
}

impl Region {
    /// The range in bytes, rounded to pages: inward for usable memory,
    /// outward for everything else. Saturates at the top of the address
    /// space.
    pub fn rounded(&self) -> (u64, u64) {
        let end = self
            .pages
            .checked_mul(PAGE_SIZE)
            .and_then(|len| self.base.checked_add(len))
            .unwrap_or(u64::MAX);
        if self.kind == RegionKind::Usable {
            let start = align_up(self.base, PAGE_SIZE).unwrap_or(u64::MAX);
            (start, align_down(end, PAGE_SIZE).max(start))
        } else {
            self.outward()
        }
    }

    /// The range in bytes, rounded outward to pages whatever its type: every
    /// page that holds any of it.
    pub fn outward(&self) -> (u64, u64) {
        let end = self
            .pages
            .checked_mul(PAGE_SIZE)
            .and_then(|len| self.base.checked_add(len))
            .unwrap_or(u64::MAX);
        let end = align_up(end, PAGE_SIZE).unwrap_or(align_down(u64::MAX, PAGE_SIZE));
        (align_down(self.base, PAGE_SIZE), end)
    }
}

/// The memory map, divided. Every set is page-aligned, and the sets
/// `usable`, `kept`, `framebuffer`, `seed`, `excluded` and `mmio` are
/// pairwise disjoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classified {
    /// Usable RAM below [`DIRECT_MAP_PA_LIMIT`]: mapped read-write in the
    /// direct map. The boot allocator takes its pages from here, and the
    /// rest becomes untyped memory.
    pub usable: ClassSet,
    /// The kernel image, initial image and boot information, kept whole and
    /// mapped read-only in the direct map.
    pub kept: ClassSet,
    /// The boot framebuffer: mapped only in the device window.
    pub framebuffer: ClassSet,
    /// The seed's page: mapped nowhere.
    pub seed: ClassSet,
    /// Firmware, ACPI, unusable and unknown memory: mapped nowhere, never
    /// given out.
    pub excluded: ClassSet,
    /// MMIO ranges that the memory map names.
    pub mmio: ClassSet,
    /// Device untyped memory: everything up to the physical address size
    /// that no range other than MMIO covers, less the kernel's own devices.
    pub device: ClassSet,
    /// Bytes of usable RAM at or above [`DIRECT_MAP_PA_LIMIT`], unused.
    pub above_direct_limit: u64,
    /// The physical address size the device complement reaches, in bits.
    pub pa_bits: u8,
}

impl Default for Classified {
    fn default() -> Self {
        Self::new()
    }
}

impl Classified {
    /// Empty sets. The kernel keeps one in a static and fills it with
    /// [`Classified::classify`].
    pub const fn new() -> Self {
        Self {
            usable: RangeSet::new(),
            kept: RangeSet::new(),
            framebuffer: RangeSet::new(),
            seed: RangeSet::new(),
            excluded: RangeSet::new(),
            mmio: RangeSet::new(),
            device: RangeSet::new(),
            above_direct_limit: 0,
            pa_bits: 0,
        }
    }

    /// Divides the memory map `regions`, in place.
    ///
    /// `kernel_devices` lists the `(base, size)` of each device the kernel
    /// drives itself, from the device tree: the UART and every frame of the
    /// interrupt controller. They are left out of device untyped memory (ADR
    /// 0048, rule 1). `pa_bits` is the physical address size, from
    /// [`crate::layout::pa_bits`].
    pub fn classify(
        &mut self,
        regions: impl IntoIterator<Item = Region> + Clone,
        kernel_devices: &[(u64, u64)],
        pa_bits: u8,
    ) -> Result<(), Full> {
        for set in self.sets_mut() {
            set.clear();
        }
        self.above_direct_limit = 0;
        self.pa_bits = pa_bits.min(48);

        for r in regions.clone() {
            let (s, e) = r.rounded();
            let set = match r.kind {
                RegionKind::Usable => &mut self.usable,
                RegionKind::KernelImage
                | RegionKind::InitialImage
                | RegionKind::BootInformation => &mut self.kept,
                RegionKind::Framebuffer => &mut self.framebuffer,
                RegionKind::Seed => &mut self.seed,
                RegionKind::Mmio => &mut self.mmio,
                RegionKind::Excluded => &mut self.excluded,
            };
            set.insert(s, e)?;
        }

        // Precedence: each class loses what a more restrictive one claims.
        self.seed.remove_set(&self.excluded)?;
        self.framebuffer.remove_set(&self.excluded)?;
        self.framebuffer.remove_set(&self.seed)?;
        for higher in [&self.excluded, &self.seed, &self.framebuffer] {
            self.kept.remove_set(higher)?;
        }
        for higher in [&self.excluded, &self.seed, &self.framebuffer, &self.kept] {
            self.mmio.remove_set(higher)?;
        }
        for higher in [
            &self.excluded,
            &self.seed,
            &self.framebuffer,
            &self.kept,
            &self.mmio,
        ] {
            self.usable.remove_set(higher)?;
        }

        // RAM the direct map can't reach isn't used.
        for (s, e) in self.usable.iter() {
            if e > DIRECT_MAP_PA_LIMIT {
                self.above_direct_limit += e - s.max(DIRECT_MAP_PA_LIMIT);
            }
        }
        self.usable.clip(0, DIRECT_MAP_PA_LIMIT);

        // Device untyped: the complement of every range that isn't MMIO,
        // RAM above the direct map's reach included, up to the physical
        // address size. Every range is rounded outward here, so a page that
        // holds any RAM is never device memory.
        self.device.insert(0, 1u64 << self.pa_bits)?;
        for r in regions {
            if r.kind != RegionKind::Mmio {
                let (s, e) = r.outward();
                self.device.remove(s, e)?;
            }
        }
        for &(base, size) in kernel_devices {
            let end = base.saturating_add(size);
            let end = align_up(end, PAGE_SIZE).unwrap_or(u64::MAX);
            self.device.remove(align_down(base, PAGE_SIZE), end)?;
        }
        Ok(())
    }

    fn sets_mut(&mut self) -> [&mut ClassSet; 7] {
        [
            &mut self.usable,
            &mut self.kept,
            &mut self.framebuffer,
            &mut self.seed,
            &mut self.excluded,
            &mut self.mmio,
            &mut self.device,
        ]
    }

    /// The ranges the direct map covers read-write: usable RAM.
    pub fn direct_map_rw(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.usable.iter()
    }

    /// The ranges the direct map covers read-only: the kept ranges, below
    /// the direct map's reach. The kernel image has no writable alias (ADR
    /// 0048, rule 4).
    pub fn direct_map_ro(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.kept
            .iter()
            .filter(|&(s, _)| s < DIRECT_MAP_PA_LIMIT)
            .map(|(s, e)| (s, e.min(DIRECT_MAP_PA_LIMIT)))
    }

    /// Whether the direct map covers all of `[pa, pa + len)`, read-write if
    /// `write`, else read-only or read-write.
    pub fn direct_map_covers(&self, pa: u64, len: u64, write: bool) -> bool {
        let Some(end) = pa.checked_add(len) else {
            return false;
        };
        if self.usable.contains(pa, end) {
            return true;
        }
        !write && end <= DIRECT_MAP_PA_LIMIT && self.kept.contains(pa, end)
    }
}
