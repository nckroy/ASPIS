// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The kernel's memory management (ADR 0048; kernel specification, "Boot
//! memory", "Untyped memory and kernel records" and "Address-space
//! layout").
//!
//! At boot, [`init`] divides the memory map, builds the kernel's own tables
//! with pages from the boot allocator, which it reaches through the boot
//! window, switches to them, and retires the bootstrap tables. Later chunks
//! make their boot objects, with pages from [`boot_page`]. Then [`seal`]
//! takes the boot CNodes' pages, seals the boot allocator, and gives the
//! rest of RAM, and the device memory, to the boot capability space as
//! untyped capabilities ([`crate::cap::boot`]). From then on the kernel
//! never allocates memory that no job supplied (ADR 0048, rule 1): user
//! address spaces, their tables and their frames are retyped from untyped
//! memory through capabilities ([`crate::cap`], [`space`]), and the kernel
//! reaches user memory only by a software walk ([`user`]).
//!
//! The pure parts are in the `kmem` and `kcap` crates, which are tested on
//! the host.
//!
//! C12: the kernel lock guards the statics here; until then one CPU runs,
//! with exceptions masked.

pub(crate) mod arch;
mod boot_objects;
pub mod boot_window;
mod devices;
mod kernel_map;
pub(crate) mod phys;
// C12 to C16 build on these: until their system calls exist, only the
// capability layer and the in-QEMU tests use them.
#[cfg_attr(not(aspis_test_build), allow(dead_code))]
pub(crate) mod space;
#[cfg(aspis_test_build)]
mod tests;
pub(crate) mod untyped;
#[cfg_attr(not(aspis_test_build), allow(dead_code))]
pub(crate) mod user;

use boot_window::BootWindow;
use bootinfo::{BootInfo, MemoryMap, MemoryType};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use devices::KernelDevices;
pub use devices::{FindError, physical_reg};
use kernel_map::DeviceWindow;
use kirq::layout::GicLayout;
use kmem::boot_alloc::{AllocError, BootAlloc};
use kmem::desc::{Half, MemType};
use kmem::layout;
use kmem::memmap::{Classified, Region, RegionKind};
use kmem::table::{FrameSource, MapError, Tables};
use kmem::{BLOCK_2M, PAGE_SIZE};

/// A static the kernel writes during boot and reads afterwards.
///
/// C12: the kernel lock guards these. Until then one CPU runs, with
/// exceptions masked, and only the panic path interrupts the kernel, which
/// never touches them.
pub struct BootCell<T>(UnsafeCell<T>);

// SAFETY: see the type's comment: no two CPUs, and no reentry.
unsafe impl<T: Send> Sync for BootCell<T> {}

impl<T> BootCell<T> {
    pub const fn new(v: T) -> Self {
        Self(UnsafeCell::new(v))
    }

    /// The contents, to change.
    ///
    /// # Safety
    ///
    /// No other reference to the contents may be live while this one is.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get_mut(&self) -> &mut T {
        // SAFETY: as the caller promises.
        unsafe { &mut *self.0.get() }
    }

    /// The contents, to read.
    ///
    /// # Safety
    ///
    /// No mutable reference to the contents may be live while this one is.
    pub unsafe fn get(&self) -> &T {
        // SAFETY: as the caller promises.
        unsafe { &*self.0.get() }
    }
}

/// Where the boot information, the device tree and the framebuffer are once
/// the boot window is gone: their direct-map and device-window addresses.
#[derive(Clone, Copy, Debug)]
pub struct Moved {
    pub boot_info: u64,
    pub device_tree: Option<u64>,
    pub framebuffer: Option<u64>,
}

/// What boot memory came to, for the boot log.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Bytes of RAM untyped memory, in `ram_pieces` pieces.
    pub untyped_bytes: u64,
    pub ram_pieces: usize,
    pub device_pieces: usize,
    /// Untyped capabilities in the boot capability space: one for each
    /// piece, RAM and device.
    pub untyped_caps: usize,
    /// Pieces beyond the boot capability space's capacity, unused, and
    /// their bytes.
    pub dropped_pieces: usize,
    pub dropped_bytes: u64,
    /// Bytes the boot allocator handed out: the kernel's page tables, and
    /// the boot CNodes.
    pub boot_pages_bytes: u64,
    /// Bytes the direct map covers.
    pub direct_map_bytes: u64,
    /// Usable RAM beyond the direct map's reach, unused.
    pub above_direct_limit: u64,
    pub asid_bits: u8,
    pub pan: bool,
}

#[cfg_attr(not(aspis_test_build), allow(dead_code))]
struct State {
    /// The physical address of the kernel's level-0 table (`TTBR1_EL1`).
    root: u64,
    /// The boot information's direct-map address.
    boot_info: u64,
    /// The UART's physical and device-window addresses.
    uart: Option<(u64, u64)>,
    /// The framebuffer's physical address, size and device-window address.
    framebuffer: Option<(u64, u64, u64)>,
    /// The interrupt controller's mapped frames: physical address, size
    /// and device-window address, in [`GicLayout::mapped`]'s order.
    gic: [(u64, u64, u64); GIC_MAPPED],
    gic_len: usize,
    report: Report,
}

/// The most interrupt-controller frames mapped: the distributor, and the
/// CPU interface or every redistributor region.
const GIC_MAPPED: usize = 1 + kirq::layout::MAX_REDIST_REGIONS;

/// Set once [`init`] and [`seal`] have begun: each runs once.
static INIT_DONE: AtomicBool = AtomicBool::new(false);
static SEALED: AtomicBool = AtomicBool::new(false);

static CLASSIFIED: BootCell<Classified> = BootCell::new(Classified::new());
static BOOT_ALLOC: BootCell<BootAlloc> = BootCell::new(BootAlloc::new());
static DEVICES: BootCell<KernelDevices> = BootCell::new(KernelDevices::new());
static STATE: BootCell<State> = BootCell::new(State {
    root: 0,
    boot_info: 0,
    uart: None,
    framebuffer: None,
    gic: [(0, 0, 0); GIC_MAPPED],
    gic_len: 0,
    report: Report {
        untyped_bytes: 0,
        ram_pieces: 0,
        device_pieces: 0,
        untyped_caps: 0,
        dropped_pieces: 0,
        dropped_bytes: 0,
        boot_pages_bytes: 0,
        direct_map_bytes: 0,
        above_direct_limit: 0,
        asid_bits: 0,
        pan: false,
    },
});

/// The memory map, as one pass of [`Classified::classify`] reads it. The
/// boot information's iterator can't be cloned, so this one walks the map
/// by index; the map holds at most a few hundred ranges.
#[derive(Clone, Copy)]
struct Regions<'a> {
    map: MemoryMap<'a>,
    at: usize,
}

impl Iterator for Regions<'_> {
    type Item = Region;

    fn next(&mut self) -> Option<Region> {
        let r = self.map.iter().nth(self.at)?;
        self.at += 1;
        let kind = match r.memory_type() {
            Some(MemoryType::Usable) => RegionKind::Usable,
            Some(MemoryType::KernelImage) => RegionKind::KernelImage,
            Some(MemoryType::InitialImage) => RegionKind::InitialImage,
            Some(MemoryType::BootInformation) => RegionKind::BootInformation,
            Some(MemoryType::Framebuffer) => RegionKind::Framebuffer,
            Some(MemoryType::Seed) => RegionKind::Seed,
            Some(MemoryType::Mmio) => RegionKind::Mmio,
            // Firmware-reserved, ACPI, unusable, and any type the kernel
            // doesn't know: never mapped, never given out.
            Some(
                MemoryType::FirmwareReserved
                | MemoryType::AcpiReclaimable
                | MemoryType::AcpiNonVolatile
                | MemoryType::Unusable,
            )
            | None => RegionKind::Excluded,
        };
        Some(Region {
            base: r.base,
            pages: r.pages,
            kind,
        })
    }
}

/// Pages for the kernel's own tables, from the boot allocator, mapped in
/// the boot window and zeroed there. After the switch, later chunks reach
/// the pages they take through the direct map instead.
struct BootFrames<'a> {
    alloc: &'a mut BootAlloc,
}

impl FrameSource for BootFrames<'_> {
    fn table(&mut self) -> Option<u64> {
        // Any usable page: the boot window reaches every one, and the
        // direct map reaches it after the switch, since `classify` leaves
        // RAM beyond the direct map out of usable memory.
        let pa = match self.alloc.alloc(None) {
            Ok(pa) => pa,
            Err(AllocError::Exhausted) => return None,
            // ADR 0048, rule 1: after boot, the kernel never allocates
            // memory that no job supplied.
            Err(AllocError::Sealed) => panic!("the boot allocator is sealed"),
        };
        let va = boot_window::map_table(pa);
        // SAFETY: a page of usable RAM the boot allocator just handed out,
        // which nothing uses, mapped read-write as normal memory in the boot
        // window.
        unsafe { arch::zero(va, PAGE_SIZE) };
        // The zeroes reach the walkers before the table is linked.
        arch::dsb_ishst();
        Some(pa)
    }
}

fn map_failed(what: &str, e: MapError) -> ! {
    panic!("can't map {what} in the kernel's tables: {e:?}")
}

/// Divides the memory map, builds the kernel's own tables, switches to
/// them and retires the bootstrap identity map (kernel specification,
/// "Address-space layout", "Bootstrap tables and the switch"). Returns the
/// new addresses of what the kernel still reads.
///
/// `info` is the boot information, at `info_range` in physical memory,
/// read through the boot window, and `fdt` the device tree. Neither may be
/// used after this returns: the boot window is gone.
///
/// It doesn't log, because the log ring is configured later. A failure
/// panics through the UART, which works throughout.
pub fn init(info_range: (u64, u64), info: &BootInfo<'_>, fdt: Option<&fdt::Fdt<'_>>) -> Moved {
    // A second run would hand the pages of the live tables out again.
    assert!(
        !INIT_DONE.swap(true, Ordering::Relaxed),
        "mm::init runs twice"
    );
    let pan = arch::has_pan();
    let asid_bits = arch::asid_bits();
    space::init(asid_bits);
    let pa_bits = layout::pa_bits((arch::id_aa64mmfr0() & 0xf) as u8);

    // SAFETY: `init` runs once, as the guard above checks, at boot, before
    // anything reads these, and holds the only references to them until it
    // returns.
    let (devices, c, alloc, state) = unsafe {
        (
            DEVICES.get_mut(),
            CLASSIFIED.get_mut(),
            BOOT_ALLOC.get_mut(),
            STATE.get_mut(),
        )
    };

    // 1. Classify the memory map (ADR 0048, rule 1). The kernel must know
    // every frame of its own devices before it gives any device memory out.
    if let Err(e) = devices.find(fdt) {
        panic!("{e}");
    }
    let regions = Regions {
        map: info.memory_map(),
        at: 0,
    };
    if c.classify(regions, devices.all(), pa_bits).is_err() {
        panic!("the memory map has more ranges than the kernel's tables hold");
    }

    // The image: where the stub put it. The trampoline runs at its physical
    // address, through the bootstrap identity map of the image's text.
    let k = info.kernel_placement();
    assert!(
        k.virtual_base == phys::kernel_start()
            && k.physical_base.is_multiple_of(BLOCK_2M)
            && k.size <= layout::KERNEL_MAX_SIZE,
        "the kernel isn't where the bootstrap tables expect it: {:#x} at {:#x}",
        k.virtual_base,
        k.physical_base
    );
    assert!(
        c.kept.contains(k.physical_base, k.physical_base + k.size),
        "the memory map doesn't keep the kernel's image"
    );
    phys::set_kernel_phys(k.physical_base);

    boot_objects::record(info, info_range, c);

    // 2. Build the tables, with pages from the boot allocator, written
    // through the boot window. Every page is zeroed before it is linked.
    if alloc.start(&c.usable).is_err() {
        panic!("the boot allocator can't hold the usable ranges");
    }
    let mut src = BootFrames { alloc };
    let Some(root) = src.table() else {
        panic!("no usable RAM for the kernel's tables");
    };
    let t = Tables::new(&BootWindow, root, Half::Kernel);
    kernel_map::map_image(&t, &mut src, phys::kernel_pa)
        .unwrap_or_else(|e| map_failed("the image", e));
    kernel_map::map_direct(&t, &mut src, c).unwrap_or_else(|e| map_failed("the direct map", e));
    let mut window = DeviceWindow::new();
    let uart = devices.uart.map(|r| {
        let va = window
            .map(&t, &mut src, r, MemType::Device)
            .unwrap_or_else(|e| map_failed("the UART", e));
        (r.0, va)
    });
    // The framebuffer is normal non-cacheable memory, so scan-out needs no
    // cache maintenance.
    let fb = info.framebuffer();
    let fb_va = fb.map(|f| {
        window
            .map(&t, &mut src, (f.base, f.size), MemType::NonCacheable)
            .unwrap_or_else(|e| map_failed("the framebuffer", e))
    });
    // The interrupt controller's frames the driver uses, as device memory
    // (C13a; kernel specification, "The kernel's interrupt controller").
    // Its other frames stay unmapped, and all of them stay out of device
    // untyped memory.
    let mut gic = [(0, 0, 0); GIC_MAPPED];
    let mut gic_len = 0;
    if let Some(layout) = &devices.layout {
        for f in layout.mapped() {
            let va = window
                .map(&t, &mut src, (f.base, f.size), MemType::Device)
                .unwrap_or_else(|e| map_failed("the interrupt controller", e));
            gic[gic_len] = (f.base, f.size, va);
            gic_len += 1;
        }
    }

    // The new addresses of what the kernel still reads, found while the
    // boot window still maps the boot information.
    let direct = |pa: u64| {
        layout::direct_va(pa).unwrap_or_else(|| panic!("{pa:#x} is beyond the direct map"))
    };
    let moved = Moved {
        boot_info: direct(info_range.0),
        device_tree: info.device_tree().map(|(pa, _)| direct(pa)),
        framebuffer: fb_va,
    };

    // 3 and 4. Replace TTBR1 from the identity map. The trampoline's DSB
    // makes every table write visible to the walker first.
    let empty = phys::kernel_pa(crate::entry::zero_table());
    // SAFETY: the identity map is live and maps the trampoline, in the
    // image's text, as executable normal memory. The new tables map the
    // image at the same addresses, and exceptions are masked.
    unsafe { arch::replace_ttbr1(phys::kernel_pa(arch::trampoline()), root, empty) };

    // 5. The boot window went with the bootstrap tables: move the console
    // to the device window at once, before anything can print.
    boot_window::close();
    crate::uart::rebase(uart.map_or(0, |(_, va)| va));

    // 6. Retire the identity map, and set WXN and PAN.
    // SAFETY: the kernel now runs, and reaches everything it uses, through
    // TTBR1. `info` and `fdt`, in the boot window, aren't used again.
    unsafe { arch::retire_identity(empty, asid_bits == 16, pan) };

    // The framebuffer's cacheability changed: the firmware had it
    // write-back. Clean and invalidate it, so no dirty line can
    // later overwrite pixels (kernel specification, "Memory types").
    if let (Some(f), Some(va)) = (fb, fb_va) {
        // SAFETY: the device window maps the whole framebuffer.
        unsafe { arch::clean_invalidate(va, f.size) };
    }

    *state = State {
        root,
        boot_info: moved.boot_info,
        uart,
        framebuffer: fb.zip(fb_va).map(|(f, va)| (f.base, f.size, va)),
        gic,
        gic_len,
        report: Report {
            direct_map_bytes: c.usable.total() + c.direct_map_ro().map(|(s, e)| e - s).sum::<u64>(),
            above_direct_limit: c.above_direct_limit,
            asid_bits,
            pan,
            ..Report::default()
        },
    };
    moved
}

/// Takes a zeroed page of usable RAM from the boot allocator, after the
/// switch to the kernel's own tables and before the seal, for a boot
/// object: the boot CNodes now; later chunks' boot objects, other cores'
/// stacks and the LPI tables (kernel specification, "Boot memory"). Boot
/// objects belong to no job and are never destroyed (ADR 0048, rule 2), so
/// the page never comes back.
///
/// Before the seal only: after it the boot allocator panics, since the
/// kernel then never allocates memory that no job supplied (ADR 0048,
/// rule 1).
pub fn boot_page() -> u64 {
    assert!(
        INIT_DONE.load(Ordering::Relaxed),
        "mm::boot_page runs before mm::init"
    );
    // SAFETY: during boot, on one CPU; the reference lives only for this
    // call, and no other reference to the allocator is live.
    let alloc = unsafe { BOOT_ALLOC.get_mut() };
    let pa = match alloc.alloc(None) {
        Ok(pa) => pa,
        Err(AllocError::Exhausted) => panic!("no usable RAM left for the boot objects"),
        Err(AllocError::Sealed) => panic!("the boot allocator is sealed"),
    };
    let Some(va) = layout::direct_va(pa) else {
        // `classify` leaves RAM beyond the direct map out of usable memory.
        panic!("boot page {pa:#x} is beyond the direct map");
    };
    // SAFETY: a page of usable RAM the boot allocator just handed out, which
    // nothing uses, mapped read-write as normal memory in the direct map.
    unsafe { arch::zero(va, PAGE_SIZE) };
    // The zeroes are visible before the page is used.
    arch::dsb_ishst();
    pa
}

/// Builds the boot capability space and seals the boot allocator (ADR 0048,
/// rule 1; kernel specification, "What the root server receives"):
///
/// 1. takes the boot CNodes' pages, with [`boot_page`]: the root CNode, the
///    page that keeps the boot CNodes' original capabilities, and a fixed
///    [`crate::cap::boot::UNTYPED_CNODES`] untyped CNodes, enough for
///    [`untyped::MAX_PIECES`] pieces whatever the pages taken do to the free
///    set;
/// 2. seals the boot allocator;
/// 3. divides what is left, and the device memory, into pieces, zeroing the
///    RAM, and puts an untyped capability to each piece in the untyped
///    CNodes.
///
/// Later chunks make their boot objects, other cores' stacks and the LPI
/// tables before this.
pub fn seal() {
    // A second seal would give the same memory out twice as untyped
    // memory (ADR 0048, rule 1); a seal before `init` would give it all.
    assert!(
        INIT_DONE.load(Ordering::Relaxed),
        "mm::seal runs before mm::init"
    );
    assert!(!SEALED.swap(true, Ordering::Relaxed), "mm::seal runs twice");
    let root = boot_page();
    let originals = boot_page();
    let cnodes: [u64; crate::cap::boot::UNTYPED_CNODES] = core::array::from_fn(|_| boot_page());
    // SAFETY: the one call, after `init` has returned; it holds the only
    // references to these until it returns.
    let (alloc, state, c) = unsafe { (BOOT_ALLOC.get_mut(), STATE.get_mut(), CLASSIFIED.get()) };
    alloc.seal();
    let mut space = crate::cap::boot::BootSpace::new(root, originals, cnodes);
    let t = untyped::build(alloc.free(), &c.device, |piece| space.add_untyped(&piece));
    state.report.untyped_bytes = t.ram_bytes;
    state.report.ram_pieces = t.ram;
    state.report.device_pieces = t.device;
    state.report.untyped_caps = space.untyped_count();
    state.report.dropped_pieces = t.dropped;
    state.report.dropped_bytes = t.dropped_bytes;
    state.report.boot_pages_bytes = alloc.taken().total();
}

/// What boot memory came to.
pub fn report() -> Report {
    // SAFETY: written only by `init` and `seal`, during boot.
    unsafe { STATE.get() }.report
}

/// The interrupt controller's frames, by role, as the device tree gave
/// them. `None` before [`init`].
pub fn gic_layout() -> Option<&'static GicLayout> {
    // SAFETY: written only by `init`, during boot.
    unsafe { DEVICES.get() }.layout.as_ref()
}

/// The `phandle` of the interrupt controller's node, if it has one. `None`
/// before [`init`].
pub fn gic_phandle() -> Option<u32> {
    // SAFETY: written only by `init`, during boot.
    unsafe { DEVICES.get() }.gic_phandle
}

/// The device-window address of `[pa, pa + size)`, if `init` mapped it as
/// part of an interrupt-controller frame.
pub fn device_va(pa: u64, size: u64) -> Option<u64> {
    let end = pa.checked_add(size)?;
    let s = state();
    s.gic[..s.gic_len]
        .iter()
        .find(|&&(base, len, _)| base <= pa && end <= base + len)
        .map(|&(base, _, va)| va + (pa - base))
}

/// The device tree, through the direct map, for tests that read it again.
#[cfg(aspis_test_build)]
pub fn device_tree() -> Option<fdt::Fdt<'static>> {
    // SAFETY: `init` recorded the boot information's direct-map address.
    let (info, _) = unsafe { crate::boot_info(state().boot_info) }?;
    let (pa, len) = info.device_tree()?;
    let va = layout::direct_va(pa)?;
    // SAFETY: the device tree, which the direct map keeps read-only.
    unsafe { crate::device_tree(va, len) }
}

/// The memory map, as `init` divided it.
#[cfg_attr(not(aspis_test_build), allow(dead_code))]
fn classified() -> &'static Classified {
    // SAFETY: written only by `init`.
    unsafe { CLASSIFIED.get() }
}

/// What `init` recorded.
fn state() -> &'static State {
    // SAFETY: written only by `init` and `seal`, during boot.
    unsafe { STATE.get() }
}
