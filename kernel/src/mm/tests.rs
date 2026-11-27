// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! In-QEMU tests of the kernel's tables and boot memory (ADR 0036, rule 5).
//! They check the invariants of ADR 0048 on the tables the kernel really
//! runs on, through the direct map, and the boot untyped pieces that
//! `mm::seal` gave to the boot capability space. User address spaces are
//! made and mapped through capabilities.

use super::*;
use kmem::desc::{self, Leaf, MAIR_DEVICE, MAIR_NC, MAIR_NORMAL};
use kmem::layout::{DEVICE_WINDOW_BASE, DEVICE_WINDOW_SIZE, DIRECT_MAP_BASE, DIRECT_MAP_PA_LIMIT};
use kmem::table::Walk;
use phys::DirectMem;

/// The kernel's tables, as `TTBR1_EL1` holds them, read through the direct
/// map.
fn kernel_tables() -> Tables<'static, DirectMem> {
    let root = arch::ttbr1() & 0x0000_ffff_ffff_f000;
    assert_eq!(root, state().root, "TTBR1_EL1 isn't the kernel's table");
    Tables::new(&DirectMem, root, Half::Kernel)
}

/// Calls `f(va, leaf)` for every leaf of the kernel's tables.
fn each_kernel_leaf(mut f: impl FnMut(u64, &Leaf)) {
    kernel_tables().for_each_leaf(&mut |va, leaf| f(va, leaf));
}

fn overlaps((s, e): (u64, u64), (s2, e2): (u64, u64)) -> bool {
    s < e2 && s2 < e
}

fn within((s, e): (u64, u64), (s2, e2): (u64, u64)) -> bool {
    s2 <= s && e <= e2
}

fn in_direct_map(va: u64) -> bool {
    va >= DIRECT_MAP_BASE && va - DIRECT_MAP_BASE < DIRECT_MAP_PA_LIMIT
}

fn in_device_window(va: u64) -> bool {
    va >= DEVICE_WINDOW_BASE && va - DEVICE_WINDOW_BASE < DEVICE_WINDOW_SIZE
}

/// The boot information, through the direct map.
fn info() -> BootInfo<'static> {
    // SAFETY: `init` recorded the boot information's direct-map address.
    let Some((info, _)) = (unsafe { crate::boot_info(state().boot_info) }) else {
        panic!("no boot information in the direct map");
    };
    info
}

/// Every memory-map range, rounded outward, with its type.
fn each_range(mut f: impl FnMut((u64, u64), Option<MemoryType>)) {
    for r in info().memory_map().iter() {
        let region = Region {
            base: r.base,
            pages: r.pages,
            kind: RegionKind::Excluded,
        };
        f(region.outward(), r.memory_type());
    }
}

fn is_kept(t: Option<MemoryType>) -> bool {
    matches!(
        t,
        Some(MemoryType::KernelImage | MemoryType::InitialImage | MemoryType::BootInformation)
    )
}

crate::kernel_test!(kernel_mappings_are_w_xor_x, {
    let l = kernel_map::image_layout();
    let image = (l.text.0, l.data.1);
    let mut text_leaves = 0;
    each_kernel_leaf(|va, leaf| {
        let span = (va, va + leaf.size());
        assert!(leaf.uxn, "kernel leaf at {va:#x} isn't UXN");
        assert!(!desc::violates_wx(leaf), "kernel leaf at {va:#x} is W+X");
        assert!(leaf.global && leaf.access_flag && !leaf.el0_read);
        if !leaf.pxn {
            // Only text is executable, and it is read-only.
            assert!(
                within(span, l.text),
                "executable leaf at {va:#x} outside text"
            );
            assert!(!leaf.el1_write);
            text_leaves += 1;
        }
        if overlaps(span, image) {
            assert_eq!(leaf.attr_index, MAIR_NORMAL);
            assert!(!overlaps(span, l.guard), "the guard page is mapped");
            if within(span, l.text) {
                assert!(!leaf.pxn && !leaf.el1_write, "text at {va:#x}");
            } else if within(span, l.rodata) {
                assert!(leaf.pxn && !leaf.el1_write, "read-only data at {va:#x}");
            } else if within(span, l.data) {
                assert!(leaf.pxn && leaf.el1_write, "data at {va:#x}");
            } else {
                panic!("leaf at {va:#x} straddles two parts of the image");
            }
        }
    });
    assert!(text_leaves > 0);
    // Below the boot stack there is nothing: an overflow faults.
    assert!(matches!(
        kernel_tables().walk(l.guard.0),
        Walk::Invalid { .. }
    ));
    assert_eq!(arch::at_s1e1r(l.guard.0) & arch::PAR_F, arch::PAR_F);
});

crate::kernel_test!(
    direct_map_is_never_executable_and_keeps_the_image_read_only,
    {
        let c = classified();
        let l = kernel_map::image_layout();
        let text = (phys::kernel_pa(l.text.0), phys::kernel_pa(l.text.1 - 1) + 1);
        let mut direct = 0;
        each_kernel_leaf(|va, leaf| {
            let pa = (leaf.pa, leaf.pa + leaf.size());
            if in_direct_map(va) {
                direct += 1;
                assert_eq!(va - DIRECT_MAP_BASE, leaf.pa, "the direct map is offset");
                assert!(
                    leaf.pxn && leaf.uxn,
                    "direct map leaf at {va:#x} is executable"
                );
                assert_eq!(leaf.attr_index, MAIR_NORMAL);
                assert!(!leaf.device_bit);
                if c.kept.overlaps(pa.0, pa.1) {
                    assert!(!leaf.el1_write, "kept memory at {va:#x} is writable");
                }
            }
            // The kernel's code has no writable alias anywhere.
            if leaf.el1_write {
                assert!(!overlaps(pa, text), "text has a writable alias at {va:#x}");
            }
        });
        assert!(direct > 0);
    }
);

crate::kernel_test!(direct_map_leaves_out_firmware_seed_framebuffer_and_mmio, {
    let c = classified();
    let mut covered = 0;
    each_kernel_leaf(|va, leaf| {
        if !in_direct_map(va) {
            return;
        }
        let pa = (leaf.pa, leaf.pa + leaf.size());
        // Only usable RAM and kept ranges, so no gap between ranges either.
        assert!(
            c.usable.contains(pa.0, pa.1) || c.kept.contains(pa.0, pa.1),
            "direct map leaf {:#x}..{:#x} isn't usable or kept memory",
            pa.0,
            pa.1
        );
        for set in [&c.excluded, &c.seed, &c.framebuffer, &c.mmio] {
            assert!(!set.overlaps(pa.0, pa.1));
        }
        // And against the memory map itself, whatever the classification
        // made of it.
        each_range(|r, t| match t {
            Some(MemoryType::Usable) => {}
            t if is_kept(t) => {}
            t => assert!(
                !overlaps(pa, r),
                "direct map leaf at {:#x} overlaps a {t:?} range at {:#x}",
                pa.0,
                r.0
            ),
        });
        covered += leaf.size();
    });
    // Every usable and kept page is covered, once.
    let kept: u64 = c.direct_map_ro().map(|(s, e)| e - s).sum();
    assert_eq!(covered, c.usable.total() + kept);
    assert_eq!(covered, report().direct_map_bytes);
});

crate::kernel_test!(seed_page_is_mapped_nowhere, {
    let Some(seed) = info().seed() else {
        crate::klog!(
            Notice,
            "test",
            "no seed from the firmware: nothing to check"
        );
        return;
    };
    let page = (
        seed.address & !(PAGE_SIZE - 1),
        (seed.address & !(PAGE_SIZE - 1)) + PAGE_SIZE,
    );
    assert!(classified().seed.contains(page.0, page.1));
    each_kernel_leaf(|va, leaf| {
        assert!(
            !overlaps((leaf.pa, leaf.pa + leaf.size()), page),
            "the seed's page is mapped at {va:#x}"
        );
    });
});

crate::kernel_test!(framebuffer_is_only_in_the_device_window, {
    let Some((pa, size, fb_va)) = state().framebuffer else {
        crate::klog!(Notice, "test", "no framebuffer: nothing to check");
        return;
    };
    let fb = (pa & !(PAGE_SIZE - 1), pa + size);
    let mut found = 0;
    each_kernel_leaf(|va, leaf| {
        if !overlaps((leaf.pa, leaf.pa + leaf.size()), fb) {
            return;
        }
        found += leaf.size();
        assert!(in_device_window(va), "the framebuffer is mapped at {va:#x}");
        assert_eq!(leaf.attr_index, MAIR_NC);
        assert!(leaf.el1_write && leaf.pxn && leaf.uxn && leaf.device_bit);
    });
    assert!(found >= size);
    assert_eq!(kernel_tables().walk(fb_va).pa(fb_va), Some(pa));
});

crate::kernel_test!(uart_is_device_memory, {
    let Some((pa, uart_va)) = state().uart else {
        panic!("no UART was mapped");
    };
    let page = (pa & !(PAGE_SIZE - 1), (pa & !(PAGE_SIZE - 1)) + PAGE_SIZE);
    let mut found = 0;
    each_kernel_leaf(|va, leaf| {
        if overlaps((leaf.pa, leaf.pa + leaf.size()), page) {
            found += 1;
            assert!(in_device_window(va));
            assert_eq!(leaf.attr_index, MAIR_DEVICE);
            assert!(leaf.el1_write && leaf.pxn && leaf.uxn && leaf.device_bit);
        }
    });
    assert_eq!(found, 1);
    assert_eq!(kernel_tables().walk(uart_va).pa(uart_va), Some(pa));
});

crate::kernel_test!(identity_map_is_gone, {
    // The kernel's own physical address no longer translates.
    let base = phys::kernel_pa(phys::kernel_start());
    assert_eq!(arch::at_s1e1r(base) & arch::PAR_F, arch::PAR_F);
    // TTBR0 holds the empty table, with ASID 0, and walks stay enabled:
    // "no user address space" is the empty table, never EPD0.
    let ttbr0 = arch::ttbr0();
    assert_eq!(ttbr0 >> 48, 0, "TTBR0_EL1 has an ASID");
    assert_eq!(ttbr0, phys::kernel_pa(crate::entry::zero_table()));
    assert_eq!(arch::tcr() & arch::TCR_EPD0, 0);
    assert_eq!(arch::tcr() & arch::TCR_A1, 0);
});

crate::kernel_test!(pan_is_on_where_implemented, {
    let sctlr = arch::sctlr();
    assert_ne!(sctlr & arch::SCTLR_WXN, 0, "WXN is off");
    if arch::has_pan() {
        assert_ne!(arch::pan() & arch::PSTATE_PAN, 0, "PAN is off");
        assert_eq!(sctlr & arch::SCTLR_SPAN, 0, "SPAN is set");
        assert!(report().pan);
    } else {
        assert_ne!(sctlr & arch::SCTLR_SPAN, 0);
        assert!(!report().pan);
    }
});

crate::kernel_test!(asid_width_matches_the_cpu, {
    let as16 = arch::tcr() & arch::TCR_AS != 0;
    assert_eq!(as16, arch::asid_bits() == 16);
    assert_eq!(report().asid_bits, arch::asid_bits());
});

/// Calls `f` with every boot untyped piece, as its capability says it is
/// now.
fn each_piece(mut f: impl FnMut(&kmem::untyped::Untyped)) {
    crate::cap::boot::for_each_untyped(|_, c| {
        let kcap::cap::Cap::Untyped {
            base,
            bits,
            device,
            watermark,
        } = c
        else {
            return;
        };
        let Some(u) = kmem::untyped::Untyped::from_parts(base, bits, device, watermark) else {
            panic!("bad untyped capability {c:x?}");
        };
        f(&u);
    });
}

crate::kernel_test!(untyped_memory_is_the_rest_of_ram, {
    let c = classified();
    // SAFETY: nothing changes the boot allocator after the seal.
    let taken = unsafe { BOOT_ALLOC.get() }.taken();
    let mut ram = 0;
    let mut prev = (0, 0);
    each_piece(|u| {
        let (s, e) = (u.base(), u.base() + u.size());
        assert!((12..=47).contains(&u.bits()) && s % u.size() == 0);
        // Every test resets the pieces it used.
        assert_eq!(u.watermark(), 0);
        if u.is_device() {
            return;
        }
        // In address order, so pieces are pairwise disjoint.
        assert!(s >= prev.1, "untyped pieces overlap at {s:#x}");
        prev = (s, e);
        assert!(
            c.usable.contains(s, e),
            "untyped piece {s:#x} isn't usable RAM"
        );
        assert!(!taken.overlaps(s, e), "untyped piece {s:#x} was handed out");
        for set in [&c.kept, &c.seed, &c.framebuffer, &c.excluded] {
            assert!(!set.overlaps(s, e));
        }
        boot_objects::for_each(|o| {
            let (os, oe) = o.pages();
            assert!(
                !overlaps((s, e), (os, oe)),
                "untyped piece {s:#x} holds {:?}",
                o.kind
            );
        });
        // Free untyped memory is zero.
        for at in [s, e - 64] {
            // SAFETY: RAM in the direct map.
            let bytes =
                unsafe { core::slice::from_raw_parts((DIRECT_MAP_BASE + at) as *const u8, 64) };
            assert!(
                bytes.iter().all(|&b| b == 0),
                "untyped memory at {at:#x} isn't zero"
            );
        }
        ram += u.size();
    });
    assert_eq!(ram + taken.total(), c.usable.total());
    assert_eq!(ram, report().untyped_bytes);
    assert_eq!(report().dropped_pieces, 0);
    assert!(report().ram_pieces > 0 && report().device_pieces > 0);
});

crate::kernel_test!(device_untyped_leaves_out_ram_uart_and_gic, {
    // SAFETY: written only by `init`.
    let devices = unsafe { DEVICES.get() };
    let uart = devices.uart.expect("no UART in the device tree");
    assert!(!devices.gic().is_empty(), "no GIC in the device tree");
    let pa_limit = 1u64 << classified().pa_bits;
    each_piece(|u| {
        if !u.is_device() {
            return;
        }
        let piece = (u.base(), u.base() + u.size());
        assert!(piece.1 <= pa_limit);
        each_range(|r, t| {
            if t != Some(MemoryType::Mmio) {
                assert!(
                    !overlaps(piece, r),
                    "device piece {:#x} overlaps a {t:?} range at {:#x}",
                    piece.0,
                    r.0
                );
            }
        });
        for &(base, size) in core::iter::once(&uart).chain(devices.gic()) {
            assert!(
                !overlaps(piece, (base, base + size)),
                "device piece {:#x} holds the kernel's device at {base:#x}",
                piece.0
            );
        }
    });
});

crate::kernel_test!(gic_frames_are_device_memory_and_withheld, {
    // SAFETY: written only by `init`.
    let devices = unsafe { DEVICES.get() };
    let layout = devices.layout.as_ref().expect("no GIC layout");
    let mapped = |pa: u64| layout.mapped().any(|f| f.base <= pa && pa < f.end());
    let mut frames = 0;
    for f in layout.mapped() {
        frames += 1;
        // Each mapped frame is one the device tree names, and withheld.
        assert!(
            devices
                .gic()
                .iter()
                .any(|&(b, s)| b <= f.base && f.end() <= b + s),
            "GIC frame {:#x} isn't the device tree's",
            f.base
        );
        each_piece(|u| {
            if u.is_device() {
                assert!(
                    !overlaps((u.base(), u.base() + u.size()), (f.base, f.end())),
                    "device piece {:#x} holds GIC frame {:#x}",
                    u.base(),
                    f.base
                );
            }
        });
        // It translates, by hardware and by software walk, to itself.
        let va = device_va(f.base, f.size).expect("a GIC frame isn't mapped");
        assert!(in_device_window(va) && in_device_window(va + f.size - 1));
        let par = arch::at_s1e1r(va);
        assert_eq!(
            par & arch::PAR_F,
            0,
            "GIC frame {:#x} doesn't translate",
            f.base
        );
        assert_eq!(par & 0x0000_ffff_ffff_f000, f.base);
        let mut at = 0;
        while at < f.size {
            assert_eq!(kernel_tables().walk(va + at).pa(va + at), Some(f.base + at));
            at += 0x1_0000;
        }
    }
    assert!(frames >= 2);
    // Every leaf over a GIC frame is device memory, in the device window,
    // never executable; the frames the kernel doesn't map have none.
    each_kernel_leaf(|va, leaf| {
        let range = (leaf.pa, leaf.pa + leaf.size());
        for &(b, s) in devices.gic() {
            if overlaps(range, (b, b + s)) {
                assert!(mapped(leaf.pa), "unmapped GIC frame {b:#x} is mapped");
                assert!(in_device_window(va));
                assert_eq!(leaf.attr_index, MAIR_DEVICE);
                assert!(leaf.el1_write && leaf.pxn && leaf.uxn && leaf.device_bit);
            }
        }
    });
});

crate::kernel_test!(boot_allocator_is_sealed, {
    // SAFETY: one CPU; nothing else holds the allocator.
    let alloc = unsafe { BOOT_ALLOC.get_mut() };
    assert!(alloc.is_sealed());
    assert_eq!(alloc.alloc(None), Err(AllocError::Sealed));
});

// Retype, user address spaces, user access and ASIDs, through capabilities.
// Each test works in a scratch CNode made from free untyped pieces, and
// revokes and resets them before it ends (`cap::testkit`), so tests can run
// in any order and leave untyped memory as the boot left it: free and zero.

mod user_space {
    use super::super::space::{self, AddressSpace, Frame, UntypedTables};
    use super::super::user::{read_user, write_user};
    use super::*;
    use crate::cap::testkit::{Scratch, base, watermark};
    use crate::cap::{self as caps, MapFailure};
    use kcap::SlotRef;
    use kcap::cap::{Cap, SlotArray};
    use kcap::ops::{Error, MintData};
    use kcap::rights::Rights;
    use kmem::desc::UserPerm;
    use kmem::untyped::{ObjectType, RetypeError};
    use kmem::user::{Access, UserError};

    const RW: UserPerm = UserPerm {
        write: true,
        exec: false,
    };
    const RO: UserPerm = UserPerm {
        write: false,
        exec: false,
    };
    const RX: UserPerm = UserPerm {
        write: false,
        exec: true,
    };
    const WX: UserPerm = UserPerm {
        write: true,
        exec: true,
    };

    /// Two read-write frames, one after the other.
    const RW_VA: u64 = 0x40_0000;
    /// A read-execute frame, in the same level-3 table.
    const RX_VA: u64 = 0x41_0000;
    /// A device frame: never touched, only mapped.
    const DEVICE_VA: u64 = 0x50_0000;
    /// No level-2 entry: nothing is mapped between 6 and 8 MiB.
    const HOLE_VA: u64 = 0x60_0000;
    /// No level-0 entry: nothing is mapped at 512 GiB.
    const FAR_VA: u64 = 0x80_0000_0000;
    /// Free for a test's own mappings.
    const SPARE_VA: u64 = 0x42_0000;

    /// The physical page `PAR_EL1` reports.
    const PAR_PA: u64 = 0x0000_ffff_ffff_f000;

    /// Writes `v` through the direct map at physical address `pa`.
    fn poke(pa: u64, v: u64) {
        // SAFETY: a RAM frame the test retyped, in the direct map.
        unsafe { core::ptr::write_volatile((DIRECT_MAP_BASE + pa) as *mut u64, v) };
    }

    /// Reads the byte at physical address `pa` through the direct map.
    fn peek(pa: u64) -> u8 {
        // SAFETY: RAM in the direct map.
        unsafe { core::ptr::read_volatile((DIRECT_MAP_BASE + pa) as *const u8) }
    }

    /// How many mappings the address space in `space` holds: its full
    /// binding slots.
    fn bindings(space: SlotRef) -> usize {
        let a = SlotArray::of_address_space(base(space));
        (1..a.count)
            .filter(|&i| !caps::cap(a.slot(i)).is_null())
            .count()
    }

    /// The test address space: two RAM frames read-write at `RW_VA`, one
    /// read-execute at `RX_VA`, and a device frame at `DEVICE_VA`, all made
    /// from untyped memory, tables included, and mapped through their
    /// capabilities.
    struct Fixture {
        sc: Scratch,
        space_cap: SlotRef,
        space: AddressSpace,
        rw: [SlotRef; 2],
        rx: SlotRef,
        device: SlotRef,
    }

    impl Fixture {
        fn new() -> Self {
            let mut sc = Scratch::with_device(17);
            let space_cap = sc.make(ObjectType::AddressSpace);
            let rw = [sc.make(ObjectType::Frame4K), sc.make(ObjectType::Frame4K)];
            let rx = sc.make(ObjectType::Frame4K);
            let dev = sc.dev();
            let device = sc.make_from(dev, ObjectType::Frame4K);
            for (va, f, perm) in [
                (RW_VA, rw[0], RW),
                (RW_VA + PAGE_SIZE, rw[1], RW),
                (RX_VA, rx, RX),
                (DEVICE_VA, device, RW),
            ] {
                caps::map(f, space_cap, va, perm, sc.ram)
                    .unwrap_or_else(|e| panic!("can't map {va:#x}: {e:?}"));
            }
            Fixture {
                space: AddressSpace::from_object(base(space_cap)),
                sc,
                space_cap,
                rw,
                rx,
                device,
            }
        }

        /// Maps the frame capability in `f` into the test space.
        fn map(&self, f: SlotRef, va: u64, perm: UserPerm) -> Result<(), MapFailure> {
            caps::map(f, self.space_cap, va, perm, self.sc.ram)
        }

        /// A frame of RAM, mapped nowhere.
        fn frame(&mut self) -> SlotRef {
            self.sc.make(ObjectType::Frame4K)
        }

        /// Revokes and resets the pieces: the space is destroyed, which
        /// deactivates it if it is active and releases its ASID.
        fn finish(self) {
            self.sc.finish();
            assert!(!self.space.is_active());
        }
    }

    crate::kernel_test!(retype_aligns_objects_and_refuses_overflow, {
        let mut sc = Scratch::with_device(18);
        // A 128 KiB child piece, so that filling it fits the scratch CNode.
        let child = sc.make(ObjectType::Untyped(17));
        let cb = base(child);
        assert_eq!(cb % (1 << 17), 0);
        let mut make = |ty, n| sc.try_make(child, ty, n).map(base);
        assert_eq!(make(ObjectType::Frame4K, 1), Ok(cb));
        assert_eq!(make(ObjectType::Frame4K, 1), Ok(cb + 0x1000));
        assert_eq!(make(ObjectType::Frame4K, 1), Ok(cb + 0x2000));
        // An address space is 8 KiB, aligned to its size: the watermark
        // skips a page.
        assert_eq!(make(ObjectType::AddressSpace, 1), Ok(cb + 0x4000));
        assert_eq!(watermark(child), 0x6000);
        // Small objects pack: a CNode of two slots, then an endpoint.
        assert_eq!(make(ObjectType::CNode(1), 1), Ok(cb + 0x6000));
        assert_eq!(make(ObjectType::Endpoint, 1), Ok(cb + 0x6040));
        assert_eq!(make(ObjectType::Frame4K, 1), Ok(cb + 0x7000));
        // Page tables have no capability: Map takes them itself.
        assert_eq!(make(ObjectType::PageTable, 1), Err(Error::BadType));
        assert_eq!(
            make(ObjectType::Frame4K, 0),
            Err(Error::Retype(RetypeError::ZeroCount))
        );
        assert_eq!(
            make(ObjectType::Untyped(18), 1),
            Err(Error::Retype(RetypeError::TooBig))
        );
        // One frame more than the free part holds: refused, unchanged.
        let w = watermark(child);
        let left = ((1 << 17) - w) / PAGE_SIZE;
        assert_eq!(
            make(ObjectType::Frame4K, left + 1),
            Err(Error::Retype(RetypeError::NoRoom))
        );
        assert_eq!(watermark(child), w);
        assert!(make(ObjectType::Frame4K, left).is_ok());
        assert_eq!(watermark(child), 1 << 17);
        assert_eq!(
            make(ObjectType::Frame4K, 1),
            Err(Error::Retype(RetypeError::NoRoom))
        );

        // Device memory makes frames, never the kernel's own records.
        let d = sc.dev();
        for ty in [
            ObjectType::AddressSpace,
            ObjectType::CNode(7),
            ObjectType::Endpoint,
        ] {
            assert_eq!(
                sc.try_make(d, ty, 1),
                Err(Error::Retype(RetypeError::DeviceMemory))
            );
        }
        assert_eq!(
            sc.try_make(d, ObjectType::PageTable, 1),
            Err(Error::BadType)
        );
        let f = sc.make_from(d, ObjectType::Frame4K);
        assert_eq!(base(f), base(d));
        assert!(matches!(caps::cap(f), Cap::Frame { device: true, .. }));
        sc.finish();
    });

    crate::kernel_test!(user_walk_says_not_resident_and_not_ram, {
        let fx = Fixture::new();
        let s = &fx.space;
        let read = |va| s.translate(va, Access::Read);
        assert_eq!(read(RW_VA + 0x10), Ok(base(fx.rw[0]) + 0x10));
        assert_eq!(
            s.translate(RW_VA + PAGE_SIZE + 8, Access::Write),
            Ok(base(fx.rw[1]) + 8)
        );
        assert_eq!(read(RX_VA + 0x123), Ok(base(fx.rx) + 0x123));
        // Device memory is never reached on a user's behalf.
        assert_eq!(read(DEVICE_VA), Err(UserError::NotRam));
        assert_eq!(
            s.translate(DEVICE_VA, Access::Write),
            Err(UserError::NotRam)
        );
        // Nothing mapped, at each level.
        assert_eq!(read(RW_VA + 2 * PAGE_SIZE), Err(UserError::NotResident));
        assert_eq!(read(HOLE_VA), Err(UserError::NotResident));
        assert_eq!(read(FAR_VA), Err(UserError::NotResident));
        let t = s.tables();
        assert_eq!(t.walk(RW_VA + 2 * PAGE_SIZE), Walk::Invalid { level: 3 });
        assert_eq!(t.walk(HOLE_VA), Walk::Invalid { level: 2 });
        assert_eq!(t.walk(FAR_VA), Walk::Invalid { level: 0 });
        // The kernel's half isn't user memory.
        assert_eq!(read(phys::kernel_start()), Err(UserError::NotUserAddress));
        assert_eq!(read(DIRECT_MAP_BASE), Err(UserError::NotUserAddress));
        fx.finish();
    });

    crate::kernel_test!(user_memory_is_read_and_written_through_the_direct_map, {
        let fx = Fixture::new();
        let s = &fx.space;
        let msg: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);

        // Across the boundary between the two read-write frames.
        let va = RW_VA + PAGE_SIZE - 16;
        assert_eq!(write_user(s, va, &msg), Ok(()));
        let mut back = [0u8; 32];
        assert_eq!(read_user(s, va, &mut back), Ok(()));
        assert_eq!(back, msg);
        assert_eq!(peek(base(fx.rw[0]) + PAGE_SIZE - 16), 1);
        assert_eq!(peek(base(fx.rw[1])), 17);

        // A read-only mapping can't be written.
        assert_eq!(write_user(s, RX_VA, &msg), Err(UserError::NoRight));

        // A span that runs into an unmapped page moves nothing.
        let edge = RW_VA + 2 * PAGE_SIZE - 16;
        assert_eq!(
            write_user(s, edge, &[0xee; 32]),
            Err(UserError::NotResident)
        );
        assert!((0..16).all(|i| peek(base(fx.rw[1]) + PAGE_SIZE - 16 + i) == 0));
        let mut buf = [0x55u8; 32];
        assert_eq!(read_user(s, edge, &mut buf), Err(UserError::NotResident));
        assert!(buf.iter().all(|&b| b == 0x55));

        // Nor does one that runs into device memory.
        assert_eq!(read_user(s, DEVICE_VA, &mut buf), Err(UserError::NotRam));
        assert!(buf.iter().all(|&b| b == 0x55));

        // A writable user mapping of a boot object, as a mapping bug might
        // make: the kernel reads it, but never stores through the direct
        // map's read-only alias, which would fault. No capability names a
        // boot object until C15, so the test maps it with the internal
        // encoder, and unmaps it by hand.
        let info_pa = state().boot_info - DIRECT_MAP_BASE;
        let page = info_pa & !(PAGE_SIZE - 1);
        let boot = Frame::new(page, PAGE_SIZE, false);
        let mut src = UntypedTables {
            slot: fx.sc.ram,
            space: base(fx.space_cap),
        };
        assert_eq!(s.map(SPARE_VA, boot, RW, &mut src), Ok(()));
        let at = SPARE_VA + (info_pa - page);
        assert_eq!(write_user(s, at, &msg), Err(UserError::NoRight));
        let mut head = [0u8; 8];
        assert_eq!(read_user(s, at, &mut head), Ok(()));
        assert!((0..8).all(|i| head[i] == peek(info_pa + i as u64)));
        assert_eq!(s.unmap(SPARE_VA, PAGE_SIZE), Ok(1));
        fx.finish();
    });

    crate::kernel_test!(writable_and_executable_user_mappings_are_refused, {
        let mut fx = Fixture::new();
        let f = fx.frame();
        assert_eq!(
            fx.map(f, SPARE_VA, WX),
            Err(MapFailure::Cap(Error::BadMapping))
        );
        assert_eq!(
            fx.map(fx.device, SPARE_VA, RX),
            Err(MapFailure::Cap(Error::BadMapping))
        );
        // A mapping never replaces another.
        assert_eq!(
            fx.map(f, RW_VA, RO),
            Err(MapFailure::Table(MapError::Occupied))
        );
        assert_eq!(fx.space.translate(RW_VA, Access::Read), Ok(base(fx.rw[0])));

        // Rights: a frame without write can't be mapped writable, one
        // without read can't be mapped at all, and an address space without
        // write can't be mapped into or unmapped from (ADR 0049, rule 2).
        let ro_frame = fx.sc.take();
        caps::mint(f, ro_frame, Rights::READ, MintData::None).expect("mint");
        let wo_frame = fx.sc.take();
        caps::mint(f, wo_frame, Rights::WRITE, MintData::None).expect("mint");
        let ro_space = fx.sc.take();
        caps::mint(fx.space_cap, ro_space, Rights::READ, MintData::None).expect("mint");
        assert_eq!(
            fx.map(ro_frame, SPARE_VA, RW),
            Err(MapFailure::Cap(Error::MissingRight))
        );
        assert_eq!(
            fx.map(wo_frame, SPARE_VA, RO),
            Err(MapFailure::Cap(Error::MissingRight))
        );
        assert_eq!(
            caps::map(f, ro_space, SPARE_VA, RO, fx.sc.ram),
            Err(MapFailure::Cap(Error::MissingRight))
        );
        assert_eq!(
            caps::unmap(ro_space, RW_VA, PAGE_SIZE),
            Err(MapFailure::Cap(Error::MissingRight))
        );
        // Nothing was mapped or bound.
        assert_eq!(fx.space.tables().walk(SPARE_VA), Walk::Invalid { level: 3 });
        assert_eq!(bindings(fx.space_cap), 4);
        // A read-only copy maps read-only.
        assert_eq!(fx.map(ro_frame, SPARE_VA, RO), Ok(()));
        assert_eq!(bindings(fx.space_cap), 5);
        fx.finish();
    });

    crate::kernel_test!(executable_user_mappings_make_the_icache_coherent, {
        use core::sync::atomic::Ordering;
        let syncs = || space::ICACHE_SYNCS.load(Ordering::Relaxed);
        let mut fx = Fixture::new();
        // Read-only and read-write mappings need no instruction-cache
        // maintenance.
        let before = syncs();
        let ro = fx.frame();
        fx.map(ro, SPARE_VA, RO)
            .unwrap_or_else(|e| panic!("can't map: {e:?}"));
        assert_eq!(syncs(), before);
        // An executable mapping of RAM does, before its descriptor is
        // stored: one sync for one frame.
        let rx = fx.frame();
        fx.map(rx, SPARE_VA + PAGE_SIZE, RX)
            .unwrap_or_else(|e| panic!("can't map: {e:?}"));
        assert_eq!(syncs(), before + 1);
        // A refused one needs none.
        let wx = fx.frame();
        assert_eq!(
            fx.map(wx, SPARE_VA + 2 * PAGE_SIZE, WX),
            Err(MapFailure::Cap(Error::BadMapping))
        );
        assert_eq!(syncs(), before + 1);
        fx.finish();
    });

    crate::kernel_test!(user_mappings_are_pxn_and_non_global, {
        let fx = Fixture::new();
        let mut leaves = 0;
        fx.space.tables().for_each_leaf(&mut |va, leaf| {
            leaves += 1;
            assert!(va < kmem::layout::USER_TOP);
            assert!(leaf.pxn, "user leaf at {va:#x} is executable at EL1");
            assert!(!leaf.global, "user leaf at {va:#x} is global");
            assert!(leaf.el0_read && leaf.access_flag);
            assert!(!desc::violates_wx(leaf), "user leaf at {va:#x} is W+X");
            if va == DEVICE_VA {
                assert_eq!(leaf.attr_index, MAIR_DEVICE);
                assert!(leaf.device_bit && leaf.uxn);
            } else {
                assert_eq!(leaf.attr_index, MAIR_NORMAL);
                assert!(!leaf.device_bit);
            }
            if va == RX_VA {
                assert!(!leaf.uxn && !leaf.el0_write && !leaf.el1_write);
            } else {
                assert!(leaf.uxn && leaf.el0_write);
            }
        });
        assert_eq!(leaves, 4);
        fx.finish();
    });

    crate::kernel_test!(hardware_walk_agrees_with_software_walk, {
        let fx = Fixture::new();
        fx.space.activate();
        let asid = kmem::asid::asid_of(fx.space.asid_word()).expect("no ASID");
        assert_ne!(asid, 0);
        assert_eq!(arch::ttbr0(), (asid as u64) << 48 | fx.space.root());
        let t = fx.space.tables();
        for va in [
            RW_VA,
            RW_VA + PAGE_SIZE,
            RW_VA + 2 * PAGE_SIZE,
            RX_VA,
            DEVICE_VA,
            HOLE_VA,
            FAR_VA,
        ] {
            let par = arch::at_s1e0r(va);
            match t.walk(va).pa(va) {
                Some(pa) => {
                    assert_eq!(par & arch::PAR_F, 0, "{va:#x} doesn't translate");
                    assert_eq!(par & PAR_PA, pa, "{va:#x} translates elsewhere");
                }
                None => assert_eq!(par & arch::PAR_F, arch::PAR_F, "{va:#x} translates"),
            }
        }
        space::deactivate();
        assert_eq!(arch::at_s1e0r(RW_VA) & arch::PAR_F, arch::PAR_F);
        assert_eq!(arch::ttbr0() >> 48, 0);
        fx.finish();
    });

    crate::kernel_test!(unmap_invalidates_the_tlb, {
        // QEMU's TLB keeps a translation until a TLBI drops it, so a missing
        // invalidation reads the old frame's pattern through the new
        // mapping. AT can't show this: it always walks the tables afresh.
        const P1: u64 = 0x1111_2222_3333_4444;
        const P2: u64 = 0x5555_6666_7777_8888;
        let mut fx = Fixture::new();
        let (f1, f2) = (fx.frame(), fx.frame());
        poke(base(f1), P1);
        poke(base(f2), P2);
        assert_eq!(fx.map(f1, SPARE_VA, RO), Ok(()));
        fx.space.activate();
        // SAFETY: mapped readable at EL0 in the active space. Test only: the
        // kernel never dereferences a user address (ADR 0048, rule 5).
        assert_eq!(unsafe { arch::ldtr_u64(SPARE_VA) }, P1);
        assert_eq!(caps::unmap(fx.space_cap, SPARE_VA, PAGE_SIZE), Ok(1));
        assert_eq!(fx.map(f2, SPARE_VA, RO), Ok(()));
        // SAFETY: as above.
        assert_eq!(
            unsafe { arch::ldtr_u64(SPARE_VA) },
            P2,
            "a stale translation survived the unmap"
        );
        fx.finish();
    });

    crate::kernel_test!(asids_roll_over_without_stale_translations, {
        // A functional check: QEMU flushes its whole TLB whenever TTBR0_EL1
        // changes ASID, so it can't show a stale translation after a
        // rollover. The kmem host tests check the rollover against a model
        // of the TLB (kernel specification, "Address-space layout", "ASIDs").
        const PA: u64 = 0xaaaa_0000_aaaa_0000;
        const PB: u64 = 0xbbbb_0000_bbbb_0000;
        let mut sc = Scratch::new(17);
        let (ca, cb) = (
            sc.make(ObjectType::AddressSpace),
            sc.make(ObjectType::AddressSpace),
        );
        let (fa, fb) = (sc.make(ObjectType::Frame4K), sc.make(ObjectType::Frame4K));
        poke(base(fa), PA);
        poke(base(fb), PB);
        assert_eq!(caps::map(fa, ca, RW_VA, RO, sc.ram), Ok(()));
        assert_eq!(caps::map(fb, cb, RW_VA, RO, sc.ram), Ok(()));
        let (a, b) = (
            AddressSpace::from_object(base(ca)),
            AddressSpace::from_object(base(cb)),
        );
        // SAFETY (each `ldtr_u64` below): `RW_VA` is mapped readable at EL0
        // in the active space. Test only, as above.
        a.activate();
        assert_eq!(unsafe { arch::ldtr_u64(RW_VA) }, PA);
        let word_a = a.asid_word();

        space::force_rollover();
        assert!(!space::is_current(word_a));
        b.activate();
        assert_eq!(unsafe { arch::ldtr_u64(RW_VA) }, PB);
        assert_ne!(
            kmem::asid::asid_of(b.asid_word()),
            kmem::asid::asid_of(word_a),
            "the new generation gave A's number, reserved for it, to B"
        );
        a.activate();
        assert_eq!(unsafe { arch::ldtr_u64(RW_VA) }, PA);
        // A was running at the rollover, so it kept its number, and its
        // word moved to the new generation.
        assert_eq!(
            kmem::asid::asid_of(a.asid_word()),
            kmem::asid::asid_of(word_a)
        );
        assert!(space::is_current(a.asid_word()));
        assert_eq!(arch::ttbr0() >> 48, (a.asid_word() & 0xffff));

        // Revoking the piece destroys both spaces: A, which is active, is
        // deactivated, and both ASIDs are released.
        sc.finish();
        assert_eq!(arch::ttbr0() >> 48, 0);
        assert_eq!((a.asid_word(), b.asid_word()), (0, 0));
    });

    crate::kernel_test!(pan_stops_the_kernel_reaching_user_pages, {
        if (arch::id_aa64mmfr1() >> 20) & 0xf < 2 {
            crate::klog!(Notice, "test", "no FEAT_PAN2 (AT S1E1RP): nothing to check");
            return;
        }
        let fx = Fixture::new();
        fx.space.activate();
        assert_ne!(arch::pan() & arch::PSTATE_PAN, 0, "PAN is off");
        // The mapping allows EL1 to read: only PAN stops it.
        assert_eq!(arch::at_s1e1r(RW_VA) & arch::PAR_F, 0);
        assert_eq!(
            arch::at_s1e1rp(RW_VA) & arch::PAR_F,
            arch::PAR_F,
            "PAN doesn't stop the kernel reading a user page"
        );
        fx.finish();
    });

    crate::kernel_test!(untyped_reset_clears_what_was_used, {
        let mut sc = Scratch::with_device(18);
        let piece = sc.make(ObjectType::Untyped(17));
        let pb = base(piece);
        // More than one 64 KiB chunk, so the reset takes several steps.
        let n = 20;
        let first = sc
            .try_make(piece, ObjectType::Frame4K, n)
            .expect("no frames");
        assert_eq!(base(first), pb);
        for i in 0..n * PAGE_SIZE / 8 {
            poke(pb + 8 * i, 0xa5a5_a5a5_a5a5_a5a5);
        }
        // Revoking destroys the frames, and leaves the watermark: the next
        // retype resets the piece, then makes from its start.
        caps::revoke(piece);
        assert_eq!(watermark(piece), n * PAGE_SIZE);
        let again = sc.make_from(piece, ObjectType::Frame4K);
        assert_eq!(base(again), pb);
        assert_eq!(watermark(piece), PAGE_SIZE);
        for i in 0..n * PAGE_SIZE / 8 {
            let at = DIRECT_MAP_BASE + pb + 8 * i;
            // SAFETY: RAM in the direct map.
            let v = unsafe { core::ptr::read_volatile(at as *const u64) };
            assert_eq!(v, 0, "untyped memory at {:#x} wasn't cleared", pb + 8 * i);
        }

        // A device piece is never written: its watermark only drops.
        let d = sc.dev();
        let f = sc.make_from(d, ObjectType::Frame4K);
        assert!(matches!(caps::cap(f), Cap::Frame { device: true, .. }));
        caps::revoke(d);
        assert_ne!(watermark(d), 0);
        let f = sc.make_from(d, ObjectType::Frame4K);
        assert_eq!(base(f), base(d));
        assert_eq!(watermark(d), PAGE_SIZE);
        sc.finish();
    });
}

/// Calls `f(half, va, leaf)` for every leaf of both bootstrap tables. They
/// are dead since the switch, and nothing has written them since: `_start`
/// built them, and the boot window's slots were filled before the switch.
fn each_bootstrap_leaf(mut f: impl FnMut(Half, u64, &Leaf)) {
    let (low, high) = crate::entry::bootstrap_roots();
    for (root, half) in [(low, Half::User), (high, Half::Kernel)] {
        let t = Tables::new(&DirectMem, phys::kernel_pa(root), half);
        t.for_each_leaf(&mut |va, leaf| f(half, va, leaf));
    }
}

fn in_boot_window(va: u64) -> bool {
    va >= boot_window::BASE && va - boot_window::BASE < boot_window::SLOTS as u64 * PAGE_SIZE
}

crate::kernel_test!(bootstrap_tables_were_w_xor_x, {
    // What ran the kernel until the switch (ADR 0048, rule 6).
    let kstart = phys::kernel_start();
    let kphys = phys::kernel_pa(kstart);
    let l = kernel_map::image_layout();
    let image_size = l.data.1 - kstart;
    let text = (kphys, kphys + (l.text.1 - l.text.0));
    let mut image_bytes = 0;
    each_bootstrap_leaf(|half, va, leaf| {
        assert!(leaf.uxn, "bootstrap leaf at {va:#x} isn't UXN");
        assert!(!desc::violates_wx(leaf), "bootstrap leaf at {va:#x} is W+X");
        if !leaf.pxn {
            // Only the kernel's text, by page, read-only.
            assert_eq!(leaf.level, 3, "executable block at {va:#x}");
            assert!(within((leaf.pa, leaf.pa + leaf.size()), text));
            assert!(!leaf.el1_write);
        }
        match half {
            Half::User => {
                // The identity map: the image's first 2 MiB, no further.
                assert_eq!(va, leaf.pa, "the identity map is offset");
                assert!(within(
                    (leaf.pa, leaf.pa + leaf.size()),
                    (kphys, kphys + image_size.min(BLOCK_2M))
                ));
            }
            Half::Kernel if in_boot_window(va) => {
                assert_eq!(leaf.level, 3, "boot window block at {va:#x}");
                assert!(leaf.pxn);
            }
            Half::Kernel => {
                assert!(
                    within((va, va + leaf.size()), (kstart, kstart + image_size)),
                    "the high map reaches {va:#x}, outside the kernel's image"
                );
                assert_eq!(leaf.pa, kphys + (va - kstart));
                image_bytes += leaf.size();
            }
        }
    });
    // The high map covers exactly the image.
    assert_eq!(image_bytes, image_size);
});

crate::kernel_test!(bootstrap_tables_map_only_what_the_kernel_kept, {
    // Even before the switch, the kernel mapped no firmware-reserved memory,
    // such as the UEFI runtime regions (ADR 0039, rule 1), and not the
    // seed's page (ADR 0048, rule 2): only its image, the boot information
    // and the device tree, the pages of its own tables, and its UART.
    let c = classified();
    // SAFETY: nothing changes the boot allocator after the seal.
    let taken = unsafe { BOOT_ALLOC.get() }.taken();
    // SAFETY: written only by `init`.
    let uart = unsafe { DEVICES.get() }
        .uart
        .expect("no UART in the device tree");
    let uart = (
        uart.0 & !(PAGE_SIZE - 1),
        (uart.0 + uart.1).next_multiple_of(PAGE_SIZE),
    );
    let mut window_pages = 0;
    each_bootstrap_leaf(|_, va, leaf| {
        let pa = (leaf.pa, leaf.pa + leaf.size());
        for set in [&c.excluded, &c.seed, &c.framebuffer] {
            assert!(
                !set.overlaps(pa.0, pa.1),
                "the bootstrap tables map {:#x}, at {va:#x}",
                pa.0
            );
        }
        each_range(|r, t| {
            if matches!(t, Some(MemoryType::Usable | MemoryType::Mmio)) || is_kept(t) {
                return;
            }
            assert!(
                !overlaps(pa, r),
                "the bootstrap tables map {:#x}, in a {t:?} range, at {va:#x}",
                pa.0
            );
        });
        if in_boot_window(va) {
            window_pages += 1;
            if leaf.attr_index == MAIR_DEVICE {
                assert!(within(pa, uart), "the boot window maps device {:#x}", pa.0);
            } else {
                assert!(
                    c.kept.contains(pa.0, pa.1) && !leaf.el1_write
                        || taken.contains(pa.0, pa.1) && leaf.el1_write,
                    "the boot window maps {:#x}, which isn't kept or a table page",
                    pa.0
                );
            }
        } else {
            assert!(c.kept.contains(pa.0, pa.1));
        }
    });
    assert!(window_pages > 0, "nothing was mapped in the boot window");
});

crate::kernel_test!(empty_table_is_read_only, {
    // TTBR0_EL1 holds it whenever no user space is active, so nothing may
    // write it: not even a stack overflow's exception frames.
    let va = crate::entry::zero_table();
    let w = kernel_tables().walk(va);
    let Walk::Leaf { leaf, .. } = w else {
        panic!("the empty table isn't mapped: {w:?}");
    };
    assert!(!leaf.el1_write, "the empty table is writable");
    // SAFETY: the empty table, mapped read-only.
    let t = unsafe { &*(va as *const [u64; 512]) };
    assert!(t.iter().all(|&e| e == 0), "the empty table isn't empty");
});

crate::kernel_test!(kernel_devices_are_found_for_certain, {
    // Without a device tree the kernel can't name its own devices, so it
    // stops rather than give their frames away (ADR 0048, rule 1).
    let mut d = devices::KernelDevices::new();
    assert_eq!(d.find(None), Err(FindError::NoDeviceTree));
    assert!(d.all().is_empty());
    // With QEMU's tree it finds the UART and the GIC, as `init` did.
    let info = info();
    let (pa, len) = info.device_tree().expect("no device tree");
    let va = layout::direct_va(pa).expect("the device tree is beyond the direct map");
    // SAFETY: the device tree, which the direct map keeps read-only.
    let fdt = unsafe { crate::device_tree(va, len) }.expect("the device tree doesn't parse");
    assert_eq!(d.find(Some(&fdt)), Ok(()));
    assert!(d.uart.is_some() && !d.gic().is_empty());
    // SAFETY: written only by `init`.
    assert_eq!(d.all(), unsafe { DEVICES.get() }.all());
});
