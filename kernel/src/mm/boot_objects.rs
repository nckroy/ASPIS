// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The boot objects: the memory the kernel kept at boot that it presents as
//! objects (ADR 0048, rule 2; kernel specification, "Boot memory").
//!
//! C10 records where each lies, and checks that it lies in memory the
//! kernel kept, so none of it can ever be untyped memory. Boot objects
//! belong to no job, count against no reservation or limit, and are never
//! destroyed (ADR 0058, rule 1).
//!
//! C15: the initial image, the device tree and the boot information become
//! resident immutable memory objects, the framebuffer a device memory
//! object, and the seed's page a frame the kernel never maps. C11: the root
//! server gets capabilities to them. The kernel interface library's pages
//! (ADR 0059, rule 3) join them when the library exists.

use super::BootCell;
use bootinfo::BootInfo;
use kmem::memmap::{ClassSet, Classified};
use kmem::{PAGE_SIZE, align_down, align_up};

/// What a boot object is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    InitialImage,
    DeviceTree,
    BootInformation,
    Framebuffer,
    Seed,
}

/// One boot object: its physical range, as the boot information gives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootObject {
    pub kind: Kind,
    pub base: u64,
    pub size: u64,
}

impl BootObject {
    /// The pages that hold it.
    pub fn pages(&self) -> (u64, u64) {
        let end = self.base.saturating_add(self.size.max(1));
        (
            align_down(self.base, PAGE_SIZE),
            align_up(end, PAGE_SIZE).unwrap_or(u64::MAX),
        )
    }
}

const MAX: usize = 8;

struct Table {
    objects: [Option<BootObject>; MAX],
    len: usize,
}

static OBJECTS: BootCell<Table> = BootCell::new(Table {
    objects: [None; MAX],
    len: 0,
});

/// Records the boot objects that `info` describes, and checks that each
/// lies wholly in the class of memory the kernel kept for it. `info_range`
/// is the boot information's own physical range.
pub fn record(info: &BootInfo<'_>, info_range: (u64, u64), c: &Classified) {
    // SAFETY: called once, from `mm::init`, before anything reads the
    // table.
    let t = unsafe { OBJECTS.get_mut() };
    t.len = 0;
    let mut add = |kind: Kind, base: u64, size: u64, class: &ClassSet| {
        let o = BootObject { kind, base, size };
        let (s, e) = o.pages();
        // The stub puts each in memory of its own type, so this holds unless
        // the stub and the kernel disagree about the boot ABI.
        assert!(
            class.contains(s, e),
            "boot object {kind:?} at {base:#x} lies outside the memory kept for it"
        );
        t.objects[t.len] = Some(o);
        t.len += 1;
    };
    add(
        Kind::BootInformation,
        info_range.0,
        info_range.1 - info_range.0,
        &c.kept,
    );
    if let Some(i) = info.initial_image() {
        add(Kind::InitialImage, i.base, i.size, &c.kept);
    }
    if let Some((base, size)) = info.device_tree() {
        add(Kind::DeviceTree, base, size, &c.kept);
    }
    if let Some(fb) = info.framebuffer() {
        add(Kind::Framebuffer, fb.base, fb.size, &c.framebuffer);
    }
    if let Some(seed) = info.seed() {
        add(Kind::Seed, seed.address, seed.length as u64, &c.seed);
    }
}

/// Calls `f` for each boot object.
#[cfg_attr(not(aspis_test_build), allow(dead_code))]
pub fn for_each(mut f: impl FnMut(&BootObject)) {
    // SAFETY: the table is written only by `record`, during boot.
    let t = unsafe { OBJECTS.get() };
    t.objects[..t.len].iter().flatten().for_each(&mut f);
}
