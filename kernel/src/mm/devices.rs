// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The devices the kernel drives itself, from the device tree: the UART and
//! every frame of the interrupt controller. They are left out of device
//! untyped memory, so no user process can map them (ADR 0048, rule 1;
//! kernel specification, "Boot memory").
//!
//! The kernel must never give a frame of its own devices away, so where it
//! can't find them for certain it stops at boot instead ([`FindError`]):
//! with no device tree, with no interrupt controller it knows, or with an
//! address it would have to translate through a bus's `ranges`, which it
//! doesn't do yet. C65 reads the same devices from ACPI's MADT and SPCR.
//!
//! Beside the flat list of withheld ranges, it records which of the GIC
//! node's own frames is which ([`kirq::layout::GicLayout`]), for the
//! mapping and the driver (C13a; kernel specification, "The kernel's
//! interrupt controller"). A node whose layout the kernel can't read stops
//! the boot too.

use fdt::Fdt;
use fdt::node::FdtNode;
use fdt::standard_nodes::MemoryRegion;
use kirq::layout::{GicKind, GicLayout, LayoutError};

/// The most `reg` ranges kept. QEMU's `virt` has at most a handful: the
/// UART, the GIC's distributor, CPU or redistributor and virtualization
/// frames, and a v2m frame or an ITS.
const MAX: usize = 32;

/// The interrupt controllers the kernel knows, by `compatible`: those of
/// [`kirq::layout::COMPATIBLE`].
const GIC: &[&str] = &["arm,cortex-a15-gic", "arm,gic-400", "arm,gic-v3"];
/// The interrupt controller's children that the kernel drives too.
const GIC_CHILDREN: &[&str] = &["arm,gic-v2m-frame", "arm,gic-v3-its"];

/// Why the kernel can't name its own devices for certain. Each stops the
/// boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindError {
    /// The boot information has no device tree. C65: ACPI.
    NoDeviceTree,
    /// The device tree has no interrupt controller the kernel knows.
    NoInterruptController,
    /// The device's node isn't a child of `/`, so its `reg` is in a bus's
    /// address space, which the kernel doesn't translate yet.
    Translated(&'static str),
    /// The device's node has no `reg` the kernel can read: none, or one
    /// with more than two address or size cells.
    NoReg(&'static str),
    /// The interrupt controller's node doesn't say which frame is which.
    Gic(LayoutError),
}

impl core::fmt::Display for FindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoDeviceTree => write!(
                f,
                "there is no device tree, so the kernel can't tell which frames are its own devices"
            ),
            Self::NoInterruptController => write!(
                f,
                "the device tree has no interrupt controller the kernel knows"
            ),
            Self::Translated(what) => write!(
                f,
                "{what} has addresses translated through a bus's ranges, which the kernel doesn't read yet"
            ),
            Self::NoReg(what) => write!(f, "{what} has no reg the kernel can read"),
            Self::Gic(e) => write!(f, "{e}"),
        }
    }
}

/// Whether `node` is a child of `/`: its `reg` is then in the processor's
/// physical address space. Nodes are compared by where their names lie in
/// the blob, which is unique to each node.
fn is_root_child(fdt: &Fdt<'_>, node: &FdtNode<'_, '_>) -> bool {
    fdt.find_node("/")
        .is_some_and(|root| root.children().any(|c| core::ptr::eq(c.name, node.name)))
}

/// `node`'s `reg` ranges as physical addresses, for `what`: only for a
/// child of `/`, and only if `reg` can be read.
pub fn physical_reg<'a>(
    fdt: &Fdt<'a>,
    node: FdtNode<'_, 'a>,
    what: &'static str,
) -> Result<impl Iterator<Item = MemoryRegion> + 'a, FindError> {
    if !is_root_child(fdt, &node) {
        return Err(FindError::Translated(what));
    }
    node.reg().ok_or(FindError::NoReg(what))
}

/// The physical ranges of the kernel's devices, as `(base, size)`.
pub struct KernelDevices {
    /// The PL011 the kernel writes to, if any.
    pub uart: Option<(u64, u64)>,
    /// The GIC's frames, from C13a's driver's point of view.
    #[cfg_attr(not(aspis_test_build), allow(dead_code))]
    pub gic: [(u64, u64); MAX],
    #[cfg_attr(not(aspis_test_build), allow(dead_code))]
    pub gic_len: usize,
    /// The GIC node's own frames, by role.
    pub layout: Option<GicLayout>,
    /// The GIC node's `phandle`, if it has one: how the timer's
    /// `interrupt-parent` names it, whatever bus its frames sit on.
    pub gic_phandle: Option<u32>,
    /// Every range above: what [`kmem::memmap::Classified::classify`] leaves
    /// out of device untyped memory.
    all: [(u64, u64); MAX],
    len: usize,
}

impl KernelDevices {
    pub const fn new() -> Self {
        Self {
            uart: None,
            gic: [(0, 0); MAX],
            gic_len: 0,
            layout: None,
            gic_phandle: None,
            all: [(0, 0); MAX],
            len: 0,
        }
    }

    /// Every range of every device the kernel drives.
    pub fn all(&self) -> &[(u64, u64)] {
        &self.all[..self.len]
    }

    /// The GIC's frames.
    #[cfg_attr(not(aspis_test_build), allow(dead_code))]
    pub fn gic(&self) -> &[(u64, u64)] {
        &self.gic[..self.gic_len]
    }

    fn push(&mut self, base: u64, size: u64) {
        // A device tree with more frames than this is a kernel bug to fix,
        // not a range to give away.
        assert!(
            self.len < MAX,
            "the device tree has too many kernel devices"
        );
        self.all[self.len] = (base, size);
        self.len += 1;
    }

    fn push_gic(&mut self, r: MemoryRegion) {
        let base = r.starting_address as u64;
        let size = r.size.unwrap_or(4096) as u64;
        assert!(self.gic_len < MAX, "the GIC has too many frames");
        self.gic[self.gic_len] = (base, size);
        self.gic_len += 1;
        self.push(base, size);
    }

    /// Fills the list from the device tree, in place. An error means the
    /// kernel can't name every frame of its own devices, and must stop
    /// rather than give one away as device untyped memory.
    pub fn find(&mut self, fdt: Option<&Fdt<'_>>) -> Result<(), FindError> {
        *self = Self::new();
        let fdt = fdt.ok_or(FindError::NoDeviceTree)?;
        if let Some((base, size)) = crate::uart::find(fdt)? {
            self.uart = Some((base, size));
            self.push(base, size);
        }
        let gic = fdt
            .find_compatible(GIC)
            .ok_or(FindError::NoInterruptController)?;
        const WHAT: &str = "the interrupt controller";
        let kind = gic
            .compatible()
            .and_then(|cs| cs.all().find_map(GicKind::from_compatible))
            .ok_or(FindError::NoInterruptController)?;
        // The node's own frames, in order, for its layout.
        let mut own = [(0, 0); MAX];
        let mut frames = 0;
        for r in physical_reg(fdt, gic, WHAT)? {
            self.push_gic(r);
            own[frames] = self.gic[self.gic_len - 1];
            frames += 1;
        }
        if frames == 0 {
            return Err(FindError::NoReg(WHAT));
        }
        let prop = |name| gic.property(name).map(|p| p.value);
        self.gic_phandle = prop("phandle").and_then(kirq::dt::be_u32);
        self.layout = Some(
            GicLayout::new(
                kind,
                &own[..frames],
                prop("#redistributor-regions"),
                prop("redistributor-stride"),
            )
            .map_err(FindError::Gic)?,
        );
        // The children's addresses are in the GIC node's own address space.
        // An empty `ranges`, as QEMU's `virt` gives, makes them physical
        // addresses. The kernel doesn't translate others.
        let is_child = |c: &FdtNode<'_, '_>| {
            c.compatible()
                .is_some_and(|cs| cs.all().any(|s| GIC_CHILDREN.contains(&s)))
        };
        let translated = gic.property("ranges").is_some_and(|p| !p.value.is_empty());
        if translated && gic.children().any(|c| is_child(&c)) {
            return Err(FindError::Translated("a frame of the interrupt controller"));
        }
        for child in gic.children().filter(is_child) {
            let regs = child
                .reg()
                .ok_or(FindError::NoReg("a frame of the interrupt controller"))?;
            for r in regs {
                self.push_gic(r);
            }
        }
        Ok(())
    }
}
