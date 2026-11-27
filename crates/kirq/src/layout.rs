// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Which `reg` entry of the device tree's GIC node is which frame, and
//! which frames the kernel maps (kernel specification, "The kernel's
//! interrupt controller"; the Linux bindings `arm,gic.yaml` and
//! `arm,gic-v3.yaml`):
//!
//! - **GICv2** (`arm,cortex-a15-gic`, `arm,gic-400`): entry 0 is the
//!   distributor and entry 1 the CPU interface. Entries 2 and 3, the
//!   virtual interface control (`GICH`) and the virtual CPU interface
//!   (`GICV`), are there only with virtualization.
//! - **GICv3** (`arm,gic-v3`): entry 0 is the distributor, and entries 1 to
//!   N the redistributor regions, with N from `#redistributor-regions`
//!   (default 1). The entries after them (`GICC`, `GICH`, `GICV`) are for
//!   a legacy or virtual interface.
//!
//! The kernel maps the distributor and the CPU interface, or the
//! distributor and every redistributor region. Every frame of the node and
//! of its children stays out of device untyped memory whether it is mapped
//! or not (ADR 0048, rule 1). C13b adds the GICv2m frames and the ITS to
//! [`GicLayout::mapped`].

use crate::dt;

/// The GIC versions the kernel drives (ADR 0007, rules 1 and 2). A GICv4 is
/// a GICv3 to the kernel, and its node says `arm,gic-v3`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GicKind {
    V2,
    V3,
}

/// The `compatible` strings the kernel knows, and their versions.
pub const COMPATIBLE: [(&str, GicKind); 3] = [
    ("arm,cortex-a15-gic", GicKind::V2),
    ("arm,gic-400", GicKind::V2),
    ("arm,gic-v3", GicKind::V3),
];

impl GicKind {
    /// The version a `compatible` string names.
    pub fn from_compatible(s: &str) -> Option<GicKind> {
        COMPATIBLE.iter().find(|(c, _)| *c == s).map(|&(_, k)| k)
    }
}

/// A frame: a physical base and a size in bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Frame {
    pub base: u64,
    pub size: u64,
}

impl Frame {
    pub const fn end(self) -> u64 {
        self.base.saturating_add(self.size)
    }
}

/// The most redistributor regions the kernel reads.
pub const MAX_REDIST_REGIONS: usize = 8;

/// The smallest distributor: 4 KiB on a GICv2, 64 KiB on a GICv3.
const DIST_MIN_V2: u64 = 0x1000;
const DIST_MIN_V3: u64 = 0x1_0000;
/// The smallest GICv2 CPU interface: its registers up to `GICC_IIDR`. The
/// GIC-400's is 8 KiB, with `GICC_DIR` at 4 KiB, which the kernel doesn't
/// use (EOI mode 0).
const CPU_MIN: u64 = 0x1000;

/// Why the GIC node's layout can't be used. Each stops the boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutError {
    /// The node has fewer `reg` entries than its version needs.
    TooFewRegs { need: usize, have: usize },
    /// `#redistributor-regions` isn't one cell, or is 0, or is more than
    /// the kernel reads.
    RedistRegions,
    /// `redistributor-stride` isn't one or two cells, or isn't a nonzero
    /// multiple of 64 KiB.
    Stride,
    /// A frame is smaller than its registers, or isn't 4 KiB aligned.
    Frame(&'static str),
}

impl core::fmt::Display for LayoutError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooFewRegs { need, have } => write!(
                f,
                "the interrupt controller's node has {have} reg entries, and needs {need}"
            ),
            Self::RedistRegions => write!(
                f,
                "the interrupt controller's #redistributor-regions isn't one cell from 1 to {MAX_REDIST_REGIONS}"
            ),
            Self::Stride => write!(
                f,
                "the interrupt controller's redistributor-stride isn't a nonzero multiple of 64 KiB"
            ),
            Self::Frame(what) => write!(
                f,
                "the interrupt controller's {what} is too small or isn't 4 KiB aligned"
            ),
        }
    }
}

/// The GIC node's frames, by role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GicLayout {
    pub kind: GicKind,
    pub dist: Frame,
    /// The GICv2 CPU interface; `None` on a GICv3.
    pub cpu: Option<Frame>,
    redist: [Frame; MAX_REDIST_REGIONS],
    n_redist: usize,
    /// `redistributor-stride`, if the node gives one (GICv3).
    pub stride: Option<u64>,
}

fn check(f: Frame, min: u64, what: &'static str) -> Result<Frame, LayoutError> {
    if f.size < min || !f.base.is_multiple_of(0x1000) || f.base.checked_add(f.size).is_none() {
        Err(LayoutError::Frame(what))
    } else {
        Ok(f)
    }
}

impl GicLayout {
    /// The layout of a node of version `kind` whose own `reg` entries, in
    /// order, are `regs` as `(base, size)`, with the raw bytes of its
    /// `#redistributor-regions` and `redistributor-stride` properties, if
    /// it has them. A GICv2 ignores both.
    pub fn new(
        kind: GicKind,
        regs: &[(u64, u64)],
        redist_regions: Option<&[u8]>,
        redist_stride: Option<&[u8]>,
    ) -> Result<GicLayout, LayoutError> {
        let frame = |i: usize| {
            regs.get(i)
                .map(|&(base, size)| Frame { base, size })
                .ok_or(LayoutError::TooFewRegs {
                    need: i + 1,
                    have: regs.len(),
                })
        };
        match kind {
            GicKind::V2 => Ok(GicLayout {
                kind,
                dist: check(frame(0)?, DIST_MIN_V2, "distributor")?,
                cpu: Some(check(frame(1)?, CPU_MIN, "CPU interface")?),
                redist: [Frame::default(); MAX_REDIST_REGIONS],
                n_redist: 0,
                stride: None,
            }),
            GicKind::V3 => {
                let n = match redist_regions {
                    None => 1,
                    Some(p) => dt::be_u32(p).ok_or(LayoutError::RedistRegions)? as usize,
                };
                if n == 0 || n > MAX_REDIST_REGIONS {
                    return Err(LayoutError::RedistRegions);
                }
                let stride = match redist_stride {
                    None => None,
                    Some(p) => {
                        let s = dt::be_u32_or_u64(p).ok_or(LayoutError::Stride)?;
                        if s == 0 || !s.is_multiple_of(0x1_0000) {
                            return Err(LayoutError::Stride);
                        }
                        Some(s)
                    }
                };
                let dist = check(frame(0)?, DIST_MIN_V3, "distributor")?;
                let mut redist = [Frame::default(); MAX_REDIST_REGIONS];
                for (i, r) in redist.iter_mut().enumerate().take(n) {
                    *r = check(
                        frame(1 + i)?,
                        crate::regs::gicr::SIZE,
                        "redistributor region",
                    )?;
                }
                Ok(GicLayout {
                    kind,
                    dist,
                    cpu: None,
                    redist,
                    n_redist: n,
                    stride,
                })
            }
        }
    }

    /// The GICv3 redistributor regions, in the node's order; empty on a
    /// GICv2.
    pub fn redistributor_regions(&self) -> &[Frame] {
        &self.redist[..self.n_redist]
    }

    /// The frames the kernel maps: the distributor, then the CPU interface
    /// or every redistributor region. Never `GICH`, `GICV`, or a GICv3's
    /// `GICC`.
    pub fn mapped(&self) -> impl Iterator<Item = Frame> + '_ {
        core::iter::once(self.dist)
            .chain(self.cpu)
            .chain(self.redistributor_regions().iter().copied())
    }
}
