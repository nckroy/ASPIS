// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Finding each core's GICv3 redistributor (kernel specification, "The
//! kernel's interrupt controller"), by Arm's walk, as Linux's
//! `gic_iterate_rdists` does. In each region, from its base:
//!
//! 1. Check that `GICR_PIDR2`'s architecture revision is 3 or 4; if it
//!    isn't, the region holds no more redistributors.
//! 2. Read `GICR_TYPER`, whose bits 63:32 are the core's affinity.
//! 3. Stop at `GICR_TYPER.Last`.
//! 4. Step by `redistributor-stride` if the node gives one, else by two
//!    64 KiB frames, or four with `GICR_TYPER.VLPIS`.
//!
//! A redistributor that wouldn't fit in what is left of the region ends the
//! region too.

use crate::affinity::Affinity;
use crate::layout::Frame;
use crate::regs::{self, gicr};

/// Reads a redistributor's identification registers, at the physical
/// address of its `RD_base` frame.
pub trait RedistRegs {
    fn pidr2(&mut self, rd_base: u64) -> u32;
    fn typer(&mut self, rd_base: u64) -> u64;
}

/// Calls `f(rd_base, typer)` for every redistributor in `regions`, in
/// order, until `f` returns `true`. Returns the `rd_base` at which `f`
/// returned `true`.
pub fn walk(
    regions: &[Frame],
    stride: Option<u64>,
    regs: &mut impl RedistRegs,
    mut f: impl FnMut(u64, u64) -> bool,
) -> Option<u64> {
    for r in regions {
        let mut at = r.base;
        while at.checked_add(gicr::SIZE).is_some_and(|end| end <= r.end()) {
            if !matches!(regs::arch_rev(regs.pidr2(at)), 3 | 4) {
                break;
            }
            let typer = regs.typer(at);
            if f(at, typer) {
                return Some(at);
            }
            if typer & gicr::TYPER_LAST != 0 {
                break;
            }
            let step = stride.unwrap_or(if typer & gicr::TYPER_VLPIS != 0 {
                gicr::SIZE_VLPIS
            } else {
                gicr::SIZE
            });
            let Some(next) = at.checked_add(step) else {
                break;
            };
            at = next;
        }
    }
    None
}

/// The `RD_base` of the redistributor of the core with `affinity`, if
/// `regions` hold one.
pub fn find(
    regions: &[Frame],
    stride: Option<u64>,
    regs: &mut impl RedistRegs,
    affinity: Affinity,
) -> Option<u64> {
    walk(regions, stride, regs, |_, typer| {
        Affinity::from_gicr_typer(typer) == affinity
    })
}
