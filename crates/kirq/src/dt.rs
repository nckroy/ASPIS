// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Decoding the device-tree properties the kernel's interrupt code reads,
//! from their raw big-endian bytes: GIC interrupt specifiers (the Linux
//! binding `arm,gic.yaml` and `arm,gic-v3.yaml`), cpu nodes' `reg`, and
//! `status`. The kernel's device-tree crate decodes only one- and two-cell
//! interrupt specifiers, and the GIC's have three.

use crate::affinity::Affinity;
use crate::intid::Intid;

/// Why a property couldn't be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DtError {
    /// The property is shorter than the entry asked for, or isn't a whole
    /// number of cells.
    Short,
    /// The GIC node's `#interrupt-cells` isn't 3.
    Cells,
    /// The specifier's first cell is neither 0 (SPI) nor 1 (PPI).
    Type(u32),
    /// The specifier's number is out of range for its type.
    Number(u32),
}

/// A big-endian 32-bit cell, if `prop` is exactly one.
pub fn be_u32(prop: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(prop.try_into().ok()?))
}

/// One or two big-endian cells, as a 64-bit value, if `prop` is exactly
/// that.
pub fn be_u32_or_u64(prop: &[u8]) -> Option<u64> {
    match prop.len() {
        4 => be_u32(prop).map(u64::from),
        8 => Some(u64::from_be_bytes(prop.try_into().ok()?)),
        _ => None,
    }
}

/// The cell at index `i` of `prop`.
fn cell(prop: &[u8], i: usize) -> Option<u32> {
    be_u32(prop.get(4 * i..4 * i + 4)?)
}

/// A GIC interrupt specifier, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Specifier {
    pub intid: Intid,
    /// The third cell: the trigger in bits 3:0 (1 rising edge, 2 falling
    /// edge, 4 active-high level, 8 active-low level), and, on a GICv2, a
    /// PPI's core mask in bits 15:8.
    pub flags: u32,
}

/// Entry `index` of an `interrupts` property whose parent is a GIC with
/// `interrupt_cells` cells per specifier: type 0 is SPI `n`, INTID 32 + `n`,
/// and type 1 is PPI `n`, INTID 16 + `n`.
pub fn gic_specifier(
    prop: &[u8],
    interrupt_cells: u32,
    index: usize,
) -> Result<Specifier, DtError> {
    if interrupt_cells != 3 {
        return Err(DtError::Cells);
    }
    if !prop.len().is_multiple_of(12) {
        return Err(DtError::Short);
    }
    let at = 3 * index;
    let (Some(kind), Some(n), Some(flags)) =
        (cell(prop, at), cell(prop, at + 1), cell(prop, at + 2))
    else {
        return Err(DtError::Short);
    };
    let intid = match kind {
        0 => Intid::spi(n),
        1 => Intid::ppi(n),
        other => return Err(DtError::Type(other)),
    }
    .ok_or(DtError::Number(n))?;
    Ok(Specifier { intid, flags })
}

/// The affinity a cpu node's `reg` gives, with its parent's
/// `#address-cells` (1 or 2), from the first entry. `None` if the property
/// is too short, the cell count isn't 1 or 2, or the value has bits that
/// aren't affinity bits.
pub fn cpu_affinity(reg: &[u8], address_cells: u32) -> Option<Affinity> {
    let v = match address_cells {
        1 => u64::from(cell(reg, 0)?),
        2 => u64::from(cell(reg, 0)?) << 32 | u64::from(cell(reg, 1)?),
        _ => return None,
    };
    Affinity::from_dt_reg(v)
}

/// Whether a node is enabled: it has no `status`, or its `status` is
/// "okay" (or the older "ok"), with or without the trailing NUL.
pub fn is_enabled(status: Option<&[u8]>) -> bool {
    match status {
        None => true,
        Some(s) => {
            let s = s.strip_suffix(&[0]).unwrap_or(s);
            s == b"okay" || s == b"ok"
        }
    }
}
