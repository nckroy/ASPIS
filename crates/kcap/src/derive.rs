// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! What a copy may be: seL4's `deriveCap` (kernel specification,
//! "Derivation and revocation"). Copy, mint, transfer and the kernel's
//! bindings all derive before they insert.

use crate::cap::Cap;

/// Why a capability can't be derived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeriveError {
    /// The slot is empty.
    Empty,
    /// The capability can't be copied: a zombie, or an untyped capability
    /// that has children, which must be revoked first, as in seL4. C12 and
    /// C13b add the control capabilities, which can't be copied at all.
    NotDerivable,
}

/// The capability a copy of `cap` gets, before any rights are dropped.
/// `has_children` says whether anything derives from `cap`.
///
/// A frame binding's copy is the frame without its mapping, as seL4's
/// `Arch_deriveCap` clears a frame capability's mapped address. The copy is
/// a child of the binding, so revoking the binding, or anything it derives
/// from, reaches it. Deleting the binding alone doesn't: the copy stays
/// under the frame capability. The kernel's Unmap revokes each binding
/// before it deletes it, so unmapping reaches the copy too (kernel
/// specification K42).
pub const fn derive(cap: &Cap, has_children: bool) -> Result<Cap, DeriveError> {
    match *cap {
        Cap::Null => Err(DeriveError::Empty),
        Cap::Zombie { .. } => Err(DeriveError::NotDerivable),
        Cap::Untyped { .. } if has_children => Err(DeriveError::NotDerivable),
        Cap::Frame {
            base,
            size,
            device,
            rights,
            mapping: Some(_),
        } => Ok(Cap::Frame {
            base,
            size,
            device,
            rights,
            mapping: None,
        }),
        other => Ok(other),
    }
}
