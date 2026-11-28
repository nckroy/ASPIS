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
    /// that has children, which must be revoked first, as in seL4. A
    /// scheduling-control capability copies like any other, as in seL4
    /// 17.0.0's `deriveCap`, whose default case returns the capability
    /// unchanged (C12); C13b decides interrupt control's, which seL4 nulls.
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
///
/// A thread's copy of an endpoint or a scheduling context (C12), of an
/// eventcount or of its IPC buffer's frame (C14), and a wait-set entry's
/// copy of its eventcount (C14), copy the same way: the copy is the plain
/// capability, without its role, and a child of the kept copy.
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
            mapping,
            binding,
        } if mapping.is_some() || binding.is_some() => Ok(Cap::Frame {
            base,
            size,
            device,
            rights,
            mapping: None,
            binding: None,
        }),
        Cap::Eventcount {
            ptr,
            rights,
            binding: Some(_),
            ..
        } => Ok(Cap::Eventcount {
            ptr,
            rights,
            binding: None,
            set_bits: 0,
        }),

        Cap::Endpoint {
            ptr,
            rights,
            badge,
            binding: Some(_),
        } => Ok(Cap::Endpoint {
            ptr,
            rights,
            badge,
            binding: None,
        }),
        Cap::SchedContext {
            ptr,
            bits,
            binding: Some(_),
        } => Ok(Cap::SchedContext {
            ptr,
            bits,
            binding: None,
        }),
        other => Ok(other),
    }
}
