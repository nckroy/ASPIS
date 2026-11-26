// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The four rights (ADR 0049, rule 2): read, write, grant and grant-reply,
//! as in seL4. A copy may drop rights, never add them. What each right
//! allows on each object type is in the kernel specification, "Rights by
//! object type".

use core::ops::BitAnd;

/// A set of rights, in four bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rights(u8);

impl Rights {
    /// No rights.
    pub const NONE: Rights = Rights(0);
    /// Read: receive on an endpoint, map a frame readable or executable,
    /// read through an address space.
    pub const READ: Rights = Rights(1);
    /// Write: send on an endpoint, map a frame writable, map into an address
    /// space.
    pub const WRITE: Rights = Rights(2);
    /// Grant: send capabilities through an endpoint.
    pub const GRANT: Rights = Rights(4);
    /// Grant-reply: call through an endpoint, so the reply may carry
    /// capabilities.
    pub const GRANT_REPLY: Rights = Rights(8);
    /// All four.
    pub const ALL: Rights = Rights(15);

    /// The set in its four bits: read is bit 0, write bit 1, grant bit 2
    /// and grant-reply bit 3. The order is the kernel's own; seL4's
    /// `seL4_CapRights_t` puts write below read. The ABI numbers are C17's.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// The set from its bits. Bits above the fourth are dropped.
    pub const fn from_bits(bits: u8) -> Rights {
        Rights(bits & 15)
    }

    /// Whether every right in `other` is in this set.
    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether this set is a subset of `other`.
    pub const fn is_subset(self, other: Rights) -> bool {
        other.contains(self)
    }

    /// Both sets: what a copy through `mask` keeps.
    pub const fn mask(self, mask: Rights) -> Rights {
        Rights(self.0 & mask.0)
    }

    /// Either set.
    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }
}

impl BitAnd for Rights {
    type Output = Rights;

    fn bitand(self, mask: Rights) -> Rights {
        self.mask(mask)
    }
}
