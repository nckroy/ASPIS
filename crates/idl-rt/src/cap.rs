// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Capability parameters (ADR 0066; docs/design/call-language.md,
//! "Capability types", "Capability indexes", "Sessions, badges and
//! proxies").
//!
//! On the wire a capability is a one-octet index into the message's
//! capability list. Generated types that hold capabilities are generic
//! over the capability, `K`: a decoded value holds [`CapRef`], the index;
//! a value a stub or a dispatcher sends holds [`CapArg`], which says
//! whether a session capability is moved or shared. The encoder hands
//! each capability to a [`CapSink`] in encoding order, and writes the
//! index the sink returns.

use crate::meta::CapType;
use crate::wire::EncodeError;

/// The most capability positions in one message, in each direction.
pub const MAX_CAPS: u8 = 3;

/// A set of the four rights (ADR 0049, rule 2), in the kernel's order:
/// read is bit 0, write bit 1, grant bit 2 and grant-reply bit 3. The
/// `missing` field of `aspis.rpc`'s `capability_rights` carries these
/// bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Rights(pub u8);

impl Rights {
    pub const NONE: Rights = Rights(0);
    pub const READ: Rights = Rights(1);
    pub const WRITE: Rights = Rights(2);
    pub const GRANT: Rights = Rights(4);
    pub const GRANT_REPLY: Rights = Rights(8);

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn union(self, o: Rights) -> Rights {
        Rights(self.0 | o.0)
    }

    pub const fn contains(self, o: Rights) -> bool {
        self.0 & o.0 == o.0
    }

    /// The rights of `self` that `have` lacks.
    pub const fn missing_from(self, have: Rights) -> Rights {
        Rights(self.0 & !have.0)
    }
}

/// A decoded capability: its index in the message's capability list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapRef(pub u8);

impl CapRef {
    pub fn index(self) -> u8 {
        self.0
    }
}

/// A capability a stub or a dispatcher sends (docs/design/
/// call-language.md, "Sessions, badges and proxies").
///
/// A session capability is moved or shared. A moved one is sent and given
/// up: the sender's binding never closes its badge, and the receiver's
/// binding owns it. A shared one stays the sender's: the stub calls
/// `session_dup` and sends the new badge. A kernel object capability is
/// attenuated to the declared rights either way, and the copy is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapArg<'c, C> {
    Move(C),
    Share(&'c C),
}

impl<C> CapArg<'_, C> {
    /// The capability, whichever way it is passed.
    pub fn cap(&self) -> &C {
        match self {
            CapArg::Move(c) => c,
            CapArg::Share(c) => c,
        }
    }
}

/// Where an encoder puts each capability, in encoding order. It returns
/// the index to write.
pub trait CapSink<'r, K> {
    fn put(&mut self, cap: &'r K, ty: &'static CapType) -> Result<u8, EncodeError>;
}

/// Re-encodes decoded indexes: each must be the next in encoding order
/// ("Capability indexes"), so a re-encoded message names its list as the
/// original did.
#[derive(Debug, Default)]
pub struct Indexes {
    next: u8,
}

impl Indexes {
    pub fn new() -> Indexes {
        Indexes::default()
    }

    /// How many indexes were written.
    pub fn count(&self) -> u8 {
        self.next
    }
}

impl<'r> CapSink<'r, CapRef> for Indexes {
    fn put(&mut self, cap: &'r CapRef, _: &'static CapType) -> Result<u8, EncodeError> {
        if cap.0 != self.next || self.next >= MAX_CAPS {
            return Err(EncodeError::Caps);
        }
        self.next += 1;
        Ok(cap.0)
    }
}

/// Numbers capabilities by their place in the encoding, whatever they
/// are: what a stub writes once it has collected and converted them.
#[derive(Debug, Default)]
pub struct Positions {
    next: u8,
}

impl Positions {
    pub fn new() -> Positions {
        Positions::default()
    }
}

impl<'r, K> CapSink<'r, K> for Positions {
    fn put(&mut self, _: &'r K, _: &'static CapType) -> Result<u8, EncodeError> {
        if self.next >= MAX_CAPS {
            return Err(EncodeError::Caps);
        }
        self.next += 1;
        Ok(self.next - 1)
    }
}

/// Collects the capabilities a value holds, in encoding order, with their
/// declared types.
pub struct Collect<'r, K> {
    items: [Option<(&'r K, &'static CapType)>; MAX_CAPS as usize],
    len: u8,
}

impl<K> Default for Collect<'_, K> {
    fn default() -> Self {
        Collect {
            items: [None; MAX_CAPS as usize],
            len: 0,
        }
    }
}

impl<'r, K> Collect<'r, K> {
    pub fn new() -> Self {
        Collect::default()
    }

    pub fn len(&self) -> u8 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The collected capabilities, in encoding order.
    pub fn iter(&self) -> impl Iterator<Item = (&'r K, &'static CapType)> + '_ {
        self.items.iter().flatten().copied()
    }
}

impl<'r, K> CapSink<'r, K> for Collect<'r, K> {
    fn put(&mut self, cap: &'r K, ty: &'static CapType) -> Result<u8, EncodeError> {
        let slot = self
            .items
            .get_mut(usize::from(self.len))
            .ok_or(EncodeError::Caps)?;
        *slot = Some((cap, ty));
        self.len += 1;
        Ok(self.len - 1)
    }
}

/// A type with no values: the capability type of a body that holds none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoCap {}
