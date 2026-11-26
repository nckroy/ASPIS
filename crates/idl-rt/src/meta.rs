// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! An interface's metadata, which the compiler records and the runtime,
//! managers, network servers and the catalog read (docs/design/
//! call-language.md, "Rights a session needs", "Local methods and
//! interfaces", "Spilling", "Server streams in the IDL").

use crate::cap::Rights;

/// A capability parameter's declared type ("Capability types").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapType {
    /// The interface it names, such as `aspis.kernel.memory`.
    pub interface: &'static str,
    pub major: u16,
    pub minor: u16,
    /// A kernel object's capability: an `aspis.kernel.*` interface other
    /// than the three the kernel calls. Otherwise a session capability.
    pub kernel_object: bool,
    /// A kernel object's declared rights: the stub attenuates to exactly
    /// these, and the receiver checks them. A session capability's are
    /// computed, and the receiver checks write and grant-reply.
    pub rights: Rights,
    /// `immutable`: only with `aspis.kernel.memory`.
    pub immutable: bool,
}

impl CapType {
    /// The rights a received capability of this type must have.
    pub fn required(&self) -> Rights {
        if self.kernel_object {
            self.rights
        } else {
            Rights::WRITE.union(Rights::GRANT_REPLY)
        }
    }

    /// Checks a received capability against the type, with what the
    /// kernel's identify operation said of it (None: nothing there). The
    /// error is the rights it lacks; a capability of the wrong kind lacks
    /// them all.
    pub fn check(&self, id: Option<Identity<'_>>) -> Result<(), Rights> {
        let need = self.required();
        let Some(id) = id else {
            return Err(need);
        };
        let kind_ok = match id.kind {
            Kind::Endpoint => !self.kernel_object,
            Kind::Object(name) => {
                self.kernel_object && name == self.interface && (!self.immutable || id.immutable)
            }
        };
        if !kind_ok {
            return Err(need);
        }
        let missing = need.missing_from(id.rights);
        if missing == Rights::NONE {
            Ok(())
        } else {
            Err(missing)
        }
    }
}

/// What kind of object a capability names, as the kernel's identify
/// operation reports it (ADR 0047, rule 3; L41).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind<'a> {
    /// An endpoint: a session capability.
    Endpoint,
    /// A kernel object, by its kernel interface's name.
    Object(&'a str),
}

/// What identify says of a received capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity<'a> {
    pub kind: Kind<'a>,
    pub rights: Rights,
    /// A memory object that is immutable.
    pub immutable: bool,
}

/// What a stub and a dispatcher know of a method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodInfo {
    pub number: u16,
    /// The minor that added it.
    pub since: u16,
    /// Local, written or inferred.
    pub local: bool,
}

/// A stream method's kind ("Server streams in the IDL").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Lossless,
    Lossy,
    Coalescing,
}

/// One direction of a method's messages, in the worst case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyMeta {
    /// The most octets the body takes. For a stream method's reply, the
    /// opening reply, with its stream ID and start position.
    pub max: u64,
    /// Capability positions, counting optional ones and a union's largest
    /// arm.
    pub caps: u8,
    /// Whether the body may spill beside the largest header ("Spilling").
    pub may_spill: bool,
}

/// A stream method's items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamMeta {
    pub kind: StreamKind,
    /// The largest item.
    pub item_max: u64,
    /// The largest entry: the item, plus 13 octets of kind, position and
    /// length. Items are at most 2^24 - 8 - 4 - 13 octets.
    pub entry_max: u64,
}

/// One method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodMeta {
    pub number: u16,
    pub name: &'static str,
    /// The minor that added it.
    pub since: u16,
    /// Written `[local]`, or inferred from a capability that can't cross
    /// nodes ("Local methods and interfaces").
    pub local: bool,
    pub oneway: bool,
    pub idempotent: bool,
    pub readonly: bool,
    pub request: BodyMeta,
    /// None for a one-way method.
    pub reply: Option<BodyMeta>,
    pub stream: Option<StreamMeta>,
}

/// One interface major, at its newest minor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceMeta {
    pub name: &'static str,
    pub id: [u8; 32],
    pub major: u16,
    pub minor: u16,
    /// Declared `[local]` or `[kernel]`.
    pub local: bool,
    pub kernel: bool,
    /// An interface the kernel calls (ADR 0063, rule 3): its requests are
    /// read tolerantly, and its dispatcher refuses nothing.
    pub kernel_called: bool,
    /// The rights a manager gives a session capability: write and
    /// grant-reply always, and grant when a request carries capabilities
    /// ("Rights a session needs").
    pub session_rights: Rights,
    pub methods: &'static [MethodMeta],
}

impl InterfaceMeta {
    pub fn method(&self, number: u16) -> Option<&'static MethodMeta> {
        self.methods.iter().find(|m| m.number == number)
    }
}
