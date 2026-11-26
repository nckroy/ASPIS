// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Capability transfer: up to three capabilities per message (ADR 0049,
//! rule 6; ADR 0047, rule 3; kernel specification, "Capability transfer").
//!
//! This is the kernel-internal primitive. C14 calls it from the IPC path,
//! with the addresses the sender named in its IPC buffer and the receive
//! slots the receiver named in its own. Apart from the number of slots it
//! follows seL4's `transferCaps`.

use crate::SlotRef;
use crate::cap::Cap;
use crate::derive::derive;
use crate::lookup::lookup_cap;
use crate::mdb;
use crate::slot::{self, Mem};

/// The most capabilities one message carries.
pub const MAX_CAPS: usize = 3;

/// What a transfer did, for the receiver's message info and IPC buffer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Transferred {
    /// How many of the named capabilities were processed, from the first.
    pub count: usize,
    /// Bit i is set when capability i was unwrapped: an endpoint capability
    /// to the endpoint the message travels through.
    pub unwrapped: u8,
    /// The badge of each unwrapped capability, at its position; 0 elsewhere.
    pub badges: [u64; MAX_CAPS],
}

/// What a transfer moves: the sender's side.
#[derive(Clone, Copy, Debug)]
pub struct Send<'a> {
    /// The sender's root CNode capability.
    pub root: Cap,
    /// The capability addresses the sender named, at most three.
    pub addrs: &'a [u64],
    /// Whether the capability used to send has the grant right (or, for a
    /// reply, whether the reply capability has it).
    pub grant: bool,
    /// The endpoint the message travels through, by its address.
    pub endpoint: u64,
}

/// Transfers capabilities from the sender's space into the receive slots
/// `recv` (at most three, already resolved).
///
/// - Without grant, nothing is transferred or unwrapped.
/// - If any address doesn't resolve to a capability, none is transferred.
/// - In the order named: an endpoint capability to `endpoint` is unwrapped,
///   reporting its badge, and fills no slot. Any other is derived into the
///   next receive slot, as a child of the sender's capability.
/// - Transfer stops at the first capability with no receive slot left, an
///   occupied slot, or one that can't be derived, as in seL4.
pub fn transfer<M: Mem>(mem: &mut M, send: &Send<'_>, recv: &[SlotRef]) -> Transferred {
    let mut out = Transferred::default();
    if !send.grant {
        return out;
    }
    let addrs = &send.addrs[..send.addrs.len().min(MAX_CAPS)];
    let recv = &recv[..recv.len().min(MAX_CAPS)];
    let mut found = [(SlotRef(0), Cap::Null); MAX_CAPS];
    for (i, &a) in addrs.iter().enumerate() {
        match lookup_cap(mem, send.root, a) {
            Ok(f) => found[i] = f,
            Err(_) => return out,
        }
    }
    let mut next_slot = 0;
    for (i, &(src, cap)) in found.iter().take(addrs.len()).enumerate() {
        if let Cap::Endpoint { ptr, badge, .. } = cap
            && ptr == send.endpoint
        {
            out.unwrapped |= 1 << i;
            out.badges[i] = badge;
            out.count += 1;
            continue;
        }
        let Some(&dst) = recv.get(next_slot) else {
            break;
        };
        if !slot::is_empty(mem, dst) || dst == src {
            break;
        }
        let Ok(new) = derive(&cap, mdb::has_children(mem, src)) else {
            break;
        };
        if crate::ops::insert_derived(mem, src, dst, new).is_err() {
            break;
        }
        next_slot += 1;
        out.count += 1;
    }
    out
}
