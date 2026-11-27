// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! seL4's guarded lookup, in both modes.

// Binary addresses are grouped by level: guard, index, guard, index.
#![allow(clippy::unusual_byte_groupings)]

mod common;

use common::{BOOT, FakeMem, World};
use kcap::SlotRef;
use kcap::cap::Cap;
use kcap::lookup::{LookupError, lookup_cap, lookup_slot, resolve};
use kcap::mdb;
use kcap::rights::Rights;

fn cnode(ptr: u64, radix: u8, guard_size: u8, guard: u64) -> Cap {
    Cap::CNode {
        ptr,
        radix,
        guard_size,
        guard,
    }
}

fn ep(ptr: u64) -> Cap {
    Cap::Endpoint {
        ptr,
        rights: Rights::ALL,
        badge: 0,
        binding: None,
    }
}

#[test]
fn one_level_with_guards_of_0_50_and_63_bits() {
    let mut mem = FakeMem::default();
    // Radix 1: two slots at 0x1000.
    mdb::insert_root(&mut mem, SlotRef(0x1020), ep(0x9000));
    for (guard_size, guard) in [(0u8, 0u64), (50, 0x2_aaaa_5555_1234), (63, (1 << 62) | 5)] {
        let root = cnode(0x1000, 1, guard_size, guard);
        let depth = guard_size as u32 + 1;
        let addr = guard << 1 | 1;
        assert_eq!(lookup_slot(&mem, root, addr, depth), Ok(SlotRef(0x1020)));
        assert_eq!(
            lookup_slot(&mem, root, addr & !1, depth),
            Ok(SlotRef(0x1000))
        );
        // A different guard, or bits beyond the depth, don't matter
        // beyond the depth; inside it, a wrong guard is a mismatch.
        if guard_size > 0 {
            assert_eq!(
                lookup_slot(&mem, root, addr ^ 2, depth),
                Err(LookupError::GuardMismatch { bits_left: depth })
            );
        }
        // Too shallow for the guard, or for the radix.
        if guard_size > 0 {
            assert_eq!(
                lookup_slot(&mem, root, addr >> 1, guard_size as u32 - 1),
                Err(LookupError::GuardMismatch {
                    bits_left: guard_size as u32 - 1
                })
            );
        }
        assert!(matches!(
            lookup_slot(&mem, root, guard, guard_size as u32),
            Err(LookupError::DepthMismatch { .. }) | Err(LookupError::BadDepth)
        ));
    }
}

#[test]
fn guard_and_radix_together_use_all_64_bits() {
    let mut mem = FakeMem::default();
    // Radix 6 with a 58-bit guard of all ones but the top bit.
    let guard = (1u64 << 57) | 0x1234;
    let root = cnode(0x10_0000, 6, 58, guard);
    mdb::insert_root(&mut mem, SlotRef(0x10_0000).offset(63), ep(0x9000));
    let addr = guard << 6 | 63;
    assert_eq!(
        lookup_slot(&mem, root, addr, 64),
        Ok(SlotRef(0x10_0000).offset(63))
    );
    assert_eq!(
        lookup_cap(&mem, root, addr),
        Ok((SlotRef(0x10_0000).offset(63), ep(0x9000)))
    );
    // Depth 64 with a guard and radix of 64 bits leaves nothing: a shift by
    // 64 must not overflow.
    assert_eq!(
        resolve(&mem, root, addr, 64),
        Ok((SlotRef(0x10_0000).offset(63), 0))
    );
    // A guard of 0 bits at depth 64 shifts by 64 too.
    let flat = cnode(0x20_0000, 1, 0, 0);
    assert_eq!(
        lookup_slot(&mem, flat, 1 << 63, 64),
        Err(LookupError::DepthMismatch { bits_left: 63 })
    );
}

#[test]
fn two_levels_and_stopping_at_a_non_cnode() {
    let mut mem = FakeMem::default();
    // Level 1: radix 4 at 0x1000, guard 4 bits of 0b1010. Slot 3 holds a
    // level-2 CNode, radix 2 at 0x2000, guard 2 bits of 0b01. Slot 5 holds
    // an endpoint.
    let l1 = cnode(0x1000, 4, 4, 0b1010);
    let l2 = cnode(0x2000, 2, 2, 0b01);
    mdb::insert_root(&mut mem, SlotRef(0x1000).offset(3), l2);
    mdb::insert_root(&mut mem, SlotRef(0x1000).offset(5), ep(0x9000));
    mdb::insert_root(&mut mem, SlotRef(0x2000).offset(2), ep(0x9040));
    // 1010 0011 01 10: 12 bits.
    let addr = 0b1010_0011_01_10;
    assert_eq!(
        lookup_slot(&mem, l1, addr, 12),
        Ok(SlotRef(0x2000).offset(2))
    );
    // At depth 8, the slot holding the level-2 CNode itself.
    assert_eq!(
        lookup_slot(&mem, l1, addr >> 4, 8),
        Ok(SlotRef(0x1000).offset(3))
    );
    // A wrong level-2 guard.
    assert_eq!(
        lookup_slot(&mem, l1, 0b1010_0011_11_10, 12),
        Err(LookupError::GuardMismatch { bits_left: 4 })
    );
    // Running out partway through level 2.
    assert_eq!(
        lookup_slot(&mem, l1, addr >> 1, 11),
        Err(LookupError::DepthMismatch { bits_left: 3 })
    );
    // A slot lookup past an endpoint is a depth mismatch; a capability
    // lookup stops there.
    let past_ep = (0b1010_0101u64 << 56) | 0xff;
    assert_eq!(
        lookup_slot(&mem, l1, past_ep, 64),
        Err(LookupError::DepthMismatch { bits_left: 56 })
    );
    let l1_64 = cnode(0x1000, 4, 4, 0b1010);
    assert_eq!(
        lookup_cap(&mem, l1_64, past_ep),
        Ok((SlotRef(0x1000).offset(5), ep(0x9000)))
    );
    // An empty slot is a missing capability for an invocation.
    let empty = 0b1010_0110u64 << 56;
    assert_eq!(
        lookup_cap(&mem, l1_64, empty),
        Err(LookupError::MissingCapability)
    );
    // The root must be a CNode, and the depth 1 to 64.
    assert_eq!(
        lookup_slot(&mem, ep(0), 0, 8),
        Err(LookupError::InvalidRoot)
    );
    assert_eq!(lookup_slot(&mem, l1, 0, 0), Err(LookupError::BadDepth));
    assert_eq!(lookup_slot(&mem, l1, 0, 65), Err(LookupError::BadDepth));
}

#[test]
fn a_cnode_holding_itself_stays_bounded() {
    let mut mem = FakeMem::default();
    // Radix 1, no guard, and slot 1 holds the CNode itself: each level
    // consumes one bit, so lookup ends after 64 levels.
    let c = cnode(0x3000, 1, 0, 0);
    mdb::insert_root(&mut mem, SlotRef(0x3020), c);
    assert_eq!(resolve(&mem, c, u64::MAX, 64), Ok((SlotRef(0x3020), 0)));
    assert_eq!(lookup_cap(&mem, c, u64::MAX), Ok((SlotRef(0x3020), c)));
    // A 0 bit anywhere stops at the empty slot 0.
    assert_eq!(
        lookup_cap(&mem, c, u64::MAX << 1),
        Err(LookupError::MissingCapability)
    );
}

#[test]
fn the_boot_layout_resolves_by_index() {
    // The kernel's root CNode has radix 7 and a 57-bit guard of zeros; the
    // tests' has radix 8 and a 56-bit guard. Either way a slot's address
    // is its index.
    let w = World::new();
    for i in [1u64, 16, 17] {
        assert_eq!(lookup_slot(&w.mem, w.root, i, 64), Ok(w.slot(i)));
        assert_eq!(lookup_cap(&w.mem, w.root, i).map(|(s, _)| s), Ok(w.slot(i)));
    }
    // An index past the radix falls in the guard of zeros.
    assert_eq!(
        lookup_slot(&w.mem, w.root, 1 << 8, 64),
        Err(LookupError::GuardMismatch { bits_left: 64 })
    );
    assert_eq!(w.slot(1), SlotRef(BOOT).offset(1));
}
