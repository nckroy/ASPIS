// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! In-QEMU tests of the capability layer (ADR 0036, rule 5; ADR 0049): the
//! boot capability space, lookup, copies and identify, and the bindings
//! that deletion and revocation remove from the hardware. The logic itself
//! is tested on the host, in `kcap`; these check it on the kernel's real
//! slots, tables and TLB. Each works in a [`Scratch`] and leaves the boot
//! capability space as it found it.

use super::boot::{self, FIRST_FREE, FIRST_UNTYPED_CNODE, RADIX, ROOT_SELF, SLOTS, UNTYPED_CNODES};
use super::testkit::{Scratch, base, watermark};
use super::*;
use crate::mm::space::{self, AddressSpace};
use kcap::cap::SlotArray;
use kcap::lookup::LookupError;
use kcap::preempt::Always;
use kcap::slot::Slot;
use kmem::BLOCK_2M;
use kmem::layout::DIRECT_MAP_BASE;
use kmem::table::Walk;
use kmem::user::{Access, UserError};

const RO: UserPerm = UserPerm {
    write: false,
    exec: false,
};
const RW: UserPerm = UserPerm {
    write: true,
    exec: false,
};
const VA: u64 = 0x40_0000;

fn finished() -> u64 {
    FINISHED.load(Ordering::Relaxed)
}

fn unbound() -> u64 {
    UNBOUND.load(Ordering::Relaxed)
}

fn read(s: SlotRef) -> Slot {
    slot::read(&DirectSlots, s)
}

fn poke(pa: u64, v: u64) {
    // SAFETY: a RAM frame the test retyped, in the direct map.
    unsafe { core::ptr::write_volatile((DIRECT_MAP_BASE + pa) as *mut u64, v) };
}

/// The slots of the root CNode, the originals page and the untyped CNodes,
/// as the boot made them.
fn boot_slots() -> impl Iterator<Item = SlotRef> + Clone {
    let cnodes: [u64; UNTYPED_CNODES] =
        core::array::from_fn(
            |i| match cap(boot::root_slot(FIRST_UNTYPED_CNODE + i as u64)) {
                Cap::CNode { ptr, .. } => ptr,
                c => panic!("root slot {} holds {c:x?}", FIRST_UNTYPED_CNODE + i as u64),
            },
        );
    (0..SLOTS)
        .map(boot::root_slot)
        .chain((0..SLOTS).map(boot::original))
        .chain(
            (0..UNTYPED_CNODES as u64 * SLOTS)
                .map(move |k| SlotRef(cnodes[(k / SLOTS) as usize]).offset(k % SLOTS)),
        )
}

/// Checks that every zombie among `slots` has left no slot it has already
/// swept holding anything: slots `n` and up of a Zombie(o, n) are empty, but
/// for the zombie's own slot.
fn verify_zombies(slots: impl Iterator<Item = SlotRef>) {
    for s in slots {
        let Cap::Zombie { kind, ptr, n } = cap(s) else {
            continue;
        };
        let a = SlotArray::of(kind, ptr);
        for i in n..a.count {
            let x = a.slot(i);
            assert!(
                x == s || cap(x).is_null(),
                "the zombie at {:#x} has swept slot {i}, which holds {:x?}",
                s.0,
                cap(x)
            );
        }
    }
}

/// Checks the derivation tree over the boot slots, the scratch CNode's, and
/// the slots of every CNode and address-space record reachable from them or
/// from `seeds` (each a slot array's base and count): `mdb::verify` needs
/// every slot a link can lead to.
fn verify(sc: &Scratch, seeds: &[(u64, u64)]) {
    const MAX: usize = 16;
    let boot_cnodes: [u64; UNTYPED_CNODES + 1] = core::array::from_fn(|i| {
        let r = if i == 0 {
            ROOT_SELF
        } else {
            FIRST_UNTYPED_CNODE + i as u64 - 1
        };
        match cap(boot::root_slot(r)) {
            Cap::CNode { ptr, .. } => ptr,
            c => panic!("root slot {r} holds {c:x?}"),
        }
    });
    let mut arrays = [(0u64, 0u64); MAX];
    let mut n = 0;
    let add = |arrays: &mut [(u64, u64); MAX], n: &mut usize, a: (u64, u64)| {
        if !arrays[..*n].contains(&a) && !boot_cnodes.contains(&a.0) {
            assert!(*n < MAX, "too many slot arrays to verify");
            arrays[*n] = a;
            *n += 1;
        }
    };
    add(&mut arrays, &mut n, (sc.slot(0).0, SLOTS));
    for &a in seeds {
        add(&mut arrays, &mut n, a);
    }
    let mut i = 0;
    while i < n {
        let (b, count) = arrays[i];
        for k in 0..count {
            match cap(SlotRef(b).offset(k)) {
                Cap::CNode { ptr, radix, .. } => add(&mut arrays, &mut n, (ptr, 1 << radix)),
                Cap::AddressSpace { base, .. } => {
                    let a = SlotArray::of_address_space(base);
                    add(&mut arrays, &mut n, (a.base, a.count));
                }
                _ => {}
            }
        }
        i += 1;
    }
    let found = arrays;
    let extra = (0..n).flat_map(move |j| {
        let (b, count) = found[j];
        (0..count).map(move |k| SlotRef(b).offset(k))
    });
    if let Err(e) = mdb::verify(&DirectSlots, boot_slots().chain(extra.clone())) {
        panic!("the derivation tree is broken: {e:?}");
    }
    verify_zombies(boot_slots().chain(extra));
}

crate::kernel_test!(boot_cspace_holds_every_untyped_piece, {
    let m = crate::mm::report();
    // The root CNode's layout.
    assert!(cap(boot::root_slot(0)).is_null());
    assert_eq!(cap(boot::root_slot(ROOT_SELF)), boot::root());
    for i in (2..FIRST_UNTYPED_CNODE).chain(FIRST_FREE..SLOTS) {
        assert!(cap(boot::root_slot(i)).is_null(), "root slot {i} is full");
    }
    for i in FIRST_UNTYPED_CNODE..FIRST_UNTYPED_CNODE + UNTYPED_CNODES as u64 {
        assert!(matches!(
            cap(boot::root_slot(i)),
            Cap::CNode {
                radix: RADIX,
                guard_size: 0,
                ..
            }
        ));
    }
    // One untyped capability for each piece: RAM pieces, then device
    // pieces, in address order within each, so none overlap. Each is a root
    // of the tree, with no parent, and every test leaves it free.
    let (mut ram, mut dev, mut bytes, mut slots) = (0, 0, 0, 0);
    let mut end = [0u64; 2];
    let mut last_slot = None;
    boot::for_each_untyped(|s, c| {
        let Cap::Untyped {
            base,
            bits,
            device,
            watermark,
        } = c
        else {
            panic!("{c:x?} isn't untyped");
        };
        assert_eq!(watermark, 0);
        let sl = read(s);
        assert_eq!((sl.depth, sl.prev, sl.next), (0, None, None));
        assert!(base >= end[device as usize], "pieces overlap at {base:#x}");
        end[device as usize] = base + (1 << bits);
        if device {
            dev += 1;
        } else {
            assert_eq!(dev, 0, "a RAM piece follows a device piece");
            ram += 1;
            bytes += 1u64 << bits;
        }
        slots += 1;
        last_slot = Some(s);
    });
    assert_eq!(
        (ram, dev, bytes),
        (m.ram_pieces, m.device_pieces, m.untyped_bytes)
    );
    assert_eq!(slots, m.untyped_caps);
    assert!(ram > 0 && dev > 0);
    // They fill the untyped CNodes from the first slot on.
    let k = slots as u64 - 1;
    let last_cnode = match cap(boot::root_slot(FIRST_UNTYPED_CNODE + k / SLOTS)) {
        Cap::CNode { ptr, .. } => ptr,
        c => panic!("{c:x?}"),
    };
    assert_eq!(last_slot, Some(SlotRef(last_cnode).offset(k % SLOTS)));
    // The tree's links are sound over all of it.
    assert_eq!(mdb::verify(&DirectSlots, boot_slots()), Ok(()));
});

crate::kernel_test!(lookup_resolves_the_boot_cspace, {
    let cn0 = match cap(boot::root_slot(FIRST_UNTYPED_CNODE)) {
        Cap::CNode { ptr, .. } => SlotRef(ptr),
        c => panic!("{c:x?}"),
    };
    let first = boot::address(FIRST_UNTYPED_CNODE, 0);
    // Depth 64, through the root's 50-bit guard and two levels of radix 7.
    assert_eq!(lookup_cap(first), Ok((cn0, cap(cn0))));
    assert_eq!(lookup_slot(first, 64), Ok(cn0));
    // A root slot itself, at depth 57, empty or not.
    assert_eq!(
        lookup_slot(FIRST_UNTYPED_CNODE, boot::ROOT_DEPTH),
        Ok(boot::root_slot(FIRST_UNTYPED_CNODE))
    );
    assert_eq!(lookup_slot(5, boot::ROOT_DEPTH), Ok(boot::root_slot(5)));
    // An empty slot stops a capability lookup.
    assert_eq!(
        lookup_cap(boot::address(5, 0)),
        Err(LookupError::MissingCapability)
    );
    // The guard must match: a high bit set, or the root's own capability in
    // slot 1, whose 50-bit guard the 7 bits left can't hold.
    assert_eq!(
        lookup_cap(1 << 63 | first),
        Err(LookupError::GuardMismatch { bits_left: 64 })
    );
    assert_eq!(
        lookup_cap(boot::address(ROOT_SELF, 0)),
        Err(LookupError::GuardMismatch { bits_left: 7 })
    );
    // Bits that run out partway through a level, and a depth out of range.
    assert_eq!(
        lookup_slot(first >> 4, 60),
        Err(LookupError::DepthMismatch { bits_left: 3 })
    );
    assert_eq!(lookup_slot(first, 0), Err(LookupError::BadDepth));
    // An invocation's lookup stops at the first capability that isn't a
    // CNode: an endpoint in the scratch CNode.
    let mut sc = Scratch::new(13);
    let ep = sc.make(ObjectType::Endpoint);
    assert_eq!(lookup_cap(sc.addr(0)), Ok((ep, cap(ep))));
    assert_eq!(lookup_slot(sc.addr(1), 64), Ok(sc.slot(1)));
    sc.finish();
});

crate::kernel_test!(copy_mint_move_and_identify, {
    let mut sc = Scratch::new(16);
    let cn = sc.make(ObjectType::CNode(4));
    let fr = sc.make(ObjectType::Frame4K);
    let asp = sc.make(ObjectType::AddressSpace);
    let ep = sc.make(ObjectType::Endpoint);
    // Identify reports the kind and the rights, and untyped and CNode
    // capabilities carry none. A copy is a child of its source.
    for (s, kind, rights) in [
        (sc.ram, Kind::Untyped, Rights::NONE),
        (cn, Kind::CNode, Rights::NONE),
        (fr, Kind::Frame, Rights::ALL),
        (asp, Kind::AddressSpace, Rights::ALL),
        (ep, Kind::Endpoint, Rights::ALL),
    ] {
        assert_eq!(identify(s), (kind, rights));
        if s == sc.ram {
            // Untyped memory with children can't be copied.
            let c = sc.take();
            assert_eq!(copy(s, c), Err(Error::NotDerivable));
            continue;
        }
        let c = sc.take();
        assert_eq!(copy(s, c), Ok(()));
        assert_eq!(identify(c), (kind, rights));
        assert_eq!(mdb::first_child(&DirectSlots, s), Some(c));
        assert_eq!(read(c).depth, read(s).depth + 1);
    }
    let empty = sc.take();
    assert_eq!(identify(empty), (Kind::Null, Rights::NONE));
    // A copy drops rights, and never adds them back (ADR 0049, rule 2).
    let r = sc.take();
    assert_eq!(mint(fr, r, Rights::READ, MintData::None), Ok(()));
    assert_eq!(identify(r), (Kind::Frame, Rights::READ));
    let r2 = sc.take();
    assert_eq!(mint(r, r2, Rights::ALL, MintData::None), Ok(()));
    assert_eq!(identify(r2), (Kind::Frame, Rights::READ));
    // A badge is set once, and identify never reports it (ADR 0049, rule 3;
    // ADR 0050, rule 1).
    let b = sc.take();
    assert_eq!(mint(ep, b, Rights::ALL, MintData::Badge(7)), Ok(()));
    assert!(matches!(cap(b), Cap::Endpoint { badge: 7, .. }));
    assert_eq!(identify(b), (Kind::Endpoint, Rights::ALL));
    let b2 = sc.take();
    assert_eq!(
        mint(b, b2, Rights::ALL, MintData::Badge(8)),
        Err(Error::InvalidData)
    );
    assert_eq!(copy(b, b2), Ok(()));
    assert!(matches!(cap(b2), Cap::Endpoint { badge: 7, .. }));
    // Mutate moves a CNode capability with a new guard, and nothing else.
    let m = sc.take();
    let guard = Guard { size: 3, value: 5 };
    assert_eq!(mutate(cn, m, guard), Ok(()));
    assert!(cap(cn).is_null());
    assert!(matches!(
        cap(m),
        Cap::CNode {
            guard_size: 3,
            guard: 5,
            ..
        }
    ));
    let m2 = sc.take();
    assert_eq!(mutate(fr, m2, guard), Err(Error::InvalidData));
    // A move keeps the capability's place in the tree, and its children.
    let mv = sc.take();
    assert_eq!(move_cap(fr, mv), Ok(()));
    assert!(cap(fr).is_null());
    assert_eq!(identify(mv), (Kind::Frame, Rights::ALL));
    assert!(mdb::has_children(&DirectSlots, mv));
    assert_eq!(move_cap(mv, r), Err(Error::DestNotEmpty));
    verify(&sc, &[]);
    // Revoking the moved frame deletes its copies, and their copies.
    revoke(mv);
    assert!(cap(r).is_null() && cap(r2).is_null());
    verify(&sc, &[]);
    sc.finish();
});

crate::kernel_test!(revoking_a_frame_unmaps_it_everywhere, {
    const P1: u64 = 0x1234_5678_9abc_def0;
    const P2: u64 = 0x0fed_cba9_8765_4321;
    let mut sc = Scratch::new(17);
    let (ca, cb) = (
        sc.make(ObjectType::AddressSpace),
        sc.make(ObjectType::AddressSpace),
    );
    let (f, g) = (sc.make(ObjectType::Frame4K), sc.make(ObjectType::Frame4K));
    poke(base(f), P1);
    poke(base(g), P2);
    // B maps a copy of the frame: its binding is a grandchild of the
    // original, which a revoke still reaches.
    let f2 = sc.take();
    assert_eq!(copy(f, f2), Ok(()));
    assert_eq!(map(f, ca, VA, RO, sc.ram), Ok(()));
    assert_eq!(map(f2, cb, VA, RO, sc.ram), Ok(()));
    let (a, b) = (
        AddressSpace::from_object(base(ca)),
        AddressSpace::from_object(base(cb)),
    );
    // SAFETY (each `ldtr_u64` below): `VA` is mapped readable at EL0 in the
    // active space. Test only: the kernel never dereferences a user address
    // (ADR 0048, rule 5).
    b.activate();
    assert_eq!(unsafe { arch::ldtr_u64(VA) }, P1);
    // A last, so its translation is in the TLB when the revoke runs.
    a.activate();
    assert_eq!(unsafe { arch::ldtr_u64(VA) }, P1);
    let u = unbound();
    revoke(f);
    assert_eq!(unbound() - u, 2);
    assert!(cap(f2).is_null());
    assert_eq!(identify(f), (Kind::Frame, Rights::ALL));
    assert!(!mdb::has_children(&DirectSlots, f));
    // Unmapped in the active space, in hardware and in software.
    assert_eq!(arch::at_s1e0r(VA) & arch::PAR_F, arch::PAR_F);
    assert_eq!(a.translate(VA, Access::Read), Err(UserError::NotResident));
    // Remapped to another frame: the old translation is gone from the TLB.
    assert_eq!(map(g, ca, VA, RO, sc.ram), Ok(()));
    assert_eq!(
        unsafe { arch::ldtr_u64(VA) },
        P2,
        "a stale translation survived the revoke"
    );
    // And unmapped in the other space.
    b.activate();
    assert_eq!(arch::at_s1e0r(VA) & arch::PAR_F, arch::PAR_F);
    assert_eq!(b.translate(VA, Access::Read), Err(UserError::NotResident));
    space::deactivate();
    verify(&sc, &[]);
    sc.finish();
});

crate::kernel_test!(deleting_an_address_space_unbinds_and_releases_its_asid, {
    let mut sc = Scratch::new(17);
    let s = sc.make(ObjectType::AddressSpace);
    let (f1, f2) = (sc.make(ObjectType::Frame4K), sc.make(ObjectType::Frame4K));
    assert_eq!(map(f1, s, VA, RW, sc.ram), Ok(()));
    assert_eq!(map(f2, s, VA + PAGE_SIZE, RO, sc.ram), Ok(()));
    let space = AddressSpace::from_object(base(s));
    space.activate();
    assert!(kmem::asid::asid_of(space.asid_word()).is_some());
    let (fin, unb) = (finished(), unbound());
    // The space's only capability: deleting it destroys the space.
    delete(s);
    assert!(cap(s).is_null());
    assert_eq!((finished() - fin, unbound() - unb), (1, 2));
    // Deactivated, and its ASID released.
    assert_eq!(
        arch::ttbr0(),
        crate::mm::phys::kernel_pa(crate::entry::zero_table())
    );
    assert_eq!(space.asid_word(), 0);
    // The frames survive, unmapped, and map again elsewhere.
    for f in [f1, f2] {
        assert_eq!(identify(f), (Kind::Frame, Rights::ALL));
        assert!(!mdb::has_children(&DirectSlots, f));
    }
    let t = sc.make(ObjectType::AddressSpace);
    assert_eq!(map(f1, t, VA, RW, sc.ram), Ok(()));
    verify(&sc, &[]);
    sc.finish();
});

crate::kernel_test!(revoking_the_untyped_destroys_a_cspace_tree, {
    let mut sc = Scratch::new(18);
    let u = sc.make(ObjectType::Untyped(16));
    let c1 = sc.make_from(u, ObjectType::CNode(4));
    let c2 = sc.make_from(u, ObjectType::CNode(3));
    let ep = sc.make_from(u, ObjectType::Endpoint);
    let fr = sc.make_from(u, ObjectType::Frame4K);
    let asp = sc.make_from(u, ObjectType::AddressSpace);
    assert_eq!(map(fr, asp, VA, RW, u), Ok(()));
    let in_cnode = |c: SlotRef, i: u64| match cap(c) {
        Cap::CNode { ptr, .. } => SlotRef(ptr).offset(i),
        x => panic!("{x:x?}"),
    };
    // Only the CNodes reach the objects: C1 holds the address space, C2 and
    // a capability to itself; C2 holds the endpoint and the frame.
    let (in1, in2) = (|i| in_cnode(c1, i), |i| in_cnode(c2, i));
    let (a1, a2, a3, b1, b2) = (in1(2), in1(3), in1(5), in2(1), in2(2));
    assert_eq!(move_cap(asp, a1), Ok(()));
    assert_eq!(move_cap(ep, b1), Ok(()));
    assert_eq!(move_cap(fr, b2), Ok(()));
    assert_eq!(move_cap(c2, a2), Ok(()));
    assert_eq!(copy(c1, a3), Ok(()));
    let c1_slots = (base(c1), 16);
    // Dropping the scratch CNode's capability to C1 leaves C1 reachable only
    // from itself: garbage that no lookup can name, which waits for its
    // untyped memory's revocation, as in seL4.
    let fin = finished();
    delete(c1);
    assert_eq!(finished(), fin);
    verify(&sc, &[c1_slots]);
    let unb = unbound();
    revoke(u);
    // C1, C2, the address space, the endpoint and the frame, once each;
    // the frame's mapping unbound.
    assert_eq!((finished() - fin, unbound() - unb), (5, 1));
    assert!(!mdb::has_children(&DirectSlots, u));
    // The piece resets on its next retype, and makes from its start.
    let again = sc.make_from(u, ObjectType::Frame4K);
    assert_eq!(base(again), base(u));
    assert_eq!(watermark(u), PAGE_SIZE);
    verify(&sc, &[]);
    sc.finish();
});

crate::kernel_test!(map_takes_tables_only_from_the_space_s_own_piece, {
    let mut sc = Scratch::with_device(17);
    // A child piece, which doesn't contain the space.
    let q = sc.make(ObjectType::Untyped(12));
    let s = sc.make(ObjectType::AddressSpace);
    let f = sc.make(ObjectType::Frame4K);
    let empty = sc.take();
    let w = watermark(sc.ram);
    for (tables, e) in [
        (q, Error::BadRegion),
        (sc.dev(), Error::BadRegion),
        (f, Error::WrongKind),
        (empty, Error::Empty),
    ] {
        assert_eq!(map(f, s, VA, RW, tables), Err(MapFailure::Cap(e)));
    }
    // Refused, unchanged: nothing bound, mapped or taken.
    let space = AddressSpace::from_object(base(s));
    assert!(!mdb::has_children(&DirectSlots, f));
    assert_eq!(space.tables().walk(VA), Walk::Invalid { level: 0 });
    assert_eq!(watermark(sc.ram), w);
    // The space's own piece gives it three tables, levels 1 to 3, from its
    // watermark.
    assert_eq!(map(f, s, VA, RW, sc.ram), Ok(()));
    assert_eq!(watermark(sc.ram), w + 3 * PAGE_SIZE);
    verify(&sc, &[]);
    sc.finish();
});

crate::kernel_test!(large_frames_map_as_one_leaf_at_an_aligned_address, {
    // 8 MiB: the scratch CNode and the space, the 2 MiB frame at its
    // alignment, and room after it for the tables.
    let mut sc = Scratch::new(23);
    let s = sc.make(ObjectType::AddressSpace);
    let big = sc.make(ObjectType::Frame2M);
    // Map needs the address aligned to the frame's size, as seL4 does, so
    // every mapping is one leaf and unbinding it clears one entry.
    assert_eq!(
        map(big, s, VA + PAGE_SIZE, RW, sc.ram),
        Err(MapFailure::Cap(Error::BadMapping))
    );
    assert_eq!(map(big, s, VA, RW, sc.ram), Ok(()));
    let space = AddressSpace::from_object(base(s));
    match space.tables().walk(VA) {
        Walk::Leaf { leaf, .. } => {
            assert_eq!(leaf.level, 2);
            assert_eq!(leaf.pa, base(big));
        }
        w => panic!("{w:?}"),
    }
    // An unmap that would cut it is refused; a whole one removes it.
    assert_eq!(unmap(s, VA, PAGE_SIZE), Err(MapFailure::CutsMapping));
    assert_eq!(unmap(s, VA + BLOCK_2M, BLOCK_2M), Ok(0));
    assert_eq!(unmap(s, VA, BLOCK_2M), Ok(1));
    assert!(matches!(space.tables().walk(VA), Walk::Invalid { .. }));
    assert!(!mdb::has_children(&DirectSlots, big));
    sc.finish();
});

/// Slot `i` of the CNode whose capability is in `c`.
fn in_cnode(c: SlotRef, i: u64) -> SlotRef {
    match cap(c) {
        Cap::CNode { ptr, .. } => SlotRef(ptr).offset(i),
        x => panic!("{x:x?} isn't a CNode"),
    }
}

/// The slot array of a CNode, or of an address space's record, for
/// [`verify`]'s seeds.
fn slots_of(s: SlotRef) -> (u64, u64) {
    match cap(s) {
        Cap::CNode { ptr, radix, .. } => (ptr, 1 << radix),
        Cap::AddressSpace { base, .. } => {
            let a = SlotArray::of_address_space(base);
            (a.base, a.count)
        }
        x => panic!("{x:x?} has no slots"),
    }
}

/// Runs `op` under budgets that preempt after every unit of work, calling
/// it again each time it stops, as C12 will restart a preempted system call
/// (kernel specification, "The kernel lock and long operations"). `between`
/// runs at each preemption. Returns how many times `op` was preempted.
fn drive(
    mut op: impl FnMut(&mut Budget<Always>) -> Result<(), Error>,
    mut between: impl FnMut(),
) -> u64 {
    let mut resumes = 0;
    loop {
        match op(&mut Budget::with_threshold(Always, 1)) {
            Ok(()) => return resumes,
            Err(Error::Preempted) => {
                resumes += 1;
                between();
            }
            Err(e) => panic!("the operation failed after {resumes} resumes: {e:?}"),
        }
    }
}

/// What a transfer sends from the boot capability space, through the
/// endpoint at `endpoint`.
fn sender(addrs: &[u64], grant: bool, endpoint: u64) -> Send<'_> {
    Send {
        root: boot::root(),
        addrs,
        grant,
        endpoint,
    }
}

/// The objects and bindings one destruction of [`nested_tree`] finishes and
/// unbinds: three CNodes, the address space, two endpoints and two frames;
/// the two mappings.
const TREE: (u64, u64) = (8, 2);

/// Makes, from the untyped capability in `u`, a capability space that only
/// the CNode capability it returns reaches, and the slot arrays inside it:
///
/// - C1 holds an address space and C2;
/// - C2 holds an endpoint, a frame and C3;
/// - C3 holds an endpoint and a frame, and with `cycle` a copy of C1's
///   capability, so that C1 reaches itself.
///
/// Both frames are mapped in the address space, so its record holds their
/// bindings.
fn nested_tree(sc: &mut Scratch, u: SlotRef, cycle: bool) -> (SlotRef, [(u64, u64); 4]) {
    let c1 = sc.make_from(u, ObjectType::CNode(4));
    let c2 = sc.make_from(u, ObjectType::CNode(3));
    let c3 = sc.make_from(u, ObjectType::CNode(2));
    let asp = sc.make_from(u, ObjectType::AddressSpace);
    let (e1, e2) = (
        sc.make_from(u, ObjectType::Endpoint),
        sc.make_from(u, ObjectType::Endpoint),
    );
    let (f1, f2) = (
        sc.make_from(u, ObjectType::Frame4K),
        sc.make_from(u, ObjectType::Frame4K),
    );
    assert_eq!(map(f1, asp, VA, RW, u), Ok(()));
    assert_eq!(map(f2, asp, VA + PAGE_SIZE, RO, u), Ok(()));
    let arrays = [slots_of(c1), slots_of(c2), slots_of(c3), slots_of(asp)];
    // Every destination first: a moved CNode capability's old slot no longer
    // names the CNode.
    let moves = [
        (asp, in_cnode(c1, 2)),
        (e1, in_cnode(c2, 1)),
        (f1, in_cnode(c2, 2)),
        (e2, in_cnode(c3, 0)),
        (f2, in_cnode(c3, 1)),
        (c3, in_cnode(c2, 3)),
        (c2, in_cnode(c1, 3)),
    ];
    for (from, to) in moves {
        assert_eq!(move_cap(from, to), Ok(()));
    }
    if cycle {
        let c3_slot = SlotRef(arrays[2].0).offset(2);
        assert_eq!(copy(c1, c3_slot), Ok(()));
    }
    assert!(matches!(cap(in_cnode(c1, 2)), Cap::AddressSpace { .. }));
    (c1, arrays)
}

crate::kernel_test!(revoke_and_delete_resume_after_preemption, {
    // Each operation runs twice on the same tree: once to the end, then
    // preempted after every unit and restarted, and both must end the same
    // way (ADR 0052, rule 2: complete and preemptible). The second build
    // resets the piece first, since nothing derives from it by then.
    let mut sc = Scratch::new(18);
    let u = sc.make(ObjectType::Untyped(16));

    // Delete: C1's only capability, so everything goes with it.
    let mut ends = [(0, 0, 0); 2];
    for (k, preempt) in [false, true].into_iter().enumerate() {
        let (c1, arrays) = nested_tree(&mut sc, u, false);
        let (fin, unb) = (finished(), unbound());
        let resumes = if preempt {
            // Between restarts C1's slot holds a zombie, and the tree is
            // consistent.
            drive(
                |b| delete_with(c1, b).map_err(Error::from),
                || {
                    assert_eq!(identify(c1), (Kind::Null, Rights::NONE));
                    verify(&sc, &arrays);
                },
            )
        } else {
            delete(c1);
            0
        };
        assert!(cap(c1).is_null());
        assert!(!mdb::has_children(&DirectSlots, u));
        verify(&sc, &arrays);
        ends[k] = (finished() - fin, unbound() - unb, resumes);
    }
    assert_eq!((ends[0].0, ends[0].1), TREE);
    assert_eq!((ends[1].0, ends[1].1), TREE);
    // Every unit was its own call: at least one per object and binding.
    assert!(
        ends[1].2 > TREE.0 + TREE.1,
        "a preempted delete resumed only {} times",
        ends[1].2
    );

    // Revoke: the tree holds a capability to itself, so dropping the
    // scratch CNode's copy leaves garbage that only revoking its untyped
    // memory finishes, as in seL4.
    for (k, preempt) in [false, true].into_iter().enumerate() {
        let (c1, arrays) = nested_tree(&mut sc, u, true);
        let fin = finished();
        delete(c1);
        assert_eq!(finished(), fin);
        let unb = unbound();
        let resumes = if preempt {
            drive(
                |b| revoke_with(u, b).map_err(Error::from),
                || verify(&sc, &arrays),
            )
        } else {
            revoke(u);
            0
        };
        assert!(!mdb::has_children(&DirectSlots, u));
        assert_eq!(identify(u), (Kind::Untyped, Rights::NONE));
        verify(&sc, &arrays);
        ends[k] = (finished() - fin, unbound() - unb, resumes);
    }
    assert_eq!((ends[0].0, ends[0].1), TREE);
    assert_eq!((ends[1].0, ends[1].1), TREE);
    assert!(ends[1].2 > TREE.0 + TREE.1);
    sc.finish();
});

crate::kernel_test!(retype_reset_resumes_after_preemption, {
    // A 4 MiB child piece, aligned, after the scratch CNode's page.
    let mut sc = Scratch::new(23);
    let piece = sc.make(ObjectType::Untyped(22));
    let pb = base(piece);
    let size = 1u64 << 22;
    let big = sc
        .try_make(piece, ObjectType::Frame2M, 2)
        .unwrap_or_else(|e| panic!("no frames: {e:?}"));
    assert_eq!(base(big), pb);
    for i in 0..size / 8 {
        poke(pb + 8 * i, !i);
    }
    // Revoking leaves the watermark at the top. The retype that follows
    // resets the piece in 64 KiB chunks from the top down, lowering the
    // watermark in the capability after each, and is preempted after each.
    revoke(piece);
    assert_eq!(watermark(piece), size);
    let dest = sc.take();
    let index = sc.index_of(dest);
    let mut last = size;
    let resumes = drive(
        |b| retype_with(piece, ObjectType::Frame4K, sc.cnode(), index, 1, b),
        || {
            // Progress is recorded, and nothing was made yet.
            let w = watermark(piece);
            assert!(w < last, "a preempted reset made no progress");
            assert_eq!(w % ops::RESET_CHUNK, 0);
            last = w;
            assert!(cap(dest).is_null());
        },
    );
    assert_eq!(resumes, size / ops::RESET_CHUNK);
    // The frame comes from the piece's start, and the piece is zero.
    assert_eq!(base(dest), pb);
    assert_eq!(watermark(piece), PAGE_SIZE);
    for i in 0..size / 8 {
        let at = DIRECT_MAP_BASE + pb + 8 * i;
        // SAFETY: RAM of the piece, in the direct map.
        let v = unsafe { core::ptr::read_volatile(at as *const u64) };
        assert_eq!(v, 0, "the reset left {:#x} uncleared", pb + 8 * i);
    }
    sc.finish();
});

crate::kernel_test!(badged_sessions_revoke_what_the_manager_derived, {
    // ADR 0049, rules 3 and 5: the manager keeps a badged copy of its
    // endpoint for each session and gives the client a copy derived from
    // it, with send rights. Revoking the kept copy ends the session: it
    // deletes the client's copy, and every copy the client made of it.
    let mut sc = Scratch::new(17);
    let ep = sc.make(ObjectType::Endpoint);
    let client = sc.make(ObjectType::CNode(4));
    let send = Rights::WRITE.union(Rights::GRANT_REPLY);
    let kept: [SlotRef; 3] = core::array::from_fn(|_| sc.take());
    for (k, &s) in kept.iter().enumerate() {
        let badge = 100 + k as u64;
        assert_eq!(mint(ep, s, Rights::ALL, MintData::Badge(badge)), Ok(()));
        let c = in_cnode(client, k as u64);
        assert_eq!(mint(s, c, send, MintData::None), Ok(()));
        // The client passes its copy on, within its own space.
        assert_eq!(copy(c, in_cnode(client, 8 + k as u64)), Ok(()));
        assert_eq!(identify(c), (Kind::Endpoint, send));
    }
    // The manager shares a frame with session 1 the same way, and the
    // client maps its copy: the binding is part of the session too.
    let f = sc.make(ObjectType::Frame4K);
    let s = sc.make(ObjectType::AddressSpace);
    let shared = sc.take();
    assert_eq!(copy(f, shared), Ok(()));
    assert_eq!(copy(shared, in_cnode(client, 4)), Ok(()));
    assert_eq!(map(in_cnode(client, 4), s, VA, RW, sc.ram), Ok(()));
    let space = AddressSpace::from_object(base(s));
    assert!(space.translate(VA, Access::Read).is_ok());

    let unb = unbound();
    revoke(kept[1]);
    revoke(shared);
    delete(shared);
    // Session 1 is gone: its endpoint copies, its frame copy and mapping.
    assert!(cap(in_cnode(client, 1)).is_null() && cap(in_cnode(client, 9)).is_null());
    assert!(cap(in_cnode(client, 4)).is_null());
    assert_eq!(unbound() - unb, 1);
    assert_eq!(
        space.translate(VA, Access::Read),
        Err(UserError::NotResident)
    );
    // The other sessions keep their badges.
    for k in [0, 2] {
        for i in [k, 8 + k] {
            assert!(matches!(
                cap(in_cnode(client, i)),
                Cap::Endpoint { badge, .. } if badge == 100 + k
            ));
        }
    }
    // Releasing the badge: revoke, then delete the kept copy (C14 also
    // cancels the badge's queued sends in between, with
    // `cancel_badged_sends`). The badge can then serve a new session.
    delete(kept[1]);
    assert_eq!(mint(ep, kept[1], Rights::ALL, MintData::Badge(101)), Ok(()));
    assert_eq!(
        mint(kept[1], in_cnode(client, 1), send, MintData::None),
        Ok(())
    );
    assert!(matches!(
        cap(in_cnode(client, 1)),
        Cap::Endpoint { badge: 101, .. }
    ));
    // The unbadged original reaches every session.
    revoke(ep);
    for i in 0..16 {
        assert!(cap(in_cnode(client, i)).is_null(), "client slot {i}");
    }
    assert!(kept.iter().all(|&s| cap(s).is_null()));
    verify(&sc, &[slots_of(client), slots_of(s)]);
    sc.finish();
});

crate::kernel_test!(endpoint_badge_is_set_once, {
    // ADR 0049, rule 3: badges are 64 bits, set once by Mint on a copy of an
    // unbadged endpoint, and kept by every copy after.
    let mut sc = Scratch::new(14);
    let ep = sc.make(ObjectType::Endpoint);
    let fr = sc.make(ObjectType::Frame4K);
    let b = sc.take();
    let x = sc.take();
    // 0 means unbadged, so it isn't a badge.
    assert_eq!(
        mint(ep, x, Rights::ALL, MintData::Badge(0)),
        Err(Error::InvalidData)
    );
    assert_eq!(mint(ep, b, Rights::ALL, MintData::Badge(u64::MAX)), Ok(()));
    assert!(matches!(
        cap(b),
        Cap::Endpoint {
            badge: u64::MAX,
            ..
        }
    ));
    // Not again, through any copy.
    assert_eq!(
        mint(b, x, Rights::ALL, MintData::Badge(1)),
        Err(Error::InvalidData)
    );
    let c = sc.take();
    assert_eq!(mint(b, c, Rights::WRITE, MintData::None), Ok(()));
    assert_eq!(
        mint(c, x, Rights::ALL, MintData::Badge(1)),
        Err(Error::InvalidData)
    );
    assert!(matches!(
        cap(c),
        Cap::Endpoint {
            badge: u64::MAX,
            ..
        }
    ));
    // Mutate never changes a badge: it takes only a CNode's guard.
    assert_eq!(
        mutate(b, x, Guard { size: 0, value: 0 }),
        Err(Error::InvalidData)
    );
    // Only endpoints take a badge.
    assert_eq!(
        mint(fr, x, Rights::ALL, MintData::Badge(1)),
        Err(Error::InvalidData)
    );
    assert!(cap(x).is_null());
    // Distinct badges on one endpoint are distinct sessions: a revoke of
    // one badged copy leaves another's copies.
    let b2 = sc.take();
    assert_eq!(mint(ep, b2, Rights::ALL, MintData::Badge(2)), Ok(()));
    let c2 = sc.take();
    assert_eq!(copy(b2, c2), Ok(()));
    revoke(b);
    assert!(cap(c).is_null());
    assert!(matches!(cap(c2), Cap::Endpoint { badge: 2, .. }));
    verify(&sc, &[]);
    sc.finish();
});

crate::kernel_test!(transfer_moves_up_to_three_capabilities, {
    // ADR 0049, rule 6: the kernel-internal transfer primitive, between the
    // boot capability space as the sender's and a receiver's CNode. C14
    // calls it from the IPC path.
    let mut sc = Scratch::new(16);
    let transit = sc.make(ObjectType::Endpoint);
    let badged = sc.take();
    assert_eq!(
        mint(transit, badged, Rights::ALL, MintData::Badge(77)),
        Ok(())
    );
    let frames: [SlotRef; 3] = core::array::from_fn(|_| sc.make(ObjectType::Frame4K));
    let other = sc.make(ObjectType::Endpoint);
    let recv_cnode = sc.make(ObjectType::CNode(3));
    let r = |i| in_cnode(recv_cnode, i);
    let tp = base(transit);
    let three = frames.map(|f| sc.addr_of(f));

    // Without grant, nothing moves and nothing unwraps.
    let t = transfer(&sender(&three, false, tp), &[r(0), r(1), r(2)]);
    assert_eq!(t, Transferred::default());
    // A name that resolves to nothing moves nothing.
    let t = transfer(&sender(&[three[0], sc.addr(100)], true, tp), &[r(0), r(1)]);
    assert_eq!(t, Transferred::default());
    assert!(cap(r(0)).is_null());

    // Three capabilities, each a child of the sender's.
    let t = transfer(&sender(&three, true, tp), &[r(0), r(1), r(2)]);
    assert_eq!((t.count, t.unwrapped), (3, 0));
    for i in 0..3 {
        assert_eq!(cap(r(i)), cap(frames[i as usize]));
        assert_eq!(
            mdb::first_child(&DirectSlots, frames[i as usize]),
            Some(r(i))
        );
    }
    // A fourth name is ignored: at most three per message.
    let four = [three[0], three[1], three[2], sc.addr_of(other)];
    let t = transfer(&sender(&four, true, tp), &[r(3), r(4), r(5), r(6)]);
    assert_eq!(t.count, 3);
    assert!(cap(r(6)).is_null());

    // The badged transit endpoint is unwrapped in its position, reports its
    // badge and fills no slot.
    let t = transfer(
        &sender(
            &[sc.addr_of(other), sc.addr_of(badged), sc.addr_of(frames[0])],
            true,
            tp,
        ),
        &[r(7)],
    );
    assert_eq!(
        t,
        Transferred {
            count: 2,
            unwrapped: 0b10,
            badges: [0, 77, 0]
        }
    );
    assert_eq!(cap(r(7)), cap(other));
    // An occupied receive slot stops it.
    let t = transfer(&sender(&[sc.addr_of(other)], true, tp), &[r(7)]);
    assert_eq!(t.count, 0);
    // So does untyped memory with children, which can't be derived.
    let piece = sc.make(ObjectType::Untyped(12));
    sc.make_from(piece, ObjectType::Endpoint);
    let fresh = sc.make(ObjectType::CNode(2));
    let t = transfer(
        &sender(&[sc.addr_of(frames[0]), sc.addr_of(piece)], true, tp),
        &[in_cnode(fresh, 0), in_cnode(fresh, 1)],
    );
    assert_eq!(t.count, 1);
    assert!(cap(in_cnode(fresh, 1)).is_null());

    // Revoking the sender's capability reaches what was transferred.
    revoke(frames[1]);
    assert!(cap(r(1)).is_null() && cap(r(4)).is_null());
    verify(&sc, &[slots_of(recv_cnode), slots_of(fresh)]);
    sc.finish();
});

crate::kernel_test!(identify_reports_kind_and_rights, {
    // ADR 0047, rule 3: identify reads a capability's kind and rights, and
    // nothing else: no badge, no address, no ID (ADR 0050, rule 1).
    let mut sc = Scratch::with_device(17);
    let cn = sc.make(ObjectType::CNode(2));
    let fr = sc.make(ObjectType::Frame4K);
    let asp = sc.make(ObjectType::AddressSpace);
    let ep = sc.make(ObjectType::Endpoint);
    let dfr = sc.make_from(sc.dev(), ObjectType::Frame4K);
    for (s, kind) in [
        (sc.ram, Kind::Untyped),
        (sc.dev(), Kind::Untyped),
        (cn, Kind::CNode),
        (dfr, Kind::Frame),
    ] {
        let rights = if kind == Kind::Frame {
            Rights::ALL
        } else {
            Rights::NONE
        };
        assert_eq!(identify(s), (kind, rights));
    }
    // Every subset of the four rights, through mint.
    let c = sc.take();
    for bits in 0..16 {
        let want = Rights::from_bits(bits);
        for (s, kind) in [
            (fr, Kind::Frame),
            (asp, Kind::AddressSpace),
            (ep, Kind::Endpoint),
        ] {
            assert_eq!(mint(s, c, want, MintData::None), Ok(()));
            assert_eq!(identify(c), (kind, want));
            delete(c);
        }
    }
    // Two endpoint copies that differ only in their badge identify alike.
    let (b1, b2) = (sc.take(), sc.take());
    assert_eq!(mint(ep, b1, Rights::READ, MintData::Badge(1)), Ok(()));
    assert_eq!(mint(ep, b2, Rights::READ, MintData::Badge(2)), Ok(()));
    assert_eq!(identify(b1), identify(b2));
    // A binding is a frame capability with the rights it was mapped with.
    let ro = sc.take();
    assert_eq!(mint(fr, ro, Rights::READ, MintData::None), Ok(()));
    assert_eq!(map(ro, asp, VA, RO, sc.ram), Ok(()));
    let binding = mdb::first_child(&DirectSlots, ro).expect("no binding");
    assert_eq!(identify(binding), (Kind::Frame, Rights::READ));
    // A zombie, a deletion in progress, names nothing: like an empty slot.
    let full = sc.make(ObjectType::CNode(2));
    for i in 0..4 {
        assert_eq!(copy(ep, in_cnode(full, i)), Ok(()));
    }
    assert_eq!(
        delete_with(full, &mut Budget::with_threshold(Always, 1)),
        Err(Preempted)
    );
    assert!(matches!(cap(full), Cap::Zombie { .. }));
    assert_eq!(identify(full), (Kind::Null, Rights::NONE));
    delete(full);
    assert_eq!(identify(full), (Kind::Null, Rights::NONE));
    verify(&sc, &[slots_of(asp)]);
    sc.finish();
});

crate::kernel_test!(boot_cnodes_are_never_destroyed, {
    // ADR 0048, rule 2: the kernel keeps each boot CNode's original
    // capability where no lookup reaches, and the root CNode holds copies.
    // Deleting a copy finishes nothing, and the copy can be made again.
    let originals = 1 + UNTYPED_CNODES as u64;
    for i in 0..originals {
        let o = read(boot::original(i));
        assert!(matches!(o.cap, Cap::CNode { .. }), "original {i}: {o:x?}");
        assert_eq!((o.depth, o.prev), (0, None));
    }
    assert_eq!(cap(boot::original(0)), boot::root());
    let root_copy = boot::root_slot(ROOT_SELF);
    let first_ut = boot::root_slot(FIRST_UNTYPED_CNODE);
    assert_eq!(
        mdb::first_child(&DirectSlots, boot::original(0)),
        Some(root_copy)
    );
    assert_eq!(
        mdb::first_child(&DirectSlots, boot::original(1)),
        Some(first_ut)
    );
    let fin = finished();
    let (root_cap, ut_cap) = (cap(root_copy), cap(first_ut));
    for (o, s) in [(0, root_copy), (1, first_ut)] {
        revoke(s);
        delete(s);
        assert!(cap(s).is_null());
        assert_eq!(finished(), fin, "deleting a boot CNode's copy destroyed it");
        assert_eq!(copy(boot::original(o), s), Ok(()));
    }
    assert_eq!((cap(root_copy), cap(first_ut)), (root_cap, ut_cap));
    let mut pieces = 0;
    boot::for_each_untyped(|_, _| pieces += 1);
    assert_eq!(pieces, crate::mm::report().untyped_caps);
    assert_eq!(mdb::verify(&DirectSlots, boot_slots()), Ok(()));
    verify_zombies(boot_slots());
});

crate::kernel_test!(a_swept_zombie_is_finished_where_it_waits, {
    // O and P from U, E from V. O's park slot holds a copy of E, and its
    // last slot P's only capability. O's deletion makes P a zombie and
    // stops; two more units, as a revoke reaching P might take, sweep P to
    // n = 0. O's deletion must then finish P where it is: deferring it
    // would leave the copy of E in P's finished memory.
    let mut sc = Scratch::new(18);
    let u = sc.make(ObjectType::Untyped(16));
    let v = sc.make(ObjectType::Untyped(16));
    let o = sc.make_from(u, ObjectType::CNode(2));
    let p = sc.make_from(u, ObjectType::CNode(1));
    let e = sc.make_from(v, ObjectType::Endpoint);
    let arrays = [slots_of(o), slots_of(p)];
    assert_eq!(copy(e, in_cnode(o, 0)), Ok(()));
    let o3 = in_cnode(o, 3);
    assert_eq!(move_cap(p, o3), Ok(()));
    let fin = finished();
    let mut b = Budget::with_threshold(Always, 1);
    assert_eq!(delete_with(o, &mut b), Err(Preempted));
    assert_eq!(delete_with(o, &mut b), Err(Preempted));
    assert!(matches!(cap(o3), Cap::Zombie { n: 2, .. }));
    delete::delete_unit(&mut DirectSlots, &mut KernelHooks, o3);
    delete::delete_unit(&mut DirectSlots, &mut KernelHooks, o3);
    assert!(matches!(cap(o3), Cap::Zombie { n: 0, .. }));
    verify(&sc, &arrays);
    delete(o);
    assert_eq!(finished() - fin, 2);
    assert!(!mdb::has_children(&DirectSlots, e));
    revoke(u);
    assert_eq!(reset_with(u, &mut budget()), Ok(()));
    verify(&sc, &[]);
    sc.finish();
});

crate::kernel_test!(unmap_takes_copies_of_the_mapping_with_it, {
    // A copy derived from a mapping's binding goes with the mapping when it
    // is unmapped (kernel specification K42); a copy of the frame itself
    // stays.
    let mut sc = Scratch::new(17);
    let s = sc.make(ObjectType::AddressSpace);
    let f = sc.make(ObjectType::Frame4K);
    assert_eq!(map(f, s, VA, RO, sc.ram), Ok(()));
    let binding = mdb::first_child(&DirectSlots, f).expect("no binding");
    let (from_binding, from_frame) = (sc.take(), sc.take());
    assert_eq!(copy(binding, from_binding), Ok(()));
    assert_eq!(copy(f, from_frame), Ok(()));
    let unb = unbound();
    assert_eq!(unmap(s, VA, PAGE_SIZE), Ok(1));
    assert_eq!(unbound() - unb, 1);
    assert!(cap(binding).is_null() && cap(from_binding).is_null());
    assert_eq!(identify(from_frame), (Kind::Frame, Rights::ALL));
    // A plain delete of a binding leaves what derives from it under the
    // frame, and a sibling's revoke doesn't reach it.
    assert_eq!(map(from_frame, s, VA, RO, sc.ram), Ok(()));
    let binding = mdb::first_child(&DirectSlots, from_frame).expect("no binding");
    let kept = sc.take();
    assert_eq!(copy(binding, kept), Ok(()));
    let other = sc.take();
    assert_eq!(copy(f, other), Ok(()));
    delete(from_frame);
    revoke(other);
    assert_eq!(identify(kept), (Kind::Frame, Rights::ALL));
    assert!(
        !cap(binding).is_null(),
        "a sibling's revoke unmapped the frame"
    );
    revoke(f);
    assert!(cap(kept).is_null() && cap(binding).is_null());
    verify(&sc, &[slots_of(s)]);
    sc.finish();
});
