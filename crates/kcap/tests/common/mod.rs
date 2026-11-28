// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Helpers shared by the tests: fake slot memory, hooks that record what
//! they are asked to do, a small world with a boot capability space, the
//! three ways of preempting, a consistency check, and a fixed-seed
//! pseudo-random generator.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use kcap::SlotRef;
use kcap::cap::{Binding, Cap, SlotArray, ZombieKind};
use kcap::delete::{self, Hooks};
use kcap::mdb;
use kcap::ops::{self, Error};
use kcap::preempt::{Budget, Pending, Preempted};
use kcap::slot::{self, Mem};
use kmem::untyped::ObjectType;

/// Sparse slot memory: slots never written read as empty. It panics on a
/// misaligned slot, as the kernel would on corrupt memory.
#[derive(Default, Clone)]
pub struct FakeMem {
    slots: BTreeMap<u64, [u64; 4]>,
    /// Every range a reset cleared, in order.
    pub cleared: Vec<(u64, u64)>,
    /// Ranges that hold no slots, such as an endpoint's or an eventcount's
    /// words (C14): reading or writing a slot there panics, so a test sees
    /// any deletion that treats a queue object's words as slots.
    pub poisoned: BTreeMap<u64, u64>,
}

impl FakeMem {
    fn check_poison(&self, s: SlotRef) {
        if let Some((&b, &l)) = self.poisoned.range(..=s.0).next_back()
            && s.0 - b < l
        {
            panic!(
                "slot {:#x} lies in the object at {b:#x}+{l:#x}, which has no slots",
                s.0
            );
        }
    }

    /// Marks `[base, base + len)` as holding no slots.
    pub fn poison(&mut self, base: u64, len: u64) {
        self.poisoned.insert(base, len);
    }

    /// Every slot that holds something.
    pub fn full(&self) -> Vec<SlotRef> {
        self.slots.keys().map(|&a| SlotRef(a)).collect()
    }

    /// The raw words of every full slot, to compare end states.
    pub fn snapshot(&self) -> BTreeMap<u64, [u64; 4]> {
        self.slots.clone()
    }
}

impl Mem for FakeMem {
    fn read(&self, s: SlotRef) -> [u64; 4] {
        assert_eq!(s.0 % 32, 0, "slot {:#x} misaligned", s.0);
        self.check_poison(s);
        self.slots.get(&s.0).copied().unwrap_or_default()
    }

    fn write(&mut self, s: SlotRef, w: [u64; 4]) {
        assert_eq!(s.0 % 32, 0, "slot {:#x} misaligned", s.0);
        self.check_poison(s);

        if w == [0; 4] {
            self.slots.remove(&s.0);
        } else {
            self.slots.insert(s.0, w);
        }
    }

    fn clear(&mut self, pa: u64, len: u64) {
        assert_eq!(pa % 4096, 0);
        assert_eq!(len % 32, 0);
        let gone: Vec<u64> = self.slots.range(pa..pa + len).map(|(&a, _)| a).collect();
        for a in gone {
            self.slots.remove(&a);
        }
        // The memory may be retyped into anything now.
        self.poisoned.retain(|&b, _| !(b >= pa && b - pa < len));

        self.cleared.push((pa, len));
    }

    fn corrupt(&self, s: SlotRef) -> ! {
        panic!("corrupt slot {:#x}: {:x?}", s.0, self.read(s))
    }
}

/// An object's identity for the tests: its kind, base and size.
pub type ObjKey = (u8, u64, u64);

/// The identity of the object a capability or zombie names.
pub fn key(cap: &Cap) -> ObjKey {
    let code = match cap {
        Cap::Untyped { .. } => 1,
        Cap::CNode { .. }
        | Cap::Zombie {
            kind: ZombieKind::CNode { .. },
            ..
        } => 2,
        Cap::Frame { .. } => 3,
        Cap::AddressSpace { .. }
        | Cap::Zombie {
            kind: ZombieKind::AddressSpace,
            ..
        } => 4,
        Cap::Thread { .. }
        | Cap::Zombie {
            kind: ZombieKind::Thread,
            ..
        } => 6,
        Cap::SchedContext { .. } => 7,
        Cap::SchedControl { core } => return (8, *core as u64, 0),
        Cap::Reply { .. } => 9,
        Cap::Endpoint { .. }
        | Cap::Zombie {
            kind: ZombieKind::Endpoint,
            ..
        } => 5,
        Cap::Eventcount { .. }
        | Cap::Zombie {
            kind: ZombieKind::Eventcount,
            ..
        } => 10,
        Cap::WaitSet { .. }
        | Cap::Zombie {
            kind: ZombieKind::WaitSet { .. },
            ..
        } => 11,
        Cap::Null => 0,
    };
    let (base, size) = cap.object().unwrap_or((0, 0));
    (code, base, size)
}

/// Hooks that record each call, and check that every object made is
/// finished exactly once.
#[derive(Default, Clone)]
pub struct Log {
    /// Every finish, in order.
    pub finished: Vec<Cap>,
    /// Every unbind, in order.
    pub unbound: Vec<(SlotRef, Cap)>,
    /// Every object made a zombie, in order (C12).
    pub zombified: Vec<Cap>,
    /// Every hook call, in order: 'z' zombify, 'u' unbind, 'f' finish, 'd'
    /// a drain step that released a waiter.
    pub order: Vec<char>,
    /// Objects made and not yet finished.
    pub live: BTreeSet<ObjKey>,
    /// Waiters still queued on each endpoint or eventcount, by address
    /// (C14): each drain step releases one.
    pub waiters: BTreeMap<u64, u64>,
    /// Drain steps that released a waiter.
    pub drained: u64,
    /// The units each wait set's zombify reports, by address: 1 plus the
    /// entries it unlinks (C14).
    pub zombify_units: BTreeMap<u64, u32>,
    /// The units each finish reports, by object address: more than 1 for a
    /// take-back that ends a holder's wait (C14). 1 if absent.
    pub finish_units: BTreeMap<u64, u32>,
    /// The units each binding's unbind reports, by the address of the
    /// object it names. 1 if absent.
    pub unbind_units: BTreeMap<u64, u32>,
}

impl Hooks for Log {
    fn finish(&mut self, cap: &Cap) -> u32 {
        let k = key(cap);
        assert!(
            self.live.remove(&k),
            "finished {cap:x?}, which isn't live: finished twice, or never made"
        );
        self.finished.push(*cap);
        self.order.push('f');
        let (base, _) = cap.object().unwrap_or((0, 0));
        self.finish_units.get(&base).copied().unwrap_or(1)
    }

    fn zombify(&mut self, cap: &Cap) -> u32 {
        assert!(
            cap.has_slots() || cap.has_queue(),
            "zombify of {cap:x?}, which has neither slots nor a queue"
        );
        self.zombified.push(*cap);
        self.order.push('z');
        let (base, _) = cap.object().unwrap_or((0, 0));
        self.zombify_units.get(&base).copied().unwrap_or(1)
    }

    fn drain(&mut self, zombie: &Cap) -> bool {
        let Cap::Zombie { kind, ptr, n: 1 } = *zombie else {
            panic!("drain of {zombie:x?}, which isn't a queue zombie with waiters");
        };
        assert!(kind.is_queue(), "drain of {zombie:x?}");
        assert!(
            self.live.contains(&key(zombie)),
            "drain of {zombie:x?}, which isn't live"
        );
        match self.waiters.get_mut(&ptr) {
            Some(w) if *w > 0 => {
                *w -= 1;
                self.drained += 1;
                self.order.push('d');
                *w == 0
            }
            _ => true,
        }
    }

    fn unbind(&mut self, slot: SlotRef, cap: &Cap) -> u32 {
        assert!(
            cap.is_binding(),
            "unbind of {cap:x?}, which isn't a binding"
        );
        match cap.binding() {
            // A frame's binding sits in a binding slot of an address-space
            // record.
            None => {
                let array = SlotArray::of_address_space(slot.0 & !0x1fff);
                assert!(array.contains(slot) && slot != array.park());
            }
            // A wait-set entry's copy sits in an entry's slot of its set,
            // which it finds from its own encoding (C14).
            Some(Binding::WaitSetEntry) => {
                let Cap::Eventcount { set_bits, .. } = *cap else {
                    panic!("an entry's binding isn't an eventcount: {cap:x?}");
                };
                let array = SlotArray::of_wait_set(slot.0 & !((1 << set_bits) - 1), set_bits);
                assert!(array.contains(slot) && slot != array.park(), "{cap:x?}");
            }
            // A thread's binding sits in its role's slot of the thread.
            Some(role) => {
                let array = SlotArray::of_thread(slot.0 & !0x7ff);
                assert_eq!(slot, array.slot(role.thread_slot()), "{cap:x?}");
            }
        }
        self.unbound.push((slot, *cap));
        self.order.push('u');
        let (base, _) = cap.object().unwrap_or((0, 0));
        self.unbind_units.get(&base).copied().unwrap_or(1)
    }
}

/// How a test preempts long operations.
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    /// Never.
    Never,
    /// At every check, after every unit.
    Every,
    /// At random checks, after every unit, from a seed.
    Random(u64),
}

pub const MODES: [Mode; 3] = [Mode::Never, Mode::Every, Mode::Random(0x5eed)];

/// A pending-interrupt source for a mode.
#[derive(Clone, Debug)]
pub struct Pend {
    mode: Mode,
    rng: Lcg,
}

impl Pending for Pend {
    fn pending(&mut self) -> bool {
        match self.mode {
            Mode::Never => false,
            Mode::Every => true,
            Mode::Random(_) => self.rng.below(3) == 0,
        }
    }
}

/// A budget for a mode: checks every unit, except when it never preempts.
pub fn budget(mode: Mode) -> Budget<Pend> {
    let rng = Lcg(match mode {
        Mode::Random(s) => s,
        _ => 0,
    });
    let p = Pend { mode, rng };
    match mode {
        Mode::Never => Budget::new(p),
        _ => Budget::with_threshold(p, 1),
    }
}

/// Where the tests put the boot root CNode: outside every untyped piece, as
/// the kernel's boot CNodes are.
pub const BOOT: u64 = 0x1000_0000;
/// The boot root CNode's radix: 256 slots.
pub const BOOT_RADIX: u8 = 8;
/// The RAM piece the tests make objects from.
pub const RAM: u64 = 0x4000_0000;
pub const RAM_BITS: u8 = 26;
/// A device piece.
pub const DEV: u64 = 0x0900_0000;
pub const DEV_BITS: u8 = 21;

/// Slot `i` of the boot root CNode.
pub fn sl(i: u64) -> SlotRef {
    SlotRef(BOOT).offset(i)
}

/// The boot root CNode's capability.
pub fn root() -> Cap {
    Cap::CNode {
        ptr: BOOT,
        radix: BOOT_RADIX,
        guard_size: 64 - BOOT_RADIX,
        guard: 0,
    }
}

/// The boot RAM piece's slot.
pub fn ram() -> SlotRef {
    sl(16)
}

/// The boot device piece's slot.
pub fn dev() -> SlotRef {
    sl(17)
}

/// A boot capability space: a root CNode of 256 slots, whose slot 1 holds
/// its own capability, slot 16 a RAM piece and slot 17 a device piece, all
/// roots of the tree. A 56-bit guard of zeros makes a slot's address its
/// index.
#[derive(Clone)]
pub struct World {
    pub mem: FakeMem,
    pub log: Log,
    pub root: Cap,
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

impl World {
    pub fn new() -> World {
        let root = root();
        let mut w = World {
            mem: FakeMem::default(),
            log: Log::default(),
            root,
        };
        let (s1, s16, s17) = (w.slot(1), w.ram(), w.dev());
        mdb::insert_root(&mut w.mem, s1, root);
        let ram = Cap::Untyped {
            base: RAM,
            bits: RAM_BITS,
            device: false,
            watermark: 0,
        };
        let dev = Cap::Untyped {
            base: DEV,
            bits: DEV_BITS,
            device: true,
            watermark: 0,
        };
        mdb::insert_root(&mut w.mem, s16, ram);
        mdb::insert_root(&mut w.mem, s17, dev);
        for c in [root, ram, dev] {
            w.log.live.insert(key(&c));
        }
        w
    }

    /// Slot `i` of the boot root CNode.
    pub fn slot(&self, i: u64) -> SlotRef {
        SlotRef(BOOT).offset(i)
    }

    pub fn ram(&self) -> SlotRef {
        self.slot(16)
    }

    pub fn dev(&self) -> SlotRef {
        self.slot(17)
    }

    pub fn cap(&self, s: SlotRef) -> Cap {
        slot::cap(&self.mem, s)
    }

    pub fn depth(&self, s: SlotRef) -> u16 {
        slot::read(&self.mem, s).depth
    }

    pub fn empty(&self, s: SlotRef) -> bool {
        slot::is_empty(&self.mem, s)
    }

    /// Retypes into the CNode `dest`, never preempted, and records the new
    /// objects as live.
    pub fn retype_into(
        &mut self,
        ut: SlotRef,
        ty: ObjectType,
        dest: Cap,
        first: u64,
        count: u64,
    ) -> Result<(), Error> {
        let mut b = budget(Mode::Never);
        ops::retype(&mut self.mem, ut, ty, &dest, first, count, &mut b)?;
        self.note_made(dest, first, count);
        Ok(())
    }

    /// Records the objects whose capabilities a retype just put in `dest`.
    pub fn note_made(&mut self, dest: Cap, first: u64, count: u64) {
        let Cap::CNode { ptr, .. } = dest else {
            panic!("not a CNode")
        };
        for i in first..first + count {
            let c = self.cap(SlotRef(ptr).offset(i));
            self.log.live.insert(key(&c));
            // An endpoint's or an eventcount's words are never slots.
            if c.has_queue()
                && let Some((b, l)) = c.object()
            {
                self.mem.poison(b, l);
            }
        }
    }

    /// Retypes into the boot root CNode.
    pub fn retype(
        &mut self,
        ut: SlotRef,
        ty: ObjectType,
        first: u64,
        count: u64,
    ) -> Result<(), Error> {
        self.retype_into(ut, ty, self.root, first, count)
    }

    /// Retypes one object into root slot `i`, and returns its slot.
    pub fn make(&mut self, ty: ObjectType, i: u64) -> SlotRef {
        let ut = self.ram();
        self.retype(ut, ty, i, 1)
            .unwrap_or_else(|e| panic!("retype {ty:?} into {i}: {e:?}"));
        self.slot(i)
    }

    /// Deletes a slot under a mode, restarting until it is done. Returns the
    /// number of restarts.
    pub fn delete_mode(&mut self, s: SlotRef, mode: Mode) -> usize {
        let mut b = budget(mode);
        let mut restarts = 0;
        while delete::delete(&mut self.mem, &mut self.log, s, &mut b) == Err(Preempted) {
            restarts += 1;
            assert!(restarts < 10_000_000, "delete never ends");
        }
        restarts
    }

    /// Revokes a slot under a mode, restarting until it is done. Returns the
    /// number of restarts.
    pub fn revoke_mode(&mut self, s: SlotRef, mode: Mode) -> usize {
        let mut b = budget(mode);
        let mut restarts = 0;
        while delete::revoke(&mut self.mem, &mut self.log, s, &mut b) == Err(Preempted) {
            restarts += 1;
            assert!(restarts < 10_000_000, "revoke never ends");
        }
        restarts
    }

    pub fn delete(&mut self, s: SlotRef) {
        self.delete_mode(s, Mode::Never);
    }

    pub fn revoke(&mut self, s: SlotRef) {
        self.revoke_mode(s, Mode::Never);
    }

    /// The consistency check, after every step of the random test:
    ///
    /// - the tree's links are sound ([`mdb::verify`]);
    /// - every zombie's object lies in a live untyped piece, and slots `n`
    ///   and up of a Zombie(o, n) are empty, but for the zombie's own slot,
    ///   so a zombie never leaves behind a slot it has already swept;
    /// - every full slot lies in the boot root CNode, or among the slots of
    ///   a CNode or address space that a capability or zombie still names,
    ///   so no slot of a finished object holds anything;
    /// - a frame's binding lies only in a binding slot of an address-space
    ///   record, a thread's binding only in its role's slot of a thread, and
    ///   a wait-set entry's only in an entry's slot of a wait set;
    /// - a queue zombie (C14) holds no slots, and nothing is ever read from
    ///   its object as a slot.
    pub fn check(&self) {
        let full = self.mem.full();
        if let Err(e) = mdb::verify(&self.mem, full.iter().copied()) {
            panic!("tree broken: {e:?}");
        }
        let caps: Vec<(SlotRef, Cap)> = full.iter().map(|&s| (s, self.cap(s))).collect();
        let pieces: Vec<(u64, u64)> = caps
            .iter()
            .filter_map(|(_, c)| match c {
                Cap::Untyped { .. } => c.object(),
                _ => None,
            })
            .collect();
        // (base, count, kind): 0 a CNode, 1 an address-space record, 2 a
        // thread, 3 a wait set.
        let mut arrays: Vec<(u64, u64, u8)> = vec![(BOOT, 1 << BOOT_RADIX, 0)];
        for (s, c) in &caps {
            if let Cap::Zombie { kind, ptr, n } = c {
                let (b, _) = c.object().unwrap_or((0, 0));
                assert!(
                    pieces.iter().any(|&(pb, ps)| b >= pb && b - pb < ps) || *ptr == BOOT,
                    "zombie at {:#x} lies in no untyped piece",
                    s.0
                );
                let Some(a) = SlotArray::of(*kind, *ptr) else {
                    assert!(kind.is_queue() && *n <= 1, "{c:x?}");
                    continue;
                };
                for i in *n..a.count {
                    let x = a.slot(i);
                    assert!(
                        x == *s || self.empty(x),
                        "zombie {c:x?} at {:#x} has swept slot {i} ({:#x}), which holds {:x?}",
                        s.0,
                        x.0,
                        self.cap(x)
                    );
                }
                let k = match kind {
                    ZombieKind::CNode { .. } => 0,
                    ZombieKind::AddressSpace => 1,
                    ZombieKind::Thread => 2,
                    ZombieKind::WaitSet { .. } => 3,
                    ZombieKind::Endpoint | ZombieKind::Eventcount => continue,
                };
                arrays.push((a.base, a.count, k));
            }
            if let Cap::CNode { ptr, radix, .. } = c {
                arrays.push((*ptr, 1 << radix, 0));
            }
            if let Cap::AddressSpace { base, .. } = c {
                let a = SlotArray::of_address_space(*base);
                arrays.push((a.base, a.count, 1));
            }
            if let Cap::Thread { ptr, .. } = c {
                let a = SlotArray::of_thread(*ptr);
                arrays.push((a.base, a.count, 2));
            }
            if let Cap::WaitSet { ptr, bits, .. } = c {
                let a = SlotArray::of_wait_set(*ptr, *bits);
                arrays.push((a.base, a.count, 3));
            }
        }
        arrays.sort();
        arrays.dedup();
        for (s, c) in &caps {
            let home = arrays
                .iter()
                .find(|&&(b, n, _)| s.0 >= b && s.0 - b < n * 32)
                .unwrap_or_else(|| panic!("slot {:#x} ({c:x?}) lies in no live object", s.0));
            if c.is_binding() {
                match c.binding() {
                    None => {
                        assert_eq!(home.2, 1, "binding at {:#x} isn't in an address space", s.0)
                    }
                    Some(Binding::WaitSetEntry) => {
                        assert_eq!(home.2, 3, "entry {c:x?} isn't in a wait set")
                    }

                    Some(role) => assert_eq!(
                        (home.2, s.0),
                        (2, home.0 + role.thread_slot() * 32),
                        "binding {c:x?} isn't in its slot of a thread"
                    ),
                }
                assert_ne!(s.0, home.0, "binding at {:#x} is in a park slot", s.0);
            }
        }
    }

    /// The descendants of a slot, in list order.
    pub fn descendants(&self, s: SlotRef) -> Vec<SlotRef> {
        let a = slot::read(&self.mem, s);
        let mut out = Vec::new();
        let mut at = a.next;
        while let Some(x) = at {
            let b = slot::read(&self.mem, x);
            if !mdb::derives_from(&a, &b) {
                break;
            }
            out.push(x);
            at = b.next;
        }
        out
    }
}

/// A fixed-seed pseudo-random generator, as kmem's tests use.
#[derive(Clone, Debug)]
pub struct Lcg(pub u64);

impl Lcg {
    pub fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 11
    }

    /// A value in `[0, n)`.
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}
