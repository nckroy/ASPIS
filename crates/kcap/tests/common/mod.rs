// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Helpers shared by the tests: fake slot memory, hooks that record what
//! they are asked to do, a small world with a boot capability space, the
//! three ways of preempting, a consistency check, and a fixed-seed
//! pseudo-random generator.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use kcap::SlotRef;
use kcap::cap::{Cap, SlotArray, ZombieKind};
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
}

impl FakeMem {
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
        self.slots.get(&s.0).copied().unwrap_or_default()
    }

    fn write(&mut self, s: SlotRef, w: [u64; 4]) {
        assert_eq!(s.0 % 32, 0, "slot {:#x} misaligned", s.0);
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
        Cap::Endpoint { .. } => 5,
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
    /// Objects made and not yet finished.
    pub live: BTreeSet<ObjKey>,
}

impl Hooks for Log {
    fn finish(&mut self, cap: &Cap) {
        let k = key(cap);
        assert!(
            self.live.remove(&k),
            "finished {cap:x?}, which isn't live: finished twice, or never made"
        );
        self.finished.push(*cap);
    }

    fn unbind(&mut self, slot: SlotRef, cap: &Cap) {
        assert!(
            cap.is_binding(),
            "unbind of {cap:x?}, which isn't a binding"
        );
        // A binding sits in a binding slot of an address-space record.
        let array = SlotArray::of_address_space(slot.0 & !0x1fff);
        assert!(array.contains(slot) && slot != array.park());
        self.unbound.push((slot, *cap));
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
    /// - a binding lies only in a binding slot of an address-space record.
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
        let mut arrays: Vec<(u64, u64, bool)> = vec![(BOOT, 1 << BOOT_RADIX, false)];
        for (s, c) in &caps {
            if let Cap::Zombie { kind, ptr, n } = c {
                let (b, _) = c.object().unwrap_or((0, 0));
                assert!(
                    pieces.iter().any(|&(pb, ps)| b >= pb && b - pb < ps) || *ptr == BOOT,
                    "zombie at {:#x} lies in no untyped piece",
                    s.0
                );
                let a = SlotArray::of(*kind, *ptr);
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
                arrays.push((a.base, a.count, matches!(kind, ZombieKind::AddressSpace)));
            }
            if let Cap::CNode { ptr, radix, .. } = c {
                arrays.push((*ptr, 1 << radix, false));
            }
            if let Cap::AddressSpace { base, .. } = c {
                let a = SlotArray::of_address_space(*base);
                arrays.push((a.base, a.count, true));
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
                assert!(home.2, "binding at {:#x} isn't in an address space", s.0);
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
