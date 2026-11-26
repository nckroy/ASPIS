// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The derivation tree against a model kept apart from it: each capability's
//! true source, recorded when it is made. Revoking a capability must delete
//! exactly its descendants in the model, never a sibling's, even after the
//! capabilities between them were deleted. The holders here are slots: two
//! holders never touch each other's.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{Lcg, World, sl};
use kcap::SlotRef;
use kcap::cap::{Cap, Mapping, SlotArray};
use kcap::mdb;
use kcap::ops::{self, Error, MintData, copy, mint, move_cap};
use kcap::rights::Rights;
use kmem::untyped::ObjectType;

fn map(w: &mut World, frame: SlotRef, space: SlotRef, va: u64) -> Result<SlotRef, Error> {
    let m = Mapping {
        va,
        write: false,
        exec: false,
    };
    ops::bind_mapping(&mut w.mem, frame, space, m).map(|(s, _)| s)
}

#[test]
fn a_sibling_s_revoke_misses_copies_whose_source_was_deleted() {
    // Holder A gets a copy of E in 40 and copies it on into 42; holder B
    // gets its own copy in 41. A deletes 40. B's revoke of 41 must leave
    // A's copy in 42, which now sits under E.
    let mut w = World::new();
    let e = w.make(ObjectType::Endpoint, 32);
    copy(&mut w.mem, e, sl(40)).unwrap();
    copy(&mut w.mem, e, sl(41)).unwrap();
    copy(&mut w.mem, sl(40), sl(42)).unwrap();
    w.delete(sl(40));
    w.revoke(sl(41));
    assert!(!w.empty(sl(42)), "B's revoke deleted A's copy");
    assert!(w.descendants(sl(41)).is_empty());
    assert_eq!(w.descendants(e), [sl(41), sl(42)]);
    w.revoke(e);
    assert!(w.empty(sl(41)) && w.empty(sl(42)));
    w.check();
}

#[test]
fn a_sibling_s_revoke_misses_a_mapping_whose_frame_copy_was_deleted() {
    // A maps its copy of a frame and drops the copy; B revokes its own
    // copy. A's mapping stays until the frame itself is revoked.
    let mut w = World::new();
    let f = w.make(ObjectType::Frame4K, 32);
    let space = w.make(ObjectType::AddressSpace, 33);
    copy(&mut w.mem, f, sl(40)).unwrap();
    copy(&mut w.mem, f, sl(41)).unwrap();
    let b = map(&mut w, sl(40), space, 0x1000).unwrap();
    w.delete(sl(40));
    w.revoke(sl(41));
    assert!(w.log.unbound.is_empty(), "B's revoke unmapped A's mapping");
    assert!(!w.empty(b));
    w.revoke(f);
    assert_eq!(w.log.unbound.len(), 1);
    assert!(w.empty(b));
    w.check();
}

#[test]
fn a_sibling_s_revoke_misses_copies_under_the_same_badge() {
    // A manager keeps a badged copy K; two clients get copies of it. Client
    // one copies its copy on and drops the first. Client two's revoke must
    // not reach client one's copy; the manager's revoke of K does.
    let mut w = World::new();
    let e = w.make(ObjectType::Endpoint, 32);
    mint(&mut w.mem, e, sl(40), Rights::ALL, MintData::Badge(5)).unwrap();
    let k = sl(40);
    copy(&mut w.mem, k, sl(41)).unwrap();
    copy(&mut w.mem, k, sl(42)).unwrap();
    copy(&mut w.mem, sl(41), sl(43)).unwrap();
    w.delete(sl(41));
    w.revoke(sl(42));
    assert!(!w.empty(sl(43)), "client two's revoke reached client one");
    w.revoke(k);
    assert!(w.empty(sl(42)) && w.empty(sl(43)));
    w.check();
}

#[test]
fn deleting_a_capability_whose_source_is_gone_keeps_the_barrier() {
    // E, then A in 40 with a chain 40 -> 41 -> 42, and B's sibling 43.
    // Deleting 40 and then 41 must leave 42 under E only, and B's 43 must
    // still reach nothing.
    let mut w = World::new();
    let e = w.make(ObjectType::Endpoint, 32);
    copy(&mut w.mem, e, sl(43)).unwrap();
    copy(&mut w.mem, e, sl(40)).unwrap();
    copy(&mut w.mem, sl(40), sl(41)).unwrap();
    copy(&mut w.mem, sl(41), sl(42)).unwrap();
    copy(&mut w.mem, sl(43), sl(44)).unwrap();
    w.delete(sl(41));
    w.delete(sl(40));
    assert_eq!(w.descendants(sl(43)), [sl(44)]);
    w.revoke(sl(43));
    assert!(!w.empty(sl(42)) && w.empty(sl(44)));
    assert_eq!(w.descendants(e), [sl(42), sl(43)]);
}

#[test]
fn an_address_space_holds_126_mappings_and_refuses_the_127th() {
    let mut w = World::new();
    let f = w.make(ObjectType::Frame4K, 32);
    let space = w.make(ObjectType::AddressSpace, 33);
    let mut bindings = BTreeSet::new();
    for i in 1..=126u64 {
        bindings.insert(map(&mut w, f, space, i << 12).unwrap());
    }
    assert_eq!(bindings.len(), 126);
    let before = w.mem.snapshot();
    assert_eq!(map(&mut w, f, space, 127 << 12), Err(Error::NoBindingSlot));
    assert_eq!(
        w.mem.snapshot(),
        before,
        "a refused mapping changed the tree"
    );
    w.revoke(f);
    assert_eq!(w.log.unbound.len(), 126);
    let unbound: BTreeSet<SlotRef> = w.log.unbound.iter().map(|&(s, _)| s).collect();
    assert_eq!(unbound, bindings, "a binding was unbound twice, or never");
    let array = SlotArray::of_address_space(w.cap(space).object().unwrap().0);
    for i in 0..array.count {
        assert!(w.empty(array.slot(i)));
    }
    w.check();
}

/// The model: each tracked slot's true source, or `None` for an object's
/// first capability, which derives from untyped memory the test never
/// revokes.
#[derive(Default)]
struct Model {
    parent: BTreeMap<SlotRef, Option<SlotRef>>,
}

impl Model {
    fn descendants(&self, r: SlotRef) -> BTreeSet<SlotRef> {
        let mut out = BTreeSet::new();
        let mut todo = vec![r];
        while let Some(x) = todo.pop() {
            for (&c, &p) in &self.parent {
                if p == Some(x) && out.insert(c) {
                    todo.push(c);
                }
            }
        }
        out
    }

    fn derive(&mut self, src: SlotRef, dst: SlotRef) {
        self.parent.insert(dst, Some(src));
    }

    fn moved(&mut self, src: SlotRef, dst: SlotRef) {
        let p = self.parent.remove(&src).flatten();
        self.parent.insert(dst, p);
        for v in self.parent.values_mut() {
            if *v == Some(src) {
                *v = Some(dst);
            }
        }
    }

    /// A deleted capability's children go to its parent.
    fn deleted(&mut self, s: SlotRef) {
        let p = self.parent.remove(&s).flatten();
        for v in self.parent.values_mut() {
            if *v == Some(s) {
                *v = p;
            }
        }
    }
}

fn run_model(seed: u64, steps: usize) {
    let mut rng = Lcg(seed);
    let mut w = World::new();
    let mut m = Model::default();
    let space = w.make(ObjectType::AddressSpace, 33);
    let array = SlotArray::of_address_space(w.cap(space).object().unwrap().0);
    // Three endpoints and two frames, in holder slots.
    for (i, ty) in [
        ObjectType::Endpoint,
        ObjectType::Endpoint,
        ObjectType::Endpoint,
        ObjectType::Frame4K,
        ObjectType::Frame4K,
    ]
    .into_iter()
    .enumerate()
    {
        let s = w.make(ty, 40 + i as u64);
        m.parent.insert(s, None);
    }
    let holders: Vec<SlotRef> = (40..100).map(sl).collect();
    for step in 0..steps {
        let mut slots: Vec<SlotRef> = holders.clone();
        slots.extend((1..array.count).map(|i| array.slot(i)));
        let full: Vec<SlotRef> = slots.iter().copied().filter(|&s| !w.empty(s)).collect();
        let empty: Vec<SlotRef> = holders.iter().copied().filter(|&s| w.empty(s)).collect();
        let pick = |rng: &mut Lcg, v: &[SlotRef]| {
            (!v.is_empty()).then(|| v[rng.below(v.len() as u64) as usize])
        };
        let (Some(src), Some(dst)) = (pick(&mut rng, &full), pick(&mut rng, &empty)) else {
            continue;
        };
        match rng.below(10) {
            0..=3 => {
                let data = match w.cap(src) {
                    Cap::Endpoint { badge: 0, .. } if rng.below(2) == 0 => {
                        MintData::Badge(1 + rng.below(3))
                    }
                    _ => MintData::None,
                };
                if mint(&mut w.mem, src, dst, Rights::ALL, data).is_ok() {
                    m.derive(src, dst);
                }
            }
            4 => {
                if move_cap(&mut w.mem, src, dst).is_ok() {
                    m.moved(src, dst);
                }
            }
            5 => {
                if matches!(w.cap(src), Cap::Frame { mapping: None, .. }) {
                    let va = (1 + rng.below(1 << 16)) << 12;
                    if let Ok(b) = map(&mut w, src, space, va) {
                        m.derive(src, b);
                    }
                }
            }
            6..=7 => {
                w.delete(src);
                m.deleted(src);
            }
            _ => {
                let expect = m.descendants(src);
                let before: BTreeMap<SlotRef, Cap> =
                    m.parent.keys().map(|&s| (s, w.cap(s))).collect();
                w.revoke(src);
                for (&s, &c) in &before {
                    if expect.contains(&s) {
                        assert!(w.empty(s), "seed {seed} step {step}: {:#x} survived", s.0);
                    } else {
                        assert_eq!(
                            w.cap(s),
                            c,
                            "seed {seed} step {step}: revoke of {:#x} reached {:#x}",
                            src.0,
                            s.0
                        );
                    }
                }
                for s in expect {
                    m.parent.remove(&s);
                }
            }
        }
        // Every tracked slot's run in the tree is its model subtree.
        for &s in m.parent.keys() {
            let got: BTreeSet<SlotRef> = w.descendants(s).into_iter().collect();
            assert_eq!(
                got,
                m.descendants(s),
                "seed {seed} step {step} at {:#x}",
                s.0
            );
        }
        let tracked: BTreeSet<SlotRef> = m.parent.keys().copied().collect();
        let held: BTreeSet<SlotRef> = full_now(&w, &slots);
        assert_eq!(tracked, held, "seed {seed} step {step}");
        w.check();
    }
    assert!(mdb::verify(&w.mem, w.mem.full().into_iter()).is_ok());
}

fn full_now(w: &World, slots: &[SlotRef]) -> BTreeSet<SlotRef> {
    slots.iter().copied().filter(|&s| !w.empty(s)).collect()
}

#[test]
fn revoke_deletes_exactly_the_model_s_descendants() {
    for seed in 1..40 {
        run_model(seed, 400);
    }
}
