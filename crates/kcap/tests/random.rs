// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Random capability spaces: a seeded generator makes objects, copies,
//! mints, moves (nesting CNodes, cycles included), mappings and wait-set
//! entries, and interleaves deletes and revokes, some left partway as a
//! preemption would leave them. Endpoints and eventcounts get waiters, so
//! their deletion drains queue zombies (C14). The tree is checked after
//! every step. At the end, revoking the pieces finishes everything, each
//! object exactly once, and releases every waiter exactly once.

mod common;

use common::{Lcg, Mode, World, budget, ram, root, sl};
use kcap::SlotRef;
use kcap::cap::{Cap, Mapping, SlotArray};
use kcap::delete;
use kcap::mdb;
use kcap::ops::{self, Error, MintData};
use kcap::rights::Rights;
use kmem::untyped::ObjectType;

const PIECES: [u64; 4] = [20, 21, 22, 23];

/// Slots a holder could name: the root CNode's free part, and every slot of
/// every CNode that a capability (not a zombie) still names.
fn reachable(w: &World) -> Vec<SlotRef> {
    let mut nodes = vec![root()];
    for s in w.mem.full() {
        let c = w.cap(s);
        if matches!(c, Cap::CNode { .. }) && !nodes.contains(&c) {
            nodes.push(c);
        }
    }
    let mut out = Vec::new();
    for n in nodes {
        let Cap::CNode { ptr, radix, .. } = n else {
            continue;
        };
        let first = if ptr == common::BOOT { 32 } else { 0 };
        for i in first..1u64 << radix {
            out.push(SlotRef(ptr).offset(i));
        }
    }
    out.sort();
    out.dedup();
    out
}

fn pick<T: Copy>(rng: &mut Lcg, v: &[T]) -> Option<T> {
    (!v.is_empty()).then(|| v[rng.below(v.len() as u64) as usize])
}

/// The CNode capability whose slots include `s`, and the index.
fn home(w: &World, s: SlotRef) -> Option<(Cap, u64)> {
    let mut nodes = vec![root()];
    nodes.extend(w.mem.full().into_iter().map(|x| w.cap(x)));
    nodes.into_iter().find_map(|c| match c {
        Cap::CNode { ptr, radix, .. } if s.0 >= ptr && s.0 - ptr < 32 << radix => {
            Some((c, (s.0 - ptr) / 32))
        }
        _ => None,
    })
}

fn run(seed: u64, steps: usize) {
    let mut rng = Lcg(seed);
    let mut w = World::new();
    for &i in &PIECES {
        w.retype(ram(), ObjectType::Untyped(20), i, 1).unwrap();
    }
    let base_live = w.log.live.len();
    let mut made = 0;
    let mut bound = 0;
    let mut waiters = 0;
    for step in 0..steps {
        let slots = reachable(&w);
        let full: Vec<SlotRef> = slots.iter().copied().filter(|&s| !w.empty(s)).collect();
        let empty: Vec<SlotRef> = slots.iter().copied().filter(|&s| w.empty(s)).collect();
        let op = rng.below(100);
        match op {
            // Make an object from a piece or a child piece.
            0..=29 => {
                let uts: Vec<SlotRef> = w
                    .mem
                    .full()
                    .into_iter()
                    .filter(|&s| matches!(w.cap(s), Cap::Untyped { device: false, .. }))
                    .filter(|&s| s != ram())
                    .collect();
                let (Some(ut), Some(dst)) = (pick(&mut rng, &uts), pick(&mut rng, &empty)) else {
                    continue;
                };
                let ty = match rng.below(9) {
                    0 | 1 => ObjectType::Endpoint,
                    2 => ObjectType::CNode(1 + rng.below(3) as u8),
                    3 => ObjectType::AddressSpace,
                    4 | 5 => ObjectType::Frame4K,
                    6 => ObjectType::Eventcount,
                    7 => ObjectType::WaitSet(7 + rng.below(3) as u8),
                    _ => ObjectType::Untyped(12 + rng.below(3) as u8),
                };
                let Some((cn, idx)) = home(&w, dst) else {
                    continue;
                };
                match w.retype_into(ut, ty, cn, idx, 1) {
                    Ok(()) => {
                        made += 1;
                        // Threads queued on an endpoint or an eventcount,
                        // which its deletion releases one by one.
                        let c = w.cap(dst);
                        if c.has_queue() {
                            let k = rng.below(5);
                            w.log.waiters.insert(c.object().unwrap().0, k);
                            waiters += k;
                        }
                    }
                    Err(Error::Retype(_)) | Err(Error::NotDerivable) => {}
                    Err(e) => panic!("step {step}: retype {ty:?}: {e:?}"),
                }
            }
            // Copy or mint.
            30..=49 => {
                let (Some(src), Some(dst)) = (pick(&mut rng, &full), pick(&mut rng, &empty)) else {
                    continue;
                };
                let rights = Rights::from_bits(rng.below(16) as u8);
                let data = match w.cap(src) {
                    Cap::Endpoint { badge: 0, .. } if rng.below(2) == 0 => {
                        MintData::Badge(1 + rng.below(4))
                    }
                    _ => MintData::None,
                };
                match ops::mint(&mut w.mem, src, dst, rights, data) {
                    Ok(()) | Err(Error::NotDerivable) => {}
                    Err(e) => panic!("step {step}: mint: {e:?}"),
                }
            }
            // Move, which nests CNodes and makes cycles.
            50..=61 => {
                let (Some(src), Some(dst)) = (pick(&mut rng, &full), pick(&mut rng, &empty)) else {
                    continue;
                };
                match ops::move_cap(&mut w.mem, src, dst) {
                    Ok(()) | Err(Error::NotDerivable) => {}
                    Err(e) => panic!("step {step}: move: {e:?}"),
                }
            }
            // Add a wait-set entry: a copy of an eventcount in one of the
            // set's entry slots (C14).
            62..=65 => {
                let ecs: Vec<SlotRef> = full
                    .iter()
                    .copied()
                    .filter(|&s| matches!(w.cap(s), Cap::Eventcount { .. }))
                    .collect();
                let sets: Vec<(u64, u8)> = full
                    .iter()
                    .filter_map(|&s| match w.cap(s) {
                        Cap::WaitSet { ptr, bits, .. } => Some((ptr, bits)),
                        _ => None,
                    })
                    .collect();
                let (Some(e), Some((ptr, bits))) = (pick(&mut rng, &ecs), pick(&mut rng, &sets))
                else {
                    continue;
                };
                let a = SlotArray::of_wait_set(ptr, bits);
                let dst = a.slot(1 + rng.below(a.count - 1));
                match ops::bind_entry(&mut w.mem, e, dst, bits) {
                    Ok(_) => bound += 1,
                    Err(Error::DestNotEmpty) => {}
                    Err(e) => panic!("step {step}: entry: {e:?}"),
                }
            }
            // Map a frame into an address space.
            66..=71 => {
                let frames: Vec<SlotRef> = full
                    .iter()
                    .copied()
                    .filter(|&s| matches!(w.cap(s), Cap::Frame { .. }))
                    .collect();
                let spaces: Vec<SlotRef> = full
                    .iter()
                    .copied()
                    .filter(|&s| matches!(w.cap(s), Cap::AddressSpace { .. }))
                    .collect();
                let (Some(f), Some(a)) = (pick(&mut rng, &frames), pick(&mut rng, &spaces)) else {
                    continue;
                };
                let m = Mapping {
                    va: rng.below(1 << 20) << 12,
                    write: false,
                    exec: rng.below(2) == 0,
                };
                match ops::bind_mapping(&mut w.mem, f, a, m) {
                    Ok(_) => bound += 1,
                    Err(Error::MissingRight) | Err(Error::NoBindingSlot) => {}
                    Err(Error::BadMapping) => {}
                    Err(e) => panic!("step {step}: map: {e:?}"),
                }
            }
            // Delete or revoke, to the end or partway.
            _ => {
                let Some(s) = pick(&mut rng, &full) else {
                    continue;
                };
                let revoke = op >= 86;
                let partial = rng.below(4) == 0;
                if partial {
                    let mut b = budget(Mode::Every);
                    for _ in 0..1 + rng.below(20) {
                        let _ = if revoke {
                            delete::revoke(&mut w.mem, &mut w.log, s, &mut b)
                        } else {
                            delete::delete(&mut w.mem, &mut w.log, s, &mut b)
                        };
                    }
                } else {
                    let mode = Mode::Random(rng.next());
                    if revoke {
                        w.revoke_mode(s, mode);
                        assert!(!mdb::has_children(&w.mem, s) || w.empty(s));
                    } else {
                        w.delete_mode(s, mode);
                        assert!(w.empty(s), "step {step}: delete left {:x?}", w.cap(s));
                    }
                }
            }
        }
        w.check();
    }
    assert!(made > steps / 10, "only {made} objects made");
    // Revoking the pieces finishes everything made from them. Each revoke
    // is preempted at random, and the tree is checked at every restart.
    for &i in &PIECES {
        let mut b = budget(Mode::Random(seed ^ i));
        let mut restarts = 0;
        while delete::revoke(&mut w.mem, &mut w.log, sl(i), &mut b).is_err() {
            w.check();
            restarts += 1;
            assert!(restarts < 10_000_000, "revoke never ends");
        }
        w.check();
        assert!(!mdb::has_children(&w.mem, sl(i)));
    }
    assert_eq!(w.log.live.len(), base_live, "left alive: {:x?}", w.log.live);
    // Only the boot capabilities and the pieces are left, and each piece
    // resets and makes objects from its start.
    let left: Vec<SlotRef> = w.mem.full();
    assert_eq!(left.len(), 3 + PIECES.len(), "{left:x?}");
    for &i in &PIECES {
        let base = w.cap(sl(i)).object().unwrap().0;
        w.retype(sl(i), ObjectType::Frame4K, 40, 1).unwrap();
        assert_eq!(w.cap(sl(40)).object().unwrap().0, base);
        w.delete(sl(40));
    }
    // Every binding made was unbound exactly once, and every waiter
    // released exactly once.
    assert_eq!(w.log.unbound.len(), bound);
    assert_eq!(w.log.drained, waiters);
}

#[test]
fn random_spaces_stay_consistent_and_end_finished() {
    for seed in [1, 2, 3, 0xa5a5, 0xdead_beef] {
        run(seed, 1500);
    }
    // Seed 154 once stranded a capability in a finished object's park slot.
    for seed in (100..132).chain([154]) {
        run(seed, 3000);
    }
}

/// More seeds, for a longer run: `cargo test -p kcap --test random --
/// --ignored`. `KCAP_SEEDS=first..end` picks the seeds.
#[test]
#[ignore]
fn random_spaces_long_run() {
    let (first, end) = std::env::var("KCAP_SEEDS")
        .ok()
        .and_then(|v| {
            let (a, b) = v.split_once("..")?;
            Some((a.parse().ok()?, b.parse().ok()?))
        })
        .unwrap_or((100u64, 1000u64));
    for seed in first..end {
        run(seed, 3000);
    }
}
