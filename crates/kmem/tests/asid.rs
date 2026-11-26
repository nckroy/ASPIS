// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! ASIDs by generation rollover (ADR 0048, rule 4).
//!
//! QEMU's TLB can't show a stale translation after a rollover: writing
//! `TTBR0_EL1` with a new ASID flushes its whole software TLB. So the
//! rollover's correctness is checked here, against a model of which address
//! spaces can have TLB entries under which number.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::Lcg;
use kmem::asid::{AsidAllocator, MAX_CORES, asid_of};

/// A space's identity: the physical address of its record, never 0.
fn space(i: u64) -> u64 {
    0x4000_0000 + i * 0x2000
}

#[test]
fn rollover_comes_only_when_every_number_is_used() {
    let mut a = AsidAllocator::new(8);
    let mut words = vec![0u64; 300];
    let mut seen = BTreeSet::new();
    for (i, w) in words.iter_mut().enumerate().take(255) {
        let act = a.activate(0, space(i as u64), w);
        assert!(!act.flush_all, "rolled over at space {i}");
        assert_ne!(act.asid, 0, "ASID 0 handed out");
        assert!(seen.insert(act.asid), "ASID {} handed out twice", act.asid);
    }
    let before = a.generation();
    let act = a.activate(0, space(255), &mut words[255]);
    assert!(act.flush_all);
    assert_eq!(a.generation(), before + 1);
    assert_ne!(act.asid, 0);
}

#[test]
fn a_space_active_on_another_core_keeps_one_asid_across_a_rollover() {
    let mut a = AsidAllocator::new(8);
    let s = space(1);
    let mut ws = 0;
    let n = a.activate(1, s, &mut ws).asid;
    a.rollover();
    assert!(!a.is_current(ws), "the space's own word is still old");
    // Core 0 runs through many other spaces; none gets n.
    let mut others = vec![0u64; 600];
    for (i, w) in others.iter_mut().enumerate() {
        let act = a.activate(0, space(100 + i as u64), w);
        assert_ne!(act.asid, n, "space {i} got the number core 1 still runs");
    }
    // Activated anywhere, the space keeps its number, now current.
    let act = a.activate(0, s, &mut ws);
    assert_eq!(act.asid, n);
    assert!(a.is_current(ws));
}

#[test]
fn a_rollover_never_gives_the_current_cores_number_away() {
    let mut a = AsidAllocator::new(8);
    // Core 1 uses up 254 numbers; core 0 runs A under the last.
    let mut w = vec![0u64; 256];
    for (i, word) in w.iter_mut().enumerate().take(254) {
        a.activate(1, space(10 + i as u64), word);
    }
    let mut wa = 0;
    let na = a.activate(0, space(1), &mut wa).asid;
    let x = asid_of(w[253]).unwrap();
    // B on core 0 forces a rollover while A is still active there.
    let mut wb = 0;
    let act = a.activate(0, space(2), &mut wb);
    assert!(act.flush_all);
    assert_ne!(act.asid, na, "B got A's number");
    assert_ne!(act.asid, x, "B got the number core 1 runs");
    // And A, back on core 0 or anywhere, keeps its number.
    assert_eq!(a.activate(2, space(1), &mut wa).asid, na);
}

#[test]
fn a_space_whose_number_is_free_keeps_it() {
    let mut a = AsidAllocator::new(16);
    let mut w = 0;
    let n = a.activate(0, space(1), &mut w).asid;
    a.deactivate(0);
    a.rollover();
    assert!(!a.is_current(w));
    assert_eq!(a.activate(0, space(1), &mut w).asid, n);
    assert!(a.is_current(w));
}

#[test]
fn release_frees_the_number_only_in_its_generation() {
    let mut a = AsidAllocator::new(8);
    let mut w = vec![0u64; 256];
    for (i, word) in w.iter_mut().enumerate().take(255) {
        a.activate(0, space(i as u64), word);
    }
    a.deactivate(0);
    let n = asid_of(w[7]).unwrap();
    assert_eq!(a.release(space(7), w[7]), Some(n));
    // The freed number is taken without a rollover.
    let act = a.activate(0, space(1000), &mut w[255]);
    assert!(!act.flush_all);
    assert_eq!(act.asid, n);
    // A space that never had a number has nothing to invalidate.
    assert_eq!(a.release(space(2000), 0), None);
    // An old-generation word still names a number to invalidate.
    a.rollover();
    let m = asid_of(w[9]).unwrap();
    assert_eq!(a.release(space(9), w[9]), Some(m));
}

#[test]
fn the_width_follows_the_processor() {
    assert_eq!(AsidAllocator::new(16).bits(), 16);
    assert_eq!(AsidAllocator::new(8).bits(), 8);
    assert_eq!(AsidAllocator::new(4).bits(), 8);
    // 16-bit: 65,535 spaces before a rollover.
    let mut a = AsidAllocator::new(16);
    let mut last = 0;
    for i in 0..65_535 {
        let mut w = 0;
        let act = a.activate(0, space(i), &mut w);
        assert!(!act.flush_all);
        last = act.asid;
    }
    assert_eq!(last, 65_535);
    let mut w = 0;
    assert!(a.activate(0, space(70_000), &mut w).flush_all);
}

#[test]
fn init_starts_afresh_in_place() {
    // The kernel's static starts at 16 bits, and boot sets the real width.
    let mut a = AsidAllocator::new(16);
    a.rollover();
    a.init(8);
    assert_eq!(a.bits(), 8);
    assert_eq!(a.generation(), 1);
    // Every number but 0 is free again: 255 spaces before a rollover.
    for i in 0..255 {
        let mut w = 0;
        let act = a.activate(0, space(100 + i), &mut w);
        assert!(!act.flush_all, "rolled over at space {i}");
        assert_ne!(act.asid, 0);
    }
    let mut w = 0;
    assert!(a.activate(0, space(400), &mut w).flush_all);
}

/// The model: which spaces may have TLB entries under which number, since
/// the last full flush. Two spaces must never share a number, and one space
/// must never have two, or an invalidation by the space's word would miss
/// entries.
#[derive(Default)]
struct Tlb {
    by_asid: BTreeMap<u16, BTreeSet<u64>>,
}

impl Tlb {
    fn fill(&mut self, asid: u16, space: u64) {
        self.by_asid.entry(asid).or_default().insert(space);
    }

    fn check(&self) {
        let mut by_space: BTreeMap<u64, BTreeSet<u16>> = BTreeMap::new();
        for (&asid, spaces) in &self.by_asid {
            assert!(spaces.len() <= 1, "ASID {asid} tags spaces {spaces:x?}");
            for &s in spaces {
                by_space.entry(s).or_default().insert(asid);
            }
        }
        for (s, asids) in by_space {
            assert!(asids.len() <= 1, "space {s:#x} has ASIDs {asids:?}");
        }
    }
}

#[test]
fn random_switching_never_shares_or_splits_a_number() {
    const SPACES: usize = 600;
    const CORES: usize = 4;
    let mut rng = Lcg(0xa51d);
    let mut a = AsidAllocator::new(8);
    let mut words = vec![0u64; SPACES];
    let mut ids: Vec<u64> = (0..SPACES as u64).map(|i| space(i + 1)).collect();
    let mut next_id = SPACES as u64 + 1;
    let mut running: [Option<(usize, u16)>; CORES] = [None; CORES];
    let mut tlb = Tlb::default();
    let mut rollovers = 0;
    for _ in 0..20_000 {
        let core = rng.below(CORES as u64) as usize;
        match rng.below(10) {
            0 => {
                a.deactivate(core);
                running[core] = None;
            }
            1 => {
                // Destroy a space that no core runs, and make a new one with
                // a new identity in its slot.
                let i = rng.below(SPACES as u64) as usize;
                if running.iter().flatten().any(|&(r, _)| r == i) {
                    continue;
                }
                if let Some(n) = a.release(ids[i], words[i]) {
                    // TLBI ASIDE1IS n.
                    tlb.by_asid.remove(&n);
                    // Cores still running a space under n refill at once.
                    for &(r, asid) in running.iter().flatten() {
                        if asid == n {
                            tlb.fill(n, ids[r]);
                        }
                    }
                }
                ids[i] = space(next_id);
                next_id += 1;
                words[i] = 0;
            }
            _ => {
                let i = rng.below(SPACES as u64) as usize;
                let act = a.activate(core, ids[i], &mut words[i]);
                assert_ne!(act.asid, 0);
                assert!(a.is_current(words[i]));
                if act.flush_all {
                    // TLBI VMALLE1IS: the other cores keep running and
                    // refill under their numbers.
                    rollovers += 1;
                    tlb.by_asid.clear();
                    for (c, r) in running.iter().enumerate() {
                        if let (Some((r, asid)), true) = (r, c != core) {
                            tlb.fill(*asid, ids[*r]);
                        }
                    }
                }
                running[core] = Some((i, act.asid));
                tlb.fill(act.asid, ids[i]);
            }
        }
        tlb.check();
    }
    assert!(rollovers > 10, "only {rollovers} rollovers");
    const { assert!(CORES <= MAX_CORES) };
}
