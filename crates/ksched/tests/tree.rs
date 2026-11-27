// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The red-black tree, against `BTreeMap`: its invariants after every
//! operation, a height within 2·log2(n + 1), and an augmented value kept
//! right through every rotation.

mod common;

use common::Lcg;
use ksched::tree::{self, Links, TreeStore};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Default)]
struct Node {
    key: u64,
    links: Links,
    max: u64,
}

struct Mem<const AUG: bool>(Vec<Node>);

impl<const AUG: bool> TreeStore for Mem<AUG> {
    type Key = (u64, u64);
    const AUGMENTED: bool = AUG;
    fn key(&self, n: u64) -> (u64, u64) {
        (self.0[n as usize].key, n)
    }
    fn links(&self, n: u64) -> Links {
        self.0[n as usize].links
    }
    fn set_links(&mut self, n: u64, l: Links) {
        self.0[n as usize].links = l;
    }
    fn update(&mut self, n: u64) {
        let x = self.0[n as usize];
        let mut m = x.key;
        for c in [x.links.left, x.links.right] {
            if c != 0 {
                m = m.max(self.0[c as usize].max);
            }
        }
        self.0[n as usize].max = m;
    }
}

/// The augmented value, recomputed from scratch.
fn real_max<const A: bool>(m: &Mem<A>, n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let x = m.0[n as usize];
    x.key
        .max(real_max(m, x.links.left))
        .max(real_max(m, x.links.right))
}

fn all_nodes<const A: bool>(m: &Mem<A>, root: u64) -> Vec<u64> {
    let mut v = vec![];
    let mut n = tree::first(m, root);
    while n != 0 {
        v.push(n);
        n = tree::next(m, n);
    }
    v
}

fn run<const A: bool>(seed: u64) {
    let size = 300usize;
    let mut rng = Lcg(seed);
    let mut m: Mem<A> = Mem(vec![Node::default(); size + 1]);
    let mut root = 0u64;
    let mut model: BTreeSet<(u64, u64)> = BTreeSet::new();
    let mut inside = vec![false; size + 1];
    for _ in 0..3000 {
        let n = rng.below(size as u64) + 1;
        if inside[n as usize] {
            tree::remove(&mut m, &mut root, n);
            model.remove(&(m.0[n as usize].key, n));
            inside[n as usize] = false;
        } else {
            // Few distinct keys, so ties are broken by the address.
            m.0[n as usize].key = rng.below(50);
            tree::insert(&mut m, &mut root, n);
            model.insert((m.0[n as usize].key, n));
            inside[n as usize] = true;
        }
        let count = tree::check(&m, root, size).expect("red-black invariants");
        assert_eq!(count, model.len());
        let order: Vec<(u64, u64)> = all_nodes(&m, root)
            .into_iter()
            .map(|n| (m.0[n as usize].key, n))
            .collect();
        assert_eq!(order, model.iter().copied().collect::<Vec<_>>());
        let h = tree::height(&m, root);
        let bound = 2.0 * ((model.len() + 1) as f64).log2();
        assert!(h as f64 <= bound + 1e-9, "height {h} for {}", model.len());
        if let Some(&(k, x)) = model.first() {
            assert_eq!(tree::first(&m, root), x);
            assert_eq!(m.0[x as usize].key, k);
        }
        if A {
            for x in all_nodes(&m, root) {
                assert_eq!(m.0[x as usize].max, real_max(&m, x));
            }
        }
    }
}

#[test]
fn random_plain() {
    for seed in 0..common::runs(4) {
        run::<false>(seed);
    }
}

#[test]
fn random_augmented() {
    for seed in 0..common::runs(4) {
        run::<true>(100 + seed);
    }
}

#[test]
fn removed_nodes_are_cleared() {
    let mut m: Mem<false> = Mem(vec![Node::default(); 4]);
    let mut root = 0;
    for n in 1..=3 {
        m.0[n].key = n as u64;
        tree::insert(&mut m, &mut root, n as u64);
    }
    tree::remove(&mut m, &mut root, 2);
    assert_eq!(m.0[2].links, Links::default());
    assert_eq!(tree::check(&m, root, 3), Ok(2));
    tree::remove(&mut m, &mut root, 1);
    tree::remove(&mut m, &mut root, 3);
    assert_eq!(root, 0);
    assert_eq!(tree::first(&m, root), 0);
}
