// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The work list is first in, first out, queues an item once, and removes
//! and replaces items in place, against a model.

mod common;

use common::Lcg;
use ksched::worklist::{Tagged, WLinks, WorkList, WorkStore};
use std::collections::HashMap;

#[derive(Default)]
struct Mem(HashMap<u64, WLinks>);

impl WorkStore for Mem {
    fn wlinks(&self, i: Tagged) -> WLinks {
        self.0.get(&i.addr()).copied().unwrap_or_default()
    }
    fn set_wlinks(&mut self, i: Tagged, l: WLinks) {
        self.0.insert(i.addr(), l);
    }
}

fn item(n: u64) -> Tagged {
    Tagged::new(
        n * 64,
        if n.is_multiple_of(2) {
            Tagged::WALK
        } else {
            Tagged::EVENTCOUNT
        },
    )
    .unwrap()
}

fn contents(l: &WorkList, m: &Mem) -> Vec<Tagged> {
    let mut v = vec![];
    let mut cur = l.front();
    while let Some(i) = cur {
        v.push(i);
        cur = Tagged::from_raw(m.wlinks(i).next);
        assert!(v.len() < 10_000);
    }
    v
}

#[test]
fn tags() {
    let t = Tagged::new(0x1000, Tagged::WALK).unwrap();
    assert_eq!(t.addr(), 0x1000);
    assert_eq!(t.tag(), Tagged::WALK);
    assert!(Tagged::new(0, 1).is_none());
    assert!(Tagged::new(0x1001, 1).is_none());
    assert!(Tagged::new(0x1000, 8).is_none());
    assert_eq!(Tagged::from_raw(t.raw()), Some(t));
}

#[test]
fn random_against_a_model() {
    let mut rng = Lcg(5);
    for _ in 0..common::runs(50) {
        let mut m = Mem::default();
        let mut l = WorkList::new();
        let mut model: Vec<Tagged> = vec![];
        for _ in 0..1000 {
            let x = item(rng.below(40) + 1);
            match rng.below(4) {
                0 | 1 => {
                    let added = l.push_back(&mut m, x);
                    assert_eq!(added, !model.contains(&x));
                    if added {
                        model.push(x);
                    }
                }
                2 => {
                    if let Some(i) = model.iter().position(|&y| y == x) {
                        l.remove(&mut m, x);
                        model.remove(i);
                    }
                }
                _ => {
                    let y = item(rng.below(40) + 1);
                    if let Some(i) = model.iter().position(|&z| z == x)
                        && !model.contains(&y)
                    {
                        l.replace(&mut m, x, y);
                        model[i] = y;
                    }
                }
            }
            assert_eq!(contents(&l, &m), model);
            assert_eq!(l.is_empty(), model.is_empty());
        }
        while let Some(x) = l.pop_front(&mut m) {
            assert_eq!(x, model.remove(0));
            assert!(!m.wlinks(x).queued);
        }
        assert!(model.is_empty());
    }
}
