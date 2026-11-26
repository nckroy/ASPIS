// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Helpers shared by the tests: a fake physical memory, a counting frame
//! source, a fake direct map, and a fixed-seed pseudo-random generator.

#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::BTreeMap;

use kmem::ranges::RangeSet;
use kmem::table::{FrameSource, PhysMem};
use kmem::user::{Access, Bytes, DirectMap};

/// Sparse physical memory: pages never written read as zero.
#[derive(Default)]
pub struct FakeMem {
    pages: RefCell<BTreeMap<u64, Box<[u8; 4096]>>>,
}

impl FakeMem {
    pub fn new() -> Self {
        Self::default()
    }

    fn with_page<R>(&self, page: u64, f: impl FnOnce(&mut [u8; 4096]) -> R) -> R {
        let mut pages = self.pages.borrow_mut();
        let p = pages.entry(page).or_insert_with(|| Box::new([0; 4096]));
        f(p)
    }
}

impl PhysMem for FakeMem {
    fn read(&self, table: u64, i: usize) -> u64 {
        assert_eq!(table % 4096, 0, "table address {table:#x} isn't a page");
        assert!(i < 512);
        self.with_page(table, |p| {
            u64::from_le_bytes(p[i * 8..i * 8 + 8].try_into().unwrap())
        })
    }

    fn write(&self, table: u64, i: usize, v: u64) {
        assert_eq!(table % 4096, 0, "table address {table:#x} isn't a page");
        assert!(i < 512);
        self.with_page(table, |p| {
            p[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes())
        });
    }
}

impl Bytes for FakeMem {
    fn read(&self, pa: u64, buf: &mut [u8]) {
        for (k, b) in buf.iter_mut().enumerate() {
            let a = pa + k as u64;
            *b = self.with_page(a & !4095, |p| p[(a & 4095) as usize]);
        }
    }

    fn write(&self, pa: u64, buf: &[u8]) {
        for (k, &b) in buf.iter().enumerate() {
            let a = pa + k as u64;
            self.with_page(a & !4095, |p| p[(a & 4095) as usize] = b);
        }
    }
}

/// Hands out zeroed pages from a high region, counting them, up to `limit`.
pub struct Frames {
    pub next: u64,
    pub count: usize,
    pub limit: usize,
}

impl Frames {
    pub fn new() -> Self {
        Self {
            next: 0x7000_0000_0000,
            count: 0,
            limit: usize::MAX,
        }
    }

    pub fn limited(limit: usize) -> Self {
        Self {
            limit,
            ..Self::new()
        }
    }
}

impl Default for Frames {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameSource for Frames {
    fn table(&mut self) -> Option<u64> {
        if self.count == self.limit {
            return None;
        }
        let pa = self.next;
        self.next += 4096;
        self.count += 1;
        Some(pa)
    }
}

/// A direct map with a read-write part and a read-only part.
#[derive(Default)]
pub struct FakeDirectMap {
    pub rw: RangeSet<16>,
    pub ro: RangeSet<16>,
}

impl DirectMap for FakeDirectMap {
    fn covers(&self, pa: u64, len: u64, access: Access) -> bool {
        let end = pa + len;
        self.rw.contains(pa, end) || (access == Access::Read && self.ro.contains(pa, end))
    }
}

/// A fixed-seed linear congruential generator (Knuth's MMIX constants), so
/// the property tests need no dependency and always run the same cases.
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
