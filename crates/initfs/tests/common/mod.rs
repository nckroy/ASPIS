// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Helpers shared by the tests.

#![allow(dead_code)]

use initfs::{Builder, Kind};

/// Header field offsets.
pub const H_MAGIC: usize = 0;
pub const H_MAJOR: usize = 8;
pub const H_MINOR: usize = 10;
pub const H_HEADER_LEN: usize = 12;
pub const H_ALIGNMENT: usize = 16;
pub const H_ENTRY_COUNT: usize = 20;
pub const H_TABLE_OFFSET: usize = 24;
pub const H_MANIFEST_INDEX: usize = 32;
pub const H_RESERVED0: usize = 36;
pub const H_IMAGE_LEN: usize = 40;
pub const H_RESERVED1: usize = 48;

/// Entry field offsets, relative to the entry.
pub const E_NAME_LEN: usize = 0;
pub const E_KIND: usize = 2;
pub const E_FLAGS: usize = 3;
pub const E_RESERVED: usize = 4;
pub const E_OFFSET: usize = 8;
pub const E_LENGTH: usize = 16;
pub const E_DIGEST: usize = 24;
pub const E_NAME: usize = 88;

/// A small image with 4 KiB alignment: entries `bootfb` (executable),
/// `font.atlas` (data), `manifest` and `root` (executable), in that order.
pub fn sample() -> Vec<u8> {
    let mut b = Builder::new(4096);
    b.add("root", Kind::Executable, b"\x7fELF root server".to_vec())
        .unwrap();
    b.add("bootfb", Kind::Executable, vec![0xab; 5000]).unwrap();
    b.add("font.atlas", Kind::Data, (0..=255u8).collect())
        .unwrap();
    b.manifest(b"root\nbootfb\n".to_vec());
    b.build().unwrap()
}

/// The offset of entry `index` in a builder's image.
pub fn entry_at(index: usize) -> usize {
    64 + 128 * index
}

pub fn put_u16(img: &mut [u8], at: usize, v: u16) {
    img[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

pub fn put_u32(img: &mut [u8], at: usize, v: u32) {
    img[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

pub fn put_u64(img: &mut [u8], at: usize, v: u64) {
    img[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

pub fn get_u64(img: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(img[at..at + 8].try_into().unwrap())
}

/// A deterministic pseudo-random sequence (xorshift64*).
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A value in `0..n`; `n` must be nonzero.
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}
