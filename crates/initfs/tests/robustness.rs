// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Mutated and truncated images never make the parser panic.

mod common;

use common::*;
use initfs::{Image, Kind};

/// Uses everything a parsed image offers, so a panic anywhere shows.
fn exercise(bytes: &[u8]) {
    if let Ok(image) = Image::parse(bytes) {
        let mut count = 0u32;
        for e in image.entries() {
            count += 1;
            let _ = e.verify();
            assert_eq!(image.entry(e.name).map(|f| f.offset), Some(e.offset));
            assert_eq!(e.offset % u64::from(image.alignment()), 0);
        }
        assert_eq!(count, image.entry_count());
        assert_eq!(image.manifest().kind, Kind::Manifest);
        let _ = image.digest();
    }
}

#[test]
fn mutations_never_panic() {
    let original = sample();
    let metadata = entry_at(4);
    let mut rng = Rng(0x0a5b_15a5_15a5_0001);
    let mut accepted = 0;
    for _ in 0..20_000 {
        let mut img = original.clone();
        let edits = 1 + rng.below(8);
        for _ in 0..edits {
            // Mostly hit the header and the table, where the checks are.
            let at = if rng.below(4) == 0 {
                rng.below(img.len())
            } else {
                rng.below(metadata)
            };
            match rng.below(4) {
                0 => img[at] ^= 1 << rng.below(8),
                1 => img[at] = rng.next() as u8,
                2 => img[at] = [0, 0xff, 1, 0x80][rng.below(4)],
                _ => {
                    // Write an interesting little-endian value.
                    let v: u64 =
                        [0, 1, 64, 4096, 8192, u64::MAX, u64::MAX - 4095, 1 << 32][rng.below(8)];
                    let end = (at + 8).min(img.len());
                    let n = end - at;
                    img[at..end].copy_from_slice(&v.to_le_bytes()[..n]);
                }
            }
        }
        if rng.below(8) == 0 {
            let len = rng.below(img.len() + 1);
            img.truncate(len);
        }
        if Image::parse(&img).is_ok() {
            accepted += 1;
        }
        exercise(&img);
    }
    // Some mutations hit only contents or allowed fields, so some images
    // still parse.
    assert!(accepted > 0);
}

#[test]
fn every_truncation_is_rejected() {
    let original = sample();
    for len in 0..original.len() {
        assert!(Image::parse(&original[..len]).is_err(), "length {len}");
    }
}

#[test]
fn random_buffers_never_panic() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for _ in 0..5_000 {
        let len = rng.below(1024);
        let mut buf: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        // Half the time, start with a plausible header so the parser gets
        // further.
        if len >= 64 && rng.below(2) == 0 {
            buf[..8].copy_from_slice(b"ASPISIMG");
            put_u16(&mut buf, H_MAJOR, 1);
            put_u32(&mut buf, H_HEADER_LEN, 64);
            put_u32(&mut buf, H_ALIGNMENT, 4096);
            put_u32(&mut buf, H_ENTRY_COUNT, rng.below(8) as u32);
            put_u64(&mut buf, H_TABLE_OFFSET, 64);
            put_u32(&mut buf, H_MANIFEST_INDEX, rng.below(8) as u32);
            put_u32(&mut buf, H_RESERVED0, 0);
            put_u64(&mut buf, H_IMAGE_LEN, len as u64);
            buf[H_RESERVED1..64].fill(0);
        }
        exercise(&buf);
    }
}
