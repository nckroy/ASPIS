// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Edge cases a hostile or careless image might hit.

mod common;

use common::*;
use initfs::{Builder, Error, Image, Kind};

/// Every single-octet change to the header or the table either is
/// rejected or leaves an image whose whole API agrees with itself.
#[test]
fn every_metadata_octet_every_value() {
    let original = sample();
    let metadata = entry_at(4);
    for at in 0..metadata {
        for v in 0..=255u8 {
            if original[at] == v {
                continue;
            }
            let mut img = original.clone();
            img[at] = v;
            let Ok(image) = Image::parse(&img) else {
                continue;
            };
            let entries: Vec<_> = image.entries().collect();
            assert_eq!(entries.len() as u32, image.entry_count(), "octet {at}");
            let mut prev_end = 0;
            for e in &entries {
                assert!(e.offset >= prev_end, "octet {at}: order");
                prev_end = e.offset + e.data.len() as u64;
                assert!(prev_end <= img.len() as u64, "octet {at}: bounds");
                assert_eq!(image.entry(e.name), Some(*e), "octet {at}: lookup");
            }
            assert_eq!(
                entries[image.manifest_index() as usize],
                image.manifest(),
                "octet {at}: manifest"
            );
        }
    }
}

#[test]
fn table_offset_and_count_overflow() {
    // table_offset + 128 * entry_count overflows u64.
    let img = {
        let mut img = sample();
        put_u64(&mut img, H_TABLE_OFFSET, u64::MAX - 7);
        put_u32(&mut img, H_ENTRY_COUNT, u32::MAX);
        img
    };
    assert_eq!(Image::parse(&img).err(), Some(Error::TableOutOfBounds));
}

/// The sample with its table moved after the entries, to a multiple of 8.
fn table_at_end() -> (Vec<u8>, usize) {
    let mut img = sample();
    let table: Vec<u8> = img[64..entry_at(4)].to_vec();
    let at = img.len().next_multiple_of(8);
    img.resize(at, 0);
    img.extend_from_slice(&table);
    let len = img.len() as u64;
    put_u64(&mut img, H_IMAGE_LEN, len);
    put_u64(&mut img, H_TABLE_OFFSET, at as u64);
    img[64..entry_at(4)].fill(0);
    (img, at)
}

#[test]
fn entry_straddling_the_table_start() {
    let (img, at) = table_at_end();
    assert!(Image::parse(&img).is_ok());
    // The last entry ("root", at 20480) now reaches one octet into the table.
    let mut bad = img.clone();
    let root = at + 128 * 3;
    put_u64(&mut bad, root + E_LENGTH, (at - 20480 + 1) as u64);
    assert_eq!(
        Image::parse(&bad).err(),
        Some(Error::EntryOverlapsTable { index: 3 })
    );
    // Ending exactly where the table starts is fine.
    let mut ok = img;
    put_u64(&mut ok, root + E_LENGTH, (at - 20480) as u64);
    assert!(Image::parse(&ok).is_ok());
}

#[test]
fn empty_entries_at_the_edges() {
    // An empty last entry may sit exactly at the end of the image.
    let len = sample().len() as u64;
    let mut img = sample();
    let end = len.next_multiple_of(4096);
    img.resize(end as usize, 0);
    put_u64(&mut img, H_IMAGE_LEN, end);
    put_u64(&mut img, entry_at(3) + E_OFFSET, end);
    put_u64(&mut img, entry_at(3) + E_LENGTH, 0);
    let image = Image::parse(&img).unwrap();
    assert!(image.entry("root").unwrap().data.is_empty());
    // One alignment unit past the end is out of bounds, even when empty.
    put_u64(&mut img, entry_at(3) + E_OFFSET, end + 4096);
    assert_eq!(
        Image::parse(&img).err(),
        Some(Error::EntryOutOfBounds { index: 3 })
    );
}

#[test]
fn names_that_share_a_prefix_are_distinct() {
    let mut b = Builder::new(4096);
    let long = "z".repeat(40);
    for (i, name) in ["a", "ab", "a.b", "a-", "a_", long.as_str()]
        .into_iter()
        .enumerate()
    {
        b.add(name, Kind::Data, vec![i as u8; i + 1]).unwrap();
    }
    b.manifest(vec![]);
    let img = b.build().unwrap();
    let image = Image::parse(&img).unwrap();
    assert_eq!(image.entry("a").unwrap().data, [0]);
    assert_eq!(image.entry("ab").unwrap().data, [1, 1]);
    assert_eq!(image.entry(&long).unwrap().data.len(), 6);
    assert!(image.entries().all(|e| e.verify()));
    // Lookups that can't match don't panic.
    for miss in ["", "A", "a\0", "zz", &"z".repeat(41), "\u{e9}"] {
        assert!(image.entry(miss).is_none(), "{miss:?}");
    }
}

#[test]
fn many_entries() {
    let mut b = Builder::new(4096);
    for i in 0..2000u32 {
        b.add(&format!("e{i:05}"), Kind::Data, i.to_le_bytes().to_vec())
            .unwrap();
    }
    b.manifest(b"m".to_vec());
    let img = b.build().unwrap();
    let image = Image::parse(&img).unwrap();
    assert_eq!(image.entry_count(), 2001);
    assert_eq!(image.entry("e01999").unwrap().data, 1999u32.to_le_bytes());
    assert!(image.entries().all(|e| e.verify()));
}
