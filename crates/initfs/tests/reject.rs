// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Each constraint, broken in a hand-mutated image, gives its own error.

mod common;

use common::*;
use initfs::{Error, Image};

/// The sample image after `f` changes it.
fn mutated(f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut img = sample();
    f(&mut img);
    img
}

fn rejects(f: impl FnOnce(&mut Vec<u8>), expected: Error) {
    let img = mutated(f);
    assert_eq!(Image::parse(&img).err(), Some(expected));
}

/// Entry `index`'s offset field.
fn offset_field(index: usize) -> usize {
    entry_at(index) + E_OFFSET
}

#[test]
fn sample_parses() {
    assert!(Image::parse(&sample()).is_ok());
}

#[test]
fn truncated_header() {
    for len in [0, 1, 8, 63] {
        rejects(|img| img.truncate(len), Error::Truncated);
    }
}

#[test]
fn magic() {
    rejects(|img| img[H_MAGIC] = b'a', Error::BadMagic);
    rejects(|img| img[H_MAGIC + 7] = b'g', Error::BadMagic);
}

#[test]
fn major_version() {
    rejects(
        |img| put_u16(img, H_MAJOR, 2),
        Error::UnsupportedVersion { major: 2, minor: 0 },
    );
    rejects(
        |img| put_u16(img, H_MAJOR, 0),
        Error::UnsupportedVersion { major: 0, minor: 0 },
    );
}

#[test]
fn unknown_minor_is_accepted() {
    let img = mutated(|img| put_u16(img, H_MINOR, 7));
    let image = Image::parse(&img).unwrap();
    assert_eq!(image.version().minor, 7);
}

#[test]
fn header_length() {
    rejects(
        |img| put_u32(img, H_HEADER_LEN, 128),
        Error::BadHeaderLength(128),
    );
}

#[test]
fn alignment() {
    for bad in [0, 1, 2048, 4095, 6144, 0x8000_0001] {
        rejects(
            |img| put_u32(img, H_ALIGNMENT, bad),
            Error::BadAlignment(bad),
        );
    }
    // A larger power of two is a valid alignment, but the sample's offsets
    // aren't multiples of it.
    rejects(
        |img| put_u32(img, H_ALIGNMENT, 8192),
        Error::Misaligned { index: 0 },
    );
}

#[test]
fn reserved_header_fields() {
    rejects(|img| img[H_RESERVED0 + 3] = 1, Error::ReservedNotZero);
    rejects(|img| img[H_RESERVED1] = 1, Error::ReservedNotZero);
    rejects(|img| img[H_RESERVED1 + 15] = 0x80, Error::ReservedNotZero);
}

#[test]
fn image_length() {
    let len = sample().len() as u64;
    rejects(
        |img| put_u64(img, H_IMAGE_LEN, len + 1),
        Error::LengthMismatch {
            declared: len + 1,
            actual: len,
        },
    );
    // A truncated or extended file no longer matches its header.
    rejects(
        |img| img.truncate(img.len() - 1),
        Error::LengthMismatch {
            declared: len,
            actual: len - 1,
        },
    );
    rejects(
        |img| img.push(0),
        Error::LengthMismatch {
            declared: len,
            actual: len + 1,
        },
    );
}

#[test]
fn table_offset() {
    rejects(
        |img| put_u64(img, H_TABLE_OFFSET, 0),
        Error::BadTableOffset(0),
    );
    rejects(
        |img| put_u64(img, H_TABLE_OFFSET, 56),
        Error::BadTableOffset(56),
    );
    rejects(
        |img| put_u64(img, H_TABLE_OFFSET, 68),
        Error::BadTableOffset(68),
    );
    rejects(
        |img| put_u64(img, H_TABLE_OFFSET, u64::MAX - 7),
        Error::TableOutOfBounds,
    );
}

#[test]
fn table_fits_in_the_image() {
    rejects(
        |img| put_u32(img, H_ENTRY_COUNT, u32::MAX),
        Error::TableOutOfBounds,
    );
    let len = sample().len() as u64;
    rejects(
        |img| put_u64(img, H_TABLE_OFFSET, len - 128 * 4 + 8),
        Error::TableOutOfBounds,
    );
}

#[test]
fn table_overlaps_an_entry() {
    // Move the table onto the first entry's contents (bootfb at 4096).
    let img = mutated(|img| {
        let table: Vec<u8> = img[64..64 + 4 * 128].to_vec();
        img[4096..4096 + 4 * 128].copy_from_slice(&table);
        put_u64(img, H_TABLE_OFFSET, 4096);
    });
    assert_eq!(
        Image::parse(&img).err(),
        Some(Error::EntryOverlapsTable { index: 0 })
    );
    // A table placed after the entries is valid.
    let img = mutated(|img| {
        let table: Vec<u8> = img[64..64 + 4 * 128].to_vec();
        let at = img.len().next_multiple_of(8);
        img.resize(at, 0);
        img.extend_from_slice(&table);
        let len = img.len() as u64;
        put_u64(img, H_IMAGE_LEN, len);
        put_u64(img, H_TABLE_OFFSET, at as u64);
        img[64..64 + 4 * 128].fill(0);
    });
    let image = Image::parse(&img).unwrap();
    assert!(image.entries().all(|e| e.verify()));
}

#[test]
fn entry_overlaps_the_header() {
    // An entry at offset 0 is aligned, but covers the header.
    rejects(
        |img| put_u64(img, offset_field(0), 0),
        Error::EntryOverlapsHeader { index: 0 },
    );
    // An empty entry at offset 0 covers nothing, but it must still come in
    // ascending order, so only the first entry may be there.
    let img = mutated(|img| {
        put_u64(img, offset_field(0), 0);
        put_u64(img, entry_at(0) + E_LENGTH, 0);
    });
    assert!(Image::parse(&img).is_ok());
}

#[test]
fn manifest_index() {
    rejects(
        |img| put_u32(img, H_MANIFEST_INDEX, 4),
        Error::BadManifestIndex(4),
    );
    rejects(
        |img| put_u32(img, H_MANIFEST_INDEX, u32::MAX),
        Error::BadManifestIndex(u32::MAX),
    );
    rejects(
        |img| put_u32(img, H_ENTRY_COUNT, 0),
        Error::BadManifestIndex(2),
    );
}

#[test]
fn exactly_one_manifest_at_its_index() {
    // The manifest index names a non-manifest entry: entry 0 is the first
    // mismatch.
    rejects(
        |img| put_u32(img, H_MANIFEST_INDEX, 0),
        Error::ManifestMisplaced { index: 0 },
    );
    // A second entry claims to be a manifest.
    rejects(
        |img| img[entry_at(3) + E_KIND] = 3,
        Error::ManifestMisplaced { index: 3 },
    );
    // The manifest entry isn't a manifest, so none is.
    rejects(
        |img| img[entry_at(2) + E_KIND] = 2,
        Error::ManifestMisplaced { index: 2 },
    );
}

#[test]
fn name_length() {
    rejects(
        |img| put_u16(img, entry_at(1) + E_NAME_LEN, 0),
        Error::BadNameLength { index: 1, len: 0 },
    );
    rejects(
        |img| put_u16(img, entry_at(1) + E_NAME_LEN, 41),
        Error::BadNameLength { index: 1, len: 41 },
    );
    rejects(
        |img| put_u16(img, entry_at(1) + E_NAME_LEN, u16::MAX),
        Error::BadNameLength {
            index: 1,
            len: u16::MAX,
        },
    );
}

#[test]
fn name_padding() {
    rejects(
        |img| img[entry_at(0) + E_NAME + 39] = b'x',
        Error::NamePaddingNotZero { index: 0 },
    );
    // A name length shorter than the name leaves name octets in the padding.
    rejects(
        |img| put_u16(img, entry_at(0) + E_NAME_LEN, 4),
        Error::NamePaddingNotZero { index: 0 },
    );
}

#[test]
fn name_utf8() {
    rejects(
        |img| img[entry_at(3) + E_NAME] = 0xff,
        Error::NameNotUtf8 { index: 3 },
    );
    // A UTF-8 character that isn't allowed.
    rejects(
        |img| {
            // "root" becomes "ro\u{e9}": four octets either way.
            img[entry_at(3) + E_NAME + 2..entry_at(3) + E_NAME + 4]
                .copy_from_slice("\u{e9}".as_bytes());
        },
        Error::BadNameCharacter { index: 3 },
    );
}

#[test]
fn name_characters() {
    for bad in [b'R', b'/', b' ', 0, b'+', 0x7f] {
        rejects(
            |img| img[entry_at(3) + E_NAME + 1] = bad,
            Error::BadNameCharacter { index: 3 },
        );
    }
    // Every allowed character is accepted.
    for good in *b"az09._-" {
        let img = mutated(|img| img[entry_at(3) + E_NAME + 1] = good);
        assert!(Image::parse(&img).is_ok(), "{}", good as char);
    }
}

#[test]
fn duplicate_names() {
    // Entry 3 takes entry 0's name field and name length.
    rejects(
        |img| {
            let (a, b) = (entry_at(0), entry_at(3));
            let name: Vec<u8> = img[a + E_NAME..a + E_NAME + 40].to_vec();
            img[b + E_NAME..b + E_NAME + 40].copy_from_slice(&name);
            let len = [img[a + E_NAME_LEN], img[a + E_NAME_LEN + 1]];
            img[b + E_NAME_LEN..b + E_NAME_LEN + 2].copy_from_slice(&len);
        },
        Error::DuplicateName { index: 3 },
    );
}

#[test]
fn kind() {
    for bad in [0, 4, 0xff] {
        rejects(
            |img| img[entry_at(1) + E_KIND] = bad,
            Error::UnknownKind {
                index: 1,
                kind: bad,
            },
        );
    }
}

#[test]
fn flags_and_reserved() {
    rejects(
        |img| img[entry_at(1) + E_FLAGS] = 0x01,
        Error::FlagsNotZero {
            index: 1,
            flags: 0x01,
        },
    );
    rejects(
        |img| img[entry_at(1) + E_RESERVED + 2] = 1,
        Error::EntryReservedNotZero { index: 1 },
    );
}

#[test]
fn entry_alignment() {
    rejects(
        |img| put_u64(img, offset_field(2), 16384 + 8),
        Error::Misaligned { index: 2 },
    );
}

#[test]
fn entry_bounds() {
    let len = sample().len() as u64;
    // The last entry, one octet longer than the image holds.
    rejects(
        |img| put_u64(img, entry_at(3) + E_LENGTH, 17),
        Error::EntryOutOfBounds { index: 3 },
    );
    rejects(
        |img| put_u64(img, offset_field(3), len.next_multiple_of(4096)),
        Error::EntryOutOfBounds { index: 3 },
    );
    // Offset plus length overflows.
    rejects(
        |img| put_u64(img, entry_at(3) + E_LENGTH, u64::MAX),
        Error::EntryOutOfBounds { index: 3 },
    );
    rejects(
        |img| put_u64(img, offset_field(3), u64::MAX - 4095),
        Error::EntryOutOfBounds { index: 3 },
    );
}

#[test]
fn entries_overlap() {
    // bootfb is 5000 octets from 4096: lengthening it to reach the next
    // entry's offset makes them overlap.
    rejects(
        |img| put_u64(img, entry_at(0) + E_LENGTH, 8192 + 1),
        Error::EntryOutOfOrder { index: 1 },
    );
    // Exactly touching is fine.
    let img = mutated(|img| put_u64(img, entry_at(0) + E_LENGTH, 8192));
    assert!(Image::parse(&img).is_ok());
}

#[test]
fn entries_in_offset_order() {
    // Swap the offsets and lengths of entries 1 and 2.
    rejects(
        |img| {
            for field in [E_OFFSET, E_LENGTH] {
                let (a, b) = (entry_at(1) + field, entry_at(2) + field);
                let va = get_u64(img, a);
                let vb = get_u64(img, b);
                put_u64(img, a, vb);
                put_u64(img, b, va);
            }
        },
        Error::EntryOutOfOrder { index: 2 },
    );
}

#[test]
fn errors_display() {
    let e = Error::DuplicateName { index: 3 };
    assert_eq!(e.to_string(), "entry 3: duplicate name");
}
