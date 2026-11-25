// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

mod common;

use common::*;
use initfs::{
    BuildError, Builder, DEFAULT_ALIGNMENT, Image, Kind, MANIFEST_NAME, Version, image_digest,
};
use sha2::{Digest, Sha512};

#[test]
fn round_trip() {
    let img = sample();
    let image = Image::parse(&img).unwrap();
    assert_eq!(image.version(), Version { major: 1, minor: 0 });
    assert_eq!(image.alignment(), 4096);
    assert_eq!(image.entry_count(), 4);
    assert_eq!(image.table_offset(), 64);

    let names: Vec<_> = image.entries().map(|e| e.name).collect();
    assert_eq!(names, ["bootfb", "font.atlas", MANIFEST_NAME, "root"]);

    let root = image.entry("root").unwrap();
    assert_eq!(root.kind, Kind::Executable);
    assert_eq!(root.data, b"\x7fELF root server");
    let bootfb = image.entry("bootfb").unwrap();
    assert_eq!(bootfb.data, &[0xab; 5000][..]);
    let atlas = image.entry("font.atlas").unwrap();
    assert_eq!(atlas.kind, Kind::Data);
    assert_eq!(atlas.data.len(), 256);
    assert!(image.entry("missing").is_none());

    let manifest = image.manifest();
    assert_eq!(manifest.kind, Kind::Manifest);
    assert_eq!(manifest.name, MANIFEST_NAME);
    assert_eq!(manifest.data, b"root\nbootfb\n");
    assert_eq!(image.manifest_index(), 2);

    for e in image.entries() {
        assert_eq!(e.offset % 4096, 0, "{} is aligned", e.name);
        assert!(e.verify(), "{} verifies", e.name);
    }
}

#[test]
fn layout_is_canonical() {
    let img = sample();
    // The table follows the header, and the first entry starts at the first
    // alignment boundary after it.
    let image = Image::parse(&img).unwrap();
    let offsets: Vec<_> = image.entries().map(|e| e.offset).collect();
    // bootfb is 5000 octets, so it takes two 4 KiB blocks.
    assert_eq!(offsets, [4096, 12288, 16384, 20480]);
    assert_eq!(get_u64(&img, H_IMAGE_LEN), img.len() as u64);
    assert_eq!(img.len(), 20480 + 16);
    // Every octet outside the header, the table and the contents is zero.
    let mut covered = vec![false; img.len()];
    covered[..64 + 4 * 128].iter_mut().for_each(|c| *c = true);
    for e in image.entries() {
        let start = e.offset as usize;
        covered[start..start + e.data.len()]
            .iter_mut()
            .for_each(|c| *c = true);
    }
    for (i, (&c, &b)) in covered.iter().zip(&img).enumerate() {
        assert!(c || b == 0, "padding octet {i} is zero");
    }
}

#[test]
fn builder_is_deterministic() {
    let mut a = Builder::new(4096);
    a.add("b", Kind::Data, vec![1]).unwrap();
    a.add("a", Kind::Executable, vec![2]).unwrap();
    a.manifest(vec![3]);
    let mut b = Builder::new(4096);
    b.manifest(vec![3]);
    b.add("a", Kind::Executable, vec![2]).unwrap();
    b.add("b", Kind::Data, vec![1]).unwrap();
    assert_eq!(a.build().unwrap(), b.build().unwrap());
}

#[test]
fn default_alignment() {
    assert_eq!(DEFAULT_ALIGNMENT, 65536);
    let mut b = Builder::default();
    b.add("boot", Kind::Executable, vec![1; 70000]).unwrap();
    b.manifest(vec![]);
    let img = b.build().unwrap();
    let image = Image::parse(&img).unwrap();
    assert_eq!(image.alignment(), 65536);
    let offsets: Vec<_> = image.entries().map(|e| e.offset).collect();
    // "boot" sorts before "manifest" and takes two 64 KiB blocks.
    assert_eq!(offsets, [65536, 196608]);
    // An empty manifest ends the image at its offset.
    assert_eq!(img.len(), 196608);
    assert!(image.manifest().data.is_empty());
    assert!(image.manifest().verify());
}

#[test]
fn empty_entries_share_an_offset() {
    let mut b = Builder::new(4096);
    b.add("a", Kind::Data, vec![]).unwrap();
    b.add("b", Kind::Data, vec![]).unwrap();
    b.add("c", Kind::Data, vec![9; 10]).unwrap();
    b.manifest(vec![]);
    let img = b.build().unwrap();
    let image = Image::parse(&img).unwrap();
    let offsets: Vec<_> = image.entries().map(|e| e.offset).collect();
    assert_eq!(offsets, [4096, 4096, 4096, 8192]);
    assert!(image.entries().all(|e| e.verify()));
}

#[test]
fn builder_errors() {
    let mut b = Builder::new(4096);
    assert_eq!(
        b.add("Root", Kind::Data, vec![]),
        Err(BuildError::BadName("Root".into()))
    );
    assert_eq!(
        b.add("", Kind::Data, vec![]),
        Err(BuildError::BadName("".into()))
    );
    let long = "a".repeat(41);
    assert_eq!(
        b.add(&long, Kind::Data, vec![]),
        Err(BuildError::BadName(long.clone()))
    );
    b.add(&"a".repeat(40), Kind::Data, vec![]).unwrap();
    assert_eq!(
        b.add("m", Kind::Manifest, vec![]),
        Err(BuildError::ManifestKind)
    );
    b.add("x", Kind::Data, vec![]).unwrap();
    assert_eq!(
        b.add("x", Kind::Data, vec![]),
        Err(BuildError::DuplicateName("x".into()))
    );
    assert_eq!(
        b.add(MANIFEST_NAME, Kind::Data, vec![]),
        Err(BuildError::DuplicateName(MANIFEST_NAME.into()))
    );
    assert_eq!(b.build(), Err(BuildError::MissingManifest));

    for bad in [0, 2048, 4095, 4097, 12288] {
        let mut b = Builder::new(bad);
        b.manifest(vec![]);
        assert_eq!(b.build(), Err(BuildError::BadAlignment(bad)));
    }
}

#[test]
fn digests() {
    let img = sample();
    let image = Image::parse(&img).unwrap();

    // The whole image's digest is SHA-512 of the file (ADR 0040).
    let expected: [u8; 64] = Sha512::digest(&img).into();
    assert_eq!(image_digest(&img), expected);
    assert_eq!(image.digest(), expected);
    // A known answer: SHA-512 of "abc" (FIPS 180-4).
    assert_eq!(
        image_digest(b"abc")[..8],
        [0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba]
    );

    // Each entry's digest is SHA-512 of its contents.
    for e in image.entries() {
        let d: [u8; 64] = Sha512::digest(e.data).into();
        assert_eq!(*e.digest, d);
    }

    // A changed content octet fails that entry's check only, and parsing
    // still succeeds.
    let root_offset = image.entry("root").unwrap().offset as usize;
    let mut bad = img.clone();
    bad[root_offset] ^= 1;
    let image = Image::parse(&bad).unwrap();
    for e in image.entries() {
        assert_eq!(e.verify(), e.name != "root", "{}", e.name);
    }
    assert_ne!(image_digest(&bad), expected);

    // A changed digest octet fails too.
    let mut bad = img.clone();
    bad[entry_at(0) + E_DIGEST + 63] ^= 0x80;
    let image = Image::parse(&bad).unwrap();
    assert!(!image.entries().next().unwrap().verify());
}
