// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

extern crate std;

use super::*;
use std::vec::Vec;

/// Builds an atlas whose bitmap for each glyph is filled with a byte
/// derived from its index, so tests can tell the bitmaps apart.
fn build(width: u16, height: u16, baseline: u16, cps: &[u32]) -> Vec<u8> {
    let header = Header {
        cell_width: width,
        cell_height: height,
        baseline,
        glyph_count: u32::try_from(cps.len()).unwrap(),
    };
    let mut out = Vec::from(header.to_bytes());
    for cp in cps {
        out.extend_from_slice(&cp.to_le_bytes());
    }
    let cell = usize::from(width) * usize::from(height);
    for (i, _) in cps.iter().enumerate() {
        let fill = u8::try_from(i % 256).unwrap();
        out.extend(core::iter::repeat_n(fill, cell));
    }
    assert_eq!(out.len(), header.encoded_len().unwrap());
    out
}

const CPS: [u32; 5] = [0x20, 0x41, 0x42, 0x3a9, 0xfffd];

#[test]
fn parses_a_valid_atlas() {
    let data = build(3, 4, 3, &CPS);
    let atlas = Atlas::parse(&data).unwrap();
    assert_eq!(atlas.cell_width(), 3);
    assert_eq!(atlas.cell_height(), 4);
    assert_eq!(atlas.baseline(), 3);
    assert_eq!(atlas.glyph_count(), 5);
    assert_eq!(atlas.glyph('A'), Some(&[1u8; 12][..]));
    assert_eq!(atlas.glyph('B'), Some(&[2u8; 12][..]));
    assert_eq!(atlas.glyph('Ω'), Some(&[3u8; 12][..]));
    assert_eq!(atlas.glyph(' '), Some(&[0u8; 12][..]));
    assert_eq!(atlas.glyph(REPLACEMENT), Some(&[4u8; 12][..]));
    assert_eq!(atlas.glyph('C'), None);
    assert_eq!(atlas.glyph('\0'), None);
    assert_eq!(atlas.glyph(char::MAX), None);
    assert_eq!(atlas.glyph_or_replacement('C'), &[4u8; 12][..]);
    assert_eq!(atlas.glyph_or_replacement('A'), &[1u8; 12][..]);
    let all: Vec<_> = atlas.iter().map(|(c, b)| (u32::from(c), b[0])).collect();
    assert_eq!(
        all,
        [(0x20, 0), (0x41, 1), (0x42, 2), (0x3a9, 3), (0xfffd, 4)]
    );
}

#[test]
fn finds_every_glyph_in_a_large_atlas() {
    let mut cps: Vec<u32> = (0x20..0x2000).step_by(3).collect();
    cps.push(0xfffd);
    let data = build(1, 1, 1, &cps);
    let atlas = Atlas::parse(&data).unwrap();
    for (i, &cp) in cps.iter().enumerate() {
        let c = char::from_u32(cp).unwrap();
        assert_eq!(atlas.glyph(c), Some(&[u8::try_from(i % 256).unwrap()][..]));
        if cp < 0x1fff {
            let next = char::from_u32(cp + 1).unwrap();
            assert_eq!(atlas.glyph(next), None);
        }
    }
}

#[test]
fn baseline_may_sit_at_the_bottom_of_the_cell() {
    let data = build(2, 2, 2, &[0xfffd]);
    assert!(Atlas::parse(&data).is_ok());
}

fn set_u16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn set_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn rejects_bad_headers() {
    let good = build(3, 4, 3, &CPS);
    let check = |edit: &dyn Fn(&mut Vec<u8>), want: Error| {
        let mut data = good.clone();
        edit(&mut data);
        assert_eq!(Atlas::parse(&data).unwrap_err(), want);
    };
    check(&|d| d[0] = b'X', Error::BadMagic);
    check(&|d| set_u16(d, 8, 2), Error::UnsupportedVersion(2));
    check(&|d| set_u16(d, 8, 0), Error::UnsupportedVersion(0));
    check(&|d| set_u16(d, 10, 0), Error::EmptyCell);
    check(&|d| set_u16(d, 12, 0), Error::EmptyCell);
    check(&|d| set_u16(d, 14, 5), Error::BaselineOutsideCell);
    check(&|d| set_u32(d, 16, 0), Error::NoGlyphs);
    check(&|d| set_u32(d, 20, 1), Error::ReservedNotZero);
    check(&|d| set_u32(d, 16, 6), Error::Truncated);
    check(&|d| set_u32(d, 16, 4), Error::TrailingData);
    check(&|d| set_u32(d, 16, u32::MAX), Error::Truncated);
    check(&|d| set_u16(d, 10, u16::MAX), Error::Truncated);
    check(&|d| d.push(0), Error::TrailingData);
    check(&|d| d.truncate(d.len() - 1), Error::Truncated);
    check(&|d| d.truncate(HEADER_LEN - 1), Error::Truncated);
    check(&|d| d.clear(), Error::Truncated);
}

#[test]
fn rejects_bad_code_points() {
    let bad = |cps: &[u32], want: Error| {
        let data = build(1, 1, 0, cps);
        assert_eq!(Atlas::parse(&data).unwrap_err(), want);
    };
    bad(&[0x41, 0x41, 0xfffd], Error::Unsorted);
    bad(&[0x42, 0x41, 0xfffd], Error::Unsorted);
    bad(&[0xfffd, 0x41], Error::Unsorted);
    bad(&[0x41, 0xd800, 0xfffd], Error::InvalidCodePoint(0xd800));
    bad(
        &[0x41, 0xfffd, 0x11_0000],
        Error::InvalidCodePoint(0x11_0000),
    );
    bad(&[0x41, 0x42], Error::MissingReplacement);
}

/// A small deterministic generator, so the mutation test needs no
/// dependency and always tries the same inputs.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }
}

/// Exercises every accessor of whatever `parse` accepts. Nothing here may
/// panic, and every bitmap must be exactly one cell long.
fn exercise(data: &[u8]) {
    let Ok(atlas) = Atlas::parse(data) else {
        return;
    };
    let cell = usize::from(atlas.cell_width()) * usize::from(atlas.cell_height());
    assert!(atlas.baseline() <= atlas.cell_height());
    assert_eq!(atlas.iter().count(), atlas.glyph_count());
    for (c, bitmap) in atlas.iter() {
        assert_eq!(bitmap.len(), cell);
        assert_eq!(atlas.glyph(c), Some(bitmap));
    }
    for c in ['\0', 'A', 'B', 'Ω', '\u{fffd}', char::MAX] {
        assert_eq!(atlas.glyph_or_replacement(c).len(), cell);
    }
}

#[test]
fn survives_mutation() {
    let good = build(3, 4, 3, &CPS);
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
    for _ in 0..200_000 {
        let mut data = good.clone();
        for _ in 0..=rng.below(4) {
            match rng.below(4) {
                0 => {
                    let i = rng.below(data.len().max(1));
                    if let Some(b) = data.get_mut(i) {
                        *b = u8::try_from(rng.next() & 0xff).unwrap();
                    }
                }
                1 => {
                    let i = rng.below(data.len().max(1));
                    if let Some(b) = data.get_mut(i) {
                        *b ^= 1 << rng.below(8);
                    }
                }
                2 => data.truncate(rng.below(data.len() + 1)),
                _ => data.push(u8::try_from(rng.next() & 0xff).unwrap()),
            }
        }
        exercise(&data);
    }
}

#[test]
fn survives_every_truncation_and_single_byte_value() {
    let good = build(2, 3, 2, &CPS);
    for len in 0..=good.len() {
        exercise(&good[..len]);
    }
    for i in 0..good.len() {
        for value in 0..=u8::MAX {
            let mut data = good.clone();
            data[i] = value;
            exercise(&data);
        }
    }
}

#[test]
fn header_lengths_report_overflow() {
    let header = Header {
        cell_width: u16::MAX,
        cell_height: u16::MAX,
        baseline: 0,
        glyph_count: u32::MAX,
    };
    if usize::BITS <= 32 {
        assert_eq!(header.encoded_len(), None);
    } else {
        assert!(header.encoded_len().is_some());
    }
}

#[test]
fn errors_display() {
    use core::fmt::Write;
    let mut s = std::string::String::new();
    write!(s, "{}", Error::InvalidCodePoint(0xd800)).unwrap();
    assert!(s.contains("0xd800"));
}

/// The kernel embeds atlases with `include_bytes!`, which gives no
/// alignment, so the reader must work at any offset.
#[test]
fn parses_at_any_alignment() {
    let good = build(3, 4, 3, &CPS);
    for pad in 0..8 {
        let mut data = std::vec![0xAAu8; pad];
        data.extend_from_slice(&good);
        let atlas = Atlas::parse(&data[pad..]).unwrap();
        assert_eq!(atlas.glyph('Ω'), Some(&[3u8; 12][..]));
    }
}

/// The ends of the code point range: U+0000 and U+10FFFF are valid, the
/// surrogate edges and anything past U+10FFFF aren't.
#[test]
fn code_point_range_edges() {
    let data = build(1, 2, 1, &[0, 0xd7ff, 0xe000, 0xfffd, 0x10_ffff]);
    let atlas = Atlas::parse(&data).unwrap();
    assert_eq!(atlas.glyph('\0'), Some(&[0u8; 2][..]));
    assert_eq!(atlas.glyph('\u{d7ff}'), Some(&[1u8; 2][..]));
    assert_eq!(atlas.glyph('\u{e000}'), Some(&[2u8; 2][..]));
    assert_eq!(atlas.glyph(char::MAX), Some(&[4u8; 2][..]));
    assert_eq!(atlas.glyph('\u{10fffe}'), None);
    for bad in [0xd800, 0xdfff, 0x11_0000, u32::MAX] {
        let data = build(1, 1, 0, &[0x41, 0xfffd, bad]);
        assert_eq!(
            Atlas::parse(&data).unwrap_err(),
            Error::InvalidCodePoint(bad)
        );
    }
}

/// A header that claims huge cells or glyph counts over a short buffer is
/// rejected from the header alone, without reading past the data.
#[test]
fn huge_claims_over_short_data() {
    for (w, h, n) in [
        (u16::MAX, u16::MAX, 1),
        (u16::MAX, u16::MAX, u32::MAX),
        (1, 1, u32::MAX),
        (1, 1, u32::MAX / 4),
        (1, 1, 0x4000_0000),
    ] {
        let header = Header {
            cell_width: w,
            cell_height: h,
            baseline: 0,
            glyph_count: n,
        };
        let mut data = Vec::from(header.to_bytes());
        data.extend_from_slice(&0xfffdu32.to_le_bytes());
        data.push(0);
        let err = Atlas::parse(&data).unwrap_err();
        assert!(
            matches!(err, Error::Truncated | Error::TooLarge),
            "{w}x{h}x{n}: {err:?}"
        );
    }
}

/// Every byte length of the bitmaps, plus or minus one, around a valid
/// atlas: only the exact length parses.
#[test]
fn only_the_exact_length_parses() {
    let good = build(2, 3, 1, &CPS);
    for len in 0..good.len() + 8 {
        let mut data = good.clone();
        data.resize(len, 0);
        assert_eq!(Atlas::parse(&data).is_ok(), len == good.len(), "{len}");
    }
}

/// `Header::to_bytes` and `parse` agree on every field.
#[test]
fn header_round_trips() {
    let data = build(9, 17, 13, &CPS);
    let atlas = Atlas::parse(&data).unwrap();
    assert_eq!(
        atlas.header(),
        Header {
            cell_width: 9,
            cell_height: 17,
            baseline: 13,
            glyph_count: 5,
        }
    );
    assert_eq!(&data[..8], b"ASPISGLA");
    assert_eq!(&data[8..10], &[1, 0]);
    assert_eq!(&data[20..24], &[0, 0, 0, 0]);
}
