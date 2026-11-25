// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The glyph atlas format, `ASPISGLA`, and a reader for it.
//!
//! The kernel console draws text from atlases rasterized at build time
//! ([ADR 0009], rule 3; [ADR 0034], rule 4). An atlas holds one cell size
//! of a monospace font: a sorted list of code points and, for each, a
//! bitmap of 8-bit coverage values that the console blends with its colors.
//!
//! # Format
//!
//! All integers are little-endian.
//!
//! | Offset | Size | Field                                             |
//! |-------:|-----:|---------------------------------------------------|
//! |      0 |    8 | magic, `"ASPISGLA"`                               |
//! |      8 |    2 | version, `u16`, 1                                 |
//! |     10 |    2 | cell width in pixels, `u16`, at least 1           |
//! |     12 |    2 | cell height in pixels, `u16`, at least 1          |
//! |     14 |    2 | baseline, `u16`, at most the cell height          |
//! |     16 |    4 | glyph count, `u32`, at least 1                    |
//! |     20 |    4 | reserved, `u32`, 0                                |
//! |     24 |  4·n | code points, `u32` each, strictly ascending       |
//! |        |  w·h·n | bitmaps, one per code point, in the same order |
//!
//! The baseline is the distance in pixels from the top of the cell to the
//! baseline: a glyph's ink above the baseline lies in rows `0..baseline`,
//! and its descenders in rows `baseline..cell_height`.
//!
//! Each bitmap is `cell_width * cell_height` bytes, row-major from the top
//! left. A byte is coverage: 0 is background and 255 is full ink.
//!
//! Every code point is a Unicode scalar value, and every atlas contains
//! U+FFFD REPLACEMENT CHARACTER, which the console draws for any character
//! the atlas lacks. The file ends after the last bitmap.
//!
//! [ADR 0009]: ../../docs/decisions/0009-text-as-graphics-console.md
//! [ADR 0034]: ../../docs/decisions/0034-noto-fonts-under-ofl.md

#![no_std]

use core::fmt;

/// The eight bytes every atlas starts with.
pub const MAGIC: [u8; 8] = *b"ASPISGLA";

/// The format version this crate reads and writes.
pub const VERSION: u16 = 1;

/// The length of the fixed header, in bytes.
pub const HEADER_LEN: usize = 24;

/// The character drawn in place of any character an atlas lacks.
pub const REPLACEMENT: char = '\u{FFFD}';

/// Why an atlas failed to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The data ends before the header, code points or bitmaps do.
    Truncated,
    /// The data doesn't start with [`MAGIC`].
    BadMagic,
    /// The version isn't [`VERSION`].
    UnsupportedVersion(u16),
    /// The cell width or height is zero.
    EmptyCell,
    /// The baseline is below the bottom of the cell.
    BaselineOutsideCell,
    /// The glyph count is zero.
    NoGlyphs,
    /// The reserved field isn't zero.
    ReservedNotZero,
    /// The sizes the header gives overflow `usize`.
    TooLarge,
    /// A code point isn't a Unicode scalar value.
    InvalidCodePoint(u32),
    /// The code points aren't strictly ascending.
    Unsorted,
    /// The atlas has no glyph for U+FFFD REPLACEMENT CHARACTER.
    MissingReplacement,
    /// Bytes follow the last bitmap.
    TrailingData,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("glyph atlas is truncated"),
            Self::BadMagic => f.write_str("not a glyph atlas (bad magic)"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported glyph atlas version {v}"),
            Self::EmptyCell => f.write_str("glyph atlas cell has zero width or height"),
            Self::BaselineOutsideCell => f.write_str("glyph atlas baseline is outside the cell"),
            Self::NoGlyphs => f.write_str("glyph atlas has no glyphs"),
            Self::ReservedNotZero => f.write_str("glyph atlas reserved field is not zero"),
            Self::TooLarge => f.write_str("glyph atlas sizes overflow"),
            Self::InvalidCodePoint(cp) => {
                write!(
                    f,
                    "glyph atlas code point {cp:#x} is not a Unicode scalar value"
                )
            }
            Self::Unsorted => f.write_str("glyph atlas code points are not strictly ascending"),
            Self::MissingReplacement => f.write_str("glyph atlas lacks U+FFFD"),
            Self::TrailingData => f.write_str("glyph atlas has trailing data"),
        }
    }
}

impl core::error::Error for Error {}

/// An atlas's fixed header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The cell width in pixels.
    pub cell_width: u16,
    /// The cell height in pixels.
    pub cell_height: u16,
    /// The distance in pixels from the top of the cell to the baseline.
    pub baseline: u16,
    /// The number of glyphs.
    pub glyph_count: u32,
}

impl Header {
    /// Encodes the header, for a writer that then appends the code points
    /// and bitmaps. It doesn't check the values; [`Atlas::parse`] does.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        let fields: [(&[u8], usize); 6] = [
            (&MAGIC, 0),
            (&VERSION.to_le_bytes(), 8),
            (&self.cell_width.to_le_bytes(), 10),
            (&self.cell_height.to_le_bytes(), 12),
            (&self.baseline.to_le_bytes(), 14),
            (&self.glyph_count.to_le_bytes(), 16),
        ];
        for (bytes, offset) in fields {
            for (dst, src) in out.iter_mut().skip(offset).zip(bytes) {
                *dst = *src;
            }
        }
        out
    }

    /// The number of bytes in one glyph's bitmap, or `None` on overflow.
    #[must_use]
    pub fn cell_len(&self) -> Option<usize> {
        usize::from(self.cell_width).checked_mul(usize::from(self.cell_height))
    }

    /// The total length of an atlas with this header, or `None` on
    /// overflow.
    #[must_use]
    pub fn encoded_len(&self) -> Option<usize> {
        let count = usize::try_from(self.glyph_count).ok()?;
        let bitmaps = count.checked_mul(self.cell_len()?)?;
        HEADER_LEN
            .checked_add(count.checked_mul(4)?)?
            .checked_add(bitmaps)
    }
}

/// A parsed, validated glyph atlas, borrowing its bytes.
#[derive(Clone, Copy)]
pub struct Atlas<'a> {
    header: Header,
    cell_len: usize,
    count: usize,
    code_points: &'a [u8],
    bitmaps: &'a [u8],
}

impl fmt::Debug for Atlas<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Atlas")
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

impl<'a> Atlas<'a> {
    /// Parses and validates an atlas. It checks every field and every
    /// code point, so the accessors never fail on a parsed atlas.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] naming the first problem found.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let header_bytes = data.get(..HEADER_LEN).ok_or(Error::Truncated)?;
        if header_bytes.get(..8) != Some(&MAGIC[..]) {
            return Err(Error::BadMagic);
        }
        let field16 = |offset| u16_at(header_bytes, offset).ok_or(Error::Truncated);
        let field32 = |offset| u32_at(header_bytes, offset).ok_or(Error::Truncated);
        let version = field16(8)?;
        if version != VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let header = Header {
            cell_width: field16(10)?,
            cell_height: field16(12)?,
            baseline: field16(14)?,
            glyph_count: field32(16)?,
        };
        if header.cell_width == 0 || header.cell_height == 0 {
            return Err(Error::EmptyCell);
        }
        if header.baseline > header.cell_height {
            return Err(Error::BaselineOutsideCell);
        }
        if header.glyph_count == 0 {
            return Err(Error::NoGlyphs);
        }
        if field32(20)? != 0 {
            return Err(Error::ReservedNotZero);
        }

        let cell_len = header.cell_len().ok_or(Error::TooLarge)?;
        let count = usize::try_from(header.glyph_count).map_err(|_| Error::TooLarge)?;
        let total = header.encoded_len().ok_or(Error::TooLarge)?;
        if data.len() < total {
            return Err(Error::Truncated);
        }
        if data.len() > total {
            return Err(Error::TrailingData);
        }
        // `total` covers both slices, so these can't fail.
        let cps_end = count
            .checked_mul(4)
            .and_then(|n| n.checked_add(HEADER_LEN))
            .ok_or(Error::TooLarge)?;
        let code_points = data.get(HEADER_LEN..cps_end).ok_or(Error::Truncated)?;
        let bitmaps = data.get(cps_end..).ok_or(Error::Truncated)?;

        let mut previous: Option<u32> = None;
        let mut has_replacement = false;
        for chunk in code_points.as_chunks::<4>().0 {
            let cp = u32::from_le_bytes(*chunk);
            if char::from_u32(cp).is_none() {
                return Err(Error::InvalidCodePoint(cp));
            }
            if previous.is_some_and(|p| p >= cp) {
                return Err(Error::Unsorted);
            }
            has_replacement |= cp == u32::from(REPLACEMENT);
            previous = Some(cp);
        }
        if !has_replacement {
            return Err(Error::MissingReplacement);
        }

        Ok(Self {
            header,
            cell_len,
            count,
            code_points,
            bitmaps,
        })
    }

    /// The header's fields.
    #[must_use]
    pub fn header(&self) -> Header {
        self.header
    }

    /// The cell width in pixels.
    #[must_use]
    pub fn cell_width(&self) -> u16 {
        self.header.cell_width
    }

    /// The cell height in pixels.
    #[must_use]
    pub fn cell_height(&self) -> u16 {
        self.header.cell_height
    }

    /// The distance in pixels from the top of the cell to the baseline.
    #[must_use]
    pub fn baseline(&self) -> u16 {
        self.header.baseline
    }

    /// The number of glyphs, always at least 1.
    #[must_use]
    pub fn glyph_count(&self) -> usize {
        self.count
    }

    fn code_point_at(&self, index: usize) -> Option<u32> {
        u32_at(self.code_points, index.checked_mul(4)?)
    }

    fn bitmap_at(&self, index: usize) -> Option<&'a [u8]> {
        let start = index.checked_mul(self.cell_len)?;
        self.bitmaps.get(start..start.checked_add(self.cell_len)?)
    }

    /// The bitmap for `c`, or `None` if the atlas lacks it. The bitmap is
    /// `cell_width * cell_height` coverage bytes, row-major.
    #[must_use]
    pub fn glyph(&self, c: char) -> Option<&'a [u8]> {
        let target = u32::from(c);
        let (mut lo, mut hi) = (0usize, self.count);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let cp = self.code_point_at(mid)?;
            match cp.cmp(&target) {
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
                core::cmp::Ordering::Equal => return self.bitmap_at(mid),
            }
        }
        None
    }

    /// The bitmap for `c`, or for U+FFFD if the atlas lacks `c`.
    #[must_use]
    pub fn glyph_or_replacement(&self, c: char) -> &'a [u8] {
        // `parse` checked that U+FFFD is present, so the fallbacks after it
        // are unreachable; they keep this free of panics all the same.
        self.glyph(c)
            .or_else(|| self.glyph(REPLACEMENT))
            .or_else(|| self.bitmap_at(0))
            .unwrap_or(&[])
    }

    /// Every glyph, in ascending code point order.
    pub fn iter(&self) -> impl Iterator<Item = (char, &'a [u8])> + 'a {
        let cell_len = self.cell_len;
        self.code_points
            .as_chunks::<4>()
            .0
            .iter()
            .zip(self.bitmaps.chunks_exact(cell_len))
            .filter_map(|(cp, bitmap)| Some((char::from_u32(u32::from_le_bytes(*cp))?, bitmap)))
    }
}

#[cfg(test)]
mod tests;
