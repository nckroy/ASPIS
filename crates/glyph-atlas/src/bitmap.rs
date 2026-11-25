// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! A coverage bitmap, such as the boot logo (ADR 0009, rule 3), rasterized
//! at build time so the kernel needs no SVG code.
//!
//! Format, little-endian: the magic `ASPISBMP`; a version, u16, = 1; the
//! width and height, u16 each; a reserved u16, = 0; then width × height
//! bytes of 8-bit coverage, row-major (0 = background, 255 = full ink).

/// `ASPISBMP`.
pub const MAGIC: [u8; 8] = *b"ASPISBMP";
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 16;

/// Why a buffer isn't a valid bitmap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitmapError {
    Truncated,
    BadMagic,
    UnsupportedVersion(u16),
    Empty,
    ReservedNotZero,
    /// The data is longer or shorter than width × height.
    WrongLength,
}

/// A parsed bitmap borrowing its bytes.
#[derive(Clone, Copy, Debug)]
pub struct Bitmap<'a> {
    width: u16,
    height: u16,
    coverage: &'a [u8],
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    let bytes = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([*bytes.first()?, *bytes.get(1)?]))
}

impl<'a> Bitmap<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, BitmapError> {
        let header = data.get(..HEADER_LEN).ok_or(BitmapError::Truncated)?;
        if header.get(..8) != Some(&MAGIC[..]) {
            return Err(BitmapError::BadMagic);
        }
        let version = u16_at(header, 8).ok_or(BitmapError::Truncated)?;
        if version != VERSION {
            return Err(BitmapError::UnsupportedVersion(version));
        }
        let width = u16_at(header, 10).ok_or(BitmapError::Truncated)?;
        let height = u16_at(header, 12).ok_or(BitmapError::Truncated)?;
        if u16_at(header, 14) != Some(0) {
            return Err(BitmapError::ReservedNotZero);
        }
        if width == 0 || height == 0 {
            return Err(BitmapError::Empty);
        }
        let coverage = data.get(HEADER_LEN..).ok_or(BitmapError::Truncated)?;
        if coverage.len() != width as usize * height as usize {
            return Err(BitmapError::WrongLength);
        }
        Ok(Self {
            width,
            height,
            coverage,
        })
    }

    pub fn width(&self) -> u16 {
        self.width
    }

    pub fn height(&self) -> u16 {
        self.height
    }

    /// width × height bytes, row-major.
    pub fn coverage(&self) -> &'a [u8] {
        self.coverage
    }

    /// Encodes a bitmap: the inverse of [`Bitmap::parse`]. Returns the number
    /// of bytes written, or `None` if `out` is too small or the size is bad.
    pub fn encode(width: u16, height: u16, coverage: &[u8], out: &mut [u8]) -> Option<usize> {
        let len = (width as usize).checked_mul(height as usize)?;
        if width == 0 || height == 0 || coverage.len() != len {
            return None;
        }
        let total = HEADER_LEN.checked_add(len)?;
        let out = out.get_mut(..total)?;
        let (head, body) = out.split_at_mut(HEADER_LEN);
        head.fill(0);
        head.get_mut(..8)?.copy_from_slice(&MAGIC);
        head.get_mut(8..10)?.copy_from_slice(&VERSION.to_le_bytes());
        head.get_mut(10..12)?.copy_from_slice(&width.to_le_bytes());
        head.get_mut(12..14)?.copy_from_slice(&height.to_le_bytes());
        body.copy_from_slice(coverage);
        Some(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let cov = [0u8, 64, 128, 255, 1, 2];
        let mut buf = [0u8; 64];
        let n = Bitmap::encode(3, 2, &cov, &mut buf).unwrap();
        let b = Bitmap::parse(&buf[..n]).unwrap();
        assert_eq!((b.width(), b.height()), (3, 2));
        assert_eq!(b.coverage(), &cov);
    }

    #[test]
    fn rejects_bad_input() {
        let mut buf = [0u8; 64];
        let n = Bitmap::encode(3, 2, &[9; 6], &mut buf).unwrap();
        assert_eq!(
            Bitmap::parse(&buf[..n - 1]).unwrap_err(),
            BitmapError::WrongLength
        );
        assert_eq!(
            Bitmap::parse(&buf[..10]).unwrap_err(),
            BitmapError::Truncated
        );
        let mut bad = buf;
        bad[0] = b'a';
        assert_eq!(Bitmap::parse(&bad[..n]).unwrap_err(), BitmapError::BadMagic);
        let mut bad = buf;
        bad[14] = 1;
        assert_eq!(
            Bitmap::parse(&bad[..n]).unwrap_err(),
            BitmapError::ReservedNotZero
        );
        assert!(Bitmap::encode(0, 2, &[], &mut buf).is_none());
        // Every truncation and every single-byte change parses or fails cleanly.
        for cut in 0..=n {
            let _ = Bitmap::parse(&buf[..cut]);
        }
        for at in 0..n {
            for v in [0u8, 1, 0x7f, 0xff] {
                let mut m = buf;
                m[at] = v;
                let _ = Bitmap::parse(&m[..n]);
            }
        }
    }
}
