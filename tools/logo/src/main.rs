// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Rasterizes the boot logo for the kernel console (ADR 0009, rule 3; C03).
//!
//! The kernel holds no SVG code, so the logo is drawn here, at build time,
//! into 8-bit coverage bitmaps that the console blends with its colors. The
//! logo is white on black, so a pixel's coverage is its luminance.
//!
//! One bitmap is made for each console atlas: four text rows high, so 64,
//! 96 and 128 pixels for the 16, 24 and 32 pixel cells (ADR 0034, rule 4).
//!
//! Usage: `logo --svg <file> --out <dir>` writes `logo-16.bin`,
//! `logo-24.bin` and `logo-32.bin`.

use glyph_atlas::bitmap::{Bitmap, HEADER_LEN};
use resvg::{tiny_skia, usvg};
use std::{env, fs, path::PathBuf, process::exit};

/// The console's cell heights, and the logo's height in rows.
const CELLS: [u16; 3] = [16, 24, 32];
const ROWS: u16 = 4;

fn fail(msg: impl AsRef<str>) -> ! {
    eprintln!("logo: {}", msg.as_ref());
    exit(1)
}

/// Renders `tree` `height` pixels high and returns (width, coverage).
fn render(tree: &usvg::Tree, height: u16) -> (u16, Vec<u8>) {
    let size = tree.size();
    let scale = height as f32 / size.height();
    let width = (size.width() * scale).round() as u16;
    let mut pixmap = tiny_skia::Pixmap::new(width as u32, height as u32)
        .unwrap_or_else(|| fail("bad bitmap size"));
    resvg::render(
        tree,
        tiny_skia::Transform::from_scale(scale, scale),
        &mut pixmap.as_mut(),
    );
    // Premultiplied RGBA over transparent; the logo paints its own black
    // background, so luminance is the coverage of the white ink.
    let coverage = pixmap
        .pixels()
        .iter()
        .map(|p| {
            let (r, g, b) = (p.red() as u32, p.green() as u32, p.blue() as u32);
            ((r * 2126 + g * 7152 + b * 722 + 5000) / 10000) as u8
        })
        .collect();
    (width, coverage)
}

fn main() {
    let mut svg = None;
    let mut out = None;
    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--svg" => svg = args.next().map(PathBuf::from),
            "--out" => out = args.next().map(PathBuf::from),
            _ => fail(format!(
                "unknown argument {a}; usage: logo --svg <file> --out <dir>"
            )),
        }
    }
    let (Some(svg), Some(out)) = (svg, out) else {
        fail("usage: logo --svg <file> --out <dir>")
    };
    let data = fs::read(&svg).unwrap_or_else(|e| fail(format!("{}: {e}", svg.display())));
    let tree = usvg::Tree::from_data(&data, &usvg::Options::default())
        .unwrap_or_else(|e| fail(format!("{}: {e}", svg.display())));
    fs::create_dir_all(&out).unwrap_or_else(|e| fail(format!("{}: {e}", out.display())));
    for cell in CELLS {
        let height = cell * ROWS;
        let (width, coverage) = render(&tree, height);
        let mut buf = vec![0u8; HEADER_LEN + coverage.len()];
        let n = Bitmap::encode(width, height, &coverage, &mut buf)
            .unwrap_or_else(|| fail("can't encode the bitmap"));
        let path = out.join(format!("logo-{cell}.bin"));
        fs::write(&path, &buf[..n]).unwrap_or_else(|e| fail(format!("{}: {e}", path.display())));
        eprintln!("{}: {width}x{height}", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checksum(bytes: &[u8]) -> u64 {
        // FNV-1a 64.
        bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
            (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3)
        })
    }

    #[test]
    fn logo_renders_white_on_black_at_four_rows() {
        let svg = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../assets/logo/aspis-boot.svg"
        );
        let tree =
            usvg::Tree::from_data(&fs::read(svg).unwrap(), &usvg::Options::default()).unwrap();
        for cell in CELLS {
            let (w, cov) = render(&tree, cell * ROWS);
            assert_eq!(cov.len(), w as usize * (cell * ROWS) as usize);
            // Mostly background, with real ink: neither blank nor solid.
            let ink = cov.iter().filter(|&&c| c > 128).count();
            assert!(
                ink > cov.len() / 20 && ink < cov.len() / 2,
                "cell {cell}: {ink} of {}",
                cov.len()
            );
            // The same input gives the same bytes.
            assert_eq!(checksum(&cov), checksum(&render(&tree, cell * ROWS).1));
        }
    }
}
