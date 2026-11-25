// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Generates the kernel console's glyph atlases from Noto Sans Mono
//! (ADR 0009, rule 3; ADR 0034, rule 4).
//!
//! ```text
//! atlas --font <ttf> --out <dir> [--check] [--preview <file.pgm>]
//! ```
//!
//! Writes `atlas-16.bin`, `atlas-24.bin` and `atlas-32.bin`, in the
//! `glyph-atlas` format, into `<dir>`. With `--check` it writes nothing,
//! and fails unless the files in `<dir>` already match, byte for byte.
//! With `--preview` it also writes a grayscale image of sample text from
//! each atlas.
//!
//! The output depends only on the font file and this program: the same
//! inputs give the same bytes on every run (ADR 0038, rule 1).

mod boxes;
mod glyphs;
mod preview;
mod raster;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use glyph_atlas::Atlas;

/// The cell heights of the three atlases (ADR 0034, rule 4).
pub const CELL_HEIGHTS: [u16; 3] = [16, 24, 32];

/// Clipped coverage at or above this is worth reporting.
const VISIBLE_CLIP: u8 = 64;

struct Args {
    font: PathBuf,
    out: PathBuf,
    check: bool,
    preview: Option<PathBuf>,
}

const USAGE: &str = "usage: atlas --font <ttf> --out <dir> [--check] [--preview <file.pgm>]";

fn parse_args(mut args: impl Iterator<Item = std::ffi::OsString>) -> Result<Args, String> {
    let (mut font, mut out, mut check, mut preview) = (None, None, false, None);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| {
            args.next()
                .map(PathBuf::from)
                .ok_or_else(|| format!("{name} needs a value\n{USAGE}"))
        };
        match arg.to_str() {
            Some("--font") => font = Some(value("--font")?),
            Some("--out") => out = Some(value("--out")?),
            Some("--preview") => preview = Some(value("--preview")?),
            Some("--check") => check = true,
            Some("-h" | "--help") => return Err(USAGE.into()),
            _ => return Err(format!("unexpected argument {arg:?}\n{USAGE}")),
        }
    }
    Ok(Args {
        font: font.ok_or_else(|| format!("--font is required\n{USAGE}"))?,
        out: out.ok_or_else(|| format!("--out is required\n{USAGE}"))?,
        check,
        preview,
    })
}

fn file_name(cell_height: u16) -> String {
    format!("atlas-{cell_height}.bin")
}

fn describe(chars: &[char]) -> String {
    chars
        .iter()
        .map(|&c| format!("U+{:04X}", u32::from(c)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn run(args: &Args) -> Result<bool, String> {
    let font = std::fs::read(&args.font)
        .map_err(|e| format!("can't read {}: {e}", args.font.display()))?;
    let set = glyphs::glyph_set();
    let mut built = Vec::new();
    for height in CELL_HEIGHTS {
        let atlas = raster::build(&font, height, &set)?;
        let g = atlas.geometry;
        eprintln!(
            "{}: {}x{} cells, baseline {}, {:.3} px, {} glyphs, {} bytes",
            file_name(height),
            g.cell_width,
            g.cell_height,
            g.baseline,
            g.px,
            set.len() - atlas.missing.len(),
            atlas.bytes.len(),
        );
        if !atlas.missing.is_empty() {
            eprintln!(
                "  not in the font, drawn as U+FFFD: {}",
                describe(&atlas.missing)
            );
        }
        if !atlas.narrowed.is_empty() {
            eprintln!(
                "  wider than a cell, drawn smaller: {}",
                describe(&atlas.narrowed)
            );
        }
        // Faint edges of anti-aliasing are routinely clipped; name only the
        // glyphs that lose visible ink.
        let visible: Vec<char> = atlas
            .clipped
            .iter()
            .filter(|(_, lost)| *lost >= VISIBLE_CLIP)
            .map(|(c, _)| *c)
            .collect();
        if !atlas.clipped.is_empty() {
            eprintln!(
                "  clipped to the cell: {} glyphs, {} losing coverage {VISIBLE_CLIP} or more: {}",
                atlas.clipped.len(),
                visible.len(),
                describe(&visible)
            );
        }
        built.push((height, atlas));
    }

    let mut ok = true;
    for (height, atlas) in &built {
        let path = args.out.join(file_name(*height));
        if args.check {
            match std::fs::read(&path) {
                Ok(existing) if existing == atlas.bytes => {}
                Ok(_) => {
                    eprintln!("{} is out of date", path.display());
                    ok = false;
                }
                Err(e) => {
                    eprintln!("can't read {}: {e}", path.display());
                    ok = false;
                }
            }
        } else {
            write(&path, &atlas.bytes)?;
        }
    }

    if let Some(preview_path) = &args.preview {
        let atlases = built
            .iter()
            .map(|(_, a)| Atlas::parse(&a.bytes).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        write(preview_path, &preview::render(&atlases))?;
    }
    Ok(ok)
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|e| format!("can't create {}: {e}", dir.display()))?;
    }
    std::fs::write(path, bytes).map_err(|e| format!("can't write {}: {e}", path.display()))
}

fn main() -> ExitCode {
    let result = parse_args(std::env::args_os().skip(1)).and_then(|args| run(&args));
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("atlas: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Result<Args, String> {
        parse_args(list.iter().map(std::ffi::OsString::from))
    }

    #[test]
    fn parses_arguments() {
        let a = args(&["--font", "f.ttf", "--out", "d", "--check"]).unwrap();
        assert_eq!(a.font, PathBuf::from("f.ttf"));
        assert_eq!(a.out, PathBuf::from("d"));
        assert!(a.check);
        assert!(a.preview.is_none());
        let a = args(&["--out", "d", "--font", "f", "--preview", "p.pgm"]).unwrap();
        assert!(!a.check);
        assert_eq!(a.preview, Some(PathBuf::from("p.pgm")));
        assert!(args(&["--font", "f"]).is_err());
        assert!(args(&["--out", "d"]).is_err());
        assert!(args(&["--font"]).is_err());
        assert!(args(&["--font", "f", "--out", "d", "--bogus"]).is_err());
    }

    /// The WGL4 characters Noto Sans Mono 2.014 has no glyph for: the soft
    /// hyphen, some arrows, math operators and technical symbols, the
    /// dingbats from code page 437, and the fi and fl ligatures.
    const NOTO_MONO_LACKS: [u32; 23] = [
        0x00AD, 0x21A8, 0x220F, 0x2211, 0x2215, 0x221F, 0x222B, 0x2302, 0x263A, 0x263B, 0x263C,
        0x2640, 0x2642, 0x2660, 0x2663, 0x2665, 0x2666, 0x266A, 0x266B, 0xF001, 0xF002, 0xFB01,
        0xFB02,
    ];

    /// The vendored font, pinned in assets/fonts/fonts.lock.
    fn noto() -> Vec<u8> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../assets/fonts/NotoSansMono-Regular.ttf"
        );
        std::fs::read(path).unwrap()
    }

    #[test]
    fn builds_deterministic_valid_atlases_from_noto() {
        let font = noto();
        let set = glyphs::glyph_set();
        for height in CELL_HEIGHTS {
            let first = raster::build(&font, height, &set).unwrap();
            let second = raster::build(&font, height, &set).unwrap();
            assert_eq!(
                first.bytes, second.bytes,
                "atlas-{height} differs between runs"
            );
            let missing: Vec<u32> = first.missing.iter().map(|&c| u32::from(c)).collect();
            assert_eq!(
                missing,
                NOTO_MONO_LACKS,
                "missing: {}",
                describe(&first.missing)
            );
            let atlas = Atlas::parse(&first.bytes).unwrap();
            assert_eq!(atlas.cell_height(), height);
            assert_eq!(atlas.glyph_count(), set.len() - first.missing.len());
            for &c in &set {
                if !first.missing.contains(&c) {
                    assert!(atlas.glyph(c).is_some(), "U+{:04X}", u32::from(c));
                }
            }
            // A space is blank, a full block is solid, and 'M' has ink.
            assert!(atlas.glyph(' ').unwrap().iter().all(|&p| p == 0));
            assert!(atlas.glyph('█').unwrap().iter().all(|&p| p == 255));
            assert!(atlas.glyph('M').unwrap().iter().any(|&p| p > 128));
        }
    }

    /// FNV-1a, 64-bit: enough to notice any change in the bytes.
    fn fnv1a(bytes: &[u8]) -> u64 {
        bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
            (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
        })
    }

    /// The atlases are the same bytes on every host, not just from run to
    /// run on one (ADR 0038, rule 1). These checksums were taken on macOS
    /// (aarch64); CI on Linux must get the same. If a change to the tool
    /// is meant to change the output, update them.
    #[test]
    fn atlases_match_their_known_checksums() {
        let font = noto();
        let set = glyphs::glyph_set();
        let known: [(u16, u64, usize); 3] = [
            (16, 0x942a_6883_c64c_8635, 86_676),
            (24, 0x52e9_72dd_ead5_6f11, 200_220),
            (32, 0x8eb4_1c11_8391_b075, 337_668),
        ];
        for (height, sum, len) in known {
            let built = raster::build(&font, height, &set).unwrap();
            assert_eq!(built.bytes.len(), len, "atlas-{height} length");
            assert_eq!(fnv1a(&built.bytes), sum, "atlas-{height} checksum");
        }
    }

    #[test]
    fn rejects_a_file_that_is_not_a_font() {
        assert!(raster::build(b"not a font", 16, &glyphs::glyph_set()).is_err());
    }

    #[test]
    fn preview_is_a_pgm() {
        let font = noto();
        let set = glyphs::glyph_set();
        let built = raster::build(&font, 16, &set).unwrap();
        let atlas = Atlas::parse(&built.bytes).unwrap();
        let image = preview::render(&[atlas]);
        assert!(image.starts_with(b"P5\n"));
    }
}
