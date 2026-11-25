// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Generates the kernel console's glyph atlases from Noto Sans Mono, with
//! Noto Sans Math and Noto Sans Symbols as fallbacks (ADR 0009, rule 3;
//! ADR 0034, rule 4; ADR 0046).
//!
//! ```text
//! atlas --font <ttf> [--fallback <ttf>]... --out <dir> [--check] [--preview <file.pgm>]
//! ```
//!
//! Writes `atlas-16.bin`, `atlas-24.bin` and `atlas-32.bin`, in the
//! `glyph-atlas` format, into `<dir>`. The cells are sized from `--font`.
//! A character `--font` lacks comes from the first `--fallback`, in the
//! order given, that has it. If any character in the set has no glyph in
//! any font, the tool reports it and fails, writing nothing (ADR 0046,
//! Consequences). With `--check` it writes nothing, and fails unless the
//! files in `<dir>` already match, byte for byte. With `--preview` it also
//! writes a grayscale image of sample text from each atlas.
//!
//! The output depends only on the font files, their order and this
//! program: the same inputs give the same bytes on every run (ADR 0038,
//! rule 1).

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
    /// The fallback fonts, in the order to try them.
    fallbacks: Vec<PathBuf>,
    out: PathBuf,
    check: bool,
    preview: Option<PathBuf>,
}

const USAGE: &str = "usage: atlas --font <ttf> [--fallback <ttf>]... --out <dir> [--check] \
                     [--preview <file.pgm>]";

fn parse_args(mut args: impl Iterator<Item = std::ffi::OsString>) -> Result<Args, String> {
    let (mut font, mut out, mut check, mut preview) = (None, None, false, None);
    let mut fallbacks = Vec::new();
    while let Some(arg) = args.next() {
        let mut value = |name: &str| {
            args.next()
                .map(PathBuf::from)
                .ok_or_else(|| format!("{name} needs a value\n{USAGE}"))
        };
        match arg.to_str() {
            Some("--font") => font = Some(value("--font")?),
            Some("--fallback") => fallbacks.push(value("--fallback")?),
            Some("--out") => out = Some(value("--out")?),
            Some("--preview") => preview = Some(value("--preview")?),
            Some("--check") => check = true,
            Some("-h" | "--help") => return Err(USAGE.into()),
            _ => return Err(format!("unexpected argument {arg:?}\n{USAGE}")),
        }
    }
    Ok(Args {
        font: font.ok_or_else(|| format!("--font is required\n{USAGE}"))?,
        fallbacks,
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

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("can't read {}: {e}", path.display()))
}

fn run(args: &Args) -> Result<bool, String> {
    let font = read(&args.font)?;
    let fallbacks = args
        .fallbacks
        .iter()
        .map(|p| read(p))
        .collect::<Result<Vec<_>, _>>()?;
    let fallback_data: Vec<&[u8]> = fallbacks.iter().map(Vec::as_slice).collect();
    let set = glyphs::glyph_set();
    let mut built = Vec::new();
    for height in CELL_HEIGHTS {
        let atlas = raster::build(&font, &fallback_data, height, &set)?;
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
        // Every character in the set must have a glyph (ADR 0046): name
        // the ones that don't, and write nothing.
        if !atlas.missing.is_empty() {
            return Err(format!(
                "{}: {} characters have no glyph in any font, and would be drawn as U+FFFD: {}",
                file_name(height),
                atlas.missing.len(),
                describe(&atlas.missing)
            ));
        }
        for (i, path) in args.fallbacks.iter().enumerate() {
            let from: Vec<char> = atlas
                .fallback
                .iter()
                .filter(|(_, f)| *f == i)
                .map(|(c, _)| *c)
                .collect();
            if !from.is_empty() {
                eprintln!(
                    "  from {}: {}",
                    path.file_name().unwrap_or(path.as_os_str()).display(),
                    describe(&from)
                );
            }
        }
        if !atlas.shrunk.is_empty() {
            eprintln!(
                "  fallback glyphs too big for a cell, drawn smaller: {}",
                describe(&atlas.shrunk)
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
        assert!(a.fallbacks.is_empty());
        assert_eq!(a.out, PathBuf::from("d"));
        assert!(a.check);
        assert!(a.preview.is_none());
        let a = args(&["--out", "d", "--font", "f", "--preview", "p.pgm"]).unwrap();
        assert!(!a.check);
        assert_eq!(a.preview, Some(PathBuf::from("p.pgm")));
        let a = args(&[
            "--fallback",
            "b.ttf",
            "--font",
            "f",
            "--fallback",
            "a.ttf",
            "--out",
            "d",
        ])
        .unwrap();
        assert_eq!(
            a.fallbacks,
            [PathBuf::from("b.ttf"), PathBuf::from("a.ttf")]
        );
        assert!(args(&["--font", "f"]).is_err());
        assert!(args(&["--out", "d"]).is_err());
        assert!(args(&["--font"]).is_err());
        assert!(args(&["--font", "f", "--out", "d", "--fallback"]).is_err());
        assert!(args(&["--font", "f", "--out", "d", "--bogus"]).is_err());
    }

    /// The one of them Noto Sans Math lacks, which Noto Sans Symbols has.
    const SMILEY: char = '\u{263A}';

    /// A vendored font, pinned in assets/fonts/fonts.lock.
    fn font(file: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../assets/fonts")
            .join(file);
        std::fs::read(path).unwrap()
    }

    const MONO: &str = "NotoSansMono-Regular.ttf";
    const MATH: &str = "NotoSansMath-Regular.ttf";
    const SYMBOLS: &str = "NotoSansSymbols-Regular.ttf";

    /// The two fallbacks, in the order the build passes them.
    fn fallbacks() -> [Vec<u8>; 2] {
        [font(MATH), font(SYMBOLS)]
    }

    fn build(height: u16) -> raster::Built {
        let fallbacks = fallbacks();
        let fallback_data = [fallbacks[0].as_slice(), fallbacks[1].as_slice()];
        raster::build(&font(MONO), &fallback_data, height, &glyphs::glyph_set()).unwrap()
    }

    #[test]
    fn without_fallbacks_the_symbols_are_missing() {
        let set = glyphs::glyph_set();
        let built = raster::build(&font(MONO), &[], 16, &set).unwrap();
        let missing: Vec<u32> = built.missing.iter().map(|&c| u32::from(c)).collect();
        assert_eq!(
            missing,
            glyphs::FALLBACK_SYMBOLS,
            "{}",
            describe(&built.missing)
        );
        // The tool refuses to write atlases that lack them.
        let args = Args {
            font: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../assets/fonts/NotoSansMono-Regular.ttf"),
            fallbacks: Vec::new(),
            out: PathBuf::from("/nonexistent/atlas-test"),
            check: false,
            preview: None,
        };
        let err = run(&args).unwrap_err();
        assert!(err.contains("U+263A"), "{err}");
    }

    /// Every character in the set has a glyph: none falls back to U+FFFD
    /// (ADR 0046, Consequences).
    #[test]
    fn the_fonts_cover_the_whole_set() {
        let set = glyphs::glyph_set();
        for height in CELL_HEIGHTS {
            let first = build(height);
            assert!(first.missing.is_empty(), "{}", describe(&first.missing));
            let second = build(height);
            assert_eq!(
                first.bytes, second.bytes,
                "atlas-{height} differs between runs"
            );
            let atlas = Atlas::parse(&first.bytes).unwrap();
            assert_eq!(atlas.cell_height(), height);
            assert_eq!(atlas.glyph_count(), set.len());
            for &c in &set {
                assert!(atlas.glyph(c).is_some(), "U+{:04X}", u32::from(c));
            }
            // Noto Sans Math gives all the symbols but U+263A, which comes
            // from Noto Sans Symbols.
            let from: Vec<(u32, usize)> = first
                .fallback
                .iter()
                .map(|&(c, i)| (u32::from(c), i))
                .collect();
            let expected: Vec<(u32, usize)> = glyphs::FALLBACK_SYMBOLS
                .iter()
                .map(|&cp| (cp, usize::from(cp == u32::from(SMILEY))))
                .collect();
            assert_eq!(from, expected);
            // A space is blank, a full block is solid, and 'M' has ink.
            assert!(atlas.glyph(' ').unwrap().iter().all(|&p| p == 0));
            assert!(atlas.glyph('█').unwrap().iter().all(|&p| p == 255));
            assert!(atlas.glyph('M').unwrap().iter().any(|&p| p > 128));
            // The soft hyphen is drawn as a hyphen (ADR 0046, rule 2).
            assert_eq!(atlas.glyph(glyphs::SOFT_HYPHEN), atlas.glyph('-'));
            for cp in glyphs::EXCLUDED {
                assert!(atlas.glyph(char::from_u32(cp).unwrap()).is_none());
            }
        }
    }

    /// Each fallback glyph has ink, fits its cell, and sits on the baseline
    /// as its font draws it. A glyph that stands on the baseline in its
    /// font, such as the card suits, has its lowest ink on the row just
    /// above the baseline, or the row below. One that descends in its font,
    /// such as the n-ary operators, the integral, the division slash and
    /// the up-down arrow with base, still descends.
    #[test]
    fn fallback_glyphs_sit_on_the_baseline() {
        let fallbacks = fallbacks()
            .map(|data| fontdue::Font::from_bytes(data, fontdue::FontSettings::default()).unwrap());
        for height in CELL_HEIGHTS {
            let built = build(height);
            let atlas = Atlas::parse(&built.bytes).unwrap();
            let (w, baseline) = (
                usize::from(atlas.cell_width()),
                usize::from(built.geometry.baseline),
            );
            for &(c, i) in &built.fallback {
                let font = &fallbacks[i];
                let ymin = font.metrics(c, font.units_per_em()).bounds.ymin / font.units_per_em();
                let glyph = atlas.glyph(c).unwrap();
                // Thin outlines, such as U+263A's at 16 px, stay faint.
                assert!(glyph.iter().any(|&p| p >= 96), "U+{:04X}", u32::from(c));
                // The spare column on the right, or the left, stays blank.
                let column_blank = |x: usize| glyph.chunks(w).all(|row| row[x] == 0);
                assert!(
                    column_blank(0) || column_blank(w - 1),
                    "U+{:04X}",
                    u32::from(c)
                );
                let bottom = glyph
                    .chunks(w)
                    .rposition(|row| row.iter().any(|&p| p >= 64))
                    .unwrap();
                let at = format!(
                    "U+{:04X} at {height} px: ink ends on row {bottom}, baseline {baseline}",
                    u32::from(c)
                );
                // Within a tenth of an em is on the baseline: U+263C and
                // U+266B dip a little below it.
                if ymin.abs() < 0.1 {
                    assert!((baseline - 1..=baseline).contains(&bottom), "{at}");
                } else {
                    assert!(ymin < -0.15, "{at}: ymin {ymin} em");
                    assert!(bottom >= baseline, "{at}");
                }
            }
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
    ///
    /// They last changed for ADR 0046: the 18 symbols from the fallback
    /// fonts and the soft hyphen joined the atlases, 19 more glyphs. The
    /// four excluded code points left the set, but had no glyph before.
    #[test]
    fn atlases_match_their_known_checksums() {
        let known: [(u16, u64, usize); 3] = [
            (16, 0x2952_b08d_681d_dd88, 88_880),
            (24, 0x3c61_35c5_15dd_0f3c, 205_312),
            (32, 0xc2a5_d654_b44c_398a, 346_256),
        ];
        for (height, sum, len) in known {
            let built = build(height);
            assert_eq!(built.bytes.len(), len, "atlas-{height} length");
            assert_eq!(fnv1a(&built.bytes), sum, "atlas-{height} checksum");
        }
    }

    #[test]
    fn rejects_a_file_that_is_not_a_font() {
        let set = glyphs::glyph_set();
        assert!(raster::build(b"not a font", &[], 16, &set).is_err());
        let mono = font(MONO);
        assert!(raster::build(&mono, &[b"not a font"], 16, &set).is_err());
    }

    #[test]
    fn preview_is_a_pgm() {
        let built = build(16);
        let atlas = Atlas::parse(&built.bytes).unwrap();
        let image = preview::render(&[atlas]);
        assert!(image.starts_with(b"P5\n"));
    }
}
