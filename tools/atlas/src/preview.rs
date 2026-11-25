// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! A grayscale preview of the atlases, for a person to check by eye.

use glyph_atlas::Atlas;

/// The sample text: Latin, Greek and Cyrillic, punctuation and symbols,
/// box-drawing frames, blocks and shades. The last line has a character no
/// atlas covers, which should come out as U+FFFD.
const SAMPLE: &[&str] = &[
    "The quick brown fox jumps over the lazy dog. 0123456789",
    "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ¡¿ «» ‹› “” ‘’ „ ‚ – — … • †‡",
    "ÀÉÎÕÜ àéîõü Çç Ñ ŁŒŠŽ łœšž ĞğİıŞş Ő ő ẀẂỲ ŷ ß Æ Ø Å ď ŀ ŉ Ǻ",
    "Ξεσκεπάζω την ψυχοφθόρα βδελυγμία. ΑΒΓΔΕΖΗΘ Ά Έ Ή Ί Ό Ϋ ΰ",
    "Съешь же ещё этих мягких французских булок, да выпей чаю. ЁЇЎҐ ЀЍ",
    "€ £ ¥ ₧ ₤ ™ № ℓ Ω ℮ ⅛⅜⅝⅞ ←↑→↓↔↕ ∂∆−∙√∞∩≈≠≡≤≥ ⌐⌠⌡ ‗ ⁄",
    "■□▪▫▬▲►▼◄◊○●◘◙◦",
    "┌──┬──┐ ╔══╦══╗ ┏━━┳━━┓ ╒══╤══╕ ╓──╥──╖ ┍━━┯━━┑ ╭──╮ ╱╲╱╲",
    "│ab│cd│ ║ab║cd║ ┃ab┃cd┃ │ab│cd│ ║ab║cd║ │ab│cd│ │  │ ╲╱╲╱",
    "├──┼──┤ ╠══╬══╣ ┣━━╋━━┫ ╞══╪══╡ ╟──╫──╢ ┝━━┿━━┥ ╰──╯ ╳╳╳╳",
    "│ab│cd│ ║ab║cd║ ┃ab┃cd┃ │ab│cd│ ║ab║cd║ │ab│cd│ ┄┄┄┄ ┆┊╎╏",
    "└──┴──┘ ╚══╩══╝ ┗━━┻━━┛ ╘══╧══╛ ╙──╨──╜ ┕━━┷━━┙ ┈┈┈┈ ╌╍┅┉",
    "░░▒▒▓▓██ ▀▄▌▐ ▁▂▃▄▅▆▇█ ▏▎▍▌▋▊▉ ▖▗▘▙▚▛▜▝▞▟ ▔▕",
    "Missing: 中 ☺ ∑ (should show the replacement character) �",
];

/// The sample lines, then every box-drawing character, 32 to a line with
/// a space between each.
fn lines() -> Vec<String> {
    let mut out: Vec<String> = SAMPLE.iter().map(|s| (*s).to_owned()).collect();
    let every: Vec<char> = (0x2500..=0x257F).filter_map(char::from_u32).collect();
    for row in every.chunks(32) {
        out.push(row.iter().flat_map(|&c| [c, ' ']).collect());
    }
    out
}

const MARGIN: usize = 8;

/// Renders the sample lines from each atlas, one block under the other, dark ink
/// on a white ground, as a binary PGM.
#[must_use]
pub fn render(atlases: &[Atlas<'_>]) -> Vec<u8> {
    let lines = lines();
    let columns = lines
        .iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0);
    let width = atlases
        .iter()
        .map(|a| columns * usize::from(a.cell_width()))
        .max()
        .unwrap_or(0)
        + 2 * MARGIN;
    let height = atlases
        .iter()
        .map(|a| lines.len() * usize::from(a.cell_height()) + MARGIN)
        .sum::<usize>()
        + MARGIN;
    let mut image = vec![255u8; width * height];
    let mut top = MARGIN;
    for atlas in atlases {
        let (cw, ch) = (
            usize::from(atlas.cell_width()),
            usize::from(atlas.cell_height()),
        );
        for (row, line) in lines.iter().enumerate() {
            for (col, c) in line.chars().enumerate() {
                let glyph = atlas.glyph_or_replacement(c);
                for (i, &coverage) in glyph.iter().enumerate() {
                    let x = MARGIN + col * cw + i % cw;
                    let y = top + row * ch + i / cw;
                    if let Some(p) = image.get_mut(y * width + x) {
                        *p = 255 - coverage;
                    }
                }
            }
        }
        top += lines.len() * ch + MARGIN;
    }
    let mut out = format!("P5\n{width} {height}\n255\n").into_bytes();
    out.extend_from_slice(&image);
    out
}
