// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Rasterizes one atlas from the main font and its fallbacks.

use fontdue::{Font, FontSettings};
use glyph_atlas::{Atlas, Header, REPLACEMENT};

use crate::{boxes, glyphs};

/// The cell geometry for one atlas.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Geometry {
    /// The font size in pixels per em.
    pub px: f32,
    pub cell_width: u16,
    pub cell_height: u16,
    /// Rows from the top of the cell to the baseline.
    pub baseline: u16,
}

/// A finished atlas, with what the main font lacked.
pub struct Built {
    pub geometry: Geometry,
    pub bytes: Vec<u8>,
    /// Characters in the glyph set that no font has a glyph for. The atlas
    /// leaves them out, and the console would draw them as U+FFFD.
    pub missing: Vec<char>,
    /// Characters taken from a fallback font, each with the fallback's
    /// index in the order given.
    pub fallback: Vec<(char, usize)>,
    /// Fallback characters too big for the cell, drawn smaller to fit.
    pub shrunk: Vec<char>,
    /// Characters whose ink reached past the cell and was clipped, each
    /// with the highest coverage value lost.
    pub clipped: Vec<(char, u8)>,
    /// Characters wider than one cell in the font, drawn smaller to fit.
    pub narrowed: Vec<char>,
}

/// Draws `c` from the font into `cell`, on the baseline at the cell's
/// pen position `x_offset`. A glyph the font makes wider than one cell,
/// such as U+FFFD, is scaled down to fit and centered on its own middle.
/// Returns the highest coverage value clipped at the cell's edges, and
/// whether the glyph was scaled down.
fn draw_glyph(
    font: &Font,
    g: &Geometry,
    advance: f32,
    x_offset: i64,
    c: char,
    cell: &mut [u8],
) -> Result<(u8, bool), String> {
    let w = i64::from(g.cell_width);
    let natural = font.metrics(c, g.px);
    let to_i64 = |v: usize| i64::try_from(v).map_err(|e| e.to_string());
    // Rounding to whole pixels: the values are small and finite.
    #[allow(clippy::cast_possible_truncation)]
    let round = |v: f32| v.round() as i64;
    let wide = natural.advance_width > advance * 1.01;
    let (metrics, coverage, left, top) = if wide {
        let ink = natural.bounds.width.max(1.0);
        let scale = (f32::from(g.cell_width) * 0.9 / ink).min(1.0);
        let (m, bitmap) = font.rasterize(c, g.px * scale);
        let middle = natural.bounds.ymin + natural.bounds.height / 2.0;
        let left = (w - to_i64(m.width)?) / 2;
        let top = i64::from(g.baseline) - round(middle + m.bounds.height / 2.0);
        (m, bitmap, left, top)
    } else {
        let (m, bitmap) = font.rasterize(c, g.px);
        // fontdue's ymin is the bitmap's bottom row, up from the baseline.
        let top = i64::from(g.baseline) - i64::from(m.ymin) - to_i64(m.height)?;
        // Some glyphs overhang their advance, such as the tonos on Greek
        // capitals and the caron on ď. If the ink fits in the cell, nudge
        // it inside rather than lose it.
        let natural_left = x_offset + i64::from(m.xmin);
        let ink = to_i64(m.width)?;
        let left = if ink <= w {
            natural_left.clamp(0, w - ink)
        } else {
            natural_left
        };
        (m, bitmap, left, top)
    };
    Ok((blit(g, &coverage, metrics.width, left, top, cell)?, wide))
}

/// Copies a glyph's coverage, `width` pixels a row, into `cell` with its
/// top-left corner at (`left`, `top`). Returns the highest coverage value
/// that fell outside the cell.
fn blit(
    g: &Geometry,
    coverage: &[u8],
    width: usize,
    left: i64,
    top: i64,
    cell: &mut [u8],
) -> Result<u8, String> {
    let (w, h) = (i64::from(g.cell_width), i64::from(g.cell_height));
    let to_i64 = |v: usize| i64::try_from(v).map_err(|e| e.to_string());
    let mut lost = 0u8;
    for (row, line) in coverage.chunks(width.max(1)).enumerate() {
        let y = top + to_i64(row)?;
        for (col, &value) in line.iter().enumerate() {
            let x = left + to_i64(col)?;
            let pixel = if (0..w).contains(&x) && (0..h).contains(&y) {
                usize::try_from(y * w + x)
                    .ok()
                    .and_then(|i| cell.get_mut(i))
            } else {
                None
            };
            match pixel {
                Some(p) => *p = value,
                None => lost = lost.max(value),
            }
        }
    }
    Ok(lost)
}

/// The most times [`draw_fallback`] shrinks a glyph that still overflows.
const SHRINK_STEPS: u32 = 64;

/// Draws `c` from a fallback font into `cell` (ADR 0046, rule 1).
///
/// The glyph is rasterized at the main font's size, `g.px`, so the
/// fallback's em matches the main font's. If its ink is wider than the
/// cell less one column, or taller than the cell's ascent plus descent,
/// it is scaled down just enough to fit, and never scaled up. The spare
/// column keeps neighbors apart, as the main font's side bearings do: the
/// fallback fonts' symbols are wider than a monospace cell, and would
/// otherwise run together. The glyph is centered across the cell, and
/// sits on the console's baseline, scaled about it, so a symbol that
/// stands on the baseline still does. If that would put ink above or
/// below the cell, it moves up or down just enough to stay inside.
/// Returns whether the glyph was scaled down.
fn draw_fallback(font: &Font, g: &Geometry, c: char, cell: &mut [u8]) -> Result<bool, String> {
    let spare = g.cell_width.saturating_sub(1);
    let (w, h) = (usize::from(spare), usize::from(g.cell_height));
    let bounds = font.metrics(c, g.px).bounds;
    let mut scale = 1.0f32;
    if bounds.width > f32::from(spare) {
        scale = scale.min(f32::from(spare) / bounds.width);
    }
    if bounds.height > f32::from(g.cell_height) {
        scale = scale.min(f32::from(g.cell_height) / bounds.height);
    }
    // The bitmap covers every pixel the outline touches, so it can be a
    // pixel wider or taller than the outline's bounds. Shrink in small
    // steps until it fits.
    for _ in 0..SHRINK_STEPS {
        let (m, coverage) = font.rasterize(c, g.px * scale);
        if m.width <= w && m.height <= h {
            let to_i64 = |v: usize| i64::try_from(v).map_err(|e| e.to_string());
            let (width, height) = (to_i64(m.width)?, to_i64(m.height)?);
            // Centered in the whole cell, not just the columns it may fill.
            let left = (i64::from(g.cell_width) - width) / 2;
            // fontdue's ymin is the bitmap's bottom row, up from the baseline.
            let top =
                (i64::from(g.baseline) - i64::from(m.ymin) - height).clamp(0, to_i64(h)? - height);
            let lost = blit(g, &coverage, m.width, left, top, cell)?;
            debug_assert_eq!(lost, 0, "U+{:04X} overflowed", u32::from(c));
            return Ok(scale < 1.0);
        }
        scale *= 0.97;
    }
    Err(format!(
        "U+{:04X} from a fallback font won't fit a {}x{h} cell",
        u32::from(c),
        g.cell_width
    ))
}

fn load(data: &[u8], px: f32) -> Result<Font, String> {
    let settings = FontSettings {
        scale: px,
        ..FontSettings::default()
    };
    Font::from_bytes(data, settings).map_err(|e| format!("can't parse the font: {e}"))
}

/// Picks the font size for cells `cell_height` pixels high: the font's
/// ascent plus descent, from its horizontal line metrics, fills the cell.
/// The cell width is the advance of '0', rounded; the baseline is the
/// ascent, rounded.
///
/// # Errors
///
/// Fails if the font has no line metrics or no '0'.
pub fn geometry(font: &Font, cell_height: u16) -> Result<Geometry, String> {
    let em = font.units_per_em();
    let units = font
        .horizontal_line_metrics(em)
        .ok_or("the font has no horizontal line metrics")?;
    let extent = units.ascent - units.descent;
    if extent.is_nan() || extent <= 0.0 {
        return Err(format!("the font's ascent plus descent is {extent}"));
    }
    let px = f32::from(cell_height) * em / extent;
    let line = font
        .horizontal_line_metrics(px)
        .ok_or("the font has no horizontal line metrics")?;
    if !font.has_glyph('0') {
        return Err("the font has no '0' to measure the cell width by".into());
    }
    let advance = font.metrics('0', px).advance_width;
    let to_u16 = |v: f32, what: &str| -> Result<u16, String> {
        let r = v.round();
        if (1.0..=f32::from(cell_height.max(1)) * 4.0).contains(&r) {
            // In range, so the cast is exact.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            Ok(r as u16)
        } else {
            Err(format!("the {what} at {px} px is {v}"))
        }
    };
    let baseline = to_u16(line.ascent, "ascent")?.min(cell_height);
    Ok(Geometry {
        px,
        cell_width: to_u16(advance, "advance of '0'")?,
        cell_height,
        baseline,
    })
}

/// Builds the atlas with cells `cell_height` pixels high, covering every
/// character of `set` that [`boxes`] draws, or that the main font or one
/// of the fallbacks has. The cell geometry comes from the main font alone.
/// Each character's glyph comes from the main font if it has one, or else
/// from the first fallback, in order, that does. The soft hyphen is drawn
/// as a hyphen ([`glyphs::drawn_as`]).
///
/// # Errors
///
/// Fails if a font doesn't parse, the main font lacks U+FFFD, or the
/// geometry is one the format can't hold.
pub fn build(
    font_data: &[u8],
    fallback_data: &[&[u8]],
    cell_height: u16,
    set: &[char],
) -> Result<Built, String> {
    // The metrics don't depend on the load-time scale; the glyphs do.
    let probe = load(font_data, f32::from(cell_height))?;
    let g = geometry(&probe, cell_height)?;
    let font = load(font_data, g.px)?;
    let fallbacks = fallback_data
        .iter()
        .enumerate()
        .map(|(i, data)| load(data, g.px).map_err(|e| format!("fallback {}: {e}", i + 1)))
        .collect::<Result<Vec<_>, _>>()?;
    if !font.has_glyph(REPLACEMENT) {
        return Err("the font has no U+FFFD REPLACEMENT CHARACTER".into());
    }
    let (w, h) = (usize::from(g.cell_width), usize::from(g.cell_height));
    let cell_len = w * h;
    // Center the font's advance in the cell, to whole pixels.
    let advance = font.metrics('0', g.px).advance_width;
    let x_offset = ((f32::from(g.cell_width) - advance) / 2.0).round();
    #[allow(clippy::cast_possible_truncation)]
    let x_offset = x_offset as i64;

    let mut code_points = Vec::new();
    let mut bitmaps = Vec::new();
    let mut missing = Vec::new();
    let mut clipped = Vec::new();
    let mut narrowed = Vec::new();
    let mut fallback = Vec::new();
    let mut shrunk = Vec::new();
    for &c in set {
        let mut cell = vec![0u8; cell_len];
        let source = glyphs::drawn_as(c);
        if boxes::is_procedural(c) {
            boxes::draw(c, g.cell_width, g.cell_height, &mut cell);
        } else if font.has_glyph(source) {
            let (lost, wide) = draw_glyph(&font, &g, advance, x_offset, source, &mut cell)?;
            if wide {
                narrowed.push(c);
            }
            if lost > 0 {
                clipped.push((c, lost));
            }
        } else if let Some(i) = fallbacks.iter().position(|f| f.has_glyph(source)) {
            if draw_fallback(&fallbacks[i], &g, source, &mut cell)? {
                shrunk.push(c);
            }
            fallback.push((c, i));
        } else {
            missing.push(c);
            continue;
        }
        code_points.push(u32::from(c));
        bitmaps.extend_from_slice(&cell);
    }

    let header = Header {
        cell_width: g.cell_width,
        cell_height: g.cell_height,
        baseline: g.baseline,
        glyph_count: u32::try_from(code_points.len()).map_err(|e| e.to_string())?,
    };
    let mut bytes = Vec::with_capacity(header.encoded_len().unwrap_or(0));
    bytes.extend_from_slice(&header.to_bytes());
    for cp in &code_points {
        bytes.extend_from_slice(&cp.to_le_bytes());
    }
    bytes.extend_from_slice(&bitmaps);
    // Every atlas the tool writes must pass the kernel's own checks.
    Atlas::parse(&bytes).map_err(|e| format!("generated atlas is invalid: {e}"))?;
    Ok(Built {
        geometry: g,
        bytes,
        missing,
        fallback,
        shrunk,
        clipped,
        narrowed,
    })
}
