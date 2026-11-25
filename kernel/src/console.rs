// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The kernel's early console: text drawn as graphics on the boot
//! framebuffer, from the first message (ADR 0009, rules 1 to 3).
//!
//! The kernel draws text, filled rectangles and bitmaps. Glyphs come from
//! atlases rasterized at build time from Noto Sans Mono, at 16, 24 and 32
//! pixels (ADR 0034). The kernel holds no rasterizer and no SVG code.

use bootinfo::{Framebuffer, pixel_format};
use core::sync::atomic::{AtomicU8, Ordering};
use glyph_atlas::Atlas;

static ATLAS_16: &[u8] = include_bytes!(concat!(env!("ASPIS_ATLAS_DIR"), "/atlas-16.bin"));
static ATLAS_24: &[u8] = include_bytes!(concat!(env!("ASPIS_ATLAS_DIR"), "/atlas-24.bin"));
static ATLAS_32: &[u8] = include_bytes!(concat!(env!("ASPIS_ATLAS_DIR"), "/atlas-32.bin"));

/// The boot logo, rasterized at build time four rows high for each atlas
/// (ADR 0009, rule 3: the kernel holds no SVG code).
static LOGO_16: &[u8] = include_bytes!(concat!(env!("ASPIS_ATLAS_DIR"), "/logo-16.bin"));
static LOGO_24: &[u8] = include_bytes!(concat!(env!("ASPIS_ATLAS_DIR"), "/logo-24.bin"));
static LOGO_32: &[u8] = include_bytes!(concat!(env!("ASPIS_ATLAS_DIR"), "/logo-32.bin"));

/// The logo's ink: white, as drawn.
pub const LOGO_INK: Rgb = Rgb(0xff, 0xff, 0xff);

/// The boot framebuffer's states (ADR 0042, rule 6). They only go forward.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FbState {
    /// The kernel draws its console.
    Kernel = 0,
    /// Display SVG has claimed the display; the kernel no longer draws, but
    /// the same memory is still scanned out, so a panic may be drawn.
    Adopted = 1,
    /// A hardware driver has changed the scan-out. Never drawn on again.
    Retired = 2,
}

static STATE: AtomicU8 = AtomicU8::new(FbState::Kernel as u8);

pub fn state() -> FbState {
    match STATE.load(Ordering::Acquire) {
        0 => FbState::Kernel,
        1 => FbState::Adopted,
        _ => FbState::Retired,
    }
}

#[cfg_attr(not(aspis_test_build), allow(dead_code))]
/// Moves the framebuffer forward to `to`. Moving backward is refused.
/// In M2 this becomes a call on the boot framebuffer's kernel object.
pub fn advance(to: FbState) -> Result<(), FbState> {
    let mut cur = STATE.load(Ordering::Acquire);
    loop {
        if to as u8 <= cur {
            return Err(state());
        }
        match STATE.compare_exchange(cur, to as u8, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(()),
            Err(now) => cur = now,
        }
    }
}

#[derive(Clone, Copy)]
pub struct Rgb(pub u8, pub u8, pub u8);

pub const BACKGROUND: Rgb = Rgb(0x14, 0x18, 0x1f);
pub const TEXT: Rgb = Rgb(0xd8, 0xde, 0xe9);
pub const DIM: Rgb = Rgb(0x8a, 0x94, 0xa6);
pub const ACCENT: Rgb = Rgb(0x3b, 0x6e, 0xa8);
pub const WARNING: Rgb = Rgb(0xe8, 0xa8, 0x38);
pub const PANIC_BG: Rgb = Rgb(0x7a, 0x1c, 0x1c);

pub struct Console {
    fb: Framebuffer,
    atlas: Atlas<'static>,
    cols: u32,
    rows: u32,
    col: u32,
    row: u32,
    /// The first text row; rows above it hold the title bar.
    top: u32,
    pub fg: Rgb,
    bg: Rgb,
    shift: [u32; 3],
}

impl Console {
    /// Picks the atlas by framebuffer width (ADR 0034, rule 4): 16 pixels
    /// below 1280, 24 below 2560, 32 from there, falling back to smaller
    /// ones until the console has at least 80 columns and 25 rows.
    pub fn new(fb: Framebuffer, cell: Option<u16>) -> Option<Self> {
        // The framebuffer must hold every pixel the console may touch.
        let needed = (fb.stride as u64)
            .checked_mul(fb.height as u64)
            .and_then(|p| p.checked_mul(4));
        if fb.width == 0
            || fb.height == 0
            || fb.stride < fb.width
            || needed.is_none_or(|n| n > fb.size)
        {
            return None;
        }
        let atlases = [(16u16, ATLAS_16), (24, ATLAS_24), (32, ATLAS_32)];
        let wanted = cell.unwrap_or(match fb.width {
            0..1280 => 16,
            1280..2560 => 24,
            _ => 32,
        });
        let mut chosen = None;
        for &(h, bytes) in atlases.iter().rev() {
            if h > wanted {
                continue;
            }
            let Ok(a) = Atlas::parse(bytes) else { continue };
            let (cw, ch) = (a.cell_width() as u32, a.cell_height() as u32);
            let fits = cw > 0 && fb.width / cw >= 80 && fb.height / ch >= 25;
            if fits || cell.is_some() || h == 16 {
                chosen = Some(a);
                break;
            }
        }
        let atlas = chosen?;
        let shift = match fb.format {
            pixel_format::BGRX8888 => [16, 8, 0],
            pixel_format::RGBX8888 => [0, 8, 16],
            pixel_format::BITMASK => [
                fb.red_mask.trailing_zeros(),
                fb.green_mask.trailing_zeros(),
                fb.blue_mask.trailing_zeros(),
            ],
            _ => return None,
        };
        let (cw, ch) = (atlas.cell_width() as u32, atlas.cell_height() as u32);
        let c = Self {
            cols: fb.width / cw,
            rows: fb.height / ch,
            fb,
            atlas,
            col: 0,
            row: 0,
            top: 0,
            fg: TEXT,
            bg: BACKGROUND,
            shift,
        };
        // A title row and at least one text row, or no console.
        if c.rows < 3 {
            return None;
        }
        Some(c)
    }

    pub fn cell(&self) -> (u32, u32) {
        (
            self.atlas.cell_width() as u32,
            self.atlas.cell_height() as u32,
        )
    }

    pub fn grid(&self) -> (u32, u32) {
        (self.cols, self.rows)
    }

    fn pack(&self, c: Rgb) -> u32 {
        (c.0 as u32) << self.shift[0]
            | (c.1 as u32) << self.shift[1]
            | (c.2 as u32) << self.shift[2]
    }

    fn pixel(&self, x: u32, y: u32, v: u32) {
        if x < self.fb.width && y < self.fb.height {
            let at = (y as u64 * self.fb.stride as u64 + x as u64) * 4;
            if at + 4 <= self.fb.size {
                // SAFETY: inside the framebuffer the stub described, which
                // the early identity map covers.
                unsafe { core::ptr::write_volatile((self.fb.base + at) as *mut u32, v) };
            }
        }
    }

    /// A filled rectangle.
    pub fn fill_rect(&self, x: u32, y: u32, w: u32, h: u32, color: Rgb) {
        let v = self.pack(color);
        for yy in y..y.saturating_add(h).min(self.fb.height) {
            for xx in x..x.saturating_add(w).min(self.fb.width) {
                self.pixel(xx, yy, v);
            }
        }
    }

    /// A coverage bitmap (8 bits per pixel), blended from `bg` to `fg`.
    pub fn bitmap(
        &self,
        (x, y): (u32, u32),
        (w, h): (u32, u32),
        coverage: &[u8],
        fg: Rgb,
        bg: Rgb,
    ) {
        let mix =
            |a: u8, b: u8, t: u8| ((a as u32 * (255 - t as u32) + b as u32 * t as u32) / 255) as u8;
        for yy in 0..h {
            for xx in 0..w {
                let t = coverage.get((yy * w + xx) as usize).copied().unwrap_or(0);
                let c = Rgb(mix(bg.0, fg.0, t), mix(bg.1, fg.1, t), mix(bg.2, fg.2, t));
                self.pixel(x + xx, y + yy, self.pack(c));
            }
        }
    }

    /// Draws one character at a cell position.
    pub fn glyph_at(&self, col: u32, row: u32, ch: char, fg: Rgb, bg: Rgb) {
        let (cw, chh) = self.cell();
        let g = self.atlas.glyph_or_replacement(ch);
        self.bitmap((col * cw, row * chh), (cw, chh), g, fg, bg);
    }

    /// Draws the boot logo below the title bar, left-aligned with the text,
    /// and moves the text area below it. Does nothing if the logo wouldn't
    /// leave room for text.
    pub fn logo(&mut self) {
        let (cw, ch) = self.cell();
        let bytes = match ch {
            0..=19 => LOGO_16,
            20..=27 => LOGO_24,
            _ => LOGO_32,
        };
        let Ok(logo) = glyph_atlas::bitmap::Bitmap::parse(bytes) else {
            return;
        };
        let (w, h) = (logo.width() as u32, logo.height() as u32);
        let rows = h.div_ceil(ch) + 1;
        if cw + w > self.fb.width || self.top + rows + 3 > self.rows {
            return;
        }
        self.bitmap(
            (cw, self.top * ch),
            (w, h),
            logo.coverage(),
            LOGO_INK,
            BACKGROUND,
        );
        self.top += rows;
        self.row = self.row.max(self.top);
    }

    /// Clears the whole screen to the console's background.
    pub fn clear(&self) {
        self.fill_rect(0, 0, self.fb.width, self.fb.height, BACKGROUND);
    }

    /// A title bar across the top row, which text never scrolls over.
    pub fn title(&mut self, left: &str, right: &str) {
        let (cw, ch) = self.cell();
        self.fill_rect(0, 0, self.fb.width, ch + ch / 2, ACCENT);
        for (i, c) in left.chars().enumerate() {
            self.bitmap(
                (cw + i as u32 * cw, ch / 4),
                (cw, ch),
                self.atlas.glyph_or_replacement(c),
                TEXT,
                ACCENT,
            );
        }
        let start = self.cols.saturating_sub(right.chars().count() as u32 + 1);
        for (i, c) in right.chars().enumerate() {
            self.bitmap(
                ((start + i as u32) * cw, ch / 4),
                (cw, ch),
                self.atlas.glyph_or_replacement(c),
                TEXT,
                ACCENT,
            );
        }
        self.top = 2;
        self.row = self.row.max(self.top);
    }

    fn newline(&mut self) {
        self.col = 0;
        if self.row + 1 < self.rows {
            self.row += 1;
            return;
        }
        // Scroll the text rows up by one.
        let (_, ch) = self.cell();
        let line = self.fb.stride as usize * 4 * ch as usize;
        let first = (self.top * ch) as usize * self.fb.stride as usize * 4;
        let count = self.rows.saturating_sub(self.top + 1) as usize * line;
        // SAFETY: both ranges lie inside the framebuffer.
        unsafe {
            core::ptr::copy(
                (self.fb.base as usize + first + line) as *const u8,
                (self.fb.base as usize + first) as *mut u8,
                count,
            );
        }
        self.fill_rect(0, self.row * ch, self.fb.width, ch, self.bg);
    }

    pub fn write_str(&mut self, s: &str) {
        for c in s.chars() {
            match c {
                '\n' => self.newline(),
                '\r' => self.col = 0,
                c => {
                    if self.col >= self.cols {
                        self.newline();
                    }
                    self.glyph_at(self.col, self.row, c, self.fg, self.bg);
                    self.col += 1;
                }
            }
        }
    }

    /// Clears the text area to `bg` and moves to its top: used by the panic
    /// path, which draws on a background of its own.
    pub fn clear_text_area(&mut self, bg: Rgb) {
        let (_, ch) = self.cell();
        self.bg = bg;
        self.fill_rect(
            0,
            self.top * ch,
            self.fb.width,
            self.fb.height - self.top * ch,
            bg,
        );
        self.row = self.top;
        self.col = 0;
    }
}
