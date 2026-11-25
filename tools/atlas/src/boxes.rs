// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Box drawing (U+2500–257F) and block elements (U+2580–259F), drawn
//! from the cell's geometry instead of the font's outlines.
//!
//! A font draws these characters for its own line height and advance.
//! The atlas cell is the font's ascent plus descent high and its advance
//! rounded to whole pixels wide, so the font's outlines stop short of the
//! cell's edges or overshoot them, and lines don't join from cell to
//! cell. Drawn from the cell instead, every line meets its neighbor's.
//!
//! Lines are one of three weights: light, heavy (twice light) and double
//! (two light strokes with a light-wide gap). Straight lines and blocks
//! fill whole pixels. Arcs, diagonals and dashes are anti-aliased by
//! supersampling on a fixed grid, so the output is the same on every
//! host. The shades (U+2591–2593) are flat 25, 50 and 75 percent
//! coverage, not dither patterns.

use crate::glyphs::{BLOCK_ELEMENTS, BOX_DRAWING};

/// Whether `c` is drawn here rather than from the font.
#[must_use]
pub fn is_procedural(c: char) -> bool {
    let cp = u32::from(c);
    BOX_DRAWING.contains(&cp) || BLOCK_ELEMENTS.contains(&cp)
}

/// The weight of one arm of a box-drawing character.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum W {
    /// No arm.
    N,
    /// Light (single).
    L,
    /// Heavy.
    H,
    /// Double.
    D,
}

use W::{D, H, L, N};

/// The box-drawing characters made of straight arms from the center to
/// the edges, with the weight of each arm: left, up, right, down. The
/// weights follow each character's Unicode name.
#[rustfmt::skip]
const ARMS: [(u32, [W; 4]); 109] = [
    (0x2500, [L, N, L, N]), // light horizontal
    (0x2501, [H, N, H, N]), // heavy horizontal
    (0x2502, [N, L, N, L]), // light vertical
    (0x2503, [N, H, N, H]), // heavy vertical
    (0x250C, [N, N, L, L]), // light down and right
    (0x250D, [N, N, H, L]), // down light and right heavy
    (0x250E, [N, N, L, H]), // down heavy and right light
    (0x250F, [N, N, H, H]), // heavy down and right
    (0x2510, [L, N, N, L]), // light down and left
    (0x2511, [H, N, N, L]), // down light and left heavy
    (0x2512, [L, N, N, H]), // down heavy and left light
    (0x2513, [H, N, N, H]), // heavy down and left
    (0x2514, [N, L, L, N]), // light up and right
    (0x2515, [N, L, H, N]), // up light and right heavy
    (0x2516, [N, H, L, N]), // up heavy and right light
    (0x2517, [N, H, H, N]), // heavy up and right
    (0x2518, [L, L, N, N]), // light up and left
    (0x2519, [H, L, N, N]), // up light and left heavy
    (0x251A, [L, H, N, N]), // up heavy and left light
    (0x251B, [H, H, N, N]), // heavy up and left
    (0x251C, [N, L, L, L]), // light vertical and right
    (0x251D, [N, L, H, L]), // vertical light and right heavy
    (0x251E, [N, H, L, L]), // up heavy and right down light
    (0x251F, [N, L, L, H]), // down heavy and right up light
    (0x2520, [N, H, L, H]), // vertical heavy and right light
    (0x2521, [N, H, H, L]), // down light and right up heavy
    (0x2522, [N, L, H, H]), // up light and right down heavy
    (0x2523, [N, H, H, H]), // heavy vertical and right
    (0x2524, [L, L, N, L]), // light vertical and left
    (0x2525, [H, L, N, L]), // vertical light and left heavy
    (0x2526, [L, H, N, L]), // up heavy and left down light
    (0x2527, [L, L, N, H]), // down heavy and left up light
    (0x2528, [L, H, N, H]), // vertical heavy and left light
    (0x2529, [H, H, N, L]), // down light and left up heavy
    (0x252A, [H, L, N, H]), // up light and left down heavy
    (0x252B, [H, H, N, H]), // heavy vertical and left
    (0x252C, [L, N, L, L]), // light down and horizontal
    (0x252D, [H, N, L, L]), // left heavy and right down light
    (0x252E, [L, N, H, L]), // right heavy and left down light
    (0x252F, [H, N, H, L]), // down light and horizontal heavy
    (0x2530, [L, N, L, H]), // down heavy and horizontal light
    (0x2531, [H, N, L, H]), // right light and left down heavy
    (0x2532, [L, N, H, H]), // left light and right down heavy
    (0x2533, [H, N, H, H]), // heavy down and horizontal
    (0x2534, [L, L, L, N]), // light up and horizontal
    (0x2535, [H, L, L, N]), // left heavy and right up light
    (0x2536, [L, L, H, N]), // right heavy and left up light
    (0x2537, [H, L, H, N]), // up light and horizontal heavy
    (0x2538, [L, H, L, N]), // up heavy and horizontal light
    (0x2539, [H, H, L, N]), // right light and left up heavy
    (0x253A, [L, H, H, N]), // left light and right up heavy
    (0x253B, [H, H, H, N]), // heavy up and horizontal
    (0x253C, [L, L, L, L]), // light vertical and horizontal
    (0x253D, [H, L, L, L]), // left heavy and right vertical light
    (0x253E, [L, L, H, L]), // right heavy and left vertical light
    (0x253F, [H, L, H, L]), // vertical light and horizontal heavy
    (0x2540, [L, H, L, L]), // up heavy and down horizontal light
    (0x2541, [L, L, L, H]), // down heavy and up horizontal light
    (0x2542, [L, H, L, H]), // vertical heavy and horizontal light
    (0x2543, [H, H, L, L]), // left up heavy and right down light
    (0x2544, [L, H, H, L]), // right up heavy and left down light
    (0x2545, [H, L, L, H]), // left down heavy and right up light
    (0x2546, [L, L, H, H]), // right down heavy and left up light
    (0x2547, [H, H, H, L]), // down light and up horizontal heavy
    (0x2548, [H, L, H, H]), // up light and down horizontal heavy
    (0x2549, [H, H, L, H]), // right light and left vertical heavy
    (0x254A, [L, H, H, H]), // left light and right vertical heavy
    (0x254B, [H, H, H, H]), // heavy vertical and horizontal
    (0x2550, [D, N, D, N]), // double horizontal
    (0x2551, [N, D, N, D]), // double vertical
    (0x2552, [N, N, D, L]), // down single and right double
    (0x2553, [N, N, L, D]), // down double and right single
    (0x2554, [N, N, D, D]), // double down and right
    (0x2555, [D, N, N, L]), // down single and left double
    (0x2556, [L, N, N, D]), // down double and left single
    (0x2557, [D, N, N, D]), // double down and left
    (0x2558, [N, L, D, N]), // up single and right double
    (0x2559, [N, D, L, N]), // up double and right single
    (0x255A, [N, D, D, N]), // double up and right
    (0x255B, [D, L, N, N]), // up single and left double
    (0x255C, [L, D, N, N]), // up double and left single
    (0x255D, [D, D, N, N]), // double up and left
    (0x255E, [N, L, D, L]), // vertical single and right double
    (0x255F, [N, D, L, D]), // vertical double and right single
    (0x2560, [N, D, D, D]), // double vertical and right
    (0x2561, [D, L, N, L]), // vertical single and left double
    (0x2562, [L, D, N, D]), // vertical double and left single
    (0x2563, [D, D, N, D]), // double vertical and left
    (0x2564, [D, N, D, L]), // down single and horizontal double
    (0x2565, [L, N, L, D]), // down double and horizontal single
    (0x2566, [D, N, D, D]), // double down and horizontal
    (0x2567, [D, L, D, N]), // up single and horizontal double
    (0x2568, [L, D, L, N]), // up double and horizontal single
    (0x2569, [D, D, D, N]), // double up and horizontal
    (0x256A, [D, L, D, L]), // vertical single and horizontal double
    (0x256B, [L, D, L, D]), // vertical double and horizontal single
    (0x256C, [D, D, D, D]), // double vertical and horizontal
    (0x2574, [L, N, N, N]), // light left
    (0x2575, [N, L, N, N]), // light up
    (0x2576, [N, N, L, N]), // light right
    (0x2577, [N, N, N, L]), // light down
    (0x2578, [H, N, N, N]), // heavy left
    (0x2579, [N, H, N, N]), // heavy up
    (0x257A, [N, N, H, N]), // heavy right
    (0x257B, [N, N, N, H]), // heavy down
    (0x257C, [L, N, H, N]), // light left and heavy right
    (0x257D, [N, L, N, H]), // light up and heavy down
    (0x257E, [H, N, L, N]), // heavy left and light right
    (0x257F, [N, H, N, L]), // heavy up and light down
];

/// A cell's coverage bitmap, row-major.
struct Canvas<'a> {
    w: i32,
    h: i32,
    px: &'a mut [u8],
}

impl Canvas<'_> {
    /// Fills the rectangle `[x0, x1) × [y0, y1)`, clipped to the cell.
    fn fill(&mut self, x0: i32, y0: i32, x1: i32, y1: i32, value: u8) {
        for y in y0.max(0)..y1.min(self.h) {
            for x in x0.max(0)..x1.min(self.w) {
                self.put(x, y, value);
            }
        }
    }

    /// Raises the pixel at `(x, y)` to at least `value`.
    fn put(&mut self, x: i32, y: i32, value: u8) {
        if x < 0 || y < 0 || x >= self.w || y >= self.h {
            return;
        }
        let Ok(i) = usize::try_from(y * self.w + x) else {
            return;
        };
        if let Some(p) = self.px.get_mut(i) {
            *p = (*p).max(value);
        }
    }

    /// Fills each pixel with the fraction of an 8 × 8 grid of sample
    /// points inside the shape `inside(x, y)`, in pixel coordinates.
    fn supersample(&mut self, inside: impl Fn(f64, f64) -> bool) {
        const N: i32 = 8;
        for y in 0..self.h {
            for x in 0..self.w {
                let mut hits = 0u32;
                for sy in 0..N {
                    for sx in 0..N {
                        let fx = f64::from(x) + (f64::from(sx) + 0.5) / f64::from(N);
                        let fy = f64::from(y) + (f64::from(sy) + 0.5) / f64::from(N);
                        if inside(fx, fy) {
                            hits += 1;
                        }
                    }
                }
                self.put(x, y, coverage(hits, 64));
            }
        }
    }
}

/// The length of `(x, y)`. `f64::hypot` calls the host's libm, whose
/// results can differ in the last bit between macOS and Linux; `sqrt`,
/// `*` and `+` are correctly rounded by IEEE 754, so this gives the same
/// bits on every host (ADR 0038, rule 1). The inputs are small, so the
/// squares can't overflow.
fn hypot(x: f64, y: f64) -> f64 {
    (x * x + y * y).sqrt()
}

/// `hits / total` as a coverage byte, rounded to nearest.
fn coverage(hits: u32, total: u32) -> u8 {
    u8::try_from((hits * 255 + total / 2) / total).unwrap_or(u8::MAX)
}

/// Stroke positions across one axis of the cell.
#[derive(Clone, Copy)]
struct Strokes {
    /// The light stroke, centered: `[light, light + t)`.
    light: (i32, i32),
    /// The heavy stroke, centered.
    heavy: (i32, i32),
    /// The double strokes: outer-first along the axis.
    double: [(i32, i32); 2],
}

impl Strokes {
    fn new(len: i32, t: i32) -> Self {
        let centered = |width: i32| {
            let start = (len - width) / 2;
            (start, start + width)
        };
        let light = centered(t);
        let heavy = centered(2 * t);
        let outer = centered(3 * t);
        Self {
            light,
            heavy,
            double: [(outer.0, outer.0 + t), (outer.1 - t, outer.1)],
        }
    }

    fn single(&self, w: W) -> (i32, i32) {
        if w == H { self.heavy } else { self.light }
    }
}

/// The light line thickness for a cell `h` pixels high.
fn light_thickness(h: i32) -> i32 {
    (h / 16).max(1)
}

/// Draws `c` into `cell`, a `w` × `h` bitmap. Returns false, leaving the
/// cell untouched, if `c` isn't a box-drawing or block character.
pub fn draw(c: char, w: u16, h: u16, cell: &mut [u8]) -> bool {
    let cp = u32::from(c);
    let mut canvas = Canvas {
        w: i32::from(w),
        h: i32::from(h),
        px: cell,
    };
    if let Some((_, arms)) = ARMS.iter().find(|(code, _)| *code == cp) {
        lines(&mut canvas, *arms);
        return true;
    }
    match cp {
        0x2504..=0x250B | 0x254C..=0x254F => dash(&mut canvas, cp),
        0x256D..=0x2570 => arc(&mut canvas, cp),
        0x2571..=0x2573 => diagonal(&mut canvas, cp),
        0x2580..=0x259F => block(&mut canvas, cp),
        _ => return false,
    }
    true
}

/// Draws a character made of straight arms. `arms` is left, up, right,
/// down.
fn lines(cv: &mut Canvas<'_>, arms: [W; 4]) {
    let [left, up, right, down] = arms;
    let t = light_thickness(cv.h);
    let xs = Strokes::new(cv.w, t);
    let ys = Strokes::new(cv.h, t);
    let (w, h) = (cv.w, cv.h);
    let has = |a: W| a != N;

    if !arms.contains(&D) {
        // Light and heavy: each arm runs from the edge across the hub, the
        // span of the perpendicular strokes, so corners and tees close.
        let span = |a: W, b: W, own: W, s: &Strokes| {
            let present: Vec<(i32, i32)> = [a, b]
                .into_iter()
                .filter(|x| has(*x))
                .map(|x| s.single(x))
                .collect();
            if present.is_empty() {
                s.single(own)
            } else {
                let lo = present.iter().map(|p| p.0).min().unwrap_or(0);
                let hi = present.iter().map(|p| p.1).max().unwrap_or(0);
                (lo, hi)
            }
        };
        let strongest = |a: W, b: W| if a == H || b == H { H } else { L };
        let hub_x = span(up, down, strongest(left, right), &xs);
        let hub_y = span(left, right, strongest(up, down), &ys);
        if has(left) {
            let (y0, y1) = ys.single(left);
            cv.fill(0, y0, hub_x.1, y1, 255);
        }
        if has(right) {
            let (y0, y1) = ys.single(right);
            cv.fill(hub_x.0, y0, w, y1, 255);
        }
        if has(up) {
            let (x0, x1) = xs.single(up);
            cv.fill(x0, 0, x1, hub_y.1, 255);
        }
        if has(down) {
            let (x0, x1) = xs.single(down);
            cv.fill(x0, hub_y.0, x1, h, 255);
        }
        return;
    }

    // Single and double. `xa`/`xb` are the left/right vertical double
    // strokes and `xc` the vertical single stroke; `ya`/`yb`/`yc` likewise
    // for horizontal strokes, top first.
    let [xa, xb] = xs.double;
    let xc = xs.light;
    let [ya, yb] = ys.double;
    let yc = ys.light;
    let v_double = up == D || down == D;
    let h_double = left == D || right == D;
    let v_through = has(up) && has(down);
    let h_through = has(left) && has(right);

    // Where a horizontal arm meets the vertical strokes: the x at which a
    // right arm starts and a left arm ends.
    let h_reach = |own: W, opposite: W, toward_up: bool| -> (i32, i32) {
        if own == D {
            // A double arm's stroke nearer an existing vertical arm stops
            // at that arm's near stroke; otherwise it runs to the far one.
            if v_double {
                let side_present = if toward_up { has(up) } else { has(down) };
                if side_present {
                    (xb.0, xa.1)
                } else {
                    (xa.0, xb.1)
                }
            } else {
                xc
            }
        } else if v_double {
            // A single arm crossing a double line, or meeting it at a corner,
            // reaches the far stroke; at a tee it stops at the near one.
            if v_through && !has(opposite) {
                (xb.0, xa.1)
            } else {
                (xa.0, xb.1)
            }
        } else {
            xc
        }
    };
    let v_reach = |own: W, opposite: W, toward_left: bool| -> (i32, i32) {
        if own == D {
            if h_double {
                let side_present = if toward_left { has(left) } else { has(right) };
                if side_present {
                    (yb.0, ya.1)
                } else {
                    (ya.0, yb.1)
                }
            } else {
                yc
            }
        } else if h_double {
            if h_through && !has(opposite) {
                (yb.0, ya.1)
            } else {
                (ya.0, yb.1)
            }
        } else {
            yc
        }
    };

    // Horizontal arms: the top stroke pairs with the up arm, the bottom
    // stroke with the down arm.
    for (arm, opposite, is_right) in [(left, right, false), (right, left, true)] {
        if !has(arm) {
            continue;
        }
        let rows: &[((i32, i32), bool)] = if arm == D {
            &[(ya, true), (yb, false)]
        } else {
            &[(yc, true)]
        };
        for &((y0, y1), toward_up) in rows {
            let (start, end) = h_reach(arm, opposite, toward_up);
            if is_right {
                cv.fill(start, y0, w, y1, 255);
            } else {
                cv.fill(0, y0, end, y1, 255);
            }
        }
    }
    // Vertical arms: the left stroke pairs with the left arm, the right
    // stroke with the right arm.
    for (arm, opposite, is_down) in [(up, down, false), (down, up, true)] {
        if !has(arm) {
            continue;
        }
        let cols: &[((i32, i32), bool)] = if arm == D {
            &[(xa, true), (xb, false)]
        } else {
            &[(xc, true)]
        };
        for &((x0, x1), toward_left) in cols {
            let (start, end) = v_reach(arm, opposite, toward_left);
            if is_down {
                cv.fill(x0, start, x1, h, 255);
            } else {
                cv.fill(x0, 0, x1, end, 255);
            }
        }
    }
}

/// Draws a dashed line: U+2504–250B and U+254C–254F.
fn dash(cv: &mut Canvas<'_>, cp: u32) {
    let (segments, heavy, horizontal) = match cp {
        0x2504..=0x2507 => (3, cp & 1 == 1, cp < 0x2506),
        0x2508..=0x250B => (4, cp & 1 == 1, cp < 0x250A),
        _ => (2, cp & 1 == 1, cp < 0x254E),
    };
    let t = light_thickness(cv.h);
    let thickness = if heavy { 2 * t } else { t };
    let len = f64::from(if horizontal { cv.w } else { cv.h });
    let across = if horizontal { cv.h } else { cv.w };
    let start = (across - thickness) / 2;
    let (a0, a1) = (f64::from(start), f64::from(start + thickness));
    let period = len / f64::from(segments);
    // Each segment is centered in its share of the line, with half the
    // gap at each end, so dashes keep their rhythm across cells.
    let gap = (period * 0.4).max(1.0).min(period * 0.6);
    cv.supersample(|x, y| {
        let (along, cross) = if horizontal { (x, y) } else { (y, x) };
        if cross < a0 || cross >= a1 {
            return false;
        }
        let phase = along - period * (along / period).floor();
        phase >= gap / 2.0 && phase < period - gap / 2.0
    });
}

/// Draws a light arc: U+256D–2570.
fn arc(cv: &mut Canvas<'_>, cp: u32) {
    let t = light_thickness(cv.h);
    let xs = Strokes::new(cv.w, t);
    let ys = Strokes::new(cv.h, t);
    let half = f64::from(t) / 2.0;
    // The centers of the vertical and horizontal light strokes.
    let cx = f64::from(xs.light.0) + half;
    let cy = f64::from(ys.light.0) + half;
    let (w, h) = (f64::from(cv.w), f64::from(cv.h));
    // Which way the arms go: toward the right edge, and toward the bottom.
    let (right, down) = match cp {
        0x256D => (true, true),
        0x256E => (false, true),
        0x256F => (false, false),
        _ => (true, false),
    };
    let room_x = if right { w - cx } else { cx };
    let room_y = if down { h - cy } else { cy };
    // Leave at least a pixel of straight line at each edge, so the arc
    // meets its neighbors exactly as a straight line does.
    let r = (room_x.min(room_y) - 1.0).max(half);
    let sx = if right { 1.0 } else { -1.0 };
    let sy = if down { 1.0 } else { -1.0 };
    // The circle's center, diagonally off the strokes' crossing point.
    let (ox, oy) = (cx + sx * r, cy + sy * r);
    cv.supersample(|x, y| {
        // Past the circle's center, the arms are straight.
        let beyond_x = (x - ox) * sx >= 0.0;
        let beyond_y = (y - oy) * sy >= 0.0;
        if beyond_x && (y - cy).abs() < half {
            return true;
        }
        if beyond_y && (x - cx).abs() < half {
            return true;
        }
        if beyond_x || beyond_y {
            return false;
        }
        let d = hypot(x - ox, y - oy);
        (d - r).abs() < half
    });
}

/// Draws a light diagonal: U+2571–2573. The lines run corner to corner,
/// so diagonals in neighboring cells join.
fn diagonal(cv: &mut Canvas<'_>, cp: u32) {
    let t = f64::from(light_thickness(cv.h));
    let (w, h) = (f64::from(cv.w), f64::from(cv.h));
    let norm = hypot(w, h);
    // Distance from (x, y) to the line through (0, h) and (w, 0), and to
    // the line through (0, 0) and (w, h).
    let rising = move |x: f64, y: f64| (h * x + w * y - w * h).abs() / norm;
    let falling = move |x: f64, y: f64| (h * x - w * y).abs() / norm;
    let half = t / 2.0;
    match cp {
        0x2571 => cv.supersample(|x, y| rising(x, y) < half),
        0x2572 => cv.supersample(|x, y| falling(x, y) < half),
        _ => cv.supersample(|x, y| rising(x, y) < half || falling(x, y) < half),
    }
}

/// Draws a block element: U+2580–259F.
fn block(cv: &mut Canvas<'_>, cp: u32) {
    let (w, h) = (cv.w, cv.h);
    // `n` eighths of `len`, rounded to whole pixels.
    let eighths = |len: i32, n: i32| (len * n + 4) / 8;
    let (mx, my) = (eighths(w, 4), eighths(h, 4));
    let quadrants = |cv: &mut Canvas<'_>, ul: bool, ur: bool, ll: bool, lr: bool| {
        for (on, x0, y0, x1, y1) in [
            (ul, 0, 0, mx, my),
            (ur, mx, 0, w, my),
            (ll, 0, my, mx, h),
            (lr, mx, my, w, h),
        ] {
            if on {
                cv.fill(x0, y0, x1, y1, 255);
            }
        }
    };
    match cp {
        0x2580 => cv.fill(0, 0, w, my, 255),
        // Lower one eighth to the full block.
        0x2581..=0x2588 => {
            let n = i32::try_from(cp - 0x2580).unwrap_or(8);
            cv.fill(0, h - eighths(h, n), w, h, 255);
        }
        // Left seven eighths to left one eighth.
        0x2589..=0x258F => {
            let n = i32::try_from(0x2590 - cp).unwrap_or(0);
            cv.fill(0, 0, eighths(w, n), h, 255);
        }
        0x2590 => cv.fill(mx, 0, w, h, 255),
        0x2591 => cv.fill(0, 0, w, h, 64),
        0x2592 => cv.fill(0, 0, w, h, 128),
        0x2593 => cv.fill(0, 0, w, h, 191),
        0x2594 => cv.fill(0, 0, w, eighths(h, 1), 255),
        0x2595 => cv.fill(w - eighths(w, 1), 0, w, h, 255),
        0x2596 => quadrants(cv, false, false, true, false),
        0x2597 => quadrants(cv, false, false, false, true),
        0x2598 => quadrants(cv, true, false, false, false),
        0x2599 => quadrants(cv, true, false, true, true),
        0x259A => quadrants(cv, true, false, false, true),
        0x259B => quadrants(cv, true, true, true, false),
        0x259C => quadrants(cv, true, true, false, true),
        0x259D => quadrants(cv, false, true, false, false),
        0x259E => quadrants(cv, false, true, true, false),
        _ => quadrants(cv, false, true, true, true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(c: char, w: u16, h: u16) -> Vec<u8> {
        let mut cell = vec![0u8; usize::from(w) * usize::from(h)];
        assert!(draw(c, w, h, &mut cell), "{c:?} not drawn");
        cell
    }

    fn at(cell: &[u8], w: u16, x: u16, y: u16) -> u8 {
        cell[usize::from(y) * usize::from(w) + usize::from(x)]
    }

    #[test]
    fn every_box_and_block_character_draws_ink() {
        for (w, h) in [(7, 16), (11, 24), (14, 32)] {
            for cp in 0x2500..=0x259F {
                let c = char::from_u32(cp).unwrap();
                let cell = render(c, w, h);
                assert!(
                    cell.iter().any(|&p| p > 0),
                    "U+{cp:04X} at {w}x{h} is empty"
                );
            }
        }
    }

    #[test]
    fn arms_table_is_sorted() {
        assert!(ARMS.windows(2).all(|p| p[0].0 < p[1].0));
        assert!(ARMS.iter().all(|(cp, _)| BOX_DRAWING.contains(cp)));
    }

    /// Lines that leave the cell reach its edges, so neighbors join.
    #[test]
    fn lines_reach_the_edges() {
        for (w, h) in [(7u16, 16u16), (11, 24), (14, 32)] {
            for (cp, [left, up, right, down]) in ARMS {
                let c = char::from_u32(cp).unwrap();
                let cell = render(c, w, h);
                let col = |x: u16| (0..h).any(|y| at(&cell, w, x, y) == 255);
                let row = |y: u16| (0..w).any(|x| at(&cell, w, x, y) == 255);
                assert_eq!(col(0), left != N, "U+{cp:04X} left edge at {w}x{h}");
                assert_eq!(col(w - 1), right != N, "U+{cp:04X} right edge at {w}x{h}");
                assert_eq!(row(0), up != N, "U+{cp:04X} top edge at {w}x{h}");
                assert_eq!(row(h - 1), down != N, "U+{cp:04X} bottom edge at {w}x{h}");
            }
        }
    }

    /// A horizontal line's rows match the rows of every character with a
    /// light left or right arm, so lines continue straight across cells.
    #[test]
    fn edge_profiles_match() {
        for (w, h) in [(7u16, 16u16), (11, 24), (14, 32)] {
            let profile = |c: char, x: u16| -> Vec<u8> {
                let cell = render(c, w, h);
                (0..h).map(|y| at(&cell, w, x, y)).collect()
            };
            let col_profile = |c: char, y: u16| -> Vec<u8> {
                let cell = render(c, w, h);
                (0..w).map(|x| at(&cell, w, x, y)).collect()
            };
            for (cp, [left, up, right, down]) in ARMS {
                let c = char::from_u32(cp).unwrap();
                let reference = |weight: W, horizontal: bool| match (weight, horizontal) {
                    (L, true) => '─',
                    (H, true) => '━',
                    (D, true) => '═',
                    (L, false) => '│',
                    (H, false) => '┃',
                    _ => '║',
                };
                if left != N {
                    assert_eq!(
                        profile(c, 0),
                        profile(reference(left, true), 0),
                        "U+{cp:04X}"
                    );
                }
                if right != N {
                    assert_eq!(profile(c, w - 1), profile(reference(right, true), w - 1));
                }
                if up != N {
                    assert_eq!(col_profile(c, 0), col_profile(reference(up, false), 0));
                }
                if down != N {
                    assert_eq!(
                        col_profile(c, h - 1),
                        col_profile(reference(down, false), h - 1)
                    );
                }
            }
            // Arcs meet straight lines the same way.
            assert_eq!(profile('╭', w - 1), profile('─', w - 1));
            assert_eq!(col_profile('╭', h - 1), col_profile('│', h - 1));
            assert_eq!(profile('╯', 0), profile('─', 0));
            assert_eq!(col_profile('╯', 0), col_profile('│', 0));
        }
    }

    #[test]
    fn blocks_split_the_cell_exactly() {
        let (w, h) = (7u16, 16u16);
        let sum = |a: char, b: char| -> Vec<u16> {
            render(a, w, h)
                .iter()
                .zip(render(b, w, h))
                .map(|(x, y)| u16::from(*x) + u16::from(y))
                .collect()
        };
        let full = vec![255u16; usize::from(w) * usize::from(h)];
        assert_eq!(sum('▀', '▄'), full);
        assert_eq!(sum('▌', '▐'), full);
        assert_eq!(sum('▘', '▟'), full);
        assert_eq!(sum('▚', '▞'), full);
        assert_eq!(render('█', w, h), vec![255u8; full.len()]);
    }

    #[test]
    fn other_characters_are_not_drawn() {
        let mut cell = vec![0u8; 16];
        assert!(!draw('A', 4, 4, &mut cell));
        assert!(cell.iter().all(|&p| p == 0));
        assert!(!is_procedural('A'));
        assert!(is_procedural('─'));
        assert!(is_procedural('▟'));
    }
}
