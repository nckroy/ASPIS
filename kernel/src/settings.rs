// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The kernel arguments the kernel reads (ADR 0041, rule 5).
//!
//! The kernel uses only the arguments before the first error. If a key
//! appears more than once, the last one counts. Keys under `root.` are for
//! the root server; keys under `test.` are reserved for test builds; any
//! other unknown key is ignored. Each of those cases is reported once the
//! console is up.

use crate::log::Level;
use kargs::{Value, lookup, parse};

#[derive(Clone, Copy, Debug)]
pub struct Settings {
    pub console_fb: bool,
    pub console_uart: bool,
    /// The atlas cell height `console.cell` asks for (ADR 0034, rule 4).
    pub cell: Option<u16>,
    /// The ring's size in bytes (ADR 0042, rule 1).
    pub log_size: usize,
    /// Records at or above this level reach the UART and the framebuffer.
    pub log_level: Level,
    /// `test.panic`: panic after boot, to show the panic path (test builds).
    pub test_panic: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            console_fb: true,
            console_uart: true,
            cell: None,
            log_size: crate::log::DEFAULT_SIZE,
            log_level: Level::Info,
            test_panic: false,
        }
    }
}

/// Something to report once the console is up.
#[derive(Clone, Copy, Debug)]
pub enum Note<'a> {
    Error { offset: usize },
    Repeated(&'a str),
    BadValue(&'a str),
    ForRootServer(&'a str),
    Ignored(&'a str),
}

pub const KNOWN: &[&str] = &["console", "console.cell", "log.size", "log.level", "initfs"];

/// Reads the settings, calling `note` for each thing worth reporting.
pub fn read<'a>(line: &'a [u8], mut note: impl FnMut(Note<'a>)) -> Settings {
    let mut s = Settings::default();

    // Find the first error, and every key that isn't the kernel's.
    let mut valid_len = line.len();
    for arg in parse(line) {
        match arg {
            Ok(a) => {
                if KNOWN.contains(&a.key) {
                    continue;
                }
                if a.key.starts_with("root.") {
                    note(Note::ForRootServer(a.key));
                } else if cfg!(aspis_test_build) && a.key.starts_with("test.") {
                    if a.key == "test.panic" {
                        s.test_panic = true;
                    }
                } else {
                    note(Note::Ignored(a.key));
                }
            }
            Err(e) => {
                note(Note::Error { offset: e.offset });
                valid_len = e.offset.min(line.len());
                break;
            }
        }
    }
    // Only the arguments before the error count.
    let line = &line[..valid_len];

    let get = |key: &'static str, note: &mut dyn FnMut(Note<'a>)| {
        let l = lookup(line, key);
        if l.count > 1 {
            note(Note::Repeated(key));
        }
        l.value.flatten().map(|v: Value<'a>| v.raw())
    };

    if let Some(v) = get("console", &mut note) {
        match v {
            "fb" => (s.console_fb, s.console_uart) = (true, false),
            "uart" => (s.console_fb, s.console_uart) = (false, true),
            "fb,uart" | "uart,fb" => (s.console_fb, s.console_uart) = (true, true),
            _ => note(Note::BadValue("console")),
        }
    }
    if let Some(v) = get("console.cell", &mut note) {
        match v {
            "16" => s.cell = Some(16),
            "24" => s.cell = Some(24),
            "32" => s.cell = Some(32),
            _ => note(Note::BadValue("console.cell")),
        }
    }
    if let Some(v) = get("log.size", &mut note) {
        match parse_size(v) {
            Some(n) if n.is_power_of_two() && (4096..=crate::log::MAX_SIZE).contains(&n) => {
                s.log_size = n
            }
            _ => note(Note::BadValue("log.size")),
        }
    }
    if let Some(v) = get("log.level", &mut note) {
        match Level::from_name(v) {
            Some(l) => s.log_level = l,
            None => note(Note::BadValue("log.level")),
        }
    }
    s
}

/// A size in bytes, with an optional `K` or `M` suffix.
fn parse_size(v: &str) -> Option<usize> {
    let (digits, mult) = match v.as_bytes().last()? {
        b'K' | b'k' => (&v[..v.len() - 1], 1024),
        b'M' | b'm' => (&v[..v.len() - 1], 1024 * 1024),
        _ => (v, 1),
    };
    digits.parse::<usize>().ok()?.checked_mul(mult)
}
