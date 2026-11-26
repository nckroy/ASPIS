// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! `cargo xtask fuzz-dict`: a libFuzzer dictionary for every grammar
//! (docs/design/call-language.md, "Layout"; ADR 0068), from its literals
//! and its byte order's interesting integers (`abnf::dict`). It writes
//! `build/fuzz/dict/<grammar>.dict` for each grammar in `grammars/` and
//! each generated grammar under the interface roots, named by its path
//! there (`aspis.catalog.v1.1.dict`). Nothing is committed: C71's targets
//! read them from `build/`, which iCloud doesn't sync.
//!
//! The files come from git, tracked or new, so iCloud's conflict copies
//! are never read.

use std::fs;

use abnf::{
    Grammar, Kind, LoadOptions,
    dict::{self, Endian},
};

use crate::{build_dir, fail, grammars, root};

/// Grammars whose integers are little-endian (ADR 0037, rule 1). Every
/// other grammar uses `core`'s big-endian integers, or has none.
const LITTLE_ENDIAN: [&str; 1] = ["grammars/initfs.abnf"];

pub fn write() {
    let mut roots = vec!["grammars"];
    roots.extend(grammars::INTERFACE_ROOTS);
    let files = grammars::tracked(&roots);
    let out = build_dir().join("fuzz/dict");
    fs::create_dir_all(&out).unwrap_or_else(|e| fail(format!("{}: {e}", out.display())));
    let mut n = 0;
    for path in files.iter().filter(|p| p.ends_with(".abnf")) {
        let text = fs::read(root().join(path)).unwrap_or_else(|e| fail(format!("{path}: {e}")));
        let shared = path.starts_with("grammars/");
        let opts = LoadOptions {
            kind: match path.as_str() {
                "grammars/core.abnf" => Kind::Core,
                // Generated grammars load as the catalog loads them.
                _ if !shared => Kind::Strict,
                _ => Kind::Auto,
            },
            ..LoadOptions::default()
        };
        let mut resolve = |used: &str| fs::read(root().join(format!("grammars/{used}.abnf"))).ok();
        // The dictionary's name: the path under its root, dotted.
        let rel = roots
            .iter()
            .find_map(|r| path.strip_prefix(&format!("{r}/")))
            .unwrap_or(path);
        let name = rel.trim_end_matches(".abnf").replace('/', ".");
        let g = Grammar::load(&name, &text, &mut resolve, &opts)
            .unwrap_or_else(|e| fail(format!("{path}: {e}")));
        let endian = if LITTLE_ENDIAN.contains(&path.as_str()) {
            Endian::Little
        } else {
            Endian::Big
        };
        let file = out.join(format!("{name}.dict"));
        fs::write(&file, dict::libfuzzer(&g, &name, endian))
            .unwrap_or_else(|e| fail(format!("{}: {e}", file.display())));
        n += 1;
    }
    eprintln!("xtask: {n} dictionaries in {}", out.display());
}
