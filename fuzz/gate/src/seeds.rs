// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Seeds made from the embedded vector files: every vector line is a seed
//! (ADR 0068, rule 3; "The gate for each target", item 4).
//!
//! A seed's name is its vector file's stem, `-vectors-` and the line, such
//! as `kernel-args-vectors-57`, so a finding on a seed points at its line.

use abnf::vectors::{self, Vector};

use crate::{
    idl_repo::WireMinor,
    repo::{GRAMMARS, RepoGrammar},
};

/// The vectors of one embedded file. The files are the repository's own,
/// which `cargo xtask grammars` reads, so they always parse.
pub fn vector_lines(g: &RepoGrammar) -> Vec<Vector> {
    vectors::parse(g.vectors)
        .unwrap_or_else(|e| panic!("{}:{e}", g.vectors_path))
        .vectors
}

/// The vectors of one embedded wire vector file (`idl-decode`). The
/// files are generated and checked by `cargo xtask idl`, so they always
/// parse.
pub fn wire_vectors(w: &WireMinor) -> Vec<Vector> {
    vectors::parse(w.vectors)
        .unwrap_or_else(|e| panic!("{}:{e}", w.vectors_path))
        .vectors
}

/// A seed name for a vector line.
pub fn name(g: &RepoGrammar, line: usize) -> String {
    format!("{}-vectors-{line}", g.name)
}

/// The vector lines of the grammar named `grammar`, each as its octets.
pub fn octets_of(grammar: &str) -> Vec<(String, Vec<u8>)> {
    GRAMMARS
        .iter()
        .filter(|g| g.name == grammar)
        .flat_map(|g| {
            vector_lines(g)
                .into_iter()
                .map(move |v| (name(g, v.line), v.octets))
        })
        .collect()
}

/// `abnf-match`'s frame: `<grammar>/<rule>`, LF, one octet holding the
/// capability count (low nibble) and the unwrapped mask (high nibble),
/// then the octets to match.
pub fn frame(grammar: &str, rule: &str, caps: u8, unwrapped: u8, octets: &[u8]) -> Vec<u8> {
    let mut out = format!("{grammar}/{rule}\n").into_bytes();
    out.push((caps & 0x0f) | (unwrapped << 4));
    out.extend_from_slice(octets);
    out
}

/// Every vector line of every embedded file, framed for `abnf-match` with
/// its own grammar, rule and capability context.
pub fn framed_vectors() -> Vec<(String, Vec<u8>)> {
    GRAMMARS
        .iter()
        .flat_map(|g| {
            vector_lines(g).into_iter().map(move |v| {
                (
                    name(g, v.line),
                    frame(g.name, &v.rule, v.caps, v.unwrapped, &v.octets),
                )
            })
        })
        .collect()
}

/// The longest line accepted at `max`: `a=b` arguments filling it
/// exactly, with spaces padding the end.
pub fn kargs_line(max: usize) -> Vec<u8> {
    let mut line = Vec::with_capacity(max);
    while line.len() + 4 <= max {
        line.extend_from_slice(b"a=b ");
    }
    line.resize(max, b' ');
    line
}
