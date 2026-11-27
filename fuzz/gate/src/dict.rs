// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! libFuzzer dictionaries, one per target (docs/design/call-language.md,
//! "The harness"). `cargo xtask fuzz build` writes each to
//! `build/fuzz/dict/targets/<target>.dict`, beside, and never over, the
//! per-grammar dictionaries C07's `cargo xtask fuzz-dict` writes to
//! `build/fuzz/dict/<grammar>.dict`.
//!
//! Each holds the literals of the target's grammars, from
//! [`abnf::Grammar::literals`] (C06 left dictionaries to C71), and the
//! target's own words. C07 has since put `abnf::dict` on main, with the
//! core widths' interesting integers as well; switching the literal half
//! here to it is left for a later follow-up.

use crate::{
    repo::{self, GRAMMARS},
    seeds,
};

/// libFuzzer skips dictionary entries longer than this.
pub const MAX_ENTRY: usize = 64;

/// One entry in libFuzzer's dictionary syntax: a quoted string with `\\`,
/// `\"` and `\xHH` escapes, and other printable ASCII as itself.
pub fn escape(entry: &[u8]) -> String {
    let mut s = String::from("\"");
    for &b in entry {
        match b {
            b'\\' => s.push_str("\\\\"),
            b'"' => s.push_str("\\\""),
            0x20..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\x{b:02X}")),
        }
    }
    s.push('"');
    s
}

/// A dictionary file: the entries sorted, each once, without the empty one
/// and those over [`MAX_ENTRY`], one a line. Empty when nothing is left.
pub fn render(mut entries: Vec<Vec<u8>>) -> String {
    entries.retain(|e| !e.is_empty() && e.len() <= MAX_ENTRY);
    entries.sort();
    entries.dedup();
    entries.iter().map(|e| escape(e) + "\n").collect()
}

/// The literals of the named repository grammars (and of RFC 5234's
/// rules, which every grammar loads).
fn literals(names: &[&str]) -> Vec<Vec<u8>> {
    names
        .iter()
        .filter_map(|n| repo::loaded(n))
        .flat_map(|g| g.literals().map(<[u8]>::to_vec).collect::<Vec<_>>())
        .collect()
}

/// The rule names a grammar text defines: a name at column 0 (RFC 5234,
/// section 4).
pub fn rule_names(text: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = text
        .split(|&b| b == b'\n')
        .filter(|l| l.first().is_some_and(u8::is_ascii_alphabetic))
        .map(|l| {
            let end = l
                .iter()
                .position(|&b| !(b.is_ascii_alphanumeric() || b == b'-'))
                .unwrap_or(l.len());
            String::from_utf8_lossy(&l[..end]).into_owned()
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

fn words(w: &[&str]) -> Vec<Vec<u8>> {
    w.iter().map(|s| s.as_bytes().to_vec()).collect()
}

/// RFC 5234's core rule names.
const RFC5234: &[&str] = &[
    "ALPHA", "BIT", "CHAR", "CR", "CRLF", "CTL", "DIGIT", "DQUOTE", "HEXDIG", "HTAB", "LF", "LWSP",
    "OCTET", "SP", "VCHAR", "WSP",
];

/// `abnf-grammar`: ABNF's tokens, the comment forms that mean something,
/// the core rule names, and every repository grammar's literals.
pub fn grammar() -> Vec<Vec<u8>> {
    let mut d = words(&[
        " = ",
        " =/ ",
        " / ",
        "*",
        "1*",
        "0*0",
        "( ",
        " )",
        "[ ",
        " ]",
        "%x",
        "%d",
        "%b",
        "%s\"",
        "%i\"",
        "\"",
        "<",
        ">",
        "-",
        ".",
        ";",
        "\r\n",
        "\n",
        "\n ",
        "\t",
        "; uses: ",
        "; uses: core\n",
        "; uses: chain-1\n",
        "; constraint: ",
        "4294967295",
    ]);
    d.extend(words(RFC5234));
    let core = GRAMMARS.iter().find(|g| g.name == "core").expect("core");
    d.extend(rule_names(core.text).into_iter().map(String::into_bytes));
    d.extend(literals(
        &repo::GRAMMARS.iter().map(|g| g.name).collect::<Vec<_>>(),
    ));
    d
}

/// Big-endian "interesting" integers at widths 1, 2, 4 and 8: 0, 1, the
/// unsigned maximum (and -1), and the signed boundaries (ADR 0062, rule 2:
/// core integers are big-endian).
pub fn be_integers() -> Vec<Vec<u8>> {
    let mut d = Vec::new();
    for w in [1usize, 2, 4, 8] {
        let bits = 8 * w as u32;
        let max = u64::MAX >> (64 - bits);
        for v in [0, 1, max, max >> 1, (max >> 1) + 1] {
            d.push(v.to_be_bytes()[8 - w..].to_vec());
        }
    }
    d
}

/// `abnf-match`: every `<grammar>/<rule>` frame header it accepts, the
/// literals of the grammars it matches against, and big-endian integers.
pub fn matcher() -> Vec<Vec<u8>> {
    let mut d = Vec::new();
    for g in GRAMMARS {
        for r in rule_names(g.text) {
            d.push(format!("{}/{r}\n", g.name).into_bytes());
        }
    }
    for f in repo::fixtures() {
        for r in rule_names(f.text.as_bytes()) {
            d.push(format!("{}/{r}\n", f.name).into_bytes());
        }
    }
    d.extend(literals(&repo::matchable_names()));
    d.extend(be_integers());
    d
}

/// `abnf-vectors`: the directives, tags and escapes of vector files, and
/// the rule names of the grammars they are checked against.
pub fn vectors() -> Vec<Vec<u8>> {
    let mut d = words(&[
        "# rule: ",
        "# max-length: ",
        "# caps: ",
        "# unwrapped: ",
        "ok\t",
        "err\t",
        "errc\t",
        "ok@",
        "err@",
        "errc@",
        "\\t",
        "\\\\",
        "\\\"",
        "\\x",
        "\\x0d",
        "\n",
        "#",
    ]);
    for g in GRAMMARS {
        d.extend(rule_names(g.text).into_iter().map(String::into_bytes));
    }
    d
}

/// `abnf-constraint`: the vocabulary's keywords, from
/// `grammars/constraint.abnf`, and the comment marker.
pub fn constraint() -> Vec<Vec<u8>> {
    let mut d = words(&[
        "; constraint: ",
        "constraint:",
        "..",
        ", ",
        "-",
        "18446744073709551615",
        "-9223372036854775808",
    ]);
    d.extend(literals(&["constraint"]));
    d
}

/// `kargs-parse`: the kernel-argument grammar's literals, and the keys
/// the kernel reads (`grammars/kernel-args.vectors`).
pub fn kargs_parse() -> Vec<Vec<u8>> {
    let mut d = words(&["=", "=\"", "\" ", "\\\"", "\\\\", "."]);
    d.extend(literals(&["kernel-args"]));
    for (_, line) in seeds::octets_of("kernel-args") {
        if let Some(meaning) = crate::oracle::kargs_meaning(&line) {
            d.extend(meaning.into_iter().map(|(k, _)| k.into_bytes()));
        }
    }
    d
}

/// `kargs-grub`: what GRUB writes, and the kernel-argument dictionary.
pub fn kargs_grub() -> Vec<Vec<u8>> {
    let mut d = kargs_parse();
    d.extend(words(&[
        "BOOT_IMAGE=",
        "BOOT_IMAGE=/aspis.efi ",
        "\\'",
        "\"",
        " ",
    ]));
    d
}

/// No dictionary: `abnf-generated`'s bytes are choices, not text.
pub fn none() -> Vec<Vec<u8>> {
    Vec::new()
}

/// `idl-names`: the names grammar's literals, the references'
/// separators and limits, the reserved words, an interface ID, and the
/// embedded interfaces' references.
pub fn idl_names() -> Vec<Vec<u8>> {
    let mut d = literals(&["names"]);
    d.extend(words(&[
        "/", ".", "!", "!#", "/@", "/*", "_", "0", "65535", "65536",
    ]));
    d.extend(words(&idl_rt::names::CEDAR_RESERVED));
    d.extend(words(&idl_rt::names::RUST_RESERVED));
    d.push(b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_vec());
    d.extend(
        crate::idl_targets::interface_refs()
            .into_iter()
            .map(String::into_bytes),
    );
    d
}

/// `idl-front-end`: the IDL grammar's literals, the built-in types, the
/// attributes the checker knows, the fragments of a file, and the
/// embedded interfaces' references.
pub fn idl_front_end() -> Vec<Vec<u8>> {
    let mut d = literals(&["idl"]);
    d.extend(words(&idl::parse::BUILTIN_TYPES));
    // The attributes the checker knows (crates/idl/src/check.rs reads the
    // table), and `json`, an argument of `format`.
    d.extend(words(&idl::canon::ATTRIBUTE_ORDER));
    d.extend(words(&["json"]));
    d.extend(words(&[
        "edition 2026;\n",
        "interface ",
        "[id(",
        "object_id(reserved(",
        "version(1.",
        "since(1.",
        "deprecated(1.",
        "use ",
        ".{",
        "};",
        "@1 ",
        "-> (",
        "stream<",
        "cap<",
        "array<",
        "seq<",
        "///",
        "//!",
        "1023",
        "1024",
        // `retry`'s other argument, and the result field the canonical
        // form writes as a bare type.
        "never",
        "retry(never)",
        "result",
        "-> (result: ",
        // Doc comments' Markdown: a fence, a link, an autolink and
        // ordered list items.
        "```",
        "](",
        "<https:",
        "1. ",
        "2) ",
        "\n///   ",
    ]));
    // UTF-8 forms of three and four octets that the lexer checks one by
    // one: U+D7FF (`ED` with its narrow second octet), U+40000 (`F1`) and
    // U+10FFFF (`F4`).
    d.extend([
        b"\xED\x9F\xBF".to_vec(),
        b"\xF1\x80\x80\x80".to_vec(),
        b"\xF4\x8F\xBF\xBF".to_vec(),
    ]);
    d.extend(
        crate::idl_targets::interface_refs()
            .into_iter()
            .map(String::into_bytes),
    );
    d
}

/// `idl-generated`: the frames only. The rest of an input is the
/// generator's choices, not text.
pub fn idl_frames() -> Vec<Vec<u8>> {
    crate::idl_repo::MODULES
        .iter()
        .map(|m| crate::idl_repo::frame(m).into_bytes())
        .collect()
}

/// `idl-decode`: the frames, big-endian integers, every embedded wire
/// grammar's literals, and JSON's tokens, for `[format(json)]` strings.
pub fn idl_decode() -> Vec<Vec<u8>> {
    let mut d = idl_frames();
    d.extend(be_integers());
    d.extend(words(&[
        "{\"",
        "\":",
        "\",\"",
        "\\u",
        "\\ud83d\\ude00",
        "\\t",
        "\u{1F600}",
        "[[[[",
    ]));
    for i in crate::idl_repo::LOADED.iter() {
        for g in &i.wire {
            d.extend(g.literals().map(<[u8]>::to_vec));
        }
    }
    d
}
