// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! C07's targets (ADR 0068, rule 4; docs/design/call-language.md,
//! "Trust-boundary parsers" and "Fuzz entry points"), wrapping C07's own
//! entry functions:
//!
//! - `idl-names`: the three reference parsers and their predicates
//!   (`idl_rt::fuzz::names`), held to `grammars/names.abnf`;
//! - `idl-front-end`: the IDL front end, projection and compatibility
//!   checker (`idl::fuzz::front_end_with`), held to `grammars/idl.abnf`;
//! - `idl-decode`: the generic decoding runtime, through every generated
//!   module (`idl_rt::fuzz::decode`), against its generated grammar and
//!   the dynamic codec (`idl::conformance::differential`);
//! - `idl-generated`: the generated decoders and the dynamic codec on
//!   valid structured messages from `idl::fuzz::generate`.
//!
//! The catalog runs the front end on publishers' files, and every node
//! runs the decoders on messages from across a trust boundary, so every
//! input must end with an answer or an error, never a panic.

use idl::{
    Code, Limits,
    conformance::{self, Judged},
    parse::{Rule, parse_rule},
    schema::{Body, Def, Schema, Top},
    value::{self, Value},
};
use idl_rt::{
    conformance::Subject,
    json::JsonWriter,
    names::{self, ActionTarget, ErrorRef, InterfaceRef, MAX_ACTION_REF, MAX_LABEL, MAX_NAME},
    rules::{Module, Op, Verdict},
};

use crate::{
    generate::SplitMix64,
    idl_repo::{self, INTERFACES, Interface},
    oracle, seeds,
};

// ---- idl-names ---------------------------------------------------------

kinds! {
    /// The kinds `idl-names` reaches: each form each parser accepts, and
    /// an input none of them accepts.
    pub const NAMES_KINDS = ["interface-ref", "interface-ref-minor", "refused"];
    fn action_kind(t: ActionTarget<'_>) {
        ActionTarget::Method(_) => "action-method",
        ActionTarget::Group(_) => "action-group",
        ActionTarget::All => "action-all",
    }
    fn error_kind(e: ErrorRef<'_>) {
        ErrorRef::Named { .. } => "error-named",
        ErrorRef::Code { .. } => "error-code",
    }
}

/// An interface reference's kind: with or without its minor.
fn interface_kind(r: &InterfaceRef<'_>) -> &'static str {
    match r.minor {
        None => "interface-ref",
        Some(_) => "interface-ref-minor",
    }
}

type Parsed<'a> = (
    Result<InterfaceRef<'a>, names::ParseError>,
    Result<names::ActionRef<'a>, names::ParseError>,
    Result<ErrorRef<'a>, names::ParseError>,
);

/// Runs the three parsers, and checks what each success holds: every
/// part is one the grammar's own parts accept.
fn run_names(data: &[u8]) -> Parsed<'_> {
    let parsed = (
        names::parse_interface_ref(data),
        names::parse_action_ref(data),
        names::parse_error_ref(data),
    );
    if let Ok(r) = &parsed.0 {
        assert!(names::is_name(r.name.as_bytes()), "interface-ref's name");
        assert_eq!(r.minor_or_zero(), r.minor.unwrap_or(0));
        let _ = r.to_string();
    }
    if let Ok(r) = &parsed.1 {
        assert!(names::is_name(r.interface.as_bytes()), "action-ref's name");
        match r.target {
            ActionTarget::Method(m) | ActionTarget::Group(m) => {
                assert!(names::is_member_name(m.as_bytes()), "action-ref's member")
            }
            ActionTarget::All => {}
        }
        assert!(data.len() <= MAX_ACTION_REF, "an action reference's length");
        let _ = r.to_string();
    }
    if let Ok(r) = &parsed.2 {
        match *r {
            ErrorRef::Named {
                interface, error, ..
            } => {
                assert!(names::is_name(interface.as_bytes()), "error-ref's name");
                assert!(names::is_member_name(error.as_bytes()), "error-ref's error");
            }
            ErrorRef::Code {
                interface_id, code, ..
            } => {
                assert!(names::is_id_text(interface_id.as_bytes()), "error-ref's ID");
                assert_ne!(code, 0, "error code 0");
            }
        }
        let _ = r.to_string();
    }
    parsed
}

/// `idl-names`: C07's entry, which checks that each accepted reference
/// renders back; determinism; what each success holds; and agreement
/// with `grammars/names.abnf` on seven of its rules ("The gate for each
/// target", items 2 and 3).
pub fn names(data: &[u8]) {
    idl_rt::fuzz::names(data);
    let a = run_names(data);
    assert_eq!(a, run_names(data), "the name parsers are deterministic");
    oracle::check_names_agreement(data, oracle::names_accepts);
}

/// The kinds an input reaches in `idl-names`.
pub fn names_kinds(data: &[u8]) -> Vec<&'static str> {
    let (i, a, e) = run_names(data);
    let mut kinds = Vec::new();
    if let Ok(r) = i {
        kinds.push(interface_kind(&r));
    }
    if let Ok(r) = a {
        kinds.push(action_kind(r.target));
    }
    if let Ok(r) = e {
        kinds.push(error_kind(r));
    }
    if kinds.is_empty() {
        kinds.push("refused");
    }
    kinds
}

/// A name of exactly `n` octets (`n` at least 3): labels of up to 63
/// `a`s, joined by `.`.
fn name_of(n: usize) -> String {
    let mut s = String::new();
    while s.len() < n {
        if !s.is_empty() {
            s.push('.');
        }
        let left = n - s.len();
        // Never leave one octet over: a label after it needs two.
        let take = match left {
            l if l <= MAX_LABEL => l,
            l if l == MAX_LABEL + 1 => MAX_LABEL - 1,
            _ => MAX_LABEL,
        };
        s.push_str(&"a".repeat(take));
    }
    s
}

/// A 64-digit interface ID, in the interim text form.
const ID_TEXT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// `idl-names`' generated seeds: every line of `grammars/names.vectors`,
/// and the limits: a label of 63 and 64 octets, a name of 255 and 256, a
/// major and a minor of 65535 and 65536, an action reference of
/// `MAX_ACTION_REF` octets and one more, error codes 0, 1, 65535 and
/// 65536, each reserved word as a label and as a member name, and a run
/// of name octets as long as the target takes, which the agreement check
/// leaves unjudged (`oracle::names_grammar_accepts`).
pub fn names_seeds() -> Vec<(String, Vec<u8>)> {
    let mut out = seeds::octets_of("names");
    let mut add = |name: String, s: String| out.push((name, s.into_bytes()));
    add("names-label-63".into(), "a".repeat(MAX_LABEL));
    add("names-label-64".into(), "a".repeat(MAX_LABEL + 1));
    add("names-name-255".into(), name_of(MAX_NAME));
    add("names-name-256".into(), name_of(MAX_NAME + 1));
    add(
        "names-name-255-ref".into(),
        format!("{}/1", name_of(MAX_NAME)),
    );
    add(
        "names-name-256-ref".into(),
        format!("{}/1", name_of(MAX_NAME + 1)),
    );
    for n in ["65535", "65536"] {
        add(format!("names-major-{n}"), format!("org.example/{n}"));
        add(format!("names-minor-{n}"), format!("org.example/1.{n}"));
    }
    let member = "a".repeat(MAX_LABEL);
    let longest = format!("{}/65535/@{member}", name_of(MAX_NAME));
    assert_eq!(longest.len(), MAX_ACTION_REF);
    add("names-action-326".into(), longest);
    add(
        "names-action-327".into(),
        format!("{}/65535/@{member}a", name_of(MAX_NAME)),
    );
    for code in ["0", "1", "65535", "65536"] {
        add(format!("names-code-{code}"), format!("{ID_TEXT}/1!#{code}"));
    }
    for w in names::CEDAR_RESERVED
        .iter()
        .chain(names::RUST_RESERVED.iter())
    {
        add(format!("names-reserved-{w}"), w.to_string());
        add(format!("names-reserved-{w}-label"), format!("org.{w}/1"));
        add(
            format!("names-reserved-{w}-member"),
            format!("org.example/1/{w}"),
        );
    }
    add("names-run-1350".into(), "a".repeat(MAX_ACTION_REF + 1024));
    out
}

// ---- idl-front-end -----------------------------------------------------

kinds! {
    /// The kinds `idl-front-end` reaches: a file that checks, and each
    /// diagnostic [`Code`].
    pub const FRONT_END_KINDS = ["ok"];
    fn code_kind(c: Code) {
        Code::Syntax => "syntax",
        Code::Limit => "limit",
        Code::Header => "header",
        Code::Duplicate => "duplicate",
        Code::Number => "number",
        Code::Attribute => "attribute",
        Code::Since => "since",
        Code::Reference => "reference",
        Code::Type => "type",
        Code::Capability => "capability",
        Code::Size => "size",
        Code::Stream => "stream",
        Code::Group => "group",
        Code::ErrorList => "error-list",
        Code::Import => "import",
        Code::Doc => "doc",
    }
}

/// `idl-front-end`: C07's entry, with imports resolved from the embedded
/// interfaces, so a `use` line that names one checks fully; determinism
/// of the syntax pass and of the whole front end (the checker resolves
/// imports and builds models, where map order could leak in); and the
/// parser's agreement with `grammars/idl.abnf` (ADR 0067, rule 11).
pub fn front_end(data: &[u8]) {
    idl::fuzz::front_end_with(data, &mut idl_repo::resolve);
    let limits = Limits::default();
    let p = parse_rule(Rule::IdlFile, data, &limits);
    assert_eq!(
        p,
        parse_rule(Rule::IdlFile, data, &limits),
        "the parser is deterministic"
    );
    assert!(
        checked(data) == checked(data),
        "the checker is deterministic: its diagnostics, or its canonical form and lock hash"
    );
    oracle::check_idl_agreement(data, oracle::idl_file_verdict);
}

/// What one run of the checker gives: its diagnostics, or the canonical
/// form and lock hash at the file's version. Only these are held, so two
/// runs don't hold two models at once.
fn checked(data: &[u8]) -> Result<(String, [u8; 32]), Vec<idl::Diagnostic>> {
    let c = idl::check(data, &mut idl_repo::resolve, &Limits::default())?;
    let v = c.unit().version.minor;
    Ok((
        idl::generate::canonical(&c, v),
        idl::generate::minor_hash(&c, v),
    ))
}

/// The kinds an input reaches in `idl-front-end`: the code of every
/// diagnostic the checker gives.
pub fn front_end_kinds(data: &[u8]) -> Vec<&'static str> {
    match idl::check(data, &mut idl_repo::resolve, &Limits::default()) {
        Ok(_) => vec!["ok"],
        Err(d) => d.iter().map(|d| code_kind(d.code)).collect(),
    }
}

/// A small IDL file: `body` inside interface `y`, with `head` the
/// lines before the interface's attributes.
fn idl_file(head: &str, attrs: &str, body: &str) -> String {
    format!(
        "edition 2026;\n{head}[id(org.example.y), object_id(reserved(0x0301)), version(1.0){attrs}]\ninterface y {{\n{body}}}\n"
    )
}

/// `idl-front-end`'s generated seeds: every line of `grammars/idl.vectors`
/// (every rule's, as C07's replay does), every embedded IDL file, each
/// file's canonical form at each minor, and the front end's limits, each
/// at the limit and one over: types nested 32 deep, 16 `use` lines, 64
/// attributes, 4096 members, a file of `source` octets, a label of 63
/// octets, 4096 names on a `use` line, 4096 errors in a method's list,
/// 4096 items in a list, and 64 qualifiers in a `cap<...>`;
/// [`comment_cut_seeds`]; an interface named by a run of 64 KiB name octets, which the
/// agreement check leaves unjudged (`oracle::names_grammar_accepts`); and
/// two files of structs of `source` octets: one whose canonical form,
/// which writes out every tag and space, is about twice as long, which
/// the checker refuses (C07's entry once panicked on a form over the
/// limit), and one written as the canonical form writes it, which
/// checks; and [`dense_minors_file`], the costliest seed, which sets the
/// target's bounds.
pub fn front_end_seeds() -> Vec<(String, Vec<u8>)> {
    let mut out = seeds::octets_of("idl");
    for i in idl_repo::LOADED.iter() {
        let stem = format!("{}-v{}", i.repo.name, i.repo.major).replace('_', "-");
        out.push((format!("file-{stem}"), i.repo.idl.to_vec()));
        for m in 0..=i.version() {
            out.push((
                format!("canonical-{stem}.{m}"),
                idl::generate::canonical(&i.checked, m).into_bytes(),
            ));
        }
    }
    let limits = Limits::default();
    for (what, n) in [("at", 0), ("over", 1)] {
        // Nesting: `seq<...>` inside `seq<...>`, as deep as the limit.
        let depth = limits.nesting + n;
        let ty = format!("{}u8{}", "seq<".repeat(depth - 1), ", 1>".repeat(depth - 1));
        let body = format!("    @1 m(a: {ty});\n");
        out.push((
            format!("limit-nesting-{what}"),
            idl_file("", "", &body).into_bytes(),
        ));
        // `use` lines.
        let uses = "use org.example.base/1.{point};\n".repeat(limits.uses + n);
        out.push((
            format!("limit-uses-{what}"),
            idl_file(&uses, "", "    @1 m();\n").into_bytes(),
        ));
        // Attributes on one item: the interface's three and more.
        let more: String = (3..limits.attrs + n).map(|k| format!(", a{k}")).collect();
        out.push((
            format!("limit-attrs-{what}"),
            idl_file("", &more, "    @1 m();\n").into_bytes(),
        ));
        // Members of one interface.
        let body: String = (1..=limits.members + n)
            .map(|k| format!("    @{k} m{k}();\n"))
            .collect();
        out.push((
            format!("limit-members-{what}"),
            idl_file("", "", &body).into_bytes(),
        ));
        // A file of `source` octets, padded with trailing spaces.
        let mut f = idl_file("", "", "    @1 m();\n").into_bytes();
        f.resize(limits.source + n, b' ');
        out.push((format!("limit-source-{what}"), f));
        // A label of 63 octets, the names grammar's limit.
        let label = "a".repeat(names::MAX_LABEL + n);
        out.push((
            format!("limit-label-{what}"),
            idl_file("", "", &format!("    @1 {label}();\n")).into_bytes(),
        ));
        // Names on one `use` line, as many as an interface's members.
        let names = vec!["point"; limits.members + n].join(",");
        out.push((
            format!("limit-imported-names-{what}"),
            idl_file(
                &format!("use org.example.base/1.{{{names}}};\n"),
                "",
                "    @1 m();\n",
            )
            .into_bytes(),
        ));
        // Errors in one method's list, likewise.
        let errors = vec!["e"; limits.members + n].join(",");
        out.push((
            format!("limit-errors-{what}"),
            idl_file(
                "",
                "",
                &format!("    error e = 1;\n    @1 m() error({errors});\n"),
            )
            .into_bytes(),
        ));
        // Items in one list: a struct's fields.
        let fields: String = (0..limits.fields + n)
            .map(|k| format!("f{k}: u8,"))
            .collect();
        out.push((
            format!("limit-items-{what}"),
            idl_file("", "", &format!("    struct s {{ {fields} }}\n")).into_bytes(),
        ));
        // Qualifiers in one `cap<...>`, as many as an item's attributes.
        let quals = ", read".repeat(limits.attrs + n);
        out.push((
            format!("limit-qualifiers-{what}"),
            idl_file(
                "",
                "",
                &format!("    @1 m(a: cap<aspis.kernel.memory/1{quals}>);\n"),
            )
            .into_bytes(),
        ));
    }
    out.extend(comment_cut_seeds());
    out.push((
        "name-run-64k".into(),
        format!(
            "edition 2026;\n[id(org.example.y), object_id(reserved(0x0301)), version(1.0)]\ninterface {} {{\n}}\n",
            "a".repeat(64 * 1024)
        )
        .into_bytes(),
    ));
    // Structs of fields of three octets, `qaa` to `qzz`: written without
    // spaces, `qab:u8,` is `@2 qab: u8, ` in the canonical form, about
    // twice as long, so the checker refuses the file; written as the
    // canonical form writes them, the form is no longer than the file,
    // and it checks.
    for (name, canonical) in [
        ("canonical-over-source", false),
        ("canonical-at-source", true),
    ] {
        let mut body = String::new();
        let mut k = 0;
        loop {
            let mut line = format!("struct s{k} {{");
            for (n, (a, b)) in ('a'..='z')
                .flat_map(|a| ('a'..='z').map(move |b| (a, b)))
                .enumerate()
            {
                line += &match (canonical, n) {
                    (false, _) => format!("q{a}{b}:u8,"),
                    (true, 0) => format!("@1 q{a}{b}: u8"),
                    (true, _) => format!(", @{} q{a}{b}: u8", n + 1),
                };
            }
            line += "}\n";
            if body.len() + line.len() + 200 > limits.source {
                break;
            }
            body += &line;
            k += 1;
        }
        let mut f = idl_file("", "", &body).into_bytes();
        // Padded to the limit before its `}`, which the form drops.
        let end = f.len() - 2;
        let pad = limits.source - f.len();
        f.splice(end..end, core::iter::repeat_n(b' ', pad));
        out.push((name.into(), f));
    }
    out.push(("dense-minors".into(), dense_minors_file(DENSE_MINORS)));
    out
}

/// The size [`dense_minors_file`] is generated at. Its canonical form at
/// version 1.40 is about 1.17 times the file, and each struct adds about
/// 5 KiB to the file. At 870 KiB the form is within 2 KiB of the source
/// limit, so the seed is 864 KiB, two structs shorter, and its form fits
/// with about 13 KiB to spare. `tests/bounds.rs` checks it is near the
/// largest of its kind that checks.
pub const DENSE_MINORS: usize = 864 << 10;

/// A valid IDL file of about `n` octets that C07's entry spends the most
/// time on: structs of 200 optional fields, each added at one of 18 even
/// minors, 1.2 to 1.36, in order, in a file of version 1.40. The entry
/// checks the file, then the canonical form of each minor it visits: 0,
/// 1.40 and 1.39, and the first four and last four of the 18 with the
/// minor before each, 19 in all, the most it ever visits
/// (`idl::fuzz::minors`).
pub fn dense_minors_file(n: usize) -> Vec<u8> {
    let mut body = String::new();
    let mut k = 0;
    while body.len() + 4096 < n {
        body += &format!("    struct s{k} {{ ");
        for f in 0..200 {
            body += &format!("[since(1.{})] f{f}: u32?, ", (f * 18 / 200 + 1) * 2);
        }
        body += "}\n";
        k += 1;
    }
    body += "    @1 m(a: s0);\n";
    format!(
        "edition 2026;\n[id(org.example.y), object_id(reserved(0x0301)), version(1.40)]\ninterface y {{\n{body}}}\n"
    )
    .into_bytes()
}

/// A small file with most of the grammar's places where trivia may come,
/// for [`comment_cut_seeds`].
pub const CUT_SOURCE: &str = "edition 2026;
use org.example.base/1.0.{point, pair};
/// Y.
[id(org.example.y), object_id(reserved(0x0301)), version(1.1), groups(g)]
interface y {
    const c: u8 = 1;
    alias a = seq<u8?, 2>;
    [closed] flags f: u8 { x = 1, reserved 2 }
    enum e: u8 { x = 1, reserved 2 }
    struct s { p: org.example.base/1.point?, [since(1.1)] a: u8? }
    union u { @1 a: u8, reserved @2 }
    [type(org.example.o)] object o { n: u64 }
    error r = 1 { a: u8, t: string<8>, b: bytes<4> };
    struct i { a: u8 }
    [group(g)] @1 m(a: cap<aspis.kernel.memory/1, read>, after: u64?) -> (b: u8) stream<i> error(r);
    @2 n() -> array<u8, 2>;
    reserved @3;
}
";

/// `idl-front-end`'s comment seeds: [`CUT_SOURCE`] cut after each token,
/// with `//` and no line feed after the cut, named `comment-cut-<offset>`.
/// A comment that ends the input without a line feed is an error, so
/// each seed reaches the parser's error return after the trivia at that
/// place in the grammar, which a campaign rarely builds.
pub fn comment_cut_seeds() -> Vec<(String, Vec<u8>)> {
    let b = CUT_SOURCE.as_bytes();
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    (1..b.len())
        .filter(|&i| {
            // Not inside a reference, a number, `->` or `seq<`, where no
            // trivia may come.
            let (p, c) = (b[i - 1], b[i]);
            let joined = |x: u8| matches!(x, b'.' | b'/' | b'@' | b'-');
            !p.is_ascii_whitespace()
                && !joined(p)
                && !joined(c)
                && c != b'<'
                && (!word(p) || !word(c))
        })
        .map(|i| {
            let mut s = b[..i].to_vec();
            s.extend_from_slice(b"//");
            (format!("comment-cut-{i}"), s)
        })
        .collect()
}

// ---- idl-decode and idl-generated: frames ------------------------------

/// The longest frame: a name of 255 octets, `/65535.65535`, and LF.
pub const FRAME_MAX: usize = MAX_NAME + 13;

/// The module an input's frame names, and the rest of the input. The
/// frame is the module's interface reference, with its own minor, and
/// LF, as in `aspis.rpc/1.0`: a text frame keeps a committed regression
/// pointing at the same module when C17 adds interfaces, where an index
/// would shift.
pub fn split_frame(data: &[u8]) -> Option<(&'static Module, &[u8])> {
    let nl = data.iter().take(FRAME_MAX).position(|&b| b == b'\n')?;
    let r = names::parse_interface_ref(&data[..nl]).ok()?;
    Some((idl_repo::module(&r)?, &data[nl + 1..]))
}

/// The embedded interface a module is a binding of. `tests/targets.rs`
/// checks every module has one, so this never fails.
fn interface_of(m: &Module) -> &'static Interface {
    idl_repo::interface_of(m)
        .unwrap_or_else(|| panic!("{}/{}: no embedded interface", m.name, m.major))
}

/// The top-level body of a rule at the schema's minor, if the minor has
/// the rule: the first top that names it, as
/// `idl::conformance::judge` picks it.
pub fn top_of(s: &Schema<'_>, rule: &str) -> Option<Top> {
    s.tops().into_iter().find(|&t| s.top_rule(t) == rule)
}

// ---- idl-decode --------------------------------------------------------

/// What `idl_rt::fuzz::decode` reads from the octets after the frame: a
/// rule, a reading minor, a capability count and the message, picked
/// exactly as it picks them. `tests/targets.rs` holds this copy of its
/// mapping to what idl-rt's entry passes to a module that records it.
#[derive(Debug, Clone, Copy)]
pub struct Pick<'a> {
    pub rule_index: usize,
    pub rule: &'static str,
    pub minor: u16,
    pub caps: u8,
    pub msg: &'a [u8],
}

/// [`Pick`] from the octets after the frame: None when fewer than three
/// follow it.
pub fn pick<'a>(m: &Module, rest: &'a [u8]) -> Option<Pick<'a>> {
    let [r, minor, caps, msg @ ..] = rest else {
        return None;
    };
    if m.rules.is_empty() {
        return None;
    }
    let rule_index = usize::from(*r) % m.rules.len();
    Some(Pick {
        rule_index,
        rule: m.rules[rule_index],
        minor: (u32::from(*minor) % (u32::from(m.minor) + 1)) as u16,
        caps: caps % 4,
        msg,
    })
}

/// What one `idl-decode` input is, decided in one place for the entry and
/// for [`decode_kinds`]. The frame's outcomes come first: a generated
/// `rule` function dispatches on the rule's name alone, so a rule added
/// at 1.1 and read at minor 0 still gets a verdict, which no grammar or
/// dynamic codec at that minor can be compared with.
pub enum Class<'a> {
    /// Fewer than three octets after the frame.
    Short,
    /// The rule isn't one of the reading minor's.
    NotAtMinor(Pick<'a>),
    /// The rule, its top-level body at the reading minor, and the module's
    /// verdict.
    Read(Pick<'a>, Top, Verdict),
}

/// Classifies the octets after a frame.
pub fn classify<'a>(m: &Module, rest: &'a [u8]) -> Class<'a> {
    let Some(p) = pick(m, rest) else {
        return Class::Short;
    };
    let iface = interface_of(m);
    let s = Schema::new(&iface.checked, p.minor);
    let Some(top) = top_of(&s, p.rule) else {
        return Class::NotAtMinor(p);
    };
    let mut out = vec![0u8; p.msg.len() + 64];
    let v = (m.rule)(p.rule, p.minor, p.caps, p.msg, Op::Encode(&mut out));
    Class::Read(p, top, v)
}

/// A verdict's kind. `Encode` and `NoRule` get no name: C07's entry
/// panics on both.
fn verdict_kind(v: Verdict) -> Option<&'static str> {
    match v {
        Verdict::Ok {
            value_too_new: None,
            ..
        } => Some("ok"),
        Verdict::Ok {
            value_too_new: Some(_),
            ..
        } => Some("value-too-new"),
        Verdict::Malformed => Some("malformed"),
        Verdict::FieldTooNew => Some("field-too-new"),
        Verdict::Encode(_) | Verdict::NoRule => None,
    }
}

/// The kinds `idl-decode` reaches: the frame's outcomes, then each
/// verdict a generated decoder gives.
pub const DECODE_KINDS: &[&str] = &[
    "no-module",
    "short",
    "not-at-minor",
    "ok",
    "value-too-new",
    "malformed",
    "field-too-new",
];

/// The longest JSON a message's octets may take, per octet, in the value
/// check: a one-octet `bool` in a struct's tail costs its tag and length
/// on the wire and a key of up to 63 octets in JSON. Both writers get the
/// same room, so a JSON that overflows one and not the other differs.
const JSON_PER_OCTET: usize = 32;

/// The value check ("The gate for each target", item 2, on the binding's
/// side): the subject's JSON for an accepted message is the dynamic
/// codec's. A binding whose decoder and encoder share one bug (two
/// same-typed fields swapped, a `u32` read as two `u16`s, an arm tag that
/// maps back) re-encodes byte for byte and agrees with the grammar's
/// verdict; only its value shows it. The JSON isn't matched against the
/// text grammar: that is C18's and C52's.
pub fn json_agrees(
    subject: &dyn Subject,
    s: &Schema<'_>,
    top: Top,
    rule: &str,
    caps: u8,
    msg: &[u8],
) {
    let minor = s.version().minor;
    let at = || {
        format!(
            "{}/{} {rule} at minor {minor}",
            subject.name(),
            subject.major()
        )
    };
    let room = JSON_PER_OCTET * msg.len() + 1024;
    let mut buf = vec![0u8; room];
    let mut j = JsonWriter::new(&mut buf);
    let v = subject.run(rule, minor, caps, msg, Op::Json(&mut j));
    assert!(
        matches!(v, Verdict::Ok { .. }),
        "{}: accepted, then {v:?} writing its JSON",
        at()
    );
    let ours = j.finish().ok().map(<[u8]>::to_vec);
    let d = value::decode(s, top, msg, caps)
        .unwrap_or_else(|e| panic!("{}: the dynamic codec refuses it: {e:?}", at()));
    let mut buf2 = vec![0u8; room];
    let mut j2 = JsonWriter::new(&mut buf2);
    value::to_json(s, top, &d.value, &mut j2);
    let want = j2.finish().ok();
    assert!(
        ours.as_deref() == want,
        "{}: the binding's JSON {} but the dynamic codec's {}",
        at(),
        String::from_utf8_lossy(ours.as_deref().unwrap_or(b"(overflows)")),
        String::from_utf8_lossy(want.unwrap_or(b"(overflows)"))
    );
}

/// [`differential_of`] judges a message a third time with the grammar, to
/// show the whole judgment is deterministic, only when it is this short.
/// A longer one is judged again without the grammar, which still shows
/// the decoders are: a wire grammar can take 190 steps an octet, so on a
/// 16 KiB message a third pair of matches would cost about a third of the
/// target's time for little gain, as `abnf-match` finds for its own
/// second matches (`REMATCH_MAX`). The matcher's determinism is C06's.
pub const REJUDGE_MAX: usize = 1 << 10;

/// The differential ("Differential tests", the first row): C07's
/// `conformance::differential`, the subject against the minor's wire
/// grammar (none for a `[kernel]` interface) and the dynamic codec; then
/// `judge` twice more, which must give the same: the second time without
/// the grammar for a message over [`REJUDGE_MAX`] octets. Returns the
/// judgment.
pub fn differential_of(
    subject: &dyn Subject,
    s: &Schema<'_>,
    grammar: Option<&abnf::Grammar>,
    rule: &str,
    caps: u8,
    msg: &[u8],
) -> Judged {
    conformance::differential(subject, s, grammar, rule, caps, msg);
    let a = conformance::judge(subject, s, grammar, rule, caps, msg)
        .unwrap_or_else(|e| panic!("{rule}: {e}"));
    let again = if msg.len() <= REJUDGE_MAX {
        grammar
    } else {
        None
    };
    let b = conformance::judge(subject, s, again, rule, caps, msg)
        .unwrap_or_else(|e| panic!("{rule}: {e}"));
    // Without the grammar, `b` is the decoders' verdict alone.
    assert!(
        a == b || (again.is_none() && a == Judged::Unjudged),
        "{rule}: the differential is deterministic: {a:?}, then {b:?}"
    );
    a
}

/// `idl-decode`'s checks on the octets after a module's frame, with
/// `subject` as the binding under test: C07's entry on the module; then,
/// for a rule the reading minor has, the differential and the value
/// check. The wire grammar must give a verdict within
/// [`WIRE_LIMITS`](crate::WIRE_LIMITS): an input it can't judge is a
/// finding. A rule the reading minor lacks has no grammar rule or body to
/// compare with, so only C07's entry runs on it: no panic, and an
/// accepted message re-encodes to itself. Returns the judgment, if one
/// was made.
pub fn decode_with(subject: &dyn Subject, m: &'static Module, rest: &[u8]) -> Option<Judged> {
    idl_rt::fuzz::decode(m, rest);
    let p = pick(m, rest)?;
    let iface = interface_of(m);
    let s = Schema::new(&iface.checked, p.minor);
    let top = top_of(&s, p.rule)?;
    let grammar = iface.wire_grammar(p.minor);
    let j = differential_of(subject, &s, grammar, p.rule, p.caps, p.msg);
    assert_ne!(
        j,
        Judged::Unjudged,
        "{}: the wire grammar gives no verdict within WIRE_LIMITS on {} octets",
        p.rule,
        p.msg.len()
    );
    if j != Judged::Refused {
        let mut out = vec![0u8; p.msg.len() + 64];
        if matches!(
            subject.run(p.rule, p.minor, p.caps, p.msg, Op::Encode(&mut out)),
            Verdict::Ok { .. }
        ) {
            json_agrees(subject, &s, top, p.rule, p.caps, p.msg);
        }
    }
    Some(j)
}

/// `idl-decode` for one module: the seam for C17's per-kernel-interface
/// targets, each a row whose entry calls this with its own module.
pub fn decode_module(m: &'static Module, rest: &[u8]) {
    let _ = decode_with(m, m, rest);
}

/// `idl-decode`: the generated decoders of every embedded module, the
/// frame picking the module.
pub fn decode(data: &[u8]) {
    let _ = decode_judged(data);
}

/// [`decode`], returning the judgment, if one was made, for the tests.
pub fn decode_judged(data: &[u8]) -> Option<Judged> {
    let (m, rest) = split_frame(data)?;
    decode_with(m, m, rest)
}

/// The kinds an input reaches in `idl-decode`.
pub fn decode_kinds(data: &[u8]) -> Vec<&'static str> {
    let Some((m, rest)) = split_frame(data) else {
        return vec!["no-module"];
    };
    match classify(m, rest) {
        Class::Short => vec!["short"],
        Class::NotAtMinor(_) => vec!["not-at-minor"],
        Class::Read(_, _, v) => verdict_kind(v).into_iter().collect(),
    }
}

/// An `idl-decode` input: a module's frame, the rule's index, the
/// reading minor, the capability count, and the message.
pub fn decode_input(m: &Module, rule: &str, minor: u16, caps: u8, msg: &[u8]) -> Option<Vec<u8>> {
    let r = m.rules.iter().position(|x| *x == rule)?;
    let mut d = idl_repo::frame(m).into_bytes();
    d.extend_from_slice(&[u8::try_from(r).ok()?, u8::try_from(minor).ok()?, caps]);
    d.extend_from_slice(msg);
    Some(d)
}

/// A seed name's part for a module: `<name>-<major>.<minor>`.
fn module_stem(m: &Module) -> String {
    format!("{}-{}.{}", m.name, m.major, m.minor).replace('_', "-")
}

/// The modules of an interface major that read minor `minor`.
fn readers(name: &str, major: u16, minor: u16) -> Vec<&'static Module> {
    idl_repo::MODULES
        .iter()
        .copied()
        .filter(|m| m.name == name && m.major == major && m.minor >= minor)
        .collect()
}

/// The largest bound the vector generator's samples reach: a longer
/// string, byte string or sequence gets bound seeds instead.
const SAMPLE_MAX: u64 = 64;

/// A value with one string, byte string or sequence set to its bound, and
/// to one over: the field's path, its bound, and the two values.
pub struct Widened {
    pub path: String,
    pub bound: u64,
    pub at: Value,
    pub over: Value,
}

/// Every place in `v`, a value of the type `t` in unit `u`, where a
/// string, byte string or sequence with a bound over [`SAMPLE_MAX`] sits,
/// with `v` rebuilt around the widened value. Sequences are widened with
/// copies of their first element, so an empty one has none; the first
/// element of a sequence or array is looked into.
fn widen_ty(s: &Schema<'_>, u: usize, t: &idl::ast::Type, v: &Value) -> Vec<Widened> {
    if t.optional
        && let Value::Opt(Some(x)) = v
    {
        return rewrap(widen_bare(s, u, t, x), |x| Value::Opt(Some(Box::new(x))));
    }
    widen_bare(s, u, t, v)
}

fn widen_bare(s: &Schema<'_>, u: usize, t: &idl::ast::Type, v: &Value) -> Vec<Widened> {
    use idl::ast::BaseType as B;
    let leaf = |bound: u64, at: Value, over: Value| {
        vec![Widened {
            path: String::new(),
            bound,
            at,
            over,
        }]
    };
    match (&t.base, v) {
        (B::String(b), Value::Text(_)) if s.bound(u, b) > SAMPLE_MAX => {
            let n = s.bound(u, b) as usize;
            leaf(
                n as u64,
                Value::Text("x".repeat(n)),
                Value::Text("x".repeat(n + 1)),
            )
        }
        (B::Bytes(b), Value::Bytes(_)) if s.bound(u, b) > SAMPLE_MAX => {
            let n = s.bound(u, b) as usize;
            leaf(
                n as u64,
                Value::Bytes(vec![0xA5; n]),
                Value::Bytes(vec![0xA5; n + 1]),
            )
        }
        (B::Seq(e, b), Value::List(items)) | (B::Array(e, b), Value::List(items))
            if !items.is_empty() =>
        {
            let mut out = Vec::new();
            if matches!(t.base, B::Seq(..)) && s.bound(u, b) > SAMPLE_MAX {
                let n = s.bound(u, b) as usize;
                out.extend(leaf(
                    n as u64,
                    Value::List(vec![items[0].clone(); n]),
                    Value::List(vec![items[0].clone(); n + 1]),
                ));
            }
            out.extend(rewrap(widen_ty(s, u, e, &items[0]), |x| {
                let mut l = items.clone();
                l[0] = x;
                Value::List(l)
            }));
            out
        }
        (B::Ref(r), _) => match s.resolve(u, r) {
            Some(id) => widen_named(s, id, v),
            None => Vec::new(),
        },
        _ => Vec::new(),
    }
}

fn widen_named(s: &Schema<'_>, id: idl::model::TypeId, v: &Value) -> Vec<Widened> {
    match s.def(id) {
        Def::Alias(t) => widen_ty(s, id.unit, t, v),
        Def::Struct { .. } => widen_body(s, &s.struct_body(id), v),
        Def::Union { .. } => match v {
            Value::Arm(tag, x) => match s.arm(id, *tag) {
                Some(a) => rewrap(widen_ty(s, id.unit, a.ty, x), |y| {
                    Value::Arm(*tag, Box::new(y))
                }),
                None => Vec::new(),
            },
            _ => Vec::new(),
        },
        Def::Enum { .. } => Vec::new(),
    }
}

fn widen_body(s: &Schema<'_>, b: &Body<'_>, v: &Value) -> Vec<Widened> {
    let Value::Struct(fv) = v else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (i, (f, x)) in s.known_fields(b).iter().zip(&fv.known).enumerate() {
        let Some(x) = x else { continue };
        let name = f.field.name.name.replace('_', "-");
        // A field's value is bare: its `?` is the field's presence. An
        // optional value inside it is `Value::Opt`.
        let ws = match x {
            Value::Opt(_) => widen_ty(s, b.unit, &f.field.ty, x),
            _ => widen_bare(s, b.unit, &f.field.ty, x),
        };
        for w in ws {
            let rebuild = |y: Value| {
                let mut fv = fv.clone();
                fv.known[i] = Some(y);
                Value::Struct(fv)
            };
            let path = if w.path.is_empty() {
                name.clone()
            } else {
                format!("{name}.{}", w.path)
            };
            out.push(Widened {
                path,
                bound: w.bound,
                at: rebuild(w.at),
                over: rebuild(w.over),
            });
        }
    }
    out
}

/// Rebuilds each widened value inside its container.
fn rewrap(ws: Vec<Widened>, wrap: impl Fn(Value) -> Value) -> Vec<Widened> {
    ws.into_iter()
        .map(|w| Widened {
            path: w.path,
            bound: w.bound,
            at: wrap(w.at),
            over: wrap(w.over),
        })
        .collect()
}

/// The bound seeds of one top-level body: each place where a string,
/// byte string or sequence with a bound over 64 sits in some sample of
/// it, taken from the first sample that holds it.
pub fn widen(s: &Schema<'_>, top: Top, v: &Value) -> Vec<Widened> {
    match top {
        Top::Request(i) => widen_body(s, &s.params(i), v),
        Top::Reply(i) => widen_body(s, &s.results(i), v),
        Top::Open(i) => match v {
            Value::List(l) if l.len() == 3 => rewrap(widen_body(s, &s.results(i), &l[2]), |x| {
                Value::List(vec![l[0].clone(), l[1].clone(), x])
            }),
            _ => Vec::new(),
        },
        Top::Item(i) => match s.item(i) {
            Some(id) => widen_named(s, id, v),
            None => Vec::new(),
        },
        Top::Error(i) => widen_body(s, &s.detail(i), v),
        Top::Type(id, _) => widen_named(s, id, v),
    }
}

/// `idl-decode`'s bound seeds: for every module at its own minor, each
/// string, byte string or sequence whose bound is over 64 (the samples
/// stop at 64) at its bound and one over, named
/// `<module>-<rule>-<field>-bound` and `-over`. The one at the bound must
/// decode and the one over must be malformed (`tests/targets.rs`). A body
/// over idl-rt's 16 KiB cap, or with more than three capabilities, can't
/// be framed, and is left out.
pub fn bound_seeds() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for &m in idl_repo::MODULES.iter() {
        let iface = interface_of(m);
        let s = Schema::new(&iface.checked, m.minor);
        let budget = idl::vectors::Budget::default();
        let Ok(samples) = idl::vectors::samples(&s, &budget) else {
            continue;
        };
        let mut seen = std::collections::BTreeSet::new();
        for x in &samples {
            let rule = s.top_rule(x.top);
            for w in widen(&s, x.top, &x.value) {
                if !seen.insert((rule.clone(), w.path.clone())) {
                    continue;
                }
                for (what, v) in [("bound", &w.at), ("over", &w.over)] {
                    let enc = value::encode(&s, x.top, v, true);
                    if enc.refused || enc.caps > 3 || enc.octets.len() > idl_rt::fuzz::MAX_MESSAGE {
                        continue;
                    }
                    if let Some(d) = decode_input(m, &rule, m.minor, enc.caps, &enc.octets) {
                        out.push((format!("{}-{rule}-{}-{what}", module_stem(m), w.path), d));
                    }
                }
            }
        }
    }
    out
}

/// The JSON texts of [`kinds_seeds`]' `note` seeds, each named: every
/// form `idl_rt::json`'s embedded validator tells apart that the
/// generated vectors never hold, valid and not. The texts fit the field's
/// `string<128>`.
pub const NOTE_JSON: &[(&str, &str)] = &[
    ("object", r#"{"a":1}"#),
    ("object-key-not-string", "{1:2}"),
    ("object-two-keys", r#"{"a":1,"b":2}"#),
    ("object-key-twice", r#"{"a":1,"a":2}"#),
    ("object-key-twice-escaped", r#"{"a":1,"\u0061":2}"#),
    ("escape-tab", r#""a\tb""#),
    ("escape-bmp", r#""\u00e9""#),
    ("escape-pair", r#""\ud83d\ude00""#),
    ("escape-low-alone", r#""\ude00""#),
    ("escape-high-alone", r#""\ud83d""#),
    ("escape-high-then-text", r#""\ud83dx""#),
    ("escape-bad-low", r#""\ud83d\u0041""#),
    ("escape-bad-hex", r#""\u00zz""#),
    ("escape-noncharacter", r#""\ufdd0""#),
    ("escape-noncharacter-fffe", r#""\ufffe""#),
    ("escape-noncharacter-pair", r#""\ud83f\udffe""#),
    ("three-octets", "\"\u{20ac}\""),
];

/// `org.example.kinds`' `thing` with its `n` fields known at a minor:
/// the required three set, the optional ones absent.
fn kinds_thing(n: usize) -> Value {
    let mut known = vec![
        Some(Value::Int(1)),
        Some(Value::Int(2)),
        Some(Value::List(Vec::new())),
    ];
    known.resize(n, None);
    Value::Struct(value::Fields {
        known,
        unknown: Vec::new(),
    })
}

/// `org.example.kinds`' `put` request at `minor`, its `item` at the
/// minor's fields: `shape` and `ev` as given.
fn kinds_put(minor: u16, shape: Value, ev: Value) -> Option<Vec<u8>> {
    let i = idl_repo::interface("org.example.kinds", 1)?;
    let s = Schema::new(&i.checked, minor);
    let top = top_of(&s, "m-put--req")?;
    let fields = if minor == 0 { 7 } else { 8 };
    let v = Value::Struct(value::Fields {
        known: vec![Some(kinds_thing(fields)), Some(shape), Some(ev)],
        unknown: Vec::new(),
    });
    let enc = value::encode(&s, top, &v, true);
    assert!(!enc.refused, "kinds put at {minor}: refused");
    Some(enc.octets)
}

/// `idl-decode`'s hand-made seeds on `org.example.kinds`' newest module,
/// for what the generated ones never hold (the coverage review of the
/// C07 targets):
///
/// - `kinds-get-too-new-8` and `-9`: a `get` request, read strictly at
///   minor 2, whose tail holds 8 and 9 fields with tags past its own,
///   each empty: both are `field-too-new`, and the 9th tag is past the 8
///   that `aspis.rpc`'s `field_too_new` lists;
/// - `kinds-put-two-too-new`: a `put` request written at minor 1 and read
///   at minor 0, holding two values new in 1.1 (a `cell`'s `level::top`
///   and the `moved` arm), so the reader keeps the newest of two;
/// - `kinds-put-note-<form>`: a `put` request whose `event` is the
///   `[format(json)]` `note` arm, holding each text of [`NOTE_JSON`]. The
///   field is length-prefixed, so mutation rarely keeps such a text whole.
pub fn kinds_seeds() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let Some(m) = idl_repo::newest("org.example.kinds", 1) else {
        return out;
    };
    for n in [8u16, 9] {
        // `key`, then the tail: its count, and each field's tag and an
        // empty length. `get` knows tags 1 and 2.
        let mut msg = vec![0u8; 8];
        msg.extend_from_slice(&u32::from(n).to_be_bytes());
        for tag in 3..3 + n {
            msg.extend_from_slice(&tag.to_be_bytes());
            msg.extend_from_slice(&0u32.to_be_bytes());
        }
        if let Some(d) = decode_input(m, "m-get--req", 2, 0, &msg) {
            out.push((format!("kinds-get-too-new-{n}"), d));
        }
    }
    let cell = Value::Struct(value::Fields {
        known: vec![
            Some(Value::Int(-1)),
            Some(Value::Int(-2)),
            Some(Value::Int(-3)),
            Some(Value::Int(-4)),
            Some(Value::F32(0)),
            Some(Value::F64(0)),
            Some(Value::Bool(true)),
            Some(Value::Uuid([0; 16])),
            Some(Value::Id([0; 32])),
            Some(Value::Flags(1)),
            // `level::top`, new in 1.1.
            Some(Value::Enum(4)),
        ],
        unknown: Vec::new(),
    });
    let pair = Value::Struct(value::Fields {
        known: vec![Some(Value::Int(1)), Some(Value::Int(2))],
        unknown: Vec::new(),
    });
    if let Some(msg) = kinds_put(
        1,
        Value::Arm(2, Box::new(cell)),
        Value::Arm(5, Box::new(pair)),
    ) && let Some(d) = decode_input(m, "m-put--req", 0, 0, &msg)
    {
        out.push(("kinds-put-two-too-new".into(), d));
    }
    let depth = idl_rt::json::EMBED_DEPTH;
    let nested = |n: usize| "[".repeat(n) + &"]".repeat(n);
    let texts = NOTE_JSON
        .iter()
        .map(|(n, t)| (n.to_string(), t.to_string()))
        .chain([
            (format!("nested-{depth}"), nested(depth)),
            (format!("nested-{}", depth + 1), nested(depth + 1)),
        ]);
    for (name, text) in texts {
        if let Some(msg) = kinds_put(
            0,
            Value::Arm(1, Box::new(Value::Int(7))),
            Value::Arm(4, Box::new(Value::Text(text))),
        ) && let Some(d) = decode_input(m, "m-put--req", 0, 0, &msg)
        {
            out.push((format!("kinds-put-note-{name}"), d));
        }
    }
    out
}

/// `idl-decode`'s generated seeds:
///
/// - every line of every embedded wire vector file of minor `m`, framed
///   for every module that reads `m`, read at `m`, as
///   `crates/interfaces/tests/fuzz_entry.rs` replays them; the malformed
///   lines give the trailing-octet and over-bound cases of bounds up to
///   64;
/// - evolution: each ok vector of minor `m > 0`, read at `m - 1` by the
///   newest module, which reaches `field-too-new`, `value-too-new` and
///   `not-at-minor`;
/// - for a `[kernel]` interface, which has no wire vectors, the dynamic
///   codec's encodings of the vector generator's samples at each minor;
/// - [`bound_seeds`];
/// - [`kinds_seeds`];
/// - a frame with two octets after it (`short`), and a frame naming no
///   module.
///
/// No seed is padded to `max_len`: one at it holds libFuzzer's length
/// control at its maximum from the start ("Overrides").
pub fn decode_seeds() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for i in idl_repo::LOADED.iter() {
        let (name, major) = (i.repo.name, i.repo.major);
        for (mi, w) in i.repo.wire.iter().enumerate() {
            let minor = mi as u16;
            let vs = seeds::wire_vectors(w);
            for m in readers(name, major, minor) {
                for v in &vs {
                    if let Some(d) = decode_input(m, &v.rule, minor, v.caps, &v.octets) {
                        out.push((format!("{}-v{major}.{minor}-{}", module_stem(m), v.line), d));
                    }
                }
            }
            if let Some(newest) = idl_repo::newest(name, major)
                && minor > 0
            {
                for v in vs.iter().filter(|v| v.tag == abnf::vectors::Tag::Ok) {
                    if let Some(d) = decode_input(newest, &v.rule, minor - 1, v.caps, &v.octets) {
                        out.push((
                            format!(
                                "{}-v{major}.{minor}-{}-at{}",
                                module_stem(newest),
                                v.line,
                                minor - 1
                            ),
                            d,
                        ));
                    }
                }
            }
        }
        if i.repo.wire.is_empty() {
            for minor in 0..=i.version() {
                let s = Schema::new(&i.checked, minor);
                let budget = idl::vectors::Budget::default();
                let samples = idl::vectors::samples(&s, &budget)
                    .unwrap_or_else(|e| panic!("{}: {e}", i.repo.path));
                for m in readers(name, major, minor) {
                    for (k, x) in samples.iter().enumerate() {
                        let rule = s.top_rule(x.top);
                        if let Some(d) = decode_input(m, &rule, minor, x.caps, &x.octets) {
                            out.push((format!("{}-sample{minor}-{k}", module_stem(m)), d));
                        }
                    }
                }
            }
        }
    }
    out.extend(bound_seeds());
    out.extend(kinds_seeds());
    let mut short = b"aspis.rpc/1.0\n".to_vec();
    short.extend_from_slice(&[0, 0]);
    out.push(("short".into(), short));
    out.push(("no-module".into(), b"org.example.none/1.0\n\0\0\0".to_vec()));
    out
}

// ---- idl-generated -----------------------------------------------------

kinds! {
    /// The kinds `idl-generated` reaches: each kind of top-level body a
    /// value is generated for, and the frame's outcomes.
    pub const GENERATED_KINDS = ["no-module", "short"];
    fn top_kind(t: Top) {
        Top::Request(_) => "request",
        Top::Reply(_) => "reply",
        Top::Open(_) => "open",
        Top::Item(_) => "item",
        Top::Error(_) => "error",
        Top::Type(..) => "type",
    }
}

/// The value with every capability index 0, as the generator makes them.
/// The encoder numbers capabilities in its own order (an open struct's
/// required fields first, then its tail), so the decoded value is
/// compared with the generated one with indexes set aside; the indexes
/// themselves are held by the re-encoding and by the decoder's rule that
/// each capability is named once.
pub fn caps_zeroed(v: &Value) -> Value {
    match v {
        Value::Cap(_) => Value::Cap(0),
        Value::List(l) => Value::List(l.iter().map(caps_zeroed).collect()),
        Value::Opt(Some(x)) => Value::Opt(Some(Box::new(caps_zeroed(x)))),
        Value::Arm(t, x) => Value::Arm(*t, Box::new(caps_zeroed(x))),
        Value::Struct(f) => Value::Struct(value::Fields {
            known: f
                .known
                .iter()
                .map(|x| x.as_ref().map(caps_zeroed))
                .collect(),
            unknown: f.unknown.clone(),
        }),
        other => other.clone(),
    }
}

/// What an `idl-generated` input names: its module, the reading minor and
/// the top-level body, and the generator's choices.
struct GenPick<'a> {
    m: &'static Module,
    minor: u16,
    top: Top,
    choices: &'a [u8],
}

enum GenClass<'a> {
    NoModule,
    Short,
    /// The minor has no top-level body, or the module lacks its rule:
    /// `tests/targets.rs` shows neither happens.
    Unreachable,
    Pick(GenPick<'a>),
}

fn gen_classify(data: &[u8]) -> GenClass<'_> {
    let Some((m, rest)) = split_frame(data) else {
        return GenClass::NoModule;
    };
    let [minor, hi, lo, choices @ ..] = rest else {
        return GenClass::Short;
    };
    let minor = (u32::from(*minor) % (u32::from(m.minor) + 1)) as u16;
    let s = Schema::new(&interface_of(m).checked, minor);
    let tops = s.tops();
    if tops.is_empty() {
        return GenClass::Unreachable;
    }
    let top = tops[usize::from(u16::from_be_bytes([*hi, *lo])) % tops.len()];
    if !m.rules.contains(&s.top_rule(top).as_str()) {
        return GenClass::Unreachable;
    }
    GenClass::Pick(GenPick {
        m,
        minor,
        top,
        choices,
    })
}

/// `idl-generated`'s checks on one generated value, with `subject` as the
/// binding under test:
///
/// 1. the generator is deterministic;
/// 2. the dynamic codec's round trip: the value encodes, decodes to
///    itself (`decode(encode(x)) == x`, capability indexes aside) and
///    re-encodes to the same octets;
/// 3. the subject, the minor's wire grammar and the dynamic codec all
///    accept it (`conformance::judge`): the generator promises a valid
///    message, so a refusal is a finding, and so is a grammar out of a
///    budget ([`WIRE_LIMITS`](crate::WIRE_LIMITS)), which gives
///    `Unjudged`;
/// 4. the value check, [`json_agrees`];
/// 5. C07's entry on the module, which checks the binding's re-encoding,
///    when the message names at most three capabilities.
///
/// Returns the judgment, or None when the value would be too large.
pub fn generated_with(
    subject: &dyn Subject,
    m: &'static Module,
    minor: u16,
    top: Top,
    choices: &[u8],
) -> Option<Judged> {
    let iface = interface_of(m);
    let s = Schema::new(&iface.checked, minor);
    let rule = s.top_rule(top);
    let v = idl::fuzz::generate(&s, top, choices);
    assert_eq!(
        v,
        idl::fuzz::generate(&s, top, choices),
        "{rule}: the generator is deterministic"
    );
    let v = v?;
    let enc = value::encode(&s, top, &v, true);
    let at = || {
        format!(
            "{}/{} {rule} at minor {minor}: {}",
            m.name,
            m.major,
            idl::vectors::escape(&enc.octets)
        )
    };
    assert!(!enc.refused, "{}: the generator made a refused value", at());
    let d = value::decode(&s, top, &enc.octets, enc.caps)
        .unwrap_or_else(|e| panic!("{}: the dynamic codec refuses it: {e:?}", at()));
    assert!(
        value::encode(&s, top, &d.value, false).octets == enc.octets,
        "{}: it re-encodes differently",
        at()
    );
    assert!(
        caps_zeroed(&d.value) == v,
        "{}: it decodes to another value: {:?}, not {v:?}",
        at(),
        d.value
    );
    let j = conformance::judge(
        subject,
        &s,
        iface.wire_grammar(minor),
        &rule,
        enc.caps,
        &enc.octets,
    );
    match j {
        Ok(Judged::Accepted) => {}
        Ok(Judged::Refused) => panic!("{}: a generated message is refused", at()),
        Ok(Judged::Unjudged) => panic!("{}: the wire grammar gives no verdict", at()),
        Err(e) => panic!("{}: {e}", at()),
    }
    json_agrees(subject, &s, top, &rule, enc.caps, &enc.octets);
    if enc.caps <= 3
        && let Some(r) = m.rules.iter().position(|x| *x == rule)
    {
        let mut d = vec![r as u8, minor as u8, enc.caps];
        d.extend_from_slice(&enc.octets);
        idl_rt::fuzz::decode(m, &d);
    }
    j.ok()
}

/// `idl-generated`: after the frame, the reading minor, a big-endian top
/// index and the generator's choices.
pub fn generated(data: &[u8]) {
    let _ = generated_judged(data);
}

/// [`generated`], returning the judgment, if one was made, for the tests.
pub fn generated_judged(data: &[u8]) -> Option<Judged> {
    match gen_classify(data) {
        GenClass::Pick(p) => generated_with(p.m, p.m, p.minor, p.top, p.choices),
        _ => None,
    }
}

/// The kinds an input reaches in `idl-generated`.
pub fn generated_kinds(data: &[u8]) -> Vec<&'static str> {
    match gen_classify(data) {
        GenClass::NoModule => vec!["no-module"],
        GenClass::Short => vec!["short"],
        GenClass::Unreachable => Vec::new(),
        GenClass::Pick(p) => vec![top_kind(p.top)],
    }
}

/// An `idl-generated` input.
pub fn generated_input(m: &Module, minor: u16, top: usize, choices: &[u8]) -> Vec<u8> {
    let mut d = idl_repo::frame(m).into_bytes();
    d.push(minor as u8);
    d.extend_from_slice(&(top as u16).to_be_bytes());
    d.extend_from_slice(choices);
    d
}

/// `idl-generated`'s generated seeds: for every module at its own minor,
/// and every top-level body, empty choices (the smallest value) and 32
/// octets from [`SplitMix64`] seeded by the top's index; and a `short`
/// and a `no-module` input.
pub fn generated_seeds() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for &m in idl_repo::MODULES.iter() {
        let s = Schema::new(&interface_of(m).checked, m.minor);
        for (k, top) in s.tops().into_iter().enumerate() {
            let stem = format!("{}-{}-top{k}-{}", module_stem(m), m.minor, top_kind(top));
            out.push((format!("{stem}-empty"), generated_input(m, m.minor, k, &[])));
            let mut src = SplitMix64(k as u64);
            let mixed: Vec<u8> = (0..4).flat_map(|_| src.next_u64().to_le_bytes()).collect();
            out.push((
                format!("{stem}-mixed"),
                generated_input(m, m.minor, k, &mixed),
            ));
        }
    }
    let mut short = b"aspis.rpc/1.0\n".to_vec();
    short.extend_from_slice(&[0, 0]);
    out.push(("short".into(), short));
    out.push(("no-module".into(), b"org.example.none/1.0\n\0\0\0".to_vec()));
    out
}

/// Every embedded interface's `name/major`, and its `name/major.minor`
/// at its version, for the dictionaries.
pub fn interface_refs() -> Vec<String> {
    INTERFACES
        .iter()
        .flat_map(|i| {
            let v = idl_repo::interface(i.name, i.major).map_or(0, Interface::version);
            [
                format!("{}/{}", i.name, i.major),
                format!("{}/{}.{v}", i.name, i.major),
            ]
        })
        .collect()
}
