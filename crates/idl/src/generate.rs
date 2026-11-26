// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The files generated for each minor of an interface file (ADR 0067,
//! rules 7 and 9; docs/design/call-language.md, "Files and the interface
//! header", "Generated grammars"):
//!
//! - `v<M>.<m>.abnf` and `v<M>.<m>.vectors`: the wire grammar and its
//!   vectors, except for a `[kernel]` interface, which has no wire form;
//! - `v<M>.<m>.text.abnf` and `v<M>.<m>.text.vectors`: the canonical-text
//!   grammar and its vectors.
//!
//! Each starts with the IDL file's own SPDX lines, so an application's
//! generated files carry its notice, then a line naming the source and
//! saying it is generated. Generation loads each grammar with crates/abnf,
//! strictly, as the catalog does, and labels every vector with it.

use alloc::{
    collections::BTreeSet,
    format,
    string::{String, ToString},
    vec::Vec,
};

use abnf::{Grammar, Kind, LoadOptions};

use crate::{abnf_gen, canon, hash, model::Checked, project, schema::Schema, vectors};

/// The generated files of one minor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generated {
    /// The wire grammar and its vectors; None for a `[kernel]` interface.
    pub wire: Option<(String, String)>,
    /// The canonical-text grammar and its vectors.
    pub text: (String, String),
}

/// The SPDX lines at the top of an IDL file, without their `// `.
pub fn spdx_lines(src: &[u8]) -> Vec<String> {
    let text = core::str::from_utf8(src).unwrap_or("");
    text.lines()
        .take_while(|l| l.starts_with("//"))
        .filter_map(|l| l.strip_prefix("// "))
        .filter(|l| l.starts_with("SPDX-"))
        .map(ToString::to_string)
        .collect()
}

/// The comment lines that open a generated file.
fn preamble(c: char, spdx: &[String], what: &str, uses: Option<&str>) -> String {
    let mut out = String::new();
    for l in spdx {
        out.push_str(&format!("{c} {l}\n"));
    }
    if let Some(u) = uses {
        out.push_str(&format!("; uses: {u}\n"));
    }
    out.push_str(&format!("{c}\n{c} {what}\n"));
    out
}

/// The canonical form of a checked file at one of its minors.
pub fn canonical(checked: &Checked, minor: u16) -> String {
    canon::canonical(&project::project(checked.file(), minor))
}

/// The lock hash of a checked file at one of its minors.
pub fn minor_hash(checked: &Checked, minor: u16) -> [u8; 32] {
    hash::sha3_256(canonical(checked, minor).as_bytes())
}

/// Generates one minor's files: what [`Generator`] makes for it, after
/// every minor before it. `source` names the IDL file, as `v1.idl`;
/// `spdx` is its SPDX lines; `shared` returns the text of a grammar that
/// `; uses:` names (`core`, `names`, `json`). To generate every minor, use
/// one [`Generator`], which this makes afresh.
pub fn generate(
    checked: &Checked,
    minor: u16,
    source: &str,
    spdx: &[String],
    shared: &mut dyn FnMut(&str) -> Option<Vec<u8>>,
) -> Result<Generated, String> {
    let mut g = Generator::new(checked, source, spdx);
    for m in 0..minor {
        let _ = g.advance(m, shared);
    }
    g.minor(minor, shared)
}

/// One generated file: its header, which names the minor, and the rest.
#[derive(Debug, Clone)]
pub struct Part<'g> {
    pub head: String,
    pub body: &'g str,
}

/// One minor's generated files, as [`Generated`] holds them, each in its
/// two parts; and whether its grammars, and its vectors, are the minor
/// before's apart from their headers.
#[derive(Debug, Clone)]
pub struct Files<'g> {
    pub wire: Option<(Part<'g>, Part<'g>)>,
    pub text: (Part<'g>, Part<'g>),
    pub same: (bool, bool),
}

impl Part<'_> {
    /// The whole file.
    pub fn text(&self) -> String {
        let mut out = String::with_capacity(self.head.len() + self.body.len());
        out.push_str(&self.head);
        out.push_str(self.body);
        out
    }

    /// Whether `have` is the whole file.
    pub fn is(&self, have: &[u8]) -> bool {
        have.len() == self.head.len() + self.body.len()
            && have.starts_with(self.head.as_bytes())
            && have[self.head.len()..] == *self.body.as_bytes()
    }
}

impl Files<'_> {
    /// The files whole.
    pub fn generated(&self) -> Generated {
        Generated {
            wire: self.wire.as_ref().map(|(g, v)| (g.text(), v.text())),
            text: (self.text.0.text(), self.text.1.text()),
        }
    }
}

/// The grammars of one projection, without their headers, loaded; or why
/// they fail, which every minor of the projection shares.
struct Grammars {
    /// The lowest minor and the highest generated with them.
    first: u16,
    last: u16,
    made: Result<Made, String>,
}

struct Made {
    /// The wire grammar's rules and their loaded grammar; None for a
    /// `[kernel]` interface.
    wire: Option<(String, Grammar)>,
    /// The text grammar's rules and their loaded grammar.
    text: (String, Grammar),
}

/// The vector lines of the minor last generated, and what they cost.
struct Lines {
    wire: Option<String>,
    text: String,
    /// The values and steps they took, when the budget lasted through
    /// them.
    cost: Option<(usize, u64)>,
    /// The budget was spent before the minor began, so there are none.
    empty: bool,
}

/// Generates a file's minors, lowest first, with one [`vectors::Budget`]
/// for all of them (docs/design/call-language.md, "Generated grammars").
///
/// A file may declare `version(1.65535)`, and one minor's vectors may
/// cost the whole budget, so the budget is the file's, never the
/// minor's: a minor that begins with it spent gets no vectors. A
/// projection changes only at a minor that some `since` or `deprecated`
/// names ([`project::changes`]). A minor whose projection is the one
/// before's has the same grammars, so they are reused, with their new
/// headers, or fail as they did; and it has the same vectors when the
/// budget still holds what they cost, which is taken from it again, or
/// none when the budget was already spent. Otherwise its vectors are made
/// again, with what is left.
pub struct Generator<'c> {
    checked: &'c Checked,
    source: String,
    spdx: Vec<String>,
    budget: vectors::Budget,
    changes: BTreeSet<u16>,
    grammars: Option<Grammars>,
    lines: Option<Lines>,
    same: (bool, bool),
}

impl<'c> Generator<'c> {
    /// A generator for a checked file, with a full budget.
    pub fn new(checked: &'c Checked, source: &str, spdx: &[String]) -> Self {
        let major = checked.unit().major();
        Generator {
            checked,
            source: source.to_string(),
            spdx: spdx.to_vec(),
            budget: vectors::Budget::default(),
            changes: project::changes(checked.file(), major),
            grammars: None,
            lines: None,
            same: (false, false),
        }
    }

    /// What the file's vectors may still cost.
    pub fn budget(&self) -> &vectors::Budget {
        &self.budget
    }

    /// Whether the minor last generated has the grammars of the minor
    /// before it, and whether it has its vectors too, apart from their
    /// headers.
    pub fn same_as_before(&self) -> (bool, bool) {
        self.same
    }

    /// Generates a minor's files. Minors are generated lowest first.
    pub fn minor(
        &mut self,
        minor: u16,
        shared: &mut dyn FnMut(&str) -> Option<Vec<u8>>,
    ) -> Result<Generated, String> {
        Ok(self.files(minor, shared)?.generated())
    }

    /// Generates a minor's files, as [`Generator::minor`] does, each as
    /// its header and the rest, which a reused minor shares with the
    /// minors before it. So a caller that compares or writes each file
    /// costs, for a reused minor, its headers and what it reads or writes,
    /// never a copy of its grammars.
    pub fn files(
        &mut self,
        minor: u16,
        shared: &mut dyn FnMut(&str) -> Option<Vec<u8>>,
    ) -> Result<Files<'_>, String> {
        self.advance(minor, shared)?;
        let unit = self.checked.unit();
        let id = format!("{}/{}.{minor}", unit.name, unit.major());
        let stem = format!("v{}.{minor}", unit.major());
        let vectors = |of: &str| {
            vector_head(
                &self.spdx,
                &format!(
                    "{id}: vectors for {of}, generated by idlc from {}; don't edit.",
                    self.source
                ),
            )
        };
        let (Some(Grammars { made: Ok(g), .. }), Some(lines)) = (&self.grammars, &self.lines)
        else {
            return Err("no minor generated".into());
        };
        let wire = g.wire.as_ref().zip(lines.wire.as_ref()).map(|((g, _), v)| {
            (
                Part {
                    head: self.head(minor, true),
                    body: g,
                },
                Part {
                    head: vectors(&format!("{stem}.abnf")),
                    body: v,
                },
            )
        });
        Ok(Files {
            wire,
            text: (
                Part {
                    head: self.head(minor, false),
                    body: &g.text.0,
                },
                Part {
                    head: vectors(&format!("{stem}.text.abnf")),
                    body: &lines.text,
                },
            ),
            same: self.same,
        })
    }

    /// The comment lines that open a minor's wire or text grammar.
    fn head(&self, minor: u16, wire: bool) -> String {
        let unit = self.checked.unit();
        let id = format!("{}/{}.{minor}", unit.name, unit.major());
        let source = &self.source;
        if wire {
            let what = format!(
                "{id}: the wire grammar, generated by idlc from {source}; don't edit (ADR 0067, rule 9)."
            );
            preamble(';', &self.spdx, &what, Some("core"))
        } else {
            let what = format!(
                "{id}: the canonical-text grammar, generated by idlc from {source}; don't edit (ADR 0063, rule 8)."
            );
            preamble(';', &self.spdx, &what, Some("core, names, json"))
        }
    }

    /// A projection's grammars, made and loaded.
    fn make_grammars(
        &self,
        s: &Schema<'_>,
        minor: u16,
        shared: &mut dyn FnMut(&str) -> Option<Vec<u8>>,
    ) -> Result<Made, String> {
        let stem = format!("v{}.{minor}", self.checked.unit().major());
        let opts = LoadOptions {
            kind: Kind::Strict,
            ..LoadOptions::default()
        };
        let wire = if s.is_kernel() {
            None
        } else {
            let g = abnf_gen::wire(s, "");
            let gr = load(&stem, &self.head(minor, true), &g, shared, &opts)?;
            Some((g, gr))
        };
        let tstem = format!("{stem}.text");
        let g = abnf_gen::text(s, "");
        let gr = load(&tstem, &self.head(minor, false), &g, shared, &opts)?;
        Ok(Made {
            wire,
            text: (g, gr),
        })
    }

    /// Generates a minor without writing its files out.
    fn advance(
        &mut self,
        minor: u16,
        shared: &mut dyn FnMut(&str) -> Option<Vec<u8>>,
    ) -> Result<(), String> {
        let major = self.checked.unit().major();
        let same_grammars = self.grammars.as_ref().is_some_and(|g| {
            g.last < minor && self.changes.range(g.last + 1..=minor).next().is_none()
        });
        let lines = self.lines.take();
        self.same = (same_grammars, false);
        // Made only when something is made, not for a minor reused whole.
        let schema = || Schema::new(self.checked, minor);
        let mut s = None;
        if !same_grammars {
            let sc = schema();
            let made = self.make_grammars(&sc, minor, shared);
            s = Some(sc);
            self.grammars = Some(Grammars {
                first: minor,
                last: minor,
                made,
            });
        }
        let Some(grammars) = self.grammars.as_mut() else {
            return Err("no grammars".into());
        };
        grammars.last = minor;
        let made = match &grammars.made {
            Ok(m) => m,
            Err(e) if grammars.first == minor => return Err(e.clone()),
            Err(e) => {
                return Err(format!(
                    "the grammars of {major}.{}, which fail: {e}",
                    grammars.first
                ));
            }
        };
        // The vectors: the minor before's, or none, or made.
        let empty = self.budget.is_spent();
        if same_grammars
            && let Some(l) = lines
            && (l.empty || l.cost.is_some_and(|(v, st)| self.budget.charge(v, st)))
        {
            self.lines = Some(l);
            self.same = (true, true);
            return Ok(());
        }
        let s = s.unwrap_or_else(schema);
        let stem = format!("v{major}.{minor}");
        let before = (self.budget.values(), self.budget.steps());
        let samples = vectors::samples(&s, &self.budget)?;
        let wire = match &made.wire {
            Some((_, gr)) => Some(wire_lines(&s, gr, &samples, &self.budget, &stem)?),
            None => None,
        };
        let text = text_lines(&s, &made.text.1, &samples, &self.budget, &stem)?;
        let cost = (!self.budget.is_spent()).then(|| {
            (
                before.0 - self.budget.values(),
                before.1 - self.budget.steps(),
            )
        });
        self.lines = Some(Lines {
            wire,
            text,
            cost,
            empty,
        });
        Ok(())
    }
}

/// Loads a generated grammar, its header and its rules, strictly, as the
/// catalog does.
fn load(
    stem: &str,
    head: &str,
    rules: &str,
    shared: &mut dyn FnMut(&str) -> Option<Vec<u8>>,
    opts: &LoadOptions,
) -> Result<Grammar, String> {
    let mut text = String::from(head);
    text.push_str(rules);
    Grammar::load(stem, text.as_bytes(), shared, opts).map_err(|e| format!("{stem}.abnf: {e}"))
}

/// A wire vector file's lines, each ending in a line feed.
fn wire_lines(
    s: &Schema<'_>,
    g: &Grammar,
    samples: &[vectors::Sample],
    budget: &vectors::Budget,
    stem: &str,
) -> Result<String, String> {
    let lines = vectors::wire(s, g, samples, budget).map_err(|e| format!("{stem}.vectors: {e}"))?;
    Ok(joined(lines))
}

/// A text vector file's lines, each ending in a line feed.
fn text_lines(
    s: &Schema<'_>,
    g: &Grammar,
    samples: &[vectors::Sample],
    budget: &vectors::Budget,
    stem: &str,
) -> Result<String, String> {
    let lines =
        vectors::text(s, g, samples, budget).map_err(|e| format!("{stem}.text.vectors: {e}"))?;
    Ok(joined(lines))
}

fn joined(lines: Vec<String>) -> String {
    let mut out = String::new();
    for l in lines {
        out.push_str(&l);
        out.push('\n');
    }
    out
}

/// A vector file's header.
fn vector_head(spdx: &[String], what: &str) -> String {
    let mut h = preamble('#', spdx, what, None);
    h.push_str(
        "#\n# Each vector is one line: a tag, \"@\" and the rule, a tab, then the\n\
         # octets, with \\t, \\\\ and \\xHH escapes. \"errc\" vectors match the\n\
         # context-free grammar and break a constraint (ADR 0062, rule 8).\n",
    );
    h
}
