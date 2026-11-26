// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Loading a grammar: its `; uses:` closure, the reserved core names
//! (ADR 0062, rule 3), name resolution, the static analyses, and the
//! constraints' attachment and strictness (ADR 0062, rule 7).
//!
//! Every analysis is linear in the grammar's size and none recurses along
//! rule references, so a publisher's grammar can't make loading slow or
//! deep: nullability is a Horn-clause propagation, and the rest run over
//! the strongly connected components of the reference graph, found
//! without recursion.

use alloc::{
    borrow::ToOwned,
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec,
    vec::Vec,
};

use crate::{
    Context, Exhausted, GrammarError, GrammarErrorKind as K, Kind, Limits, LoadOptions,
    constraint::{self, Compiled, Constraint},
    matcher,
    syntax::{self, Comment, Node, NodeId, ParsedFile},
};

/// A rule of a loaded grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleId(pub(crate) u32);

impl RuleId {
    pub(crate) fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Debug)]
pub(crate) struct Rule {
    /// The name as its definition spells it.
    pub name: String,
    pub body: NodeId,
    /// The file that defines it, an index into `Grammar::files`.
    pub file: usize,
    pub line: usize,
    pub constraints: Vec<(usize, Constraint)>,
    /// The fewest octets a match can hold: a lower bound, exact outside
    /// recursion.
    pub min_width: u64,
    /// The octets every match holds, if that is one number.
    pub fixed_width: Option<u64>,
    /// Every octet the rule can match is an ASCII digit.
    pub digit_only: bool,
    /// The rule is core `i8` to `i64`, or defined as just one of them,
    /// possibly through a chain of one-name definitions.
    pub signed: bool,
}

#[derive(Debug)]
struct File {
    /// The grammar's name, as `; uses:` gives it.
    name: String,
    /// The file is `core.abnf`.
    core: bool,
}

/// A loaded grammar.
#[derive(Debug)]
pub struct Grammar {
    pub(crate) nodes: Vec<Node>,
    /// Each node's fewest octets, as [`Rule::min_width`].
    pub(crate) node_min: Vec<u64>,
    pub(crate) rules: Vec<Rule>,
    keys: BTreeMap<String, RuleId>,
    files: Vec<File>,
    pub(crate) limits: Limits,
    prose: usize,
    /// The constraints, compiled for the matcher.
    pub(crate) compiled: Compiled,
}

/// RFC 5234's core rules (appendix B.1), which every grammar may use and
/// none may redefine, as abnf 2.9.1's `Rule` class holds them.
const RFC5234: &str = "\
ALPHA  = %x41-5A / %x61-7A
BIT    = \"0\" / \"1\"
CHAR   = %x01-7F
CR     = %x0D
CRLF   = CR LF
CTL    = %x00-1F / %x7F
DIGIT  = %x30-39
DQUOTE = %x22
HEXDIG = DIGIT / \"A\" / \"B\" / \"C\" / \"D\" / \"E\" / \"F\"
HTAB   = %x09
LF     = %x0A
LWSP   = *(WSP / CRLF WSP)
OCTET  = %x00-FF
SP     = %x20
VCHAR  = %x21-7E
WSP    = SP / HTAB
";

/// The file index of RFC 5234's rules.
const BUILTIN: usize = 0;
/// The file index of the grammar being loaded.
const MAIN: usize = 1;

/// The signed core integers (ADR 0062, rule 2).
const SIGNED: [&str; 4] = ["i8", "i16", "i32", "i64"];

fn err(file: &str, line: usize, kind: K) -> GrammarError {
    GrammarError {
        file: file.to_owned(),
        line,
        kind,
    }
}

/// `;` and spaces or tabs, then `uses:`: a uses line, which must be
/// exactly `; uses: ` and names, at column 0, before the first rule.
fn uses_like(c: &Comment) -> bool {
    c.text
        .strip_prefix(';')
        .is_some_and(|t| t.trim_start_matches([' ', '\t']).starts_with("uses:"))
}

/// The names of a well-formed uses line, `; uses: a, b`.
fn uses_names(c: &Comment) -> Option<Vec<String>> {
    let list = c.text.strip_prefix("; uses: ")?;
    let names: Vec<String> = list.split(", ").map(String::from).collect();
    let valid = |n: &String| {
        let mut b = n.bytes();
        b.next().is_some_and(|c| c.is_ascii_lowercase())
            && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    };
    names.iter().all(valid).then_some(names)
}

/// The uses lines of a parsed file: the names, each with its line.
fn uses_of(file: &str, p: &ParsedFile) -> Result<Vec<(String, usize)>, GrammarError> {
    let mut out: Vec<(String, usize)> = Vec::new();
    let misplaced = |line| {
        err(
            file,
            line,
            K::Uses(
                "a uses line is '; uses: ' and names, at column 0, before the first rule".into(),
            ),
        )
    };
    for (c, before_first) in &p.loose {
        if !uses_like(c) {
            continue;
        }
        let names = (*before_first && c.column0)
            .then(|| uses_names(c))
            .flatten()
            .ok_or_else(|| misplaced(c.line))?;
        for n in names {
            if out.iter().any(|(m, _)| *m == n) {
                return Err(err(file, c.line, K::Uses(format!("{n} twice"))));
            }
            out.push((n, c.line));
        }
    }
    if let Some(c) = p
        .rules
        .iter()
        .flat_map(|r| &r.comments)
        .find(|c| uses_like(c))
    {
        return Err(misplaced(c.line));
    }
    Ok(out)
}

/// The keys (lowercase names) of the rules a file defines.
fn defined_keys(p: &ParsedFile) -> BTreeSet<String> {
    p.rules
        .iter()
        .map(|r| r.name.to_ascii_lowercase())
        .collect()
}

impl Grammar {
    /// Loads a grammar. `name` is its name, as `; uses:` lines and errors
    /// give it ("core", "initfs"). `resolve` returns the text of a used
    /// grammar by name. Unless `opts.kind` is [`Kind::Core`], it is always
    /// asked for "core", whose rule names are reserved (ADR 0062, rule 3).
    pub fn load(
        name: &str,
        text: &[u8],
        resolve: &mut dyn FnMut(&str) -> Option<Vec<u8>>,
        opts: &LoadOptions,
    ) -> Result<Grammar, GrammarError> {
        let limits = &opts.limits;
        let mut nodes = Vec::new();
        let mut files = Vec::new();
        let mut parsed = Vec::new();

        // RFC 5234's rules first: they can't fail.
        let builtin_limits = Limits {
            nodes: usize::MAX,
            ..Limits::default()
        };
        let builtin = syntax::parse(RFC5234.as_bytes(), 0, &mut nodes, &builtin_limits)
            .map_err(|(line, kind)| err("RFC 5234", line, kind))?;
        files.push(File {
            name: "RFC 5234".into(),
            core: false,
        });
        parsed.push(builtin);
        let node_budget = Limits {
            nodes: limits.nodes.saturating_add(nodes.len()),
            ..limits.clone()
        };

        // 1. The main file, then its uses, depth-first, each once. A file
        //    loads before the files that use it.
        let mut octets = text.len();
        if octets > limits.grammar_octets {
            return Err(err(name, 0, K::TooLarge));
        }
        let main = syntax::parse(text, 1, &mut nodes, &node_budget)
            .map_err(|(line, kind)| err(name, line, kind))?;
        files.push(File {
            name: name.into(),
            core: opts.kind == Kind::Core,
        });
        parsed.push(main);

        let mut index: BTreeMap<String, usize> = BTreeMap::new();
        index.insert(name.into(), MAIN);
        let mut done = vec![false, false];
        let mut uses: Vec<Vec<usize>> = vec![Vec::new(), Vec::new()];
        let mut order = Vec::new();
        let mut stack = vec![(MAIN, uses_of(name, &parsed[MAIN])?, 0usize)];
        while let Some((f, list, next)) = stack.last_mut() {
            let f = *f;
            let Some((u, line)) = list.get(*next).cloned() else {
                done[f] = true;
                order.push(f);
                stack.pop();
                continue;
            };
            *next += 1;
            if let Some(&i) = index.get(&u) {
                if !done[i] {
                    return Err(err(
                        &files[f].name,
                        line,
                        K::Uses(format!("a cycle through {u}")),
                    ));
                }
                uses[f].push(i);
                continue;
            }
            if stack.len() > limits.uses_depth {
                return Err(err(&files[f].name, line, K::Uses("nested too deep".into())));
            }
            let Some(t) = resolve(&u) else {
                return Err(err(
                    &files[f].name,
                    line,
                    K::Uses(format!("no grammar named {u}")),
                ));
            };
            octets = octets.saturating_add(t.len());
            if octets > limits.grammar_octets {
                return Err(err(&u, 0, K::TooLarge));
            }
            let i = files.len();
            let file_no = u16::try_from(i).map_err(|_| err(&u, 0, K::TooLarge))?;
            let p = syntax::parse(&t, file_no, &mut nodes, &node_budget)
                .map_err(|(line, kind)| err(&u, line, kind))?;
            let list = uses_of(&u, &p)?;
            files.push(File {
                name: u.clone(),
                core: opts.kind != Kind::Core && u == "core",
            });
            parsed.push(p);
            index.insert(u, i);
            done.push(false);
            uses.push(Vec::new());
            uses[f].push(i);
            stack.push((i, list, 0));
        }

        // 2. The reserved names: core's rule names.
        let core_names = match index.get("core") {
            _ if opts.kind == Kind::Core => defined_keys(&parsed[MAIN]),
            Some(&i) if files[i].core => defined_keys(&parsed[i]),
            _ => {
                let Some(t) = resolve("core") else {
                    return Err(err(
                        name,
                        0,
                        K::Uses("no core grammar, whose names are reserved".into()),
                    ));
                };
                let mut scratch = Vec::new();
                let p = syntax::parse(&t, 0, &mut scratch, limits)
                    .map_err(|(line, kind)| err("core", line, kind))?;
                defined_keys(&p)
            }
        };

        // 3. Strictness, per file: core, a file that uses core (directly or
        //    not), or every file when the caller asks.
        let mut strict = vec![false; files.len()];
        for &f in &order {
            strict[f] = opts.kind == Kind::Strict
                || files[f].core
                || uses[f].iter().any(|&u| files[u].core || strict[u]);
        }

        // 4. Merge every file's rules into one namespace.
        let mut rules: Vec<Rule> = Vec::new();
        let mut keys: BTreeMap<String, RuleId> = BTreeMap::new();
        let mut comments: Vec<Vec<Comment>> = Vec::new();
        let mut defined = 0usize;
        for f in core::iter::once(BUILTIN).chain(order.iter().copied()) {
            let file = &files[f].name;
            for r in core::mem::take(&mut parsed[f].rules) {
                let key = r.name.to_ascii_lowercase();
                if f != BUILTIN && !files[f].core && core_names.contains(&key) {
                    return Err(err(file, r.line, K::Reserved(r.name)));
                }
                match (keys.get(&key), r.incremental) {
                    (None, false) => {
                        if f != BUILTIN {
                            defined += 1;
                            if defined > limits.rules {
                                return Err(err(file, r.line, K::TooLarge));
                            }
                        }
                        let id = RuleId(
                            u32::try_from(rules.len())
                                .map_err(|_| err(file, r.line, K::TooLarge))?,
                        );
                        keys.insert(key, id);
                        rules.push(Rule {
                            name: r.name,
                            body: r.body,
                            file: f,
                            line: r.line,
                            constraints: Vec::new(),
                            min_width: 0,
                            fixed_width: None,
                            digit_only: false,
                            signed: false,
                        });
                        comments.push(r.comments);
                    }
                    (Some(_), false) => return Err(err(file, r.line, K::Duplicate(r.name))),
                    (Some(&id), true) if rules[id.index()].file == f => {
                        // `=/` adds alternatives (RFC 5234, section 3.3).
                        let old = rules[id.index()].body;
                        match &mut nodes[old as usize] {
                            Node::Alt(alts) => alts.push(r.body),
                            _ => {
                                if nodes.len() >= node_budget.nodes {
                                    return Err(err(file, r.line, K::TooLarge));
                                }
                                rules[id.index()].body = NodeId::try_from(nodes.len())
                                    .map_err(|_| err(file, r.line, K::TooLarge))?;
                                nodes.push(Node::Alt(vec![old, r.body]));
                            }
                        }
                        comments[id.index()].extend(r.comments);
                    }
                    (_, true) => return Err(err(file, r.line, K::IncrementalUndefined(r.name))),
                }
            }
        }

        // A strict grammar holds no prose-val, not even one that names a
        // rule, so this comes before names are resolved.
        for (f, p) in parsed.iter().enumerate() {
            if let (true, Some(&line)) = (strict[f], p.prose_vals.first()) {
                return Err(err(&files[f].name, line, K::ProseVal));
            }
        }

        // 5. Resolve every name.
        for node in nodes.iter_mut() {
            if let Node::Name { key, file, line } = node {
                let Some(&id) = keys.get(key.as_str()) else {
                    return Err(err(
                        &files[usize::from(*file)].name,
                        *line as usize,
                        K::Undefined(core::mem::take(key)),
                    ));
                };
                *node = Node::Ref(id.0);
            }
        }

        // 6. Constraints, attachment and strictness (ADR 0062, rule 7).
        let mut prose = 0;
        for (f, p) in parsed.iter().enumerate() {
            if let Some((c, _)) = p
                .loose
                .iter()
                .find(|(c, _)| constraint::constraint_text(&c.text).is_some())
            {
                return Err(err(&files[f].name, c.line, K::Attachment));
            }
        }
        for (rule, list) in rules.iter_mut().zip(comments) {
            for c in list {
                let parsed = match constraint::constraint_text(&c.text) {
                    None => continue,
                    Some(Ok(text)) => constraint::parse(text).ok(),
                    Some(Err(())) => None,
                };
                match parsed {
                    Some(k) => rule.constraints.push((c.line, k)),
                    None if strict[rule.file] => {
                        return Err(err(&files[rule.file].name, c.line, K::Prose));
                    }
                    None if rule.file == MAIN => prose += 1,
                    None => {}
                }
            }
        }

        let mut g = Grammar {
            node_min: vec![0; nodes.len()],
            nodes,
            rules,
            keys,
            files,
            limits: limits.clone(),
            prose,
            compiled: Compiled::default(),
        };
        g.analyze()?;

        // 7. Bind and validate the vocabulary constraints, in every file
        //    (docs/design/call-language.md, "How constraints bind").
        g.compiled = constraint::compile(&g).map_err(|(r, line, m)| {
            let rule = &g.rules[r];
            err(&g.files[rule.file].name, line, K::Constraint(m))
        })?;
        Ok(g)
    }

    /// The nodes a node calls or contains. A reference's child is the
    /// referenced rule's body.
    fn children(&self, n: NodeId) -> &[NodeId] {
        match &self.nodes[n as usize] {
            Node::Alt(c) | Node::Cat(c) => c,
            Node::Rep { node, .. } => core::slice::from_ref(node),
            Node::Ref(r) => core::slice::from_ref(&self.rules[*r as usize].body),
            _ => &[],
        }
    }

    /// Every node of a rule's body, parents before children, without
    /// following references.
    fn body_nodes(&self, rule: usize, out: &mut Vec<NodeId>) {
        out.clear();
        let mut stack = vec![self.rules[rule].body];
        while let Some(n) = stack.pop() {
            out.push(n);
            if !matches!(self.nodes[n as usize], Node::Ref(_)) {
                stack.extend_from_slice(self.children(n));
            }
        }
    }

    /// The static analyses: nullability, left recursion, and each rule's
    /// widths and readings.
    fn analyze(&mut self) -> Result<(), GrammarError> {
        let nullable = self.nullable();

        // Left recursion: "A can call B before reading an octet". A cycle
        // in that graph would let a match call itself forever, so it is an
        // error; it is also what lets the matcher terminate on any grammar
        // it accepts.
        let mut left: Vec<Vec<u32>> = vec![Vec::new(); self.rules.len()];
        for (r, edges) in left.iter_mut().enumerate() {
            let mut stack = vec![self.rules[r].body];
            while let Some(n) = stack.pop() {
                match &self.nodes[n as usize] {
                    Node::Alt(c) => stack.extend_from_slice(c),
                    Node::Cat(c) => {
                        for &x in c {
                            stack.push(x);
                            if !nullable[x as usize] {
                                break;
                            }
                        }
                    }
                    Node::Rep { max, node, .. } if *max != Some(0) => stack.push(*node),
                    Node::Ref(s) => edges.push(*s),
                    _ => {}
                }
            }
        }
        for comp in sccs(&left) {
            let cyclic = comp.len() > 1 || left[comp[0] as usize].contains(&comp[0]);
            if cyclic {
                let &r = comp.iter().min().unwrap_or(&comp[0]);
                let rule = &self.rules[r as usize];
                return Err(err(
                    &self.files[rule.file].name,
                    rule.line,
                    K::LeftRecursive(rule.name.clone()),
                ));
            }
        }

        // Widths and readings, over the reference graph's components with
        // each after every component it calls. Inside a cycle, a rule's
        // fewest octets is a lower bound, it has no fixed width and it is
        // not signed.
        let mut calls: Vec<Vec<u32>> = vec![Vec::new(); self.rules.len()];
        let mut body = Vec::new();
        for (r, edges) in calls.iter_mut().enumerate() {
            self.body_nodes(r, &mut body);
            edges.extend(body.iter().filter_map(|&n| match self.nodes[n as usize] {
                Node::Ref(s) => Some(s),
                _ => None,
            }));
        }
        let mut fixed: Vec<Option<u64>> = vec![None; self.nodes.len()];
        let mut digits: Vec<bool> = vec![false; self.nodes.len()];
        for comp in sccs(&calls) {
            let cyclic = comp.len() > 1 || calls[comp[0] as usize].contains(&comp[0]);
            let mut all_digits = true;
            for &r in &comp {
                self.body_nodes(r as usize, &mut body);
                for &n in body.iter().rev() {
                    self.node_min[n as usize] = self.eval_min(n);
                    fixed[n as usize] = self.eval_fixed(n, &fixed);
                    digits[n as usize] = self.eval_digits(n, &digits, &comp);
                }
                let b = self.rules[r as usize].body as usize;
                all_digits &= digits[b];
                let rule = &mut self.rules[r as usize];
                rule.min_width = self.node_min[b];
                if !cyclic {
                    rule.fixed_width = fixed[b];
                }
            }
            for &r in &comp {
                self.rules[r as usize].digit_only = all_digits;
            }
            if !cyclic {
                let r = comp[0] as usize;
                let rule = &self.rules[r];
                let signed = (self.files[rule.file].core && SIGNED.contains(&rule.name.as_str()))
                    || matches!(self.nodes[rule.body as usize], Node::Ref(s) if self.rules[s as usize].signed);
                self.rules[r].signed = signed;
            }
        }
        Ok(())
    }

    /// Which nodes can match the empty string: a Horn-clause propagation,
    /// linear in nodes and edges.
    fn nullable(&self) -> Vec<bool> {
        let n = self.nodes.len();
        let mut nullable = vec![false; n];
        let mut need = vec![0usize; n];
        let mut parents: Vec<Vec<NodeId>> = vec![Vec::new(); n];
        let mut queue = Vec::new();
        for (i, node) in self.nodes.iter().enumerate() {
            let id = i as NodeId;
            match node {
                Node::Alt(_) | Node::Ref(_) => need[i] = 1,
                Node::Cat(c) => need[i] = c.len(),
                Node::Rep { min: 0, .. } => {}
                Node::Rep { .. } => need[i] = 1,
                Node::Lit { octets, .. } if octets.is_empty() => {}
                // Terminals that read an octet never match empty.
                _ => need[i] = usize::MAX,
            }
            if need[i] == 0 {
                nullable[i] = true;
                queue.push(id);
            } else if !matches!(node, Node::Rep { min: 0, .. }) {
                for &c in self.children(id) {
                    parents[c as usize].push(id);
                }
            }
        }
        while let Some(x) = queue.pop() {
            for &p in &parents[x as usize] {
                let p = p as usize;
                if nullable[p] {
                    continue;
                }
                need[p] -= 1;
                if need[p] == 0 {
                    nullable[p] = true;
                    queue.push(p as NodeId);
                }
            }
        }
        nullable
    }

    /// A node's fewest octets, from its children's (already computed).
    fn eval_min(&self, n: NodeId) -> u64 {
        let m = |c: &NodeId| self.node_min[*c as usize];
        match &self.nodes[n as usize] {
            Node::Alt(c) => c.iter().map(m).min().unwrap_or(0),
            Node::Cat(c) => c.iter().map(m).fold(0, u64::saturating_add),
            Node::Rep { min, node, .. } => u64::from(*min).saturating_mul(m(node)),
            // A rule in the current component has 0 so far: a lower bound.
            Node::Ref(r) => self.rules[*r as usize].min_width,
            Node::Lit { octets, .. } => octets.len() as u64,
            Node::Range(..) => 1,
            Node::Prose | Node::Name { .. } => u64::MAX,
        }
    }

    /// A node's fixed width, if it has one.
    fn eval_fixed(&self, n: NodeId, fixed: &[Option<u64>]) -> Option<u64> {
        let f = |c: &NodeId| fixed[*c as usize];
        match &self.nodes[n as usize] {
            Node::Alt(c) => {
                let first = f(c.first()?)?;
                c.iter().all(|x| f(x) == Some(first)).then_some(first)
            }
            Node::Cat(c) => c.iter().try_fold(0u64, |a, x| a.checked_add(f(x)?)),
            Node::Rep { min, max, node, .. } => match f(node)? {
                0 => Some(0),
                w if *max == Some(*min) => w.checked_mul(u64::from(*min)),
                _ => None,
            },
            Node::Ref(r) => self.rules[*r as usize].fixed_width,
            Node::Lit { octets, .. } => Some(octets.len() as u64),
            Node::Range(..) => Some(1),
            Node::Prose | Node::Name { .. } => None,
        }
    }

    /// Whether every octet a node can match is an ASCII digit. A reference
    /// into the current component counts as digits: the component's answer
    /// is the conjunction over all its members.
    fn eval_digits(&self, n: NodeId, digits: &[bool], comp: &[u32]) -> bool {
        match &self.nodes[n as usize] {
            Node::Alt(c) | Node::Cat(c) => c.iter().all(|x| digits[*x as usize]),
            Node::Rep { node, .. } => digits[*node as usize],
            Node::Ref(r) => comp.contains(r) || self.rules[*r as usize].digit_only,
            Node::Lit { octets, .. } => octets.iter().all(u8::is_ascii_digit),
            Node::Range(lo, hi) => lo.is_ascii_digit() && hi.is_ascii_digit(),
            Node::Prose | Node::Name { .. } => false,
        }
    }

    /// Finds a rule by name, in any letter case.
    pub fn rule(&self, name: &str) -> Option<RuleId> {
        self.keys.get(name.to_ascii_lowercase().as_str()).copied()
    }

    /// The rule's name, as its definition spells it.
    pub fn name(&self, r: RuleId) -> &str {
        &self.rules[r.index()].name
    }

    /// Whether `core.abnf` defines the rule.
    pub fn is_core(&self, r: RuleId) -> bool {
        self.files[self.rules[r.index()].file].core
    }

    /// The constraints written on the rule, each with its line.
    pub fn constraints(&self, r: RuleId) -> &[(usize, Constraint)] {
        &self.rules[r.index()].constraints
    }

    /// Prose constraints in the loaded file (not in the files it uses):
    /// counted, never enforced.
    pub fn prose_constraints(&self) -> usize {
        self.prose
    }

    /// The fewest octets a match of the rule holds (a lower bound for a
    /// recursive rule).
    pub fn min_width(&self, r: RuleId) -> u64 {
        self.rules[r.index()].min_width
    }

    /// The octets every match of the rule holds, if that is one number.
    pub fn fixed_width(&self, r: RuleId) -> Option<u64> {
        self.rules[r.index()].fixed_width
    }

    /// Whether every octet the rule can match is an ASCII digit.
    pub fn is_digit_only(&self, r: RuleId) -> bool {
        self.rules[r.index()].digit_only
    }

    /// Whether the rule reads as a signed core integer.
    pub fn is_signed(&self, r: RuleId) -> bool {
        self.rules[r.index()].signed
    }

    /// Every literal octet string in the grammar, such as a fuzzer's
    /// dictionary takes.
    pub fn literals(&self) -> impl Iterator<Item = &[u8]> {
        self.nodes.iter().filter_map(|n| match n {
            Node::Lit { octets, .. } if !octets.is_empty() => Some(octets.as_slice()),
            _ => None,
        })
    }

    /// The limits the grammar was loaded with, which its matches use.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Whether `input` matches the rule, read as a context-free grammar, as
    /// the Python checker reads it.
    pub fn matches(&self, r: RuleId, input: &[u8]) -> Result<bool, Exhausted> {
        let mut unlimited = u64::MAX;
        matcher::matches(self, r, input, None, &mut unlimited)
    }

    /// Whether `input` matches the rule and keeps every vocabulary
    /// constraint, with `cx` standing in for what the message's framing
    /// carries (ADR 0062, rule 8).
    ///
    /// When `r` is a core rule, `input` is a fragment of a body: each
    /// capability index is checked against the count, once. Otherwise it
    /// is a whole body: the indexes appear in ascending order, each once,
    /// and every one below the count appears ("Capability indexes").
    pub fn matches_constrained(
        &self,
        r: RuleId,
        input: &[u8],
        cx: &Context,
    ) -> Result<bool, Exhausted> {
        let mut unlimited = u64::MAX;
        matcher::matches(self, r, input, Some(cx), &mut unlimited)
    }

    /// [`Grammar::matches`] when `cx` is None, and
    /// [`Grammar::matches_constrained`] otherwise, taking the match's steps
    /// from `allowance`, whatever the result. The match keeps its own
    /// limits too, so it takes no more steps than either allows. A caller
    /// that matches many inputs passes one allowance to all of them, and
    /// bounds their total, as [`crate::vectors::check`] does. A match that
    /// runs out of the allowance stops with [`Exhausted::Steps`] and leaves
    /// it at 0.
    pub fn matches_within(
        &self,
        r: RuleId,
        input: &[u8],
        cx: Option<&Context>,
        allowance: &mut u64,
    ) -> Result<bool, Exhausted> {
        matcher::matches(self, r, input, cx, allowance)
    }
}

/// Tarjan's strongly connected components, without recursion. Each
/// component comes after every component it reaches.
fn sccs(adj: &[Vec<u32>]) -> Vec<Vec<u32>> {
    const UNSEEN: usize = usize::MAX;
    let n = adj.len();
    let mut index = vec![UNSEEN; n];
    let mut low = vec![0usize; n];
    let mut on_stack = vec![false; n];
    let mut stack: Vec<u32> = Vec::new();
    let mut out = Vec::new();
    let mut next = 0;
    let mut calls: Vec<(usize, usize)> = Vec::new();
    for root in 0..n {
        if index[root] != UNSEEN {
            continue;
        }
        index[root] = next;
        low[root] = next;
        next += 1;
        stack.push(root as u32);
        on_stack[root] = true;
        calls.push((root, 0));
        while let Some((v, i)) = calls.last_mut() {
            let v = *v;
            if let Some(&w) = adj[v].get(*i) {
                *i += 1;
                let w = w as usize;
                if index[w] == UNSEEN {
                    index[w] = next;
                    low[w] = next;
                    next += 1;
                    stack.push(w as u32);
                    on_stack[w] = true;
                    calls.push((w, 0));
                } else if on_stack[w] {
                    low[v] = low[v].min(index[w]);
                }
                continue;
            }
            calls.pop();
            if let Some(&(u, _)) = calls.last() {
                low[u] = low[u].min(low[v]);
            }
            if low[v] == index[v] {
                let mut comp = Vec::new();
                while let Some(w) = stack.pop() {
                    on_stack[w as usize] = false;
                    comp.push(w);
                    if w as usize == v {
                        break;
                    }
                }
                out.push(comp);
            }
        }
    }
    out
}
