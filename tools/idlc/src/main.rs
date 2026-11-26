// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! `idlc`: the ASPIS IDL compiler's command-line tool (ADR 0067; docs/
//! design/call-language.md, "Crates", "The lock and the canonical form").
//!
//! ```text
//! idlc check [--write] [options] [FILE...]   check files, their locks and
//!                                            generated files
//! idlc build [--write] [options] [FILE...]   the generated files only
//! idlc lock [options] FILE                   publish the file's version
//! idlc canon [options] FILE [MINOR]          print a canonical form
//! idlc rust [options] [--runtime] FILE       print the Rust binding
//! ```
//!
//! Options: `--root DIR` (repeatable; default `interfaces`) gives the
//! interface roots that `use` lines resolve in, and that are walked when no
//! FILE is given; `--grammars DIR` (default `grammars`) holds `core.abnf`,
//! `names.abnf` and `json.abnf`. A path with a space in any component is
//! one of iCloud's conflict copies, and is skipped.
//!
//! `idlc rust` prints the module crates/interfaces' build script generates
//! for the file; `--runtime` prints it as idl-rt includes it, which is how
//! `crates/idl-rt/src/rpc/v1.rs` is made.
//!
//! `idlc check`, for each `v<M>.idl`:
//!
//! 1. parses and checks it at its version, M.v, and refuses it when its
//!    Rust module path is another interface's: `x.v<M>` beside `x` major
//!    M, which both nest at `x::v<M>`;
//! 2. reads its lock, whose entries are minors 0 to p, and requires v to be
//!    p or p + 1;
//! 3. for each published minor, compares the canonical form's hash with
//!    the lock, and requires every `use` line's minor to be published in
//!    the imported file's lock (checked at minor 0 and where the
//!    projection changes, since only there can the `use` lines change);
//! 4. runs the compatibility check on each step from M.(m-1) to M.m
//!    where m is a minor some `since` or `deprecated` names: at any other
//!    minor the projection is the one before's, apart from its version;
//! 5. regenerates each minor's grammars and vectors, lowest first, with
//!    one budget for the file (`idl::generate::Generator`), and compares
//!    them with the committed files (`--write` writes them), and fails on
//!    generated files for minors above v;
//! 6. checks each committed vector file with crates/abnf, and the vector
//!    evolution rule: every reply, error-detail, item and type vector of
//!    M.m matches M.(m-1)'s grammar, and every request vector gets the
//!    same answer from M.(m-1)'s grammar as from its decoder. A minor
//!    whose grammar and vectors are the minor before's, apart from their
//!    headers, has nothing new to check. The matches against M.(m-1)'s
//!    grammars take their steps from one allowance for the file,
//!    crates/abnf's `Limits::file_steps`.
//!
//! It holds one minor's generated files at a time, and the wire grammar
//! of the minor before.

use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    process::exit,
};

use abnf::{Context, Grammar, Kind, LoadOptions, vectors};
use idl::{
    Checked, Diagnostic, Limits,
    generate::{self, Files, Generator, Part},
    lock::{self, Lock},
    schema::{Mode, Schema, Top},
    value,
};
use idl_rt::names::InterfaceRef;

struct Options {
    write: bool,
    runtime: bool,
    roots: Vec<PathBuf>,
    grammars: PathBuf,
    files: Vec<PathBuf>,
}

fn usage() -> ! {
    eprintln!(
        "usage: idlc check|build [--write] [--root DIR]... [--grammars DIR] [FILE...]\n       \
         idlc lock [--root DIR]... [--grammars DIR] FILE\n       \
         idlc canon [--root DIR]... FILE [MINOR]\n       \
         idlc rust [--root DIR]... [--runtime] FILE"
    );
    exit(2)
}

fn parse_args(args: &[String]) -> (Options, Vec<String>) {
    let mut o = Options {
        write: false,
        runtime: false,
        roots: Vec::new(),
        grammars: PathBuf::from("grammars"),
        files: Vec::new(),
    };
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--write" => o.write = true,
            "--runtime" => o.runtime = true,
            "--root" => {
                i += 1;
                o.roots
                    .push(PathBuf::from(args.get(i).unwrap_or_else(|| usage())));
            }
            "--grammars" => {
                i += 1;
                o.grammars = PathBuf::from(args.get(i).unwrap_or_else(|| usage()));
            }
            a if a.starts_with("--") => usage(),
            a => rest.push(a.to_string()),
        }
        i += 1;
    }
    if o.roots.is_empty() {
        o.roots.push(PathBuf::from("interfaces"));
    }
    (o, rest)
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some(cmd) = args.first() else { usage() };
    let (mut o, rest) = parse_args(&args[1..]);
    let ok = match cmd.as_str() {
        "check" | "build" => {
            o.files = rest.iter().map(PathBuf::from).collect();
            if o.files.is_empty() {
                o.files = walk(&o.roots);
            }
            let mut ok = true;
            for f in &o.files {
                ok &= check(&o, f, cmd == "build");
            }
            ok
        }
        "lock" => match rest.as_slice() {
            [f] => publish(&o, Path::new(f)),
            _ => usage(),
        },
        "canon" => match rest.as_slice() {
            [f] => canon(&o, Path::new(f), None),
            [f, m] => canon(
                &o,
                Path::new(f),
                Some(m.parse().unwrap_or_else(|_| usage())),
            ),
            _ => usage(),
        },
        "rust" => match rest.as_slice() {
            [f] => rust(&o, Path::new(f)),
            _ => usage(),
        },
        _ => usage(),
    };
    exit(if ok { 0 } else { 1 })
}

/// Every `v<M>.idl` under the roots, sorted, skipping iCloud's copies.
fn walk(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut dirs: Vec<PathBuf> = roots.to_vec();
    while let Some(d) = dirs.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.contains(' ') {
                continue;
            }
            let p = e.path();
            if p.is_dir() {
                dirs.push(p);
            } else if is_idl(&name) {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

fn is_idl(name: &str) -> bool {
    name.strip_prefix('v')
        .and_then(|r| r.strip_suffix(".idl"))
        .is_some_and(|m| !m.is_empty() && m.bytes().all(|b| b.is_ascii_digit()))
}

/// Two interfaces whose Rust modules would share a path: `x` major M nests
/// at `x::v<M>`, as interface `x.v<M>` does (docs/design/
/// call-language.md, "Generated Rust names").
fn module_clash(roots: &[PathBuf], name: &str, major: u16) -> Option<String> {
    // This interface's major module, and an interface named after it.
    let child = format!("{name}.v{major}");
    for r in roots {
        let dir = r.join(child.replace('.', "/"));
        let has_idl = fs::read_dir(&dir).is_ok_and(|es| {
            es.flatten()
                .any(|e| is_idl(&e.file_name().to_string_lossy()))
        });
        if has_idl {
            return Some(format!(
                "interface {child} is under {}, and its Rust module would be this major's, v{major}: rename one",
                r.display()
            ));
        }
    }
    // This interface, named after another's major module.
    let (parent, last) = name.rsplit_once('.')?;
    let digits = last.strip_prefix('v')?;
    let valid = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'));
    let m: u16 = digits.parse().ok().filter(|_| valid)?;
    path_of(roots, parent, m).map(|p| {
        format!(
            "{parent} major {m} is {}, and its Rust module, v{m}, would be this interface's: rename one",
            p.display()
        )
    })
}

/// The file an interface major lives in, under any root.
fn path_of(roots: &[PathBuf], name: &str, major: u16) -> Option<PathBuf> {
    roots
        .iter()
        .map(|r| r.join(name.replace('.', "/")).join(format!("v{major}.idl")))
        .find(|p| p.exists())
}

/// Prints diagnostics as `path:line:col: error: ...`, with the line and a
/// caret.
fn report(path: &Path, src: &[u8], diags: &[Diagnostic]) {
    for d in diags {
        let (line, col) = d.line_col(src);
        println!("{}:{line}:{col}: error: {d}", path.display());
        let text = String::from_utf8_lossy(src);
        if let Some(l) = text.lines().nth(line - 1) {
            println!("    {l}");
            println!("    {}^", " ".repeat(col.saturating_sub(1)));
        }
    }
}

fn fail(path: &Path, msg: impl AsRef<str>) -> bool {
    println!("{}: error: {}", path.display(), msg.as_ref());
    false
}

/// Parses and checks a file.
fn load(o: &Options, path: &Path) -> Option<(Vec<u8>, Checked)> {
    let src = match fs::read(path) {
        Ok(s) => s,
        Err(e) => {
            fail(path, format!("{e}"));
            return None;
        }
    };
    let roots = o.roots.clone();
    let mut resolve =
        |r: &InterfaceRef<'_>| path_of(&roots, r.name, r.major).and_then(|p| fs::read(p).ok());
    match idl::check(&src, &mut resolve, &Limits::default()) {
        Ok(c) => Some((src, c)),
        Err(d) => {
            report(path, &src, &d);
            None
        }
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".lock");
    PathBuf::from(p)
}

fn read_lock(path: &Path, major: u16) -> Result<Lock, String> {
    let lp = lock_path(path);
    let text = fs::read(&lp).map_err(|e| format!("{}: {e}", lp.display()))?;
    lock::parse(&text, major).map_err(|(line, m)| format!("{}:{line}: {m}", lp.display()))
}

/// The generated files' names and contents for one minor.
fn files_of<'f, 'g>(
    dir: &Path,
    major: u16,
    minor: u16,
    g: &'f Files<'g>,
) -> Vec<(PathBuf, &'f Part<'g>)> {
    let stem = format!("v{major}.{minor}");
    let mut out = Vec::new();
    if let Some((grammar, vectors)) = &g.wire {
        out.push((dir.join(format!("{stem}.abnf")), grammar));
        out.push((dir.join(format!("{stem}.vectors")), vectors));
    }
    out.push((dir.join(format!("{stem}.text.abnf")), &g.text.0));
    out.push((dir.join(format!("{stem}.text.vectors")), &g.text.1));
    out
}

/// Writes a generated file, its header and the rest.
fn write_part(p: &Path, part: &Part<'_>) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = fs::File::create(p)?;
    f.write_all(part.head.as_bytes())?;
    f.write_all(part.body.as_bytes())
}

/// A generated file's minor: `v<M>.<m>.abnf`, `.vectors`, `.text.abnf`
/// or `.text.vectors`.
fn generated_minor(name: &str, major: u16) -> Option<(u16, bool)> {
    let rest = name.strip_prefix(&format!("v{major}."))?;
    let (m, kind) = rest.split_once('.')?;
    let wire = match kind {
        "abnf" | "vectors" => true,
        "text.abnf" | "text.vectors" => false,
        _ => return None,
    };
    Some((m.parse().ok()?, wire))
}

fn shared(o: &Options) -> impl FnMut(&str) -> Option<Vec<u8>> + '_ {
    |name: &str| fs::read(o.grammars.join(format!("{name}.abnf"))).ok()
}

/// `idlc check` and `idlc build` on one file.
fn check(o: &Options, path: &Path, build_only: bool) -> bool {
    let Some((src, c)) = load(o, path) else {
        return false;
    };
    let unit = c.unit();
    let (major, v) = (unit.major(), unit.version.minor);
    let name = unit.name.clone();
    let dir = path.parent().unwrap_or(Path::new("."));
    let source = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let spdx = generate::spdx_lines(&src);
    let mut ok = true;
    if let Some(e) = module_clash(&o.roots, &name, major) {
        ok &= fail(path, e);
    }

    if !build_only {
        // The lock (ADR 0067, rule 7).
        let lock = match read_lock(path, major) {
            Ok(l) => l,
            Err(e) if o.write && !lock_path(path).exists() => {
                let l = Lock::default();
                if let Err(err) = fs::write(lock_path(path), lock::render(&spdx, &name, major, &l))
                {
                    return fail(path, format!("{e}; writing it: {err}"));
                }
                l
            }
            Err(e) => return fail(path, e),
        };
        if !lock.allows(v) {
            ok &= fail(
                path,
                format!(
                    "version {major}.{v}, but the lock publishes minors up to {}: the version is the newest published minor, or the one after it",
                    lock.published()
                        .map_or("none".into(), |p| format!("{major}.{p}"))
                ),
            );
        }
        // A minor's `use` lines are the minor before's unless its
        // projection changes there.
        let changes = idl::project::changes(c.file(), major);
        for (m, want) in lock.hashes.iter().enumerate() {
            let m = m as u16;
            if m > v {
                break;
            }
            let got = generate::minor_hash(&c, m);
            if &got != want {
                ok &= fail(
                    path,
                    format!(
                        "minor {major}.{m} is published with hash {}, but its canonical form now hashes to {}: a published minor changed",
                        lock::hex(want),
                        lock::hex(&got)
                    ),
                );
            }
            if m == 0 || changes.contains(&m) {
                ok &= imports_published(o, path, &c, m);
            }
        }
        // The compatibility check, each step that changes the projection.
        for m in changes.into_iter().filter(|&m| m >= 1 && m <= v) {
            let prev = idl::project::project(c.file(), m - 1);
            let next = idl::project::project(c.file(), m);
            for viol in idl::compat::step(&prev, &next) {
                ok &= fail(
                    path,
                    format!(
                        "{major}.{} to {major}.{m}: {}: {}",
                        m - 1,
                        viol.kind,
                        viol.message
                    ),
                );
            }
        }
    }

    // The generated files, and the evolution check, a minor at a time.
    let mut shared = shared(o);
    let mut generator = Generator::new(&c, &source, &spdx);
    let mut evolution = (!build_only && !unit.is_kernel()).then(|| Evolution::new(o));
    for m in 0..=v {
        match generator.files(m, &mut shared) {
            Ok(g) => {
                for (p, part) in files_of(dir, major, m, &g) {
                    match fs::read(&p) {
                        Ok(have) if part.is(&have) => {}
                        _ if o.write => {
                            if let Err(e) = write_part(&p, part) {
                                ok &= fail(&p, format!("{e}"));
                            }
                        }
                        Ok(_) => {
                            ok &= fail(
                                &p,
                                "differs from what idlc generates; run cargo xtask idl --write",
                            )
                        }
                        Err(_) => ok &= fail(&p, "missing; run cargo xtask idl --write"),
                    }
                }
                if ok && let Some(e) = &mut evolution {
                    ok &= e.minor(path, &c, m, &g);
                }
            }
            Err(e) => ok &= fail(path, format!("{major}.{m}: {e}")),
        }
    }
    // Stale generated files.
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.contains(' ') {
                continue;
            }
            if let Some((m, wire)) = generated_minor(&n, major)
                && (m > v || (wire && unit.is_kernel()))
            {
                if o.write {
                    let _ = fs::remove_file(e.path());
                } else {
                    ok &= fail(
                        &e.path(),
                        "a generated file for no minor of the IDL file; remove it",
                    );
                }
            }
        }
    }
    if ok {
        println!("ok   {}: {name}/{major}.{v}", path.display());
    }
    ok
}

/// A published minor's `use` lines name published minors (a published
/// importer can't change under it).
fn imports_published(o: &Options, path: &Path, c: &Checked, m: u16) -> bool {
    let mut ok = true;
    for u in &idl::project::project(c.file(), m).uses {
        let (n, maj, min) = (&u.iface.name, u.iface.major, u.iface.minor_or_zero());
        let Some(p) = path_of(&o.roots, n, maj) else {
            continue;
        };
        match read_lock(&p, maj) {
            Ok(l) if l.published().is_some_and(|q| q >= min) => {}
            Ok(_) => {
                ok &= fail(
                    path,
                    format!(
                        "published minor {}.{m} uses {n}/{maj}.{min}, which isn't published in {}",
                        c.unit().major(),
                        lock_path(&p).display()
                    ),
                )
            }
            Err(e) => ok &= fail(path, e),
        }
    }
    ok
}

/// Checks the committed vectors with crates/abnf, and the vector
/// evolution rule between each minor and the one before it, a minor at a
/// time, lowest first.
struct Evolution<'o> {
    o: &'o Options,
    /// The wire grammar of the minor before.
    prev: Option<Grammar>,
    /// Steps left for the matches against the minor before's grammar.
    allowance: u64,
    /// A grammar or vector file didn't load: nothing after it is checked.
    stopped: bool,
}

impl<'o> Evolution<'o> {
    fn new(o: &'o Options) -> Self {
        Evolution {
            o,
            prev: None,
            allowance: abnf::Limits::default().file_steps,
            stopped: false,
        }
    }

    /// Checks minor m's files.
    fn minor(&mut self, path: &Path, c: &Checked, m: u16, g: &Files<'_>) -> bool {
        let Some((grammar, vtext)) = &g.wire else {
            return true;
        };
        let (same_grammar, same_vectors) = g.same;
        if self.stopped {
            return true;
        }
        // The minor before's grammar and vectors, checked already.
        if same_grammar && same_vectors && self.prev.is_some() {
            return true;
        }
        let opts = LoadOptions {
            kind: Kind::Strict,
            ..LoadOptions::default()
        };
        let stem = format!("v{}.{m}", c.unit().major());
        let reused = same_grammar.then(|| self.prev.take()).flatten();
        let gr = match reused {
            Some(g) => g,
            None => {
                match Grammar::load(&stem, grammar.text().as_bytes(), &mut shared(self.o), &opts) {
                    Ok(g) => g,
                    Err(e) => {
                        self.stopped = true;
                        return fail(path, format!("{stem}.abnf: {e}"));
                    }
                }
            }
        };
        let vf = match vectors::parse(vtext.text().as_bytes()) {
            Ok(v) => v,
            Err(e) => {
                self.stopped = true;
                return fail(path, format!("{stem}.vectors:{e}"));
            }
        };
        let mut ok = true;
        let report = vectors::check(&gr, &vf);
        if report.disagree > 0 {
            ok &= fail(
                path,
                format!("{stem}.vectors: {} vectors disagree", report.disagree),
            );
        }
        // The same grammar as the minor before's is the minor before's.
        let prev = if same_grammar {
            Some(&gr)
        } else {
            self.prev.as_ref()
        };
        if let Some(prev) = prev.filter(|_| m > 0) {
            let s = Schema::new(c, m - 1);
            let tops: BTreeMap<String, Top> =
                s.tops().into_iter().map(|t| (s.top_rule(t), t)).collect();
            for vec in vf.vectors.iter().filter(|v| v.tag == vectors::Tag::Ok) {
                let (Some(&top), Some(r)) = (tops.get(&vec.rule), prev.rule(&vec.rule)) else {
                    continue;
                };
                let cx = Context {
                    caps: vec.caps,
                    unwrapped: vec.unwrapped,
                };
                let matches = match prev.matches_within(
                    r,
                    &vec.octets,
                    Some(&cx),
                    &mut self.allowance,
                ) {
                    Ok(b) => b,
                    Err(abnf::Exhausted::Steps) if self.allowance == 0 => {
                        self.stopped = true;
                        return fail(
                            path,
                            format!(
                                "{stem}.vectors:{}: the evolution check ran out of its steps, {} for the file",
                                vec.line,
                                abnf::Limits::default().file_steps
                            ),
                        );
                    }
                    Err(_) => false,
                };
                let strict = s.mode(top) == Mode::Strict;
                let decoded = value::decode(&s, top, &vec.octets, vec.caps).is_ok();
                if (!strict && !matches) || (strict && matches != decoded) {
                    ok &= fail(
                        path,
                        format!(
                            "{stem}.vectors:{}: an ok vector of {} that {}.{} reads {}",
                            vec.line,
                            vec.rule,
                            c.unit().major(),
                            m - 1,
                            if matches {
                                "differently from its decoder"
                            } else {
                                "as malformed"
                            }
                        ),
                    );
                }
            }
        }
        self.prev = Some(gr);
        ok
    }
}

/// `idlc lock FILE`: publishes the file's version.
fn publish(o: &Options, path: &Path) -> bool {
    if !check(o, path, false) {
        return fail(path, "not published: the check fails");
    }
    let Some((src, c)) = load(o, path) else {
        return false;
    };
    let unit = c.unit();
    let (major, v) = (unit.major(), unit.version.minor);
    let mut lock = match read_lock(path, major) {
        Ok(l) => l,
        Err(e) => return fail(path, e),
    };
    if lock.published() == Some(v) {
        println!("ok   {}: {major}.{v} is already published", path.display());
        return true;
    }
    if !imports_published(o, path, &c, v) {
        return false;
    }
    lock.hashes.push(generate::minor_hash(&c, v));
    let text = lock::render(&generate::spdx_lines(&src), &unit.name, major, &lock);
    match fs::write(lock_path(path), text) {
        Ok(()) => {
            println!("ok   {}: published {major}.{v}", path.display());
            true
        }
        Err(e) => fail(path, format!("{e}")),
    }
}

/// `idlc canon FILE [MINOR]`.
fn canon(o: &Options, path: &Path, minor: Option<u16>) -> bool {
    let Some((_, c)) = load(o, path) else {
        return false;
    };
    let m = minor.unwrap_or(c.unit().version.minor);
    if m > c.unit().version.minor {
        return fail(
            path,
            format!("the file describes minors up to {}", c.unit().version.minor),
        );
    }
    print!("{}", generate::canonical(&c, m));
    true
}

/// `idlc rust FILE`: the generated Rust module, at the file's version.
fn rust(o: &Options, path: &Path) -> bool {
    let Some((src, c)) = load(o, path) else {
        return false;
    };
    let flavor = if o.runtime {
        idl::rust::Flavor::Runtime
    } else {
        idl::rust::Flavor::Crate
    };
    let source = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let module = format!("v{}", c.unit().major());
    print!(
        "{}",
        idl::rust::generate(&c, flavor, &module, &source, &generate::spdx_lines(&src))
    );
    true
}
