// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The harness's pure logic, kept out of the binary so `cargo test`
//! covers it: the tool pins, the product lock's check, libFuzzer's flags
//! for a target, the names seeds may have, libFuzzer's status lines, the
//! targets a change selects, time boxes, and run records
//! (docs/design/call-language.md, "The harness").

use crate::Target;

/// The crates of a fuzz engine or its tools. None may appear in the
/// product `Cargo.lock` (ADR 0068, rule 3).
pub const ENGINE_CRATES: &[&str] = &[
    "libfuzzer-sys",
    "arbitrary",
    "derive_arbitrary",
    "afl",
    "honggfuzz",
    "cargo-fuzz",
];

/// A tool's pinned version from `fuzz/Cargo.toml`'s
/// `[workspace.metadata.aspis]` table, such as `cargo-fuzz = "0.13.2"`.
pub fn pin<'a>(manifest: &'a str, tool: &str) -> Option<&'a str> {
    let mut in_table = false;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            in_table = line == "[workspace.metadata.aspis]";
            continue;
        }
        if !in_table {
            continue;
        }
        if let Some((k, v)) = line.split_once('=')
            && k.trim() == tool
        {
            return Some(v.trim().trim_matches('"'));
        }
    }
    None
}

/// The version a tool prints for `--version`, such as `cargo-fuzz 0.13.2`.
pub fn version_of<'a>(output: &'a str, tool: &str) -> Option<&'a str> {
    output
        .lines()
        .find_map(|l| l.trim().strip_prefix(tool)?.strip_prefix(' '))
        .map(str::trim)
}

/// The engine crates a `Cargo.lock` names.
pub fn engine_crates_in(lock: &str) -> Vec<&'static str> {
    ENGINE_CRATES
        .iter()
        .copied()
        .filter(|c| {
            lock.lines()
                .any(|l| l.trim() == format!("name = \"{c}\"").as_str())
        })
        .collect()
}

/// The host triple from `rustc -vV`.
pub fn host_triple(rustc_vv: &str) -> Option<&str> {
    rustc_vv
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .map(str::trim)
}

/// libFuzzer's flags for a target, on every replay and run: the input
/// length, the timeout, and the RSS backstop. `-malloc_limit_mb` isn't
/// passed: without a sanitizer it does nothing, and
/// [`fuzz_alloc::Bounded`] enforces the target's memory bound instead.
/// `-max_len` is always passed, since without it libFuzzer caps inputs
/// at 1 MiB and would replay a longer seed truncated.
pub fn libfuzzer_flags(t: &Target) -> Vec<String> {
    vec![
        format!("-max_len={}", t.max_len),
        format!("-timeout={}", t.timeout_s),
        format!("-rss_limit_mb={}", t.rss_limit_mb),
    ]
}

/// Whether a committed seed, regression or differential case has a name
/// the tools accept: lowercase letters, digits, hyphens and dots, starting
/// with a letter or digit. iCloud's conflict copies have a space, so they
/// never qualify.
pub fn valid_name(name: &str) -> bool {
    let mut b = name.bytes();
    b.next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.')
}

/// What libFuzzer's last status line says: executions, coverage
/// (`cov`), features (`ft`), corpus size, and in fork mode the counts of
/// OOMs, timeouts and crashes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Status {
    pub execs: u64,
    pub cov: u64,
    pub ft: u64,
    pub corpus: u64,
    pub ooms: u64,
    pub timeouts: u64,
    pub crashes: u64,
}

/// The number after `key` in a status line, such as `cov: 270`.
fn field(line: &str, key: &str) -> Option<u64> {
    let rest = &line[line.find(key)? + key.len()..];
    let n: String = rest
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    n.parse().ok()
}

/// Reads one libFuzzer status line, in normal mode
/// (`#2197582\tREDUCE cov: 270 ft: 1248 corp: 298/52Kb ...`) or fork mode
/// (`#810072: cov: 275 ft: 1209 corp: 253 exec/s: ... oom/timeout/crash:
/// 0/0/0 ...`). Other lines give `None`.
pub fn status_line(line: &str) -> Option<Status> {
    let rest = line.strip_prefix('#')?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    let execs = digits.parse().ok()?;
    let cov = field(line, " cov:")?;
    let mut s = Status {
        execs,
        cov,
        ft: field(line, " ft:").unwrap_or(0),
        corpus: field(line, " corp:").unwrap_or(0),
        ..Status::default()
    };
    if let Some(i) = line.find("oom/timeout/crash:") {
        let counts: Vec<u64> = line[i + "oom/timeout/crash:".len()..]
            .split_whitespace()
            .next()?
            .split('/')
            .map(|n| n.parse().ok())
            .collect::<Option<_>>()?;
        if let [o, t, c] = counts[..] {
            (s.ooms, s.timeouts, s.crashes) = (o, t, c);
        }
    }
    Some(s)
}

/// The last status in a libFuzzer log. In normal mode, `Done N runs`
/// gives the final count of executions, and so does
/// `stat::number_of_executed_units: N` when the harness stopped the run
/// (it counts the run's own executions, and is 0 in a fork-mode parent,
/// so it only ever raises the count).
pub fn last_status(log: &str) -> Status {
    let mut last = Status::default();
    for line in log.lines() {
        if let Some(s) = status_line(line) {
            last = s;
        } else if let Some(n) = line
            .strip_prefix("Done ")
            .and_then(|r| r.split_whitespace().next())
            .and_then(|n| n.parse().ok())
        {
            last.execs = n;
        } else if let Some(n) = line
            .strip_prefix("stat::number_of_executed_units:")
            .and_then(|n| n.trim().parse().ok())
        {
            last.execs = last.execs.max(n);
        }
    }
    last
}

/// Whether a libFuzzer line ends the corpus load, so fuzzing starts:
/// `INITED` in normal mode, and `starting to fuzz` in fork mode. A run's
/// time box counts from this line, not from the process's start, so a
/// growing corpus doesn't eat into the fuzzing.
pub fn fuzzing_starts(line: &str) -> bool {
    (line.starts_with('#') && line.split_whitespace().nth(1) == Some("INITED"))
        || line.contains(", starting to fuzz in ")
}

/// The CPU seconds `/usr/bin/time -p` reports (user plus sys), which
/// include the fork-mode children libFuzzer waits for, and the wall
/// seconds (`real`). It writes them last, so the last of each counts.
pub fn time_p(log: &str) -> Option<(f64, f64)> {
    let mut real = None;
    let mut user = None;
    let mut sys = None;
    for line in log.lines() {
        let mut w = line.split_whitespace();
        let (Some(k), Some(v), None) = (w.next(), w.next(), w.next()) else {
            continue;
        };
        let Ok(v) = v.parse::<f64>() else { continue };
        match k {
            "real" => real = Some(v),
            "user" => user = Some(v),
            "sys" => sys = Some(v),
            _ => {}
        }
    }
    Some((user? + sys?, real?))
}

/// Whether `path` is `prefix` or lies under it.
fn under(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|r| r.starts_with('/'))
}

/// The paths whose change selects every target: the fuzz workspace's
/// manifest and lock, the harness and the allocator, the toolchain pin
/// (which changes codegen, overflow checks and libFuzzer's
/// instrumentation), and the xtask command that runs the harness.
pub const SELECTS_ALL: &[&str] = &[
    "fuzz/Cargo.toml",
    "fuzz/Cargo.lock",
    "fuzz/gate",
    "fuzz/alloc",
    "rust-toolchain.toml",
    "xtask/src/fuzz.rs",
];

/// The reference matcher every target with a grammar is judged against.
pub const REFERENCE: &str = "crates/abnf";

/// Whether a change to `path` selects `t` for per-change fuzzing: one of
/// its `paths`, its target file, its seeds or regressions, the reference
/// matcher if it has a grammar, or anything in [`SELECTS_ALL`].
pub fn selects(t: &Target, path: &str) -> bool {
    let own = [
        format!("fuzz/fuzz_targets/{}.rs", t.name),
        format!("fuzz/seeds/{}", t.name),
        format!("fuzz/regressions/{}", t.name),
    ];
    t.paths.iter().any(|p| under(path, p))
        || (t.grammar.is_some() && under(path, REFERENCE))
        || own.iter().any(|p| under(path, p))
        || SELECTS_ALL.iter().any(|p| under(path, p))
}

/// The targets a change to `paths` selects, in the table's order.
pub fn selected_by<'a>(targets: &'a [Target], paths: &[String]) -> Vec<&'a Target> {
    targets
        .iter()
        .filter(|t| paths.iter().any(|p| selects(t, p)))
        .collect()
}

/// Each selected target's seconds in a smoke run: `per` each, cut so that
/// `n` targets take at most `total` together, and never under 1 s. The
/// seconds are fuzzing time, counted from [`fuzzing_starts`]; loading the
/// corpus comes on top.
pub fn time_box(n: usize, per: u32, total: u32) -> u32 {
    match n {
        0 => 0,
        n => per.min(total / n as u32).max(1),
    }
}

/// One `cargo xtask fuzz run`, as a line of `build/fuzz/runs/<t>.tsv`.
#[derive(Debug, Clone, PartialEq)]
pub struct RunRecord {
    /// When it ended, in UTC (ISO 8601).
    pub utc: String,
    /// The target binary's SHA-256, its first 16 hex digits ([`build_id`]):
    /// what ran, uncommitted changes and all. `report` counts only the
    /// runs of the binary built now.
    pub build: String,
    pub commit: String,
    /// Whether the working tree had changes.
    pub dirty: bool,
    pub rustc: String,
    pub cargo_fuzz: String,
    /// libFuzzer's `-seed`.
    pub seed: u64,
    pub workers: u32,
    pub wall_s: f64,
    /// Wall seconds from [`fuzzing_starts`] to the end: the time spent
    /// fuzzing, after the corpus load.
    pub fuzz_s: f64,
    /// Executions after the corpus load (in normal mode; in fork mode,
    /// all of them).
    pub fuzz_execs: u64,
    /// User plus sys seconds, measured: the gate's CPU time.
    pub cpu_s: f64,
    pub status: Status,
    /// Finding files the run wrote.
    pub artifacts: u64,
    /// Whether libFuzzer ended cleanly: it exited 0, or it stopped when
    /// the harness interrupted it at the end of its time. A crash on an
    /// input whose artifact is already on disk writes no new file, and an
    /// in-process run prints no crash count, so this is what records it.
    pub clean: bool,
}

/// The run records' column names, the file's first line.
pub const RUN_HEADER: &str = "# utc\tbuild\tcommit\tdirty\trustc\tcargo-fuzz\tseed\tworkers\twall-s\tfuzz-s\tcpu-s\tworkers-x-wall-s\texecs\tfuzz-execs\tcov\tft\tcorpus\tcrashes\ttimeouts\tooms\tartifacts\tclean";

impl RunRecord {
    /// Workers times wall seconds: the CPU time the run asked for, beside
    /// the measured one.
    pub fn asked_s(&self) -> f64 {
        f64::from(self.workers) * self.wall_s
    }

    /// Whether the run found anything: a crash, timeout or out-of-memory
    /// count, a new finding file, or an unclean end.
    pub fn finding(&self) -> bool {
        !self.clean
            || self.status.crashes + self.status.timeouts + self.status.ooms + self.artifacts > 0
    }

    pub fn to_line(&self) -> String {
        let s = &self.status;
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.utc,
            self.build,
            self.commit,
            u8::from(self.dirty),
            self.rustc,
            self.cargo_fuzz,
            self.seed,
            self.workers,
            self.wall_s,
            self.fuzz_s,
            self.cpu_s,
            self.asked_s(),
            s.execs,
            self.fuzz_execs,
            s.cov,
            s.ft,
            s.corpus,
            s.crashes,
            s.timeouts,
            s.ooms,
            self.artifacts,
            u8::from(self.clean)
        )
    }

    /// A record from its line. A line in another layout, such as an older
    /// harness's without a build, gives `None`.
    pub fn from_line(line: &str) -> Option<RunRecord> {
        let f: Vec<&str> = line.split('\t').collect();
        let [
            utc,
            build,
            commit,
            dirty,
            rustc,
            cargo_fuzz,
            seed,
            workers,
            wall,
            fuzz,
            cpu,
            _asked,
            execs,
            fuzz_execs,
            cov,
            ft,
            corpus,
            crashes,
            timeouts,
            ooms,
            artifacts,
            clean,
        ] = f[..]
        else {
            return None;
        };
        let n = |s: &str| s.parse::<u64>().ok();
        Some(RunRecord {
            utc: utc.into(),
            build: build.into(),
            commit: commit.into(),
            dirty: dirty == "1",
            rustc: rustc.into(),
            cargo_fuzz: cargo_fuzz.into(),
            seed: n(seed)?,
            workers: workers.parse().ok()?,
            wall_s: wall.parse().ok()?,
            fuzz_s: fuzz.parse().ok()?,
            fuzz_execs: n(fuzz_execs)?,
            cpu_s: cpu.parse().ok()?,
            status: Status {
                execs: n(execs)?,
                cov: n(cov)?,
                ft: n(ft)?,
                corpus: n(corpus)?,
                crashes: n(crashes)?,
                timeouts: n(timeouts)?,
                ooms: n(ooms)?,
            },
            artifacts: n(artifacts)?,
            clean: match clean {
                "1" => true,
                "0" => false,
                _ => return None,
            },
        })
    }
}

/// What `report` sums from a target's run records.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Summary {
    pub runs: usize,
    pub cpu_s: f64,
    pub asked_s: f64,
    /// Measured CPU seconds since the last run with a finding: the gate's
    /// number ("The gate for each target", item 5).
    pub clean_cpu_s: f64,
    pub execs: u64,
    pub findings: usize,
    pub last: Option<RunRecord>,
}

/// Sums a target's run records of build `build`, in the order they were
/// made: runs of any other build, earlier or later, aren't evidence for
/// this one.
pub fn summarize(records: &[RunRecord], build: &str) -> Summary {
    let mut s = Summary::default();
    for r in records.iter().filter(|r| r.build == build) {
        s.runs += 1;
        s.cpu_s += r.cpu_s;
        s.asked_s += r.asked_s();
        s.execs += r.status.execs;
        if r.finding() {
            s.findings += 1;
            s.clean_cpu_s = 0.0;
        } else {
            s.clean_cpu_s += r.cpu_s;
        }
        s.last = Some(r.clone());
    }
    s
}

/// A build's id: the first 16 hex digits of the SHA-256 of its target
/// binary, which `shasum -a 256` or `sha256sum` also print.
pub fn build_id(binary: &[u8]) -> String {
    sha256(binary)[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// SHA-256 (FIPS 180-4).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64).wrapping_mul(8)).to_be_bytes());
    for block in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 32];
    for (i, x) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&x.to_be_bytes());
    }
    out
}

/// A nightly shard, `i/n` with 1 ≤ i ≤ n: the seam for splitting the
/// nightly into a matrix once its targets near the job's 2-hour limit
/// (docs/design/call-language.md, "The harness").
pub fn shard(spec: &str) -> Option<(usize, usize)> {
    let (i, n) = spec.split_once('/')?;
    let (i, n) = (i.parse().ok()?, n.parse().ok()?);
    (1..=n).contains(&i).then_some((i, n))
}

/// Whether the table's `index`th target (from 0) is in shard `i/n`: the
/// targets are dealt out in turn, so a new row lands in one shard only.
pub fn in_shard(index: usize, (i, n): (usize, usize)) -> bool {
    index % n == i - 1
}

/// The source directories a target's coverage is reported on: the
/// `src/` of each crate in its `paths` (`crates/<name>`). Grammar files
/// and the harness's own code aren't counted.
pub fn coverage_dirs(t: &Target) -> Vec<String> {
    t.paths
        .iter()
        .filter(|p| p.strip_prefix("crates/").is_some_and(|c| !c.contains('/')))
        .map(|p| format!("{p}/src"))
        .collect()
}

/// Region, function and line counts from `llvm-cov report`. Branch
/// coverage needs an unstable `-Z` option, so it isn't counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Coverage {
    pub regions: u64,
    pub regions_missed: u64,
    pub functions: u64,
    pub functions_missed: u64,
    pub lines: u64,
    pub lines_missed: u64,
}

impl Coverage {
    fn percent(total: u64, missed: u64) -> f64 {
        if total == 0 {
            100.0
        } else {
            100.0 * (total - missed) as f64 / total as f64
        }
    }

    pub fn regions_percent(&self) -> f64 {
        Self::percent(self.regions, self.regions_missed)
    }

    pub fn functions_percent(&self) -> f64 {
        Self::percent(self.functions, self.functions_missed)
    }

    pub fn lines_percent(&self) -> f64 {
        Self::percent(self.lines, self.lines_missed)
    }
}

/// The `TOTAL` line of `llvm-cov report`, whose columns are regions,
/// missed regions, cover, functions, missed functions, executed, lines,
/// missed lines and cover (then branches, which are left out).
pub fn coverage_totals(report: &str) -> Option<Coverage> {
    let line = report.lines().rev().find(|l| l.starts_with("TOTAL"))?;
    let f: Vec<&str> = line.split_whitespace().collect();
    let n = |i: usize| f.get(i)?.parse::<u64>().ok();
    Some(Coverage {
        regions: n(1)?,
        regions_missed: n(2)?,
        functions: n(4)?,
        functions_missed: n(5)?,
        lines: n(7)?,
        lines_missed: n(8)?,
    })
}

/// A time in UTC, ISO 8601, from seconds since the Unix epoch (Howard
/// Hinnant's `civil_from_days`).
pub fn utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins() {
        let m = "[package]\ncargo-fuzz = \"9\"\n[workspace.metadata.aspis]\n\
                 cargo-fuzz = \"0.13.2\"\ncargo-deny = \"0.20.2\"\n[profile.dev]\n";
        assert_eq!(pin(m, "cargo-fuzz"), Some("0.13.2"));
        assert_eq!(pin(m, "cargo-deny"), Some("0.20.2"));
        assert_eq!(pin(m, "afl"), None);
    }

    #[test]
    fn versions() {
        assert_eq!(
            version_of("cargo-fuzz 0.13.2\n", "cargo-fuzz"),
            Some("0.13.2")
        );
        assert_eq!(
            version_of("cargo-deny 0.20.2\n", "cargo-deny"),
            Some("0.20.2")
        );
        assert_eq!(version_of("error: no such command", "cargo-fuzz"), None);
    }

    #[test]
    fn engine_crates() {
        let lock = "[[package]]\nname = \"abnf\"\n\n[[package]]\nname = \"libfuzzer-sys\"\n";
        assert_eq!(engine_crates_in(lock), ["libfuzzer-sys"]);
        assert!(engine_crates_in("[[package]]\nname = \"arbitrary-ish\"\n").is_empty());
    }

    #[test]
    fn triples() {
        let vv = "rustc 1.100.0\nbinary: rustc\nhost: aarch64-apple-darwin\nrelease: 1.100.0\n";
        assert_eq!(host_triple(vv), Some("aarch64-apple-darwin"));
    }

    #[test]
    fn sha256_vectors() {
        let hex = |d: [u8; 32]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        // FIPS 180-4's examples, and the empty string.
        assert_eq!(
            hex(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(build_id(b"abc"), "ba7816bf8f01cfea");
    }

    #[test]
    fn fuzzing_start_lines() {
        assert!(fuzzing_starts(
            "#680\tINITED cov: 1584 ft: 3000 corp: 600/1Mb exec/s: 68 rss: 90Mb"
        ));
        assert!(fuzzing_starts(
            "INFO: -fork=2: 1683 seed inputs, starting to fuzz in /tmp/libFuzzerTemp.FuzzWithFork1.dir"
        ));
        assert!(!fuzzing_starts("#2\tNEW    cov: 1 ft: 1 corp: 1/1b"));
        assert!(!fuzzing_starts("INFO: Loaded 1 modules"));
    }

    #[test]
    fn interrupted_runs_count_their_executions() {
        let log = "#4096\tpulse  cov: 10 ft: 20 corp: 5/1Kb exec/s: 2048 rss: 40Mb\n\
                   ==1== libFuzzer: run interrupted; exiting\n\
                   stat::number_of_executed_units: 5000\n";
        assert_eq!(last_status(log).execs, 5000);
        // A fork-mode parent's own count is 0, and doesn't lower it.
        let fork = "#9000: cov: 10 ft: 20 corp: 5 exec/s: 30 oom/timeout/crash: 0/0/0 time: 9s\n\
                    stat::number_of_executed_units: 0\n";
        assert_eq!(last_status(fork).execs, 9000);
    }

    #[test]
    fn names() {
        assert!(valid_name("kernel-args-vectors-57"));
        assert!(valid_name("bad-escape.txt"));
        assert!(!valid_name("bad-escape 2"));
        assert!(!valid_name("Bad"));
        assert!(!valid_name(".hidden"));
        assert!(!valid_name(""));
    }
}
