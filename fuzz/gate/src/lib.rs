// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The fuzzing gate's targets (ADR 0068; docs/design/call-language.md,
//! "The fuzzing gate" and "The harness").
//!
//! Everything that runs inside a fuzz target lives here, so plain
//! `cargo test` runs it too: the entry functions, each panicking only on a
//! broken property; the target table, [`TARGETS`]; and the generated
//! seeds. `cargo xtask test` replays every target's seeds and regressions
//! through the same entry functions without libFuzzer (ADR 0068, rule 7),
//! and the `fuzz-gate` binary is the harness `cargo xtask fuzz` runs.
//!
//! The crate is a member of the `fuzz/` workspace, not the product one,
//! so nothing about fuzzing enters the product lock file (ADR 0068,
//! rule 3). It is `std` and host-only; the parsers it tests stay `no_std`
//! and `#![forbid(unsafe_code)]` (rule 2), and so does this crate.

#![forbid(unsafe_code)]

/// A target's kinds table and the functions that name its outcomes, from
/// one list, so they can't drift apart: each function is a `match`
/// without a wildcard, so a new error variant fails to compile until it
/// has a name, and the name is then in the table, which `tests/kinds.rs`
/// asks some seed to reach.
///
/// ```text
/// kinds! {
///     pub const TABLE = ["extra", ...];      // names no function gives
///     fn name_of(x: &Type) { Pattern => "name", ... }
///     ...
/// }
/// ```
macro_rules! kinds {
    (
        $(#[$cm:meta])* $cvis:vis const $table:ident = [$($extra:literal),* $(,)?];
        $(
            $(#[$fm:meta])* fn $f:ident($arg:ident: $ty:ty) {
                $($pat:pat => $name:literal),+ $(,)?
            }
        )+
    ) => {
        $(#[$cm])* $cvis const $table: &[&str] = &[$($extra,)* $($($name,)+)+];
        $(
            $(#[$fm])* fn $f($arg: $ty) -> &'static str {
                match $arg {
                    $($pat => $name,)+
                }
            }
        )+
    };
}

pub mod abnf_targets;
pub mod dict;
pub mod generate;
pub mod harness;
pub mod kargs_targets;
pub mod oracle;
pub mod repo;
pub mod seeds;

use abnf::Limits;

/// The match budgets every target matches with: the defaults, with the
/// per-match steps, the per-file steps and the match memory cut, so the
/// slowest input stays under a quarter of its target's timeout and the
/// average one is fast enough for coverage to grow. A match gets 1 M
/// steps and a vector file 8 M: the longest repository vectors, whole
/// interface files in C07's `grammars/idl.vectors` of about 6.4 KiB,
/// take about 450,000 steps a match and 3 M for the file, and every
/// repository vector must be judged within these budgets
/// (`tests/linear.rs`). The repository's grammars are linear, at about
/// 12 ns a step uninstrumented, so only an input that needs the steps
/// takes them. The costliest steps measured in C71, about 117 ns each in
/// the instrumented build, are the quadratic matcher fixtures', which
/// keep a smaller budget, [`SYNTHETIC_LIMITS`], as generated grammars do.
/// The load limits are the defaults, so the loader's
/// own limits are what is fuzzed; the defaults' match budgets stay
/// covered by `crates/abnf/tests/budgets.rs` (docs/design/call-language.md,
/// "The harness").
pub const FUZZ_LIMITS: Limits = Limits {
    grammar_octets: 1 << 20,
    rules: 16_384,
    nodes: 262_144,
    nesting: 64,
    uses_depth: 8,
    input_octets: 64 << 10,
    steps_base: 1_000_000,
    steps_per_octet: 10_000,
    steps_max: 1_000_000,
    file_steps: 8_000_000,
    memory: 16 << 20,
    depth: 768,
};

/// The match budgets for grammars that aren't the repository's:
/// `abnf-match`'s budget fixtures and `abnf-generated`'s and the
/// differential's generated grammars. They are [`FUZZ_LIMITS`] with
/// 250,000 steps a match and 1 M a file. A fixture's steps are the
/// costliest measured (about 117 ns each instrumented), and a valid
/// generated grammar can make a match exponential, so these grammars
/// don't take the larger step budget that long repository vectors need.
pub const SYNTHETIC_LIMITS: Limits = Limits {
    steps_max: 250_000,
    file_steps: 1_000_000,
    ..FUZZ_LIMITS
};

/// The longest input the agreement oracles judge ("The gate for each
/// target", item 3): the matcher's default input limit, which every
/// vector is held to, plus 1 KiB. Every input up to it gets a verdict;
/// a longer one isn't compared with the grammar. Only `abnf-constraint`
/// takes longer inputs (1 MiB, the grammar loader's limit): judging one
/// takes the reference matcher about 2 s and 320 MiB, over the target's
/// bounds, so `tests/linear.rs` judges such inputs outside the fuzzer.
pub const AGREEMENT_MAX: usize = 64 * KIB + KIB;

/// The budgets the agreement oracles judge with: [`FUZZ_LIMITS`], with
/// room for inputs up to [`AGREEMENT_MAX`] and a step budget linear in
/// the input with no cap, so the reference matcher gives a verdict on
/// every input it is asked about. `tests/linear.rs` shows that
/// `kernel-args` and `constraint` judge inputs of that length within
/// them and within the targets' time and memory bounds; an input they
/// can't judge is a finding, since both grammars are linear (item 6).
pub const ORACLE_LIMITS: Limits = Limits {
    input_octets: AGREEMENT_MAX,
    steps_base: 100_000,
    steps_per_octet: 1_000,
    steps_max: u64::MAX,
    memory: 64 << 20,
    ..FUZZ_LIMITS
};

/// One fuzz target: a `fuzz/fuzz_targets/<name>.rs` file and its `[[bin]]`
/// in `fuzz/Cargo.toml`, its committed `fuzz/seeds/<name>/` and
/// `fuzz/regressions/<name>/`, and what the harness needs to run it.
pub struct Target {
    /// The target's name: its bin, and its seeds and regressions
    /// directories.
    pub name: &'static str,
    /// The chunks that own the parser (docs/design/build-plan.md).
    pub chunk: &'static str,
    /// The record that makes it a target.
    pub adr: &'static str,
    /// The files and directories whose change selects it for per-change
    /// fuzzing, besides fuzz/ itself (and `crates/abnf`, the reference
    /// matcher, for a target with a `grammar`). Its coverage is reported
    /// on the `crates/<name>` among them.
    pub paths: &'static [&'static str],
    /// libFuzzer's `-max_len`: the format's limit plus 1 KiB, or 1 MiB for
    /// a format without one ("The gate for each target", item 1).
    pub max_len: usize,
    /// libFuzzer's `-timeout`, in seconds.
    pub timeout_s: u32,
    /// libFuzzer's `-rss_limit_mb`, a backstop only.
    pub rss_limit_mb: u32,
    /// The memory bound, in MiB, which [`fuzz_alloc::Bounded`] enforces.
    pub malloc_limit_mb: u32,
    /// The grammar and rule the parser must agree with, if it has one.
    pub grammar: Option<(&'static str, &'static str)>,
    /// The entry function: it panics only on a broken property.
    pub run: fn(&[u8]),
    /// Every error kind the parser has, and its other outcomes.
    pub kinds: &'static [&'static str],
    /// The kinds an input reaches.
    pub kinds_of: fn(&[u8]) -> Vec<&'static str>,
    /// The generated seeds: vector lines and limit inputs, named.
    pub seeds: fn() -> Vec<(String, Vec<u8>)>,
    /// The dictionary's entries ([`dict`]).
    pub dict: fn() -> Vec<Vec<u8>>,
}

/// The gate's defaults ("The gate for each target", item 1).
const TIMEOUT_S: u32 = 1;
const RSS_LIMIT_MB: u32 = 512;
const MALLOC_LIMIT_MB: u32 = 64;
const MIB: usize = 1 << 20;
const KIB: usize = 1 << 10;

/// The ABNF toolchain's parsers (C06): the text parser and loader.
pub const ABNF_GRAMMAR: Target = Target {
    name: "abnf-grammar",
    chunk: "C06",
    adr: "0062, rule 8; 0027, rule 2",
    paths: &["crates/abnf", "grammars"],
    // The loader's limit is 1 MiB of grammar text.
    max_len: MIB + KIB,
    // Three loads of a grammar at the loader's limits, and up to 40
    // matches of 100,000 steps: the slowest seed took 307 ms in C71.
    timeout_s: 2,
    // libFuzzer holds its corpus in memory, and with inputs of up to
    // 1 MiB the process's peak RSS passed 512 MB within a minute in C71
    // (the corpus, and pages the system allocator keeps after loads of
    // 50 MiB): 2048 MB leaves room. The bound that counts is the next one.
    rss_limit_mb: 2048,
    // Auto and Strict loads are held at once, to compare them: 51 MiB at
    // the loader's node limit, measured in C71.
    malloc_limit_mb: 128,
    grammar: None,
    run: abnf_targets::grammar,
    kinds: abnf_targets::GRAMMAR_KINDS,
    kinds_of: abnf_targets::grammar_kinds,
    seeds: abnf_targets::grammar_seeds,
    dict: dict::grammar,
};

/// The matcher, context-free and with constraints (C06).
pub const ABNF_MATCH: Target = Target {
    name: "abnf-match",
    chunk: "C06",
    adr: "0062, rule 8; 0027, rule 2",
    paths: &["crates/abnf", "grammars"],
    // One input of at most 64 KiB, after a frame of at most 64 octets.
    max_len: 64 * KIB + KIB + 64,
    // Up to four matches, of 250,000 steps on a fixture
    // (SYNTHETIC_LIMITS) and 1 M on a repository grammar (FUZZ_LIMITS).
    // With 1 M steps on the quadratic `fixture-steps`, the slowest seed
    // took 464 ms in C71; 2 s leaves room for corpus inputs near 64 KiB.
    timeout_s: 2,
    rss_limit_mb: RSS_LIMIT_MB,
    malloc_limit_mb: MALLOC_LIMIT_MB,
    grammar: None,
    run: abnf_targets::match_framed,
    kinds: abnf_targets::MATCH_KINDS,
    kinds_of: abnf_targets::match_kinds,
    seeds: abnf_targets::match_seeds,
    dict: dict::matcher,
};

/// The vector-file reader and checker (C06).
pub const ABNF_VECTORS: Target = Target {
    name: "abnf-vectors",
    chunk: "C06",
    adr: "0013, rule 6; 0062, rule 8",
    paths: &["crates/abnf", "grammars"],
    // No format limit.
    max_len: MIB,
    // Two checks of up to 1 M steps each (FUZZ_LIMITS). With 4 M steps a
    // file, the slowest seed took 279 ms in C71 (`kernel-args-vectors`,
    // with its 4096-octet lines); 2 s leaves room for corpus inputs.
    timeout_s: 2,
    rss_limit_mb: RSS_LIMIT_MB,
    malloc_limit_mb: MALLOC_LIMIT_MB,
    grammar: None,
    run: abnf_targets::vectors,
    kinds: abnf_targets::VECTORS_KINDS,
    kinds_of: abnf_targets::vectors_kinds,
    seeds: abnf_targets::vectors_seeds,
    dict: dict::vectors,
};

/// The constraint vocabulary's reader (C06).
pub const ABNF_CONSTRAINT: Target = Target {
    name: "abnf-constraint",
    chunk: "C06",
    adr: "0062, rules 7 and 8",
    paths: &[
        "crates/abnf",
        "grammars/constraint.abnf",
        "grammars/constraint.vectors",
    ],
    // No format limit.
    max_len: MIB,
    timeout_s: TIMEOUT_S,
    rss_limit_mb: RSS_LIMIT_MB,
    malloc_limit_mb: MALLOC_LIMIT_MB,
    grammar: Some(("constraint", "constraint")),
    run: abnf_targets::constraint,
    kinds: abnf_targets::CONSTRAINT_KINDS,
    kinds_of: abnf_targets::constraint_kinds,
    seeds: abnf_targets::constraint_seeds,
    dict: dict::constraint,
};

/// The loader and matcher on valid grammars from [`generate`] (C06).
pub const ABNF_GENERATED: Target = Target {
    name: "abnf-generated",
    chunk: "C06",
    adr: "0062, rule 8; 0068, rule 6",
    paths: &["crates/abnf"],
    // The generator reads a few hundred octets at most; the rest is
    // ignored.
    max_len: 16 * KIB,
    timeout_s: TIMEOUT_S,
    rss_limit_mb: RSS_LIMIT_MB,
    malloc_limit_mb: MALLOC_LIMIT_MB,
    grammar: None,
    run: abnf_targets::generated,
    kinds: abnf_targets::GENERATED_KINDS,
    kinds_of: abnf_targets::generated_kinds,
    seeds: abnf_targets::generated_seeds,
    dict: dict::none,
};

/// The kernel-argument parser (C04, C05).
pub const KARGS_PARSE: Target = Target {
    name: "kargs-parse",
    chunk: "C04, C05",
    adr: "0041, rule 5",
    paths: &[
        "crates/kargs",
        "grammars/kernel-args.abnf",
        "grammars/kernel-args.vectors",
    ],
    max_len: kargs::MAX_LEN + KIB,
    timeout_s: TIMEOUT_S,
    rss_limit_mb: RSS_LIMIT_MB,
    malloc_limit_mb: MALLOC_LIMIT_MB,
    grammar: Some(("kernel-args", "kernel-args")),
    run: kargs_targets::parse,
    kinds: kargs_targets::PARSE_KINDS,
    kinds_of: kargs_targets::parse_kinds,
    seeds: kargs_targets::parse_seeds,
    dict: dict::kargs_parse,
};

/// The stub's conversion of GRUB's command line (C05).
pub const KARGS_GRUB: Target = Target {
    name: "kargs-grub",
    chunk: "C05",
    adr: "0041, rule 5",
    // The oracle copies the stub's buffer sizes, so a change to the stub
    // selects the target too.
    paths: &[
        "crates/kargs",
        "boot/stub/src/main.rs",
        "grammars/kernel-args.abnf",
        "grammars/kernel-args.vectors",
    ],
    // No format limit: the stub converts whatever UEFI gives it.
    max_len: MIB,
    timeout_s: TIMEOUT_S,
    rss_limit_mb: RSS_LIMIT_MB,
    malloc_limit_mb: MALLOC_LIMIT_MB,
    grammar: None,
    run: kargs_targets::grub,
    kinds: kargs_targets::GRUB_KINDS,
    kinds_of: kargs_targets::grub_kinds,
    seeds: kargs_targets::grub_seeds,
    dict: dict::kargs_grub,
};

/// Every gate target. A later trust-boundary parser joins with one row
/// here, one file in `fuzz/fuzz_targets/` and one `[[bin]]`. C07's
/// parsers join as a C71 follow-up, wrapping C07's own fuzz entry
/// functions; `crates/initfs` joins with C19.
pub const TARGETS: &[Target] = &[
    ABNF_GRAMMAR,
    ABNF_MATCH,
    ABNF_VECTORS,
    ABNF_CONSTRAINT,
    ABNF_GENERATED,
    KARGS_PARSE,
    KARGS_GRUB,
];

/// The bins in `fuzz/Cargo.toml` that aren't gate targets: `build` runs
/// them to check the fuzz build's oracle.
pub const PROBES: &[&str] = &["oracle-probe"];

/// A target by name.
pub fn target(name: &str) -> Option<&'static Target> {
    TARGETS.iter().find(|t| t.name == name)
}

/// The oracle probe's entry (`fuzz/fuzz_targets/oracle-probe.rs`). An
/// input starting `overflow` adds past `u8::MAX`, which must panic with
/// overflow checks on; one starting `debug` fails a `debug_assert!`,
/// which must panic with debug assertions on; one starting `alloc` asks
/// for 256 MiB, which the memory bound must refuse. Anything else does
/// nothing.
pub fn oracle_probe(data: &[u8]) {
    if data.starts_with(b"debug") {
        debug_assert!(
            std::hint::black_box(data.is_empty()),
            "aspis-debug-assertions"
        );
    } else if let Some(rest) = data.strip_prefix(b"overflow") {
        let x = std::hint::black_box(rest.len() as u8).wrapping_add(200);
        let y = std::hint::black_box(100u8);
        std::hint::black_box(x + y);
    } else if data.starts_with(b"alloc") {
        let v = std::hint::black_box(vec![1u8; 256 << 20]);
        std::hint::black_box(v.len());
    }
}
