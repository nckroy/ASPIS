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
//! rule 3): not the engine, and not libcrux, `crypto-differential`'s
//! oracle ([`crypto_oracle`]). It builds the parsers it wraps, ABNF's,
//! `kargs`, C07's and `aspis-crypto` (with its `quic` feature), from their
//! paths. It is `std` and host-only; the parsers it tests stay `no_std`
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
pub mod crypto_oracle;
pub mod crypto_repo;
pub mod crypto_targets;
pub mod dict;
pub mod generate;
pub mod harness;
pub mod idl_repo;
pub mod idl_targets;
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

/// The match budgets of the generated wire grammars, which `idl-decode`
/// and `idl-generated` match with: [`FUZZ_LIMITS`] with 8 M steps a
/// match. A wire grammar's repetitions stop at the declared bounds, so
/// its work is linear, but a message of 16 KiB, `idl-decode`'s longest,
/// can take more than [`FUZZ_LIMITS`]' 1 M: the fixtures' structs with
/// an open tail, padded to 16 KiB, took 3.1 M, about 190 steps an octet.
/// So every input the targets take gets a verdict, with about 2.5 times
/// room, and an input they can't judge is a finding, as for the
/// agreement oracles below (`tests/linear.rs`).
pub const WIRE_LIMITS: Limits = Limits {
    steps_max: 8_000_000,
    ..FUZZ_LIMITS
};

/// The longest input the agreement oracles judge ("The gate for each
/// target", item 3): the matcher's default input limit, which every
/// vector is held to, plus 1 KiB. Every input up to it gets a verdict;
/// a longer one isn't compared with the grammar. Only `abnf-constraint`
/// and `idl-front-end` take longer inputs (1 MiB, the grammar loader's
/// and the IDL front end's limits): judging a 1 MiB constraint line takes
/// the reference matcher about 2 s and 320 MiB, over the target's bounds,
/// so `tests/linear.rs` judges such inputs outside the fuzzer.
pub const AGREEMENT_MAX: usize = 64 * KIB + KIB;

/// The budgets the agreement oracles judge with: [`FUZZ_LIMITS`], with
/// room for inputs up to [`AGREEMENT_MAX`] and a step budget linear in
/// the input with no cap, so the reference matcher gives a verdict on
/// every input it is asked about. `tests/linear.rs` shows that
/// `kernel-args`, `constraint`, `names` and `idl` judge inputs of that
/// length within them and within the targets' time and memory bounds; an
/// input they can't judge is a finding, since the grammars are linear
/// (item 6). The one exception is a long run of name octets, on which
/// the constrained match of a label or member name is quadratic
/// ([`oracle::names_grammar_accepts`]).
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
    /// Paths whose change also selects the target for per-change fuzzing,
    /// but whose code isn't counted in its coverage: the reference matcher
    /// its oracle uses, crates whose code is generated into `OUT_DIR` (so
    /// `src/` holds only an `include!`), tools that regenerate committed
    /// files, and ASPIS crates the entry calls that have targets of their
    /// own, such as `aspis-crypto`'s SHA3-256 for the IDL front end.
    pub extra_paths: &'static [&'static str],
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
    extra_paths: &[],
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
    extra_paths: &[],
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
    extra_paths: &[],
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
    extra_paths: &[],
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
    extra_paths: &[],
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
    extra_paths: &[],
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
    extra_paths: &[],
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

/// The name parsers (C06, C07): `interface-ref`, `action-ref` and
/// `error-ref`, and the predicates they rest on. Its `grammar` is the
/// longest form; the oracle holds the parsers to seven of
/// `grammars/names.abnf`'s rules (`oracle::NAMES_RULES`).
pub const IDL_NAMES: Target = Target {
    name: "idl-names",
    chunk: "C06, C07",
    adr: "0063, rule 10; 0068, rule 4",
    paths: &[
        "crates/idl-rt",
        "grammars/names.abnf",
        "grammars/names.vectors",
    ],
    // The grammars names.abnf uses, which its oracle loads.
    extra_paths: &["grammars/json.abnf", "grammars/core.abnf"],
    max_len: idl_rt::names::MAX_ACTION_REF + KIB,
    timeout_s: TIMEOUT_S,
    rss_limit_mb: RSS_LIMIT_MB,
    malloc_limit_mb: MALLOC_LIMIT_MB,
    grammar: Some(("names", "action-ref")),
    run: idl_targets::names,
    kinds: idl_targets::NAMES_KINDS,
    kinds_of: idl_targets::names_kinds,
    seeds: idl_targets::names_seeds,
    dict: dict::idl_names,
};

/// The IDL front end, projection, canonical form and compatibility
/// checker (C07), as the catalog runs them on publishers' files.
pub const IDL_FRONT_END: Target = Target {
    name: "idl-front-end",
    chunk: "C07",
    adr: "0067, rule 11; 0068, rule 4",
    paths: &[
        "crates/idl",
        "crates/idl-rt",
        "grammars/idl.abnf",
        "grammars/idl.vectors",
        "interfaces",
        "crates/idl/tests/data/interfaces",
    ],
    // The grammars idl.abnf uses, which its oracle loads; idlc, which
    // regenerates the interfaces' committed files; aspis-crypto, whose
    // SHA3-256 hashes each canonical form (ADR 0069, rule 2); and the
    // root manifest, which pins sha3, as for the crypto- targets.
    extra_paths: &[
        "grammars/core.abnf",
        "grammars/names.abnf",
        "grammars/json.abnf",
        "tools/idlc",
        "crates/crypto",
        "Cargo.toml",
    ],
    // The front end's source limit (`idl::Limits::default().source`).
    max_len: MIB + KIB,
    // C07's entry checks a file, then each visited minor's canonical form
    // again; the target checks it twice more, for determinism. The
    // checker refuses a file whose canonical form is over the source
    // limit, so each form is at most 1 MiB. The slowest seed,
    // `dense-minors`, an 864 KiB file checked at the most minors the
    // entry visits, 19, is near the largest of its kind that checks
    // (`idl_targets::dense_minors_file`). It took 1.7 to 1.9 s in the
    // fuzz build (0.84 s in the test build): under a fifth of 10 s, and
    // on a CI runner twice as slow still under half (`tests/bounds.rs`).
    timeout_s: 10,
    // libFuzzer holds a corpus of inputs up to 1 MiB, as for
    // abnf-grammar.
    rss_limit_mb: 2048,
    // C07's entry holds a file's model and its projections, and checks
    // each canonical form: the seeds peaked at 82 MiB, under half of
    // 192 MiB.
    malloc_limit_mb: 192,
    grammar: Some(("idl", "idl-file")),
    run: idl_targets::front_end,
    kinds: idl_targets::FRONT_END_KINDS,
    kinds_of: idl_targets::front_end_kinds,
    seeds: idl_targets::front_end_seeds,
    dict: dict::idl_front_end,
};

/// The generated decoders (C07): the generic decoding runtime, through
/// every generated module (aspis.rpc, the bootstrap protocol; the
/// catalog's two minors; a `[kernel]` interface; and the compiler's
/// fixtures, which cover every type kind and older minors' bindings),
/// against each minor's generated grammar and the dynamic codec. Each
/// module's grammar is its own, so `grammar` is None.
pub const IDL_DECODE: Target = Target {
    name: "idl-decode",
    chunk: "C07",
    adr: "0068, rules 4 and 6; 0067, rule 10",
    paths: &[
        "crates/idl-rt",
        "crates/idl",
        "interfaces",
        "crates/idl/tests/data/interfaces",
    ],
    // The reference matcher, the crates whose modules are generated into
    // OUT_DIR, the core grammar the generated grammars use, and idlc.
    extra_paths: &[
        "crates/abnf",
        "crates/interfaces",
        "crates/idl-fixtures",
        "grammars/core.abnf",
        "tools/idlc",
    ],
    // A body, spilled or not, up to idl-rt's 16 KiB cap
    // (`idl_rt::fuzz::MAX_MESSAGE`), after the frame and three octets:
    // the embedded interfaces declare bodies past 2 KiB, whose upper
    // range a 960-octet IPC message would never reach.
    max_len: idl_targets::FRAME_MAX + 3 + idl_rt::fuzz::MAX_MESSAGE,
    // The wire grammar judges every input ([`WIRE_LIMITS`]), and a 16 KiB
    // message can take it 3.1 M steps a match: the costliest found, a
    // fixture's reply padded to the longest input, took about 840 ms in
    // the fuzz build, under a quarter of 4 s. The slowest seed took 76 ms.
    timeout_s: 4,
    rss_limit_mb: RSS_LIMIT_MB,
    malloc_limit_mb: MALLOC_LIMIT_MB,
    grammar: None,
    run: idl_targets::decode,
    kinds: idl_targets::DECODE_KINDS,
    kinds_of: idl_targets::decode_kinds,
    seeds: idl_targets::decode_seeds,
    dict: dict::idl_decode,
};

/// The generated decoders and the dynamic codec on valid structured
/// messages from C07's generator (`idl::fuzz::generate`), driven by
/// libFuzzer's octets: deep valid messages, and `decode(encode(x)) == x`.
pub const IDL_GENERATED: Target = Target {
    name: "idl-generated",
    chunk: "C07",
    adr: "0068, rule 6; 0067, rule 9",
    paths: &[
        "crates/idl-rt",
        "crates/idl",
        "interfaces",
        "crates/idl/tests/data/interfaces",
    ],
    extra_paths: &[
        "crates/abnf",
        "crates/interfaces",
        "crates/idl-fixtures",
        "grammars/core.abnf",
        "tools/idlc",
    ],
    // The generator reads a few KiB at most (a budget of 256 values); the
    // rest is ignored, as for abnf-generated.
    max_len: idl_targets::FRAME_MAX + 3 + 16 * KIB,
    timeout_s: TIMEOUT_S,
    rss_limit_mb: RSS_LIMIT_MB,
    malloc_limit_mb: MALLOC_LIMIT_MB,
    grammar: None,
    run: idl_targets::generated,
    kinds: idl_targets::GENERATED_KINDS,
    kinds_of: idl_targets::generated_kinds,
    seeds: idl_targets::generated_seeds,
    dict: dict::idl_frames,
};

/// C08's six decoding entries (`aspis_crypto::fuzz`): public keys, the
/// ML-KEM-768 ciphertext, X25519MLKEM768's key shares, signatures,
/// decoding with verification, and algorithm identifiers. Octet 0 picks
/// the entry; the rest is the entry's own input
/// ([`crypto_targets`]).
pub const CRYPTO_DECODE: Target = Target {
    name: "crypto-decode",
    chunk: "C08",
    adr: "0069, rules 5 and 8; 0068, rule 4",
    // Code, vectors, the test reader the seeds use, and the manifest.
    paths: &["crates/crypto"],
    // The product's root manifest, whose `[workspace.dependencies]` pins
    // aspis-crypto's primitives: their versions and features. A change
    // to features alone changes neither lock.
    extra_paths: &["Cargo.toml"],
    // The entry's octet and `verify`'s limit, the largest of the six
    // (aspis_crypto::fuzz's module doc).
    max_len: crypto_targets::DECODE_MAX,
    // The slowest seeds, composite verification (twice in the entry and
    // twice for the target), took about 1.8 ms in the fuzz build (0.7 ms
    // in the test build). Neither aspis-crypto nor libcrux allocates.
    timeout_s: TIMEOUT_S,
    rss_limit_mb: RSS_LIMIT_MB,
    malloc_limit_mb: MALLOC_LIMIT_MB,
    grammar: None,
    run: crypto_targets::decode,
    kinds: crypto_targets::DECODE_KINDS,
    kinds_of: crypto_targets::decode_kinds,
    seeds: crypto_targets::decode_seeds,
    dict: dict::crypto_decode,
};

/// C08's AEAD opening (`aspis_crypto::fuzz::aead_open`): TLS records and
/// QUIC packets, with ChaCha20-Poly1305, AES-256-GCM and, with the
/// `quic` feature the fuzz workspace builds, AES-128-GCM.
pub const CRYPTO_AEAD: Target = Target {
    name: "crypto-aead",
    chunk: "C08",
    adr: "0069, rule 5; 0068, rule 4",
    paths: &["crates/crypto"],
    // The root manifest, which pins the primitives, as for crypto-decode.
    extra_paths: &["Cargo.toml"],
    // TLS 1.3's protected record, after the nonce and an aad of up to 255
    // octets (aspis_crypto::fuzz's module doc).
    max_len: crypto_targets::AEAD_MAX,
    // The slowest seeds, 16 KiB records, took about 0.3 ms in the fuzz
    // build (0.2 ms in the test build).
    timeout_s: TIMEOUT_S,
    rss_limit_mb: RSS_LIMIT_MB,
    malloc_limit_mb: MALLOC_LIMIT_MB,
    grammar: None,
    run: crypto_targets::aead,
    kinds: crypto_targets::AEAD_KINDS,
    kinds_of: crypto_targets::aead_kinds,
    seeds: crypto_targets::aead_seeds,
    dict: dict::crypto_aead,
};

/// C08's differential (`aspis_crypto::fuzz::differential`): its 24
/// primitives against libcrux ([`crypto_oracle::Libcrux`]; ADR 0069,
/// rule 8).
pub const CRYPTO_DIFFERENTIAL: Target = Target {
    name: "crypto-differential",
    chunk: "C08",
    adr: "0069, rule 8; 0068, rule 6",
    paths: &["crates/crypto"],
    // The root manifest, which pins the primitives, as for crypto-decode.
    extra_paths: &["Cargo.toml"],
    // ML-DSA-65 verification's key, signature and context, and 1 KiB of
    // message (aspis_crypto::fuzz's module doc).
    max_len: crypto_targets::DIFFERENTIAL_MAX,
    // The slowest seed, composite signing on both sides with its own
    // verification and the one-bit-flip check
    // (composite-rfc10073-hedged-flip-ed25519), took about 12 ms in the
    // fuzz build (8 to 9 ms in the test build, which also runs libcrux's
    // portable code). ML-DSA-65 signing took about 4 and 5 ms.
    timeout_s: TIMEOUT_S,
    rss_limit_mb: RSS_LIMIT_MB,
    malloc_limit_mb: MALLOC_LIMIT_MB,
    grammar: None,
    run: crypto_targets::differential,
    kinds: crypto_targets::DIFFERENTIAL_KINDS,
    kinds_of: crypto_targets::differential_kinds,
    seeds: crypto_targets::differential_seeds,
    dict: dict::crypto_differential,
};

/// Every gate target. A later trust-boundary parser joins with one row
/// here, one file in `fuzz/fuzz_targets/` and one `[[bin]]`. C07's
/// parsers are the four `idl-` rows, which wrap C07's own fuzz entry
/// functions, and C08's are the three `crypto-` rows, which wrap
/// `aspis_crypto::fuzz`'s (docs/design/call-language.md, "The harness",
/// for why eight entries are three targets); each kernel interface gets a row of its own with C17,
/// wrapping [`idl_targets::decode_module`] for its module, and
/// `crates/initfs` joins with C19. The order matters: the nightly deals
/// the rows out to its shards in turn ([`harness::in_shard`]), so a row
/// inserted mid-table moves the rows after it to other shards. Each
/// shard restores every shard's corpus cache and keeps its own targets'
/// directories, so a moved target keeps its corpus.
pub const TARGETS: &[Target] = &[
    ABNF_GRAMMAR,
    ABNF_MATCH,
    ABNF_VECTORS,
    ABNF_CONSTRAINT,
    ABNF_GENERATED,
    KARGS_PARSE,
    KARGS_GRUB,
    IDL_NAMES,
    IDL_FRONT_END,
    IDL_DECODE,
    IDL_GENERATED,
    CRYPTO_DECODE,
    CRYPTO_AEAD,
    CRYPTO_DIFFERENTIAL,
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
