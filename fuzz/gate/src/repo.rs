// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The repository's grammars and vectors, embedded, and the grammars
//! loaded once for the targets that match against them.
//!
//! They are embedded with `include_bytes!`, so the seeds made from them
//! can't drift from the vectors (ADR 0068, rule 3: "every vector line is
//! also a seed"), and nothing reads files while fuzzing. `targets.rs`
//! checks that this list is every tracked grammar.

use std::sync::LazyLock;

use abnf::{Grammar, Kind, Limits, LoadOptions};

use crate::{FUZZ_LIMITS, ORACLE_LIMITS, SYNTHETIC_LIMITS};

/// One embedded grammar, and its vectors if it has them.
pub struct RepoGrammar {
    /// Its name, as `; uses:` lines give it.
    pub name: &'static str,
    /// Its path in the repository.
    pub path: &'static str,
    pub text: &'static [u8],
    pub vectors_path: &'static str,
    pub vectors: &'static [u8],
}

macro_rules! repo_grammar {
    ($name:literal, $dir:literal) => {
        RepoGrammar {
            name: $name,
            path: concat!($dir, "/", $name, ".abnf"),
            text: include_bytes!(concat!("../../../", $dir, "/", $name, ".abnf")),
            vectors_path: concat!($dir, "/", $name, ".vectors"),
            vectors: include_bytes!(concat!("../../../", $dir, "/", $name, ".vectors")),
        }
    };
}

/// Every grammar in `grammars/`, then `crates/abnf`'s vocabulary grammar,
/// C06's vectors for constraint enforcement. A grammar that defines a
/// rule comes before any later one that does, so [`defining`] finds the
/// owner first, and each comes after the grammars its `; uses:` names.
/// C07's grammars (`json`, `names`, `idl`, `idl-lock`) are here as
/// inputs to C06's checker, and `names` and `idl` as the references
/// `idl-names` and `idl-front-end` agree with. The generated wire
/// grammars are in [`crate::idl_repo`].
pub const GRAMMARS: &[RepoGrammar] = &[
    repo_grammar!("core", "grammars"),
    repo_grammar!("constraint", "grammars"),
    repo_grammar!("initfs", "grammars"),
    repo_grammar!("kernel-args", "grammars"),
    repo_grammar!("json", "grammars"),
    repo_grammar!("names", "grammars"),
    repo_grammar!("idl", "grammars"),
    repo_grammar!("idl-lock", "grammars"),
    repo_grammar!("vocabulary", "crates/abnf/tests/data"),
];

/// The text of a repository grammar, by name.
pub fn text(name: &str) -> Option<&'static [u8]> {
    GRAMMARS.iter().find(|g| g.name == name).map(|g| g.text)
}

/// A resolver offering the repository's grammars by name.
pub fn resolve(name: &str) -> Option<Vec<u8>> {
    text(name).map(<[u8]>::to_vec)
}

/// Loads a repository grammar as `cargo xtask grammars` does: `core` as
/// the core grammar, the rest as hand-written ones.
fn load(g: &RepoGrammar, limits: Limits) -> Grammar {
    let opts = LoadOptions {
        limits,
        kind: if g.name == "core" {
            Kind::Core
        } else {
            Kind::Auto
        },
    };
    Grammar::load(g.name, g.text, &mut resolve, &opts).unwrap_or_else(|e| panic!("{}: {e}", g.path))
}

/// The repository's grammars, loaded with [`FUZZ_LIMITS`], in the order
/// of [`GRAMMARS`].
pub static LOADED: LazyLock<Vec<(&'static str, Grammar)>> = LazyLock::new(|| {
    GRAMMARS
        .iter()
        .map(|g| (g.name, load(g, FUZZ_LIMITS)))
        .collect()
});

/// A loaded repository grammar, by name.
pub fn loaded(name: &str) -> Option<&'static Grammar> {
    LOADED.iter().find(|(n, _)| *n == name).map(|(_, g)| g)
}

/// The repository's grammars, loaded with [`ORACLE_LIMITS`] for the
/// agreement oracles.
pub static ORACLE: LazyLock<Vec<(&'static str, Grammar)>> = LazyLock::new(|| {
    GRAMMARS
        .iter()
        .map(|g| (g.name, load(g, ORACLE_LIMITS)))
        .collect()
});

/// A repository grammar loaded for the agreement oracles, by name.
pub fn oracle(name: &str) -> Option<&'static Grammar> {
    ORACLE.iter().find(|(n, _)| *n == name).map(|(_, g)| g)
}

/// The first repository grammar that defines `rule`.
pub fn defining(rule: &str) -> Option<&'static Grammar> {
    LOADED
        .iter()
        .map(|(_, g)| g)
        .find(|g| g.rule(rule).is_some())
}

/// What the matcher fixtures are for: each reaches one budget's
/// [`abnf::Exhausted`] on a short input (from `crates/abnf/tests/budgets.rs`).
pub struct Fixture {
    pub name: &'static str,
    pub text: &'static str,
    pub limits: Limits,
}

/// The matcher fixtures `abnf-match` offers beside the repository's
/// grammars. Their limits are [`SYNTHETIC_LIMITS`] with one budget cut, so
/// a short input reaches it: long seeds slow the target and keep
/// libFuzzer's length control at its maximum.
pub fn fixtures() -> Vec<Fixture> {
    vec![
        // Over the input limit: 257 octets against 256.
        Fixture {
            name: "fixture-input",
            text: "s = *OCTET\n",
            limits: Limits {
                input_octets: 256,
                ..SYNTHETIC_LIMITS
            },
        },
        // Nested calls: 100 "(" reach a depth limit of 64.
        Fixture {
            name: "fixture-depth",
            text: "a = \"(\" a \")\" / \"x\"\n",
            limits: Limits {
                depth: 64,
                ..SYNTHETIC_LIMITS
            },
        },
        // Quadratic work: each "a" starts a *OCTET that reads to the end,
        // so 200 octets take more than 10,000 steps.
        Fixture {
            name: "fixture-steps",
            text: "s = *( OCTET / OCTET *OCTET \"!\" ) \"?\"\n",
            limits: Limits {
                steps_max: 10_000,
                ..SYNTHETIC_LIMITS
            },
        },
        // Three overlapping repetitions hold many states at once; 4 KiB
        // of match state runs out on a 200-octet input.
        Fixture {
            name: "fixture-memory",
            text: "s = *OCTET *OCTET *OCTET \"!\"\n",
            limits: Limits {
                memory: 4 << 10,
                ..SYNTHETIC_LIMITS
            },
        },
        // A nullable element counted 2^32 - 1 times runs out of steps.
        Fixture {
            name: "fixture-nullable",
            text: "x = 4294967295( *\"a\" )\n",
            limits: SYNTHETIC_LIMITS,
        },
    ]
}

/// The fixtures, loaded.
pub static FIXTURES: LazyLock<Vec<(&'static str, Grammar)>> = LazyLock::new(|| {
    fixtures()
        .into_iter()
        .map(|f| {
            let opts = LoadOptions {
                limits: f.limits,
                kind: Kind::Auto,
            };
            let g = Grammar::load(f.name, f.text.as_bytes(), &mut resolve, &opts)
                .unwrap_or_else(|e| panic!("{}: {e}", f.name));
            (f.name, g)
        })
        .collect()
});

/// A grammar `abnf-match` can name: a repository grammar or a fixture.
pub fn matchable(name: &str) -> Option<&'static Grammar> {
    loaded(name).or_else(|| FIXTURES.iter().find(|(n, _)| *n == name).map(|(_, g)| g))
}

/// The names `abnf-match` frames accept, in order.
pub fn matchable_names() -> Vec<&'static str> {
    GRAMMARS
        .iter()
        .map(|g| g.name)
        .chain(fixtures().iter().map(|f| f.name))
        .collect()
}
