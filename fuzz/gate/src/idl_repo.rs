// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The repository's IDL interfaces, embedded, with each minor's wire
//! grammar and vectors, for the `idl-` targets (docs/design/call-language.md,
//! "The harness"; ADR 0068, rules 3 and 4).
//!
//! Both interface roots are here: `interfaces/`, and the compiler's
//! fixtures in `crates/idl/tests/data/interfaces/`, whose generated
//! modules are `idl-fixtures`'. They are embedded with `include_bytes!`,
//! as [`crate::repo`] embeds the grammars, so the seeds made from the
//! vectors can't drift from them and nothing reads files while fuzzing.
//! `tests/targets.rs` checks that this list is every tracked IDL file,
//! wire grammar and wire vector file. Text grammars, text vectors and
//! locks aren't embedded: they are C18's and C52's inputs, not the
//! decoders'.

use std::sync::LazyLock;

use abnf::{Grammar, Kind, LoadOptions};
use idl::{Checked, Limits};
use idl_rt::{names::InterfaceRef, rules::Module};

use crate::{WIRE_LIMITS, repo};

/// One minor's generated wire grammar and its vectors.
pub struct WireMinor {
    pub abnf_path: &'static str,
    pub abnf: &'static [u8],
    pub vectors_path: &'static str,
    pub vectors: &'static [u8],
}

/// One interface major's IDL file, and the wire files of each of its
/// minors, from 0. A `[kernel]` interface has no wire files (ADR 0013,
/// rule 3).
pub struct RepoInterface {
    /// Its name, such as `aspis.catalog`.
    pub name: &'static str,
    pub major: u16,
    /// The IDL file's path in the repository.
    pub path: &'static str,
    pub idl: &'static [u8],
    pub wire: &'static [WireMinor],
}

macro_rules! wire_minor {
    ($dir:literal, $major:literal, $minor:literal) => {
        WireMinor {
            abnf_path: concat!($dir, "/v", $major, ".", $minor, ".abnf"),
            abnf: include_bytes!(concat!(
                "../../../",
                $dir,
                "/v",
                $major,
                ".",
                $minor,
                ".abnf"
            )),
            vectors_path: concat!($dir, "/v", $major, ".", $minor, ".vectors"),
            vectors: include_bytes!(concat!(
                "../../../",
                $dir,
                "/v",
                $major,
                ".",
                $minor,
                ".vectors"
            )),
        }
    };
}

macro_rules! repo_interface {
    ($name:literal, $dir:literal, $major:literal, [$($minor:literal),*]) => {
        RepoInterface {
            name: $name,
            major: $major,
            path: concat!($dir, "/v", $major, ".idl"),
            idl: include_bytes!(concat!("../../../", $dir, "/v", $major, ".idl")),
            wire: &[$(wire_minor!($dir, $major, $minor)),*],
        }
    };
}

/// Every interface major in the two roots, each with its wire minors.
pub const INTERFACES: &[RepoInterface] = &[
    repo_interface!("aspis.catalog", "interfaces/aspis/catalog", 1, [0, 1]),
    // A `[kernel]` interface: no wire grammar.
    repo_interface!(
        "aspis.kernel.eventcount",
        "interfaces/aspis/kernel/eventcount",
        1,
        []
    ),
    // The bootstrap protocol; its binding is committed in idl-rt.
    repo_interface!("aspis.rpc", "interfaces/aspis/rpc", 1, [0]),
    repo_interface!(
        "aspis.kernel.pager",
        "crates/idl/tests/data/interfaces/aspis/kernel/pager",
        1,
        [0]
    ),
    repo_interface!(
        "org.example.base",
        "crates/idl/tests/data/interfaces/org/example/base",
        1,
        [0, 1]
    ),
    repo_interface!(
        "org.example.kinds",
        "crates/idl/tests/data/interfaces/org/example/kinds",
        1,
        [0, 1, 2]
    ),
];

/// Serves the embedded IDL files to `idl::check` by name and major, from
/// both roots, as `crates/interfaces/tests/common`'s `check` does from
/// the files, so a `use` line that names a real interface checks fully.
pub fn resolve(r: &InterfaceRef<'_>) -> Option<Vec<u8>> {
    INTERFACES
        .iter()
        .find(|i| i.name == r.name && i.major == r.major)
        .map(|i| i.idl.to_vec())
}

/// An embedded interface, checked, with its wire grammars loaded.
pub struct Interface {
    pub repo: &'static RepoInterface,
    pub checked: Checked,
    /// Each minor's wire grammar, loaded as the catalog loads a
    /// publisher's (strict, `; uses:` names from `grammars/`), with
    /// [`WIRE_LIMITS`]: 8 M steps a match.
    pub wire: Vec<Grammar>,
}

impl Interface {
    /// The wire grammar of a minor: None for a `[kernel]` interface.
    pub fn wire_grammar(&self, minor: u16) -> Option<&Grammar> {
        self.wire.get(usize::from(minor))
    }

    /// The newest minor the file declares.
    pub fn version(&self) -> u16 {
        self.checked.unit().version.minor
    }
}

/// Loads one minor's wire grammar.
fn load_wire(w: &WireMinor) -> Grammar {
    let opts = LoadOptions {
        limits: WIRE_LIMITS,
        kind: Kind::Strict,
    };
    Grammar::load(w.abnf_path, w.abnf, &mut repo::resolve, &opts)
        .unwrap_or_else(|e| panic!("{}: {e}", w.abnf_path))
}

/// Every embedded interface, checked with the default limits, in the
/// order of [`INTERFACES`]. They are the repository's own files, which
/// `cargo xtask idl` checks, so a failure here is a broken checkout.
pub static LOADED: LazyLock<Vec<Interface>> = LazyLock::new(|| {
    INTERFACES
        .iter()
        .map(|i| {
            let checked = idl::check(i.idl, &mut resolve, &Limits::default())
                .unwrap_or_else(|d| panic!("{}: {d:?}", i.path));
            Interface {
                repo: i,
                checked,
                wire: i.wire.iter().map(load_wire).collect(),
            }
        })
        .collect()
});

/// An embedded interface, by name and major.
pub fn interface(name: &str, major: u16) -> Option<&'static Interface> {
    LOADED
        .iter()
        .find(|i| i.repo.name == name && i.repo.major == major)
}

/// Every generated module: `aspis-interfaces`' (aspis.rpc's is idl-rt's
/// committed binding) and `idl-fixtures'`, which include the fixtures'
/// bindings of earlier minors.
pub static MODULES: LazyLock<Vec<&'static Module>> = LazyLock::new(|| {
    aspis_interfaces::MODULES
        .iter()
        .chain(idl_fixtures::MODULES)
        .copied()
        .collect()
});

/// The module an interface reference names: its name, its major and the
/// module's own minor, a missing minor meaning `.0`.
pub fn module(r: &InterfaceRef<'_>) -> Option<&'static Module> {
    MODULES
        .iter()
        .copied()
        .find(|m| m.name == r.name && m.major == r.major && m.minor == r.minor_or_zero())
}

/// The newest module of an interface major.
pub fn newest(name: &str, major: u16) -> Option<&'static Module> {
    MODULES
        .iter()
        .copied()
        .filter(|m| m.name == name && m.major == major)
        .max_by_key(|m| m.minor)
}

/// The interface a module is a binding of. `tests/targets.rs` checks that
/// every module has one.
pub fn interface_of(m: &Module) -> Option<&'static Interface> {
    interface(m.name, m.major)
}

/// The frame that names a module in the `idl-decode` and `idl-generated`
/// inputs: its interface reference, with its own minor, and LF.
pub fn frame(m: &Module) -> String {
    format!("{}/{}.{}\n", m.name, m.major, m.minor)
}
