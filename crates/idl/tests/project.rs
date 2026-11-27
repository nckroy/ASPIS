// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Projection and the canonical form (ADR 0067, rule 7): golden forms of
//! the catalog example at 1.0 and 1.1, round trips of every file, and the
//! committed locks' hashes.

mod common;

use idl::{Limits, canon::canonical, hash::sha3_256, ids, parse::parse, project::project};

const CATALOG_1_0: &str = "edition 2026;
[id(aspis.catalog), object_id(reserved(513)), version(1.0), groups(discover, register)] interface catalog {
const max_page: u32 = 256;
enum change_kind: u8 {registered = 1, withdrawn = 2, available = 3, unavailable = 4}
struct change {@1 seq: u64, @2 kind: change_kind, @3 entry: id}
[closed] struct interface_req {@1 interface: id, @2 major: u16, @3 min_minor: u16}
union selector {@1 by_id: id, @2 by_name: string<255>, @3 by_interface: interface_req}
struct query {@1 select: selector, @2 limit: u32?}
error query_too_broad = 1 {@1 limit: u32};
[refused] error already_registered = 2;
[group(discover), idempotent, readonly] @1 list(@1 query: query, @2 page: bytes<64>?) -> (@1 at: u64, @2 entries: seq<id, max_page>, @3 next_page: bytes<64>?) error(query_too_broad);
[group(discover), readonly] @2 watch(@1 query: query, @2 after: u64?) -> (@1 at: u64) stream<change> error(query_too_broad);
[group(register)] @3 register(@1 definition: cap<aspis.kernel.memory/1.0, immutable, read>, @2 length: u32, [sensitive] @3 proof: string<8192>) -> u64 error(already_registered);
}
";

const CATALOG_1_1: &str = "edition 2026;
[id(aspis.catalog), object_id(reserved(513)), version(1.1), groups(discover, register)] interface catalog {
const max_page: u32 = 256;
enum change_kind: u8 {registered = 1, withdrawn = 2, available = 3, unavailable = 4}
struct change {@1 seq: u64, @2 kind: change_kind, @3 entry: id, [since(1.1)] @4 publisher: id?}
[closed] struct interface_req {@1 interface: id, @2 major: u16, @3 min_minor: u16}
union selector {@1 by_id: id, @2 by_name: string<255>, @3 by_interface: interface_req}
struct query {@1 select: selector, @2 limit: u32?}
error query_too_broad = 1 {@1 limit: u32};
[refused] error already_registered = 2;
[group(discover), idempotent, readonly] @1 list(@1 query: query, @2 page: bytes<64>?) -> (@1 at: u64, @2 entries: seq<id, max_page>, @3 next_page: bytes<64>?) error(query_too_broad);
[group(discover), readonly] @2 watch(@1 query: query, @2 after: u64?) -> (@1 at: u64) stream<change> error(query_too_broad);
[group(register)] @3 register(@1 definition: cap<aspis.kernel.memory/1.0, immutable, read>, @2 length: u32, [sensitive] @3 proof: string<8192>, [since(1.1)] @4 dry_run: bool?) -> u64 error(already_registered);
}
";

#[test]
fn the_catalogs_canonical_forms() {
    let c = common::check_file(&common::repo().join("interfaces/aspis/catalog/v1.idl"));
    assert_eq!(canonical(&project(c.file(), 0)), CATALOG_1_0);
    assert_eq!(canonical(&project(c.file(), 1)), CATALOG_1_1);
    // The note's own block gives the same octets: docs, comments and
    // layout aren't in the canonical form.
    assert_eq!(canonical(c.file()), CATALOG_1_1);
}

/// Every canonical form parses back, passes the checker, and gives itself
/// again.
#[test]
fn canonical_forms_round_trip() {
    for p in common::idl_files() {
        let c = common::check_file(&p);
        for m in 0..=c.unit().version.minor {
            let canon = canonical(&project(c.file(), m));
            let back = common::check(canon.as_bytes())
                .unwrap_or_else(|d| panic!("{}.{m}:\n{canon}\n{d:#?}", p.display()));
            assert_eq!(
                canonical(back.file()),
                canon,
                "{} at minor {m}",
                p.display()
            );
            // Projecting the projection again changes nothing.
            assert_eq!(canonical(&project(back.file(), m)), canon);
        }
    }
}

/// Spelling that means the same gives the same canonical form.
#[test]
fn the_canonical_form_ignores_spelling() {
    let a = "edition 2026;
// A comment.
[version(1.0), object_id(reserved(0x10)), id(org.example.t)]
interface t {
    /// Docs.
    [readonly, group(b, a)] @1 m(x: cap<aspis.kernel.memory/1, read, immutable>) -> (result: u64);
    [since(1.0), retry(never)] error e = 1 {};
}
";
    let b = "edition 2026;[id(org.example.t),object_id(reserved(16)),version(1.0)]interface t{[group(a,b),readonly]@1 m(@1 x:cap<aspis.kernel.memory/1.0,immutable,read>)->u64;error e=1;}";
    let pa = parse(a.as_bytes(), &Limits::default()).unwrap();
    let pb = parse(b.as_bytes(), &Limits::default()).unwrap();
    assert_eq!(canonical(&pa), canonical(&pb));
}

#[test]
fn projection_drops_what_is_newer() {
    let c = common::check_file(
        &common::repo().join("crates/idl/tests/data/interfaces/org/example/kinds/v1.idl"),
    );
    let at_1_0 = canonical(&project(c.file(), 0));
    // The 1.1 group, method, error, field, arm and values are gone; the
    // group that only a 1.1 method names is dropped from groups(...).
    assert!(at_1_0.contains("groups(read, write)]"));
    for gone in [
        "later_op",
        "error gone",
        "extra: u64",
        "moved: pair",
        "mid =",
        "top =",
        "deprecated(1.1)",
        "newest",
    ] {
        assert!(!at_1_0.contains(gone), "{gone} at 1.0");
    }
    assert!(at_1_0.contains("error(not_found);"));
    let at_1_1 = canonical(&project(c.file(), 1));
    assert!(at_1_1.contains("[deprecated(1.1)] alias label") && !at_1_1.contains("newest"));
    assert!(at_1_1.contains("error(not_found, gone)"));
}

/// SHA3-256 against FIPS 202's example digests, and the interim reserved
/// IDs.
#[test]
fn the_hash_and_the_reserved_ids() {
    let hex = |d: [u8; 32]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hex(sha3_256(b"")),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
    assert_eq!(
        hex(sha3_256(b"abc")),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    );
    let id = ids::reserved(0x0201);
    assert_eq!(&id[..16], &[0u8; 16]);
    assert_eq!(&id[16..24], &0x0201u64.to_be_bytes());
    assert_eq!(id[24], 1);
    assert_eq!(&id[25..], &[0u8; 7]);
}

/// Every committed lock holds the hashes of its file's published minors,
/// and allows the file's version (p or p + 1).
#[test]
fn the_hashes_equal_the_committed_locks() {
    for p in common::idl_files() {
        let c = common::check_file(&p);
        let major = c.unit().major();
        let text = std::fs::read(format!("{}.lock", p.display())).unwrap();
        let lock = idl::lock::parse(&text, major).unwrap();
        assert!(lock.allows(c.unit().version.minor), "{}", p.display());
        for (m, h) in lock.hashes.iter().enumerate() {
            assert_eq!(
                &idl::generate::minor_hash(&c, m as u16),
                h,
                "{} {major}.{m}",
                p.display()
            );
        }
        // The lock re-renders to its own octets.
        let spdx = idl::generate::spdx_lines(&std::fs::read(&p).unwrap());
        assert_eq!(
            idl::lock::render(&spdx, &c.unit().name, major, &lock).as_bytes(),
            text
        );
    }
}

/// The lock reader refuses what `grammars/idl-lock.abnf` refuses, and what
/// it leaves to idlc: minors out of order, another major.
#[test]
fn locks_are_read_strictly() {
    let h = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    let ok = format!("# x\n1.0 sha3-256 {h}\n1.1 sha3-256 {h}\n");
    assert_eq!(
        idl::lock::parse(ok.as_bytes(), 1).unwrap().published(),
        Some(1)
    );
    assert_eq!(idl::lock::parse(b"", 1).unwrap().published(), None);
    for bad in [
        format!("1.1 sha3-256 {h}\n"),
        format!("1.0 sha3-256 {h}\n1.0 sha3-256 {h}\n"),
        format!("2.0 sha3-256 {h}\n"),
        format!("1.0 sha3-256 {h}"),
        format!("1.0 sha3-256 {}\n", h.to_uppercase()),
        format!("1.0 sha3-256 {h}\n# late\n"),
        format!("1.0  sha3-256 {h}\n"),
        // CRLF line ends, on an entry and on a comment.
        format!("1.0 sha3-256 {h}\r\n"),
        format!("# x\r\n1.0 sha3-256 {h}\n"),
        // An empty line, and DEL in a comment.
        format!("\n1.0 sha3-256 {h}\n"),
        "# \u{7f}\n".to_string(),
    ] {
        assert!(idl::lock::parse(bad.as_bytes(), 1).is_err(), "{bad}");
    }
    // A C1 control is a character `lock-char` admits, through utf8-2.
    assert!(idl::lock::parse("# \u{85}\n".as_bytes(), 1).is_ok());
    let l = idl::lock::parse(ok.as_bytes(), 1).unwrap();
    assert!(l.allows(1) && l.allows(2) && !l.allows(0) && !l.allows(3));
}

/// `[nonzero]` takes its place in the attribute table's order, after
/// `sensitive`, in the canonical form, and parses back.
#[test]
fn nonzero_in_the_canonical_form() {
    let src = "edition 2026;\n[id(org.example.t), object_id(reserved(1)), version(1.1)]\ninterface t {\n\
               struct s { [nonzero, sensitive, since(1.1)] a: u32? }\n}\n";
    let f = parse(src.as_bytes(), &Limits::default()).unwrap();
    let c = canonical(&f);
    assert!(
        c.contains("struct s {[since(1.1), sensitive, nonzero] @1 a: u32?}"),
        "{c}"
    );
    let back = parse(c.as_bytes(), &Limits::default()).unwrap();
    assert_eq!(canonical(&back), c);
}

/// The lock reader refuses more than 1,024 entries: a major has at most
/// 1,024 minors, 0 to 1,023 (`idl::MAX_MINOR`).
#[test]
fn a_lock_has_at_most_1024_entries() {
    let h = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    let lock = |n: u32| {
        let mut s = String::from("# x\n");
        for m in 0..n {
            s += &format!("1.{m} sha3-256 {h}\n");
        }
        s
    };
    let l = idl::lock::parse(lock(1024).as_bytes(), 1).unwrap();
    assert_eq!(l.published(), Some(1023));
    let e = idl::lock::parse(lock(1025).as_bytes(), 1).unwrap_err();
    assert_eq!(e.0, 1026, "{e:?}");
    assert!(e.1.contains("1024"), "{e:?}");
}

/// A canonical form that reuses the minor before's member lines is the
/// canonical form, at every minor of every file, and of a file whose
/// members change from one minor to the next.
#[test]
fn reused_lines_give_the_canonical_form() {
    let mut sources: Vec<Vec<u8>> = common::idl_files()
        .iter()
        .map(|p| std::fs::read(p).unwrap())
        .collect();
    sources.push(
        b"edition 2026;\n[id(org.example.t), object_id(reserved(1)), version(1.3)]\ninterface t {\n\
          enum e: u8 { a = 1, [since(1.1)] b = 2, [since(1.3)] c = 3 }\n\
          [since(1.2)] struct s { a: u8, [since(1.3)] b: u8? }\n\
          struct u { a: u8, [deprecated(1.2)] b: u8? }\n\
          @1 m(a: u8);\n}\n"
            .to_vec(),
    );
    for src in sources {
        let c = common::check(&src).unwrap();
        let mut last: Option<(idl::ast::File, Vec<String>)> = None;
        for m in 0..=c.unit().version.minor {
            let p = project(c.file(), m);
            let (text, lines) =
                idl::canon::canonical_reusing(&p, last.as_ref().map(|(f, l)| (f, l.as_slice())));
            assert_eq!(text, canonical(&p), "minor {m}");
            last = Some((p, lines));
        }
    }
}
