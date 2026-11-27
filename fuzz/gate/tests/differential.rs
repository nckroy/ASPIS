// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The committed ABNF differential cases, `fuzz/differential/<name>.abnf`
//! and `.vectors`: each was a disagreement between the two checkers once,
//! and is committed with the tags RFC 5234 gives. crates/abnf must agree
//! with every one (`cargo xtask fuzz differential` holds the Python
//! checker to them too). It passes when there are none.

mod common;

use abnf::{Kind, vectors};
use fuzz_gate::abnf_targets::load_generated;

#[test]
fn every_committed_case_agrees_with_crates_abnf() {
    let files = common::tracked(&["fuzz/differential"]);
    let mut checked = 0;
    for f in &files {
        let Some(stem) = f.strip_suffix(".vectors") else {
            assert!(f.ends_with(".abnf"), "{f}: only .abnf and .vectors files");
            assert!(
                files.contains(&format!("{}.vectors", f.strip_suffix(".abnf").unwrap())),
                "{f} has no vectors"
            );
            continue;
        };
        let grammar = std::fs::read(common::root().join(format!("{stem}.abnf")))
            .unwrap_or_else(|e| panic!("{stem}.abnf: {e}"));
        let text = std::fs::read(common::root().join(f)).unwrap();
        let g = load_generated(&grammar, Kind::Auto).unwrap_or_else(|e| panic!("{stem}.abnf: {e}"));
        let v = vectors::parse(&text).unwrap_or_else(|e| panic!("{f}: {e}"));
        let r = vectors::check(&g, &v);
        assert_eq!((r.disagree, r.unjudged), (0, 0), "{f}: {:?}", r.results);
        checked += 1;
    }
    eprintln!("{checked} committed differential cases agree");
}
