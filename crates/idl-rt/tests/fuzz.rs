// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Replays of idl-rt's name-parser fuzz entry, `idl_rt::fuzz::names`
//! (ADR 0068, rule 4: "seeds include every vector line"): every line of
//! `grammars/names.vectors`, and mutations of each, under plain `cargo
//! test`, with no fuzz engine. The generated decoders' entry,
//! `idl_rt::fuzz::decode`, is replayed by crates/interfaces'
//! `fuzz_entry` test, which has generated modules to give it.

use std::{fs, path::Path};

use abnf::vectors;
use idl_rt::fuzz;

/// A small deterministic generator (SplitMix64), so a failure replays.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

#[test]
fn the_name_parsers_over_every_vector_and_mutations() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../grammars/names.vectors");
    let file = vectors::parse(&fs::read(path).unwrap()).unwrap();
    let mut rng = Rng(1);
    let mut runs = 0;
    // The octets the grammar is made of, for insertions.
    let alphabet = b"az09_./@!#-*";
    for v in &file.vectors {
        fuzz::names(&v.octets);
        for _ in 0..32 {
            let mut m = v.octets.clone();
            let at = rng.below(m.len());
            match rng.below(4) {
                0 if !m.is_empty() => {
                    m.remove(at);
                }
                1 => m.insert(at, alphabet[rng.below(alphabet.len())]),
                2 if !m.is_empty() => m[at] = rng.next() as u8,
                _ => m.truncate(at),
            }
            fuzz::names(&m);
            runs += 1;
        }
    }
    // Long input: the parsers bound names, and refuse rather than panic.
    fuzz::names(&[b'a'; 4096]);
    fuzz::names(&[b'.'; 4096]);
    assert!(runs > 1000, "{runs}");
}
