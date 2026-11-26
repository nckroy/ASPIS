// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Replays of the generated decoders' fuzz entries (ADR 0068, rule 4;
//! docs/design/call-language.md, "Per change"), under plain `cargo test`
//! with no fuzz engine:
//!
//! - each generated module's `fuzz::decode`, over every committed wire
//!   vector of every minor it reads, and mutations of each;
//! - `idl::conformance::differential`, the decoder against the generated
//!   grammar and the dynamic codec, over values from `idl::fuzz::generate`
//!   and mutations of their encodings, for every module and minor.

mod common;

use abnf::vectors::Tag;
use idl::{conformance, fuzz, schema::Schema, value};
use idl_rt::rules::Module;

/// The input `fuzz::decode` takes for a rule, a minor and a message.
fn input(m: &Module, rule: &str, minor: u16, caps: u8, octets: &[u8]) -> Vec<u8> {
    let r = m.rules.iter().position(|x| *x == rule).unwrap();
    let mut d = vec![r as u8, minor as u8, caps];
    d.extend_from_slice(octets);
    d
}

#[test]
fn generated_entries_by_name() {
    // The entries C71's targets call, by path.
    aspis_interfaces::aspis::catalog::v1::fuzz::decode(&[0, 0, 0, 0]);
    aspis_interfaces::aspis::kernel::eventcount::v1::fuzz::decode(&[1, 0, 0]);
    aspis_interfaces::aspis::rpc::v1::fuzz::decode(&[2, 0, 0, 0, 0]);
    idl_fixtures::org::example::kinds::v1::fuzz::decode(&[3, 2, 1, 0xFF]);
    idl_fixtures::org::example::kinds::v1_0::fuzz::decode(&[]);
    for m in common::modules() {
        assert!(!m.rules.is_empty(), "{}", m.name);
        // Fewer than 256 rules, so the first octet reaches each.
        assert!(m.rules.len() < 256, "{}", m.name);
    }
}

#[test]
fn decode_entries_over_every_vector_and_mutations() {
    let modules = common::modules();
    let mut runs = 0;
    for (name, path) in common::all_idl_files() {
        let c = common::check(&path);
        let (major, v) = (c.unit().major(), c.unit().version.minor);
        for m in 0..=v {
            let Some(file) = common::vectors(&path.with_file_name(format!("v{major}.{m}.vectors")))
            else {
                continue;
            };
            for module in modules
                .iter()
                .filter(|x| x.name == name && x.major == major && x.minor >= m)
            {
                let mut rng = common::Rng(u64::from(m) << 8 | u64::from(module.minor));
                for x in &file.vectors {
                    let d = input(module, &x.rule, m, x.caps, &x.octets);
                    idl_rt::fuzz::decode(module, &d);
                    runs += 1;
                    if x.tag != Tag::Ok {
                        continue;
                    }
                    for k in 0..4 {
                        let mut d = d.clone();
                        let at = 3 + (rng.next() as usize) % (d.len() - 2);
                        match k {
                            0 if at < d.len() => d[at] ^= 1 << (rng.next() % 8),
                            1 => d.truncate(at),
                            2 => d.insert(at, rng.next() as u8),
                            // Another rule, minor and count, same octets.
                            _ => {
                                d[0] = rng.next() as u8;
                                d[1] = rng.next() as u8;
                                d[2] = rng.next() as u8;
                            }
                        }
                        idl_rt::fuzz::decode(module, &d);
                        runs += 1;
                    }
                }
            }
        }
    }
    eprintln!("{runs} fuzz::decode runs");
    assert!(runs > 10_000, "{runs}");
}

#[test]
fn the_differential_over_generated_values() {
    let modules = common::modules();
    let mut runs = 0;
    for (name, path) in common::all_idl_files() {
        let c = common::check(&path);
        let (major, v) = (c.unit().major(), c.unit().version.minor);
        for m in 0..=v {
            let g = common::grammar(&path.with_file_name(format!("v{major}.{m}.abnf")));
            let s = Schema::new(&c, m);
            let mut rng = common::Rng(u64::from(m) << 16 | name.len() as u64);
            for module in modules
                .iter()
                .filter(|x| x.name == name && x.major == major && x.minor >= m)
            {
                for top in s.tops() {
                    let rule = s.top_rule(top);
                    for k in 0..12 {
                        let data: Vec<u8> = (0..k * 16).map(|_| rng.next() as u8).collect();
                        let val = fuzz::generate(&s, top, &data).expect("within the budget");
                        let enc = value::encode(&s, top, &val, true);
                        conformance::differential(
                            *module,
                            &s,
                            g.as_ref(),
                            &rule,
                            enc.caps,
                            &enc.octets,
                        );
                        for mutated in conformance::mutations(&enc.octets, rng.next(), 4) {
                            conformance::differential(
                                *module,
                                &s,
                                g.as_ref(),
                                &rule,
                                enc.caps,
                                &mutated,
                            );
                        }
                        runs += 1;
                    }
                }
            }
        }
    }
    eprintln!("{runs} generated values through the differential");
    assert!(runs > 2000, "{runs}");
}
