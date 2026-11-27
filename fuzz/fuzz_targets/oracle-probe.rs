// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Not a gate target: `cargo xtask fuzz build` runs it to show that the
//! fuzz build's overflow checks and memory bound fire (ADR 0068, rule 2).

#![no_main]

#[global_allocator]
static ALLOC: fuzz_alloc::Bounded = fuzz_alloc::Bounded::mib(64);

libfuzzer_sys::fuzz_target!(|data: &[u8]| fuzz_gate::oracle_probe(data));
