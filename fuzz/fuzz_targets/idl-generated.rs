// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The `idl-generated` target: its entry, limits and seeds are `fuzz_gate::IDL_GENERATED`.

#![no_main]

#[global_allocator]
static ALLOC: fuzz_alloc::Bounded =
    fuzz_alloc::Bounded::mib(fuzz_gate::IDL_GENERATED.malloc_limit_mb);

libfuzzer_sys::fuzz_target!(|data: &[u8]| fuzz_gate::idl_targets::generated(data));
