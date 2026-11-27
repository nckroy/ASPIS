// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The `idl-front-end` target: its entry, limits and seeds are `fuzz_gate::IDL_FRONT_END`.

#![no_main]

#[global_allocator]
static ALLOC: fuzz_alloc::Bounded =
    fuzz_alloc::Bounded::mib(fuzz_gate::IDL_FRONT_END.malloc_limit_mb);

libfuzzer_sys::fuzz_target!(|data: &[u8]| fuzz_gate::idl_targets::front_end(data));
