// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The generated Rust bindings of the IDL compiler's test fixtures
//! (`crates/idl/tests/data/interfaces/`), for tests only: crates/
//! interfaces' tests use them, since an integration test can't see a
//! crate's `cfg(test)` items. Each fixture has a module at its version,
//! and one per earlier minor (`org::example::kinds::v1_0`).

#![no_std]
#![forbid(unsafe_code)]

include!(concat!(env!("OUT_DIR"), "/fixtures.rs"));
