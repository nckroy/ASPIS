// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The Rust bindings of ASPIS's interfaces (ADR 0067, rule 10;
//! docs/design/call-language.md, "Back ends").
//!
//! `build.rs` generates one module per interface major under
//! `interfaces/`, nested by name: `aspis_interfaces::aspis::catalog::v1`.
//! `aspis::rpc` is idl-rt's binding of the system errors. The crate is
//! `no_std` and forbids `unsafe`, because its decoders read input from
//! across a trust boundary (ADR 0068, rule 2). The `alloc` feature adds
//! owned values (`idl_rt::view::IntoOwned`).
//!
//! Which interfaces are here: `aspis.catalog` and
//! `aspis.kernel.eventcount` are the design note's examples, which C51
//! and C17 replace.

#![no_std]
#![forbid(unsafe_code)]

include!(concat!(env!("OUT_DIR"), "/interfaces.rs"));
