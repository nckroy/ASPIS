// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The runtime of IDL-generated ASPIS bindings (ADR 0067, rule 10).
//!
//! It holds what generated code shares, and what the PDP, the token
//! library and the catalog parse. It is `no_std`, forbids `unsafe`, and
//! has no dependencies, because it decodes input from across a trust
//! boundary (ADR 0068, rule 2). The design is
//! docs/design/call-language.md ("Back ends", "Crates").
//!
//! - [`wire`]: the core codecs, open-struct tails, and the decoding and
//!   encoding contexts; [`view`]: borrowed views and unknown carriers;
//!   [`cap`]: capability indexes and how they are sent.
//! - [`error`] and [`envelope`]: outcomes, dispositions, error keys and
//!   the error envelope's codec (ADR 0065).
//! - [`meta`]: interface metadata; [`rules`]: a generated module's codecs
//!   by grammar rule name, for vector tests and conformance;
//!   [`conformance`]: the subject the conformance runner drives.
//! - [`fuzz`]: entry functions for fuzz targets: the name parsers, and any
//!   generated module's decoders (ADR 0068).
//! - [`json`] and [`text`]: the JSON mapping and the canonical call text
//!   (ADR 0063, rule 9; ADR 0067, rule 8); [`names`]: interface, action
//!   and error references (ADR 0063, rule 10).
//! - With the default `rpc` feature: [`rpc`], `aspis.rpc` 1's generated
//!   binding (the system errors), [`channel`], the seams that stubs and
//!   dispatchers use, and `CallError`. The IDL compiler, which generates
//!   [`rpc`], builds this crate without the feature, so a stale binding
//!   never stops it from regenerating one (`cargo xtask idl --write`).

#![no_std]
#![forbid(unsafe_code)]

pub mod cap;
#[cfg(feature = "rpc")]
pub mod channel;
pub mod conformance;
pub mod envelope;
pub mod error;
pub mod fuzz;
pub mod json;
pub mod meta;
pub mod names;
#[cfg(feature = "rpc")]
pub mod rpc;
pub mod rules;
pub mod text;
pub mod view;
pub mod wire;
