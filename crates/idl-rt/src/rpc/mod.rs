// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! `aspis.rpc`: the system errors, the error key and the extension kinds
//! (ADR 0065, rule 6; docs/design/call-language.md, "The system errors").
//!
//! `v1.rs` is generated from `interfaces/aspis/rpc/v1.idl` by `idlc rust
//! --runtime`, and committed, so this crate needs no build script. `cargo
//! xtask idl` checks it is current, and `cargo xtask idl --write`
//! regenerates it. It is included, not a module file, so rustfmt leaves
//! the generator's layout alone.

include!("v1.rs");
