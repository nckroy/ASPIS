// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The lock's hash: SHA3-256 of a canonical form (ADR 0067, rule 7), the
//! authorization tree's hash function (ADR 0016). The `sha3` crate is
//! RustCrypto's, pending D33's choice of crypto crates.

use sha3::{Digest, Sha3_256};

/// SHA3-256 of `data`.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    Sha3_256::digest(data).into()
}
