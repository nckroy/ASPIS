// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The lock's hash: SHA3-256 of a canonical form (ADR 0067, rule 7), the
//! authorization tree's hash function (ADR 0016). It comes from
//! `aspis-crypto`, ASPIS's one crypto wrapper (ADR 0069, rule 2).

/// SHA3-256 of `data`.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    aspis_crypto::hash::sha3_256(data)
}
