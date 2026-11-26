// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Typed errors (ADR 0065; docs/design/call-language.md, "The error
//! envelope", "Outcomes", "Errors in bindings and text").
//!
//! An error names its interface by ID, with the major and a code: the
//! [`ErrorKey`]. Its envelope carries an [`Outcome`] and a
//! [`Disposition`]. A call returns a [`CallError`] (under the `rpc`
//! feature, which brings `aspis.rpc`'s generated binding): the interface's
//! own error, a system error, or a foreign one, with the envelope's octets
//! kept for re-encoding.

use crate::{
    view::Unknown,
    wire::{EncodeCx, EncodeError, Writer},
};

/// What happened to a call ("The error envelope", position 1). Closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Outcome {
    /// Delivered, and the server guarantees the method didn't run.
    Refused = 1,
    /// The server ran it, or may have, and answers with an error.
    Failed = 2,
    /// Never delivered.
    Unreachable = 3,
    /// May have run, and no answer came.
    Indeterminate = 4,
}

impl Outcome {
    pub fn from_u8(v: u8) -> Option<Outcome> {
        Some(match v {
            1 => Outcome::Refused,
            2 => Outcome::Failed,
            3 => Outcome::Unreachable,
            4 => Outcome::Indeterminate,
            _ => return None,
        })
    }

    /// The word the call text uses (`outcome-word`).
    pub fn word(self) -> &'static str {
        match self {
            Outcome::Refused => "refused",
            Outcome::Failed => "failed",
            Outcome::Unreachable => "unreachable",
            Outcome::Indeterminate => "indeterminate",
        }
    }
}

/// Whether and how to retry ("The error envelope", position 2). Open: a
/// client treats an unknown value as [`Disposition::NONE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Disposition(pub u8);

impl Disposition {
    /// Don't retry unchanged.
    pub const NONE: Disposition = Disposition(0);
    /// Retry later with the same request ID.
    pub const LATER: Disposition = Disposition(1);
    /// Bind again, then retry.
    pub const REBIND: Disposition = Disposition(2);
    /// Retry at a higher level: re-read state, then decide.
    pub const HIGHER: Disposition = Disposition(3);
}

/// An error's key: its interface's ID, the major and the code (36
/// octets, the closed struct `aspis.rpc/1.error_key`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ErrorKey {
    pub interface: [u8; 32],
    pub major: u16,
    pub code: u16,
}

/// A generated interface's own errors, as a dispatcher sends them.
pub trait AppError {
    fn key(&self) -> ErrorKey;
    /// Refused when the IDL declares the error `[refused]`; failed
    /// otherwise.
    fn outcome(&self) -> Outcome;
    /// From the IDL's `retry(...)`.
    fn disposition(&self) -> Disposition;
    /// The detail struct.
    fn encode_detail(&self, w: &mut Writer<'_>, cx: &EncodeCx) -> Result<(), EncodeError>;
}

/// An error envelope, decoded but kept whole: what a binding exposes for
/// an error key it doesn't know, and re-encodes unchanged when it forwards
/// the error as a cause ("The error envelope").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawError<'a> {
    /// The whole envelope's octets.
    pub octets: &'a [u8],
    pub outcome: Outcome,
    pub disposition: Disposition,
    pub key: ErrorKey,
    /// The detail struct's octets.
    pub detail: &'a [u8],
    /// The cause: another envelope's octets.
    pub cause: Option<&'a [u8]>,
    /// When to try again, in nanoseconds.
    pub retry_after: Option<u64>,
    /// Tail fields a later minor of `aspis.rpc` adds.
    pub unknown: Unknown<'a>,
}

#[cfg(feature = "rpc")]
pub use self::rpc::*;

#[cfg(feature = "rpc")]
mod rpc {
    use super::*;

    /// `aspis.rpc` 1's errors: the system errors.
    pub type RpcError<'a> = crate::rpc::v1::errors::Error<'a>;

    /// What a call's error is.
    #[derive(Debug, Clone, PartialEq)]
    pub enum ErrorKind<'a, E> {
        /// The interface's own error.
        App(E),
        /// A system error.
        Rpc(RpcError<'a>),
        /// An error of another interface, such as a cause a server didn't
        /// wrap, or one whose detail doesn't decode.
        Foreign(RawError<'a>),
    }

    /// A call's error (docs/design/call-language.md, "Errors in bindings
    /// and text").
    #[derive(Debug, Clone, PartialEq)]
    pub struct CallError<'a, E> {
        pub outcome: Outcome,
        pub disposition: Disposition,
        pub kind: ErrorKind<'a, E>,
        /// The envelope as it came, or None for an error the caller's own
        /// runtime made: a stub's refusal, or a channel's kernel result.
        pub raw: Option<RawError<'a>>,
    }

    impl<'a, E> CallError<'a, E> {
        /// A system error made on the caller's side, with nothing on the
        /// wire.
        pub fn local(outcome: Outcome, error: RpcError<'a>) -> Self {
            CallError {
                outcome,
                disposition: error.disposition(),
                kind: ErrorKind::Rpc(error),
                raw: None,
            }
        }

        /// The system error, if it is one.
        pub fn rpc(&self) -> Option<&RpcError<'a>> {
            match &self.kind {
                ErrorKind::Rpc(e) => Some(e),
                _ => None,
            }
        }

        /// The interface's own error, if it is one.
        pub fn app(&self) -> Option<&E> {
            match &self.kind {
                ErrorKind::App(e) => Some(e),
                _ => None,
            }
        }
    }

    /// A system error a channel or a capability operation made: a kernel
    /// result turned into `aspis.rpc` terms ("Kernel results").
    #[derive(Debug, Clone, PartialEq)]
    pub struct LocalError {
        pub outcome: Outcome,
        pub error: RpcError<'static>,
    }
}
