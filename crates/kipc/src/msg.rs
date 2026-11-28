// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Messages: the registers, the info word, the IPC buffer's layout and the
//! receive slots (kernel specification K28); the results and the kernel's
//! internal error names (K30); and the provisional fault message (kernel
//! specification, "Fault delivery").
//!
//! **The layout is seL4's AArch64 layout, with lengths in octets** (ADR
//! 0054, rule 3; ADR 0064, rule 2). A message is one octet string of up to
//! 960 octets. Its first four words travel in registers x2 to x5, each the
//! big-endian reading of its octets; the rest, words 4 to 119, in the
//! sender's and receiver's IPC buffers, which the kernel copies a word at a
//! time without reading or swapping them (ADR 0054, rule 4). The buffer's
//! message area also covers the four register words, so a decoder sees one
//! contiguous octet string: the library mirrors them there, and the kernel
//! never reads or writes those 32 octets.
//!
//! **Registers in:** x0 the capability the operation is on: the endpoint,
//! eventcount, wait set or thread (for cancel badged sends, the badged
//! endpoint capability); x7 the deadline, 0 for none, for every operation
//! that waits. The endpoint operations take x1 the info word, x2 to x5
//! words 0 to 3, and x6 the reply object, for every operation that takes
//! one (receive, reply, and reply and receive). The other operations take
//! their arguments in x1 to x3: an eventcount wait its target in x1; a
//! wait-set add the entry's index, the eventcount and the target in x1 to
//! x3, and a remove the index in x1; binding a thread's eventcount the
//! eventcount in x1; registering an IPC buffer the frame in x1 and the
//! address in x2, 0 to unregister. The test build passes the call number in
//! x8 ([`regs::TEST_CALL`]); C17 chooses its own call-number register as
//! part of the private ABI.
//!
//! **Registers out:** x0 the status ([`Status`]), with [`DELIVERED`] set
//! when a call that ended canceled, timed out or "object destroyed" had been
//! delivered. The endpoint operations return x1 the info word; x2 to x5
//! words 0 to 3, zero past the length; x6 the sender's badge, 0 for a
//! reply, or for a bound eventcount's advance, the count. An eventcount's
//! advance, read and wait return the count in x1, and a wait set's wait its
//! mask, only when the status is ok: a call refused, or a wait that ends
//! canceled, timed out or destroyed, leaves x1 as the caller passed it.
//!
//! **Reading the buffer.** Each word the kernel interprets (the capability
//! addresses to send, the receive-slot triples) is read once into kernel
//! memory before any check, since other threads of the address space may
//! write the page at the same time. The functions here take those copies,
//! never the page, and check each as a `u64` before narrowing it.
//!
//! The call numbers, the status numbers and the IDL's typed errors are
//! C17's: the numbers here are the test build's until C17 adopts or
//! renumbers them, and the names are the kernel's internal ones (K30).

use crate::{MAX_CAPS, MAX_LEN};
use ksched::donation::Res;

/// The octets in a word.
pub const WORD: u64 = 8;
/// The words that travel in registers.
pub const REG_WORDS: u64 = 4;
/// The octets that travel in registers.
pub const REG_OCTETS: u64 = REG_WORDS * WORD;
/// The most words in a message.
pub const MAX_WORDS: u64 = MAX_LEN / WORD;

/// The registers of an IPC operation (module docs), as indexes into the
/// saved x registers.
pub mod regs {
    /// In: the capability the operation is on. Out: the status.
    pub const CAP: usize = 0;
    pub const STATUS: usize = 0;
    /// The info word of an endpoint operation, in and out; for the other
    /// operations, their first argument in, and a count or mask out.
    pub const INFO: usize = 1;
    /// Words 0 to 3 of the message.
    pub const MSG: [usize; 4] = [2, 3, 4, 5];
    /// In: the reply object. Out: the badge, or a bound eventcount's count.
    pub const REPLY: usize = 6;
    pub const BADGE: usize = 6;
    /// In: the deadline, a value of the virtual count, 0 for none.
    pub const DEADLINE: usize = 7;
    /// In, in the test build only: the call number (C17 chooses its own).
    pub const TEST_CALL: usize = 8;
}

/// The info word (module docs).
///
/// | Bits | Field |
/// |---|---|
/// | 0-9 | The length in octets, 0 to 960 |
/// | 10-11 | The number of capabilities, 0 to 3; on receive, how many were transferred |
/// | 12-14 | Receive only: the unwrapped mask, one bit per capability position |
/// | 15 | Receive only: the receive reports a bound eventcount's advance, with length 0 |
/// | 16-63 | A 48-bit label, copied unchanged, as seL4 copies its label |
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Info {
    pub label: u64,
    /// The length in octets.
    pub len: u16,
    pub caps: u8,
    /// Receive only: bit i set when capability i named the endpoint the
    /// message came through, and the receiver got its badge instead (ADR
    /// 0054, rule 7).
    pub unwrapped: u8,
    /// Receive only: a bound eventcount's advance, not a message (ADR 0053,
    /// rule 5).
    pub advance: bool,
}

impl Info {
    const LEN_MASK: u64 = 0x3ff;
    const CAPS_SHIFT: u32 = 10;
    const UNWRAPPED_SHIFT: u32 = 12;
    const ADVANCE: u64 = 1 << 15;
    /// The bits only a receive reports.
    const RECEIVE_ONLY: u64 = 0xf << 12;
    const LABEL_SHIFT: u32 = 16;
    /// The largest label: 48 bits.
    pub const MAX_LABEL: u64 = (1 << 48) - 1;

    /// The fields of an info word, as they stand: nothing is checked.
    pub const fn decode(w: u64) -> Info {
        Info {
            label: w >> Self::LABEL_SHIFT,
            len: (w & Self::LEN_MASK) as u16,
            caps: ((w >> Self::CAPS_SHIFT) & 3) as u8,
            unwrapped: ((w >> Self::UNWRAPPED_SHIFT) & 7) as u8,
            advance: w & Self::ADVANCE != 0,
        }
    }

    /// The info word. Fields past their widths are cut to them.
    pub const fn encode(&self) -> u64 {
        (self.label & Self::MAX_LABEL) << Self::LABEL_SHIFT
            | (self.len as u64 & Self::LEN_MASK)
            | (self.caps as u64 & 3) << Self::CAPS_SHIFT
            | (self.unwrapped as u64 & 7) << Self::UNWRAPPED_SHIFT
            | if self.advance { Self::ADVANCE } else { 0 }
    }

    /// A sender's info word, checked: a length over 960 octets, or a bit
    /// only a receive reports, fails with [`Status::InvalidArgument`], and
    /// nothing is sent. The two bits of the count hold at most 3
    /// capabilities. seL4 clamps instead; ASPIS refuses, since a clamped
    /// octet length would lose the message's exact end (ADR 0064, rule 2).
    pub const fn for_send(w: u64) -> Result<Info, Status> {
        let info = Info::decode(w);
        if info.len as u64 > MAX_LEN || w & Self::RECEIVE_ONLY != 0 {
            return Err(Status::InvalidArgument);
        }
        Ok(info)
    }

    /// The words the length covers, the last perhaps partly.
    pub const fn words(&self) -> u64 {
        (self.len as u64).div_ceil(WORD)
    }

    /// The words that travel in the buffers: words 4 and up.
    pub const fn buffer_words(&self) -> u64 {
        self.words().saturating_sub(REG_WORDS)
    }

    /// The message as it can travel: whole, when both threads have IPC
    /// buffers; otherwise cut to its first 32 octets and carrying no
    /// capabilities, as seL4 copies only the message registers without a
    /// buffer (K28).
    pub const fn as_sent(self, both_buffers: bool) -> Info {
        if both_buffers {
            self
        } else {
            Info {
                len: if self.len as u64 > REG_OCTETS {
                    REG_OCTETS as u16
                } else {
                    self.len
                },
                caps: 0,
                ..self
            }
        }
    }

    /// What the receiver is told: the label and length as sent, the
    /// capabilities transferred, and which of them were unwrapped.
    pub const fn received(self, caps: u8, unwrapped: u8) -> Info {
        Info {
            label: self.label,
            len: self.len,
            caps,
            unwrapped,
            advance: false,
        }
    }

    /// A receive that reports a bound eventcount's advance: label 0, length
    /// 0, the count in x6 (ADR 0053, rule 5).
    pub const fn advance() -> Info {
        Info {
            label: 0,
            len: 0,
            caps: 0,
            unwrapped: 0,
            advance: true,
        }
    }
}

/// How many capabilities a send carries: the info word's count, at most
/// [`MAX_CAPS`], and none unless both threads have IPC buffers (K28).
pub const fn cap_count(info: &Info, both_buffers: bool) -> usize {
    if !both_buffers {
        return 0;
    }
    let n = info.caps as usize;
    if n > MAX_CAPS { MAX_CAPS } else { n }
}

/// The IPC buffer's layout: one page, page-aligned (K28). Offsets in
/// octets.
pub mod buffer {
    /// The buffer's size: one page.
    pub const SIZE: u64 = 4096;
    /// The message area, 960 octets. Octets 0 to 31 mirror the register
    /// words: the library writes and reads them, the kernel never does.
    pub const MSG: u64 = 0x000;
    /// Where word 4, the first the kernel copies, starts.
    pub const BUFFER_WORDS: u64 = 0x020;
    /// Kept for the library, which the kernel never touches (seL4's
    /// `userData`).
    pub const USER_DATA: u64 = 0x3c0;
    /// The addresses of up to three capabilities to send.
    pub const CAPS: u64 = 0x3c8;
    /// The badges of unwrapped capabilities, at their positions; zero
    /// elsewhere. Every message, reply or fault received into the buffer
    /// writes all three; a bound eventcount's advance writes none.
    pub const BADGES: u64 = 0x3e0;
    /// Three receive slots, each a CNode's address, an index and a depth,
    /// as seL4's `receiveCNode`, `receiveIndex` and `receiveDepth`.
    pub const RECV_SLOTS: u64 = 0x3f8;
    /// The words of the receive slots.
    pub const RECV_SLOT_WORDS: usize = 9;
    /// Where the kept part starts: zero, untouched, to the page's end.
    pub const KEPT: u64 = 0x440;

    /// Where word `i` of the message lies.
    pub const fn word(i: u64) -> u64 {
        MSG + i * super::WORD
    }
}

/// A receive slot the receiver names (K28), checked: seL4's
/// `lookupTargetSlot` resolves it from the receiver's capability space, as
/// a CNode by its address, then the index at the depth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecvSlot {
    /// The CNode's capability address, from the receiver's root.
    pub cnode: u64,
    /// The slot's index in it, below `2^depth`.
    pub index: u64,
    /// The bits the index consumes, 1 to 64.
    pub depth: u32,
}

impl RecvSlot {
    /// The slot that three words, read once from the receiver's buffer,
    /// name; `None` if they name none, which ends the list. A depth of 0,
    /// or over 64, names no slot; the depth is checked as a 64-bit value
    /// before it is narrowed, so 2^32 + 5 isn't read as 5. An index with
    /// bits at or above the depth names no slot either.
    pub const fn from_words(cnode: u64, index: u64, depth: u64) -> Option<RecvSlot> {
        if depth == 0 || depth > 64 {
            return None;
        }
        if depth < 64 && index >> depth != 0 {
            return None;
        }
        Some(RecvSlot {
            cnode,
            index,
            depth: depth as u32,
        })
    }
}

/// The receive slots that the nine words at [`buffer::RECV_SLOTS`], read
/// once, name: each triple in turn, up to the first that names none. The
/// count is how many there are, 0 to 3.
pub fn recv_slots(words: &[u64; buffer::RECV_SLOT_WORDS]) -> ([RecvSlot; MAX_CAPS], usize) {
    let mut out = [RecvSlot {
        cnode: 0,
        index: 0,
        depth: 0,
    }; MAX_CAPS];
    let mut n = 0;
    let (triples, _) = words.as_chunks::<3>();
    for (slot, &[cnode, index, depth]) in out.iter_mut().zip(triples) {
        let Some(s) = RecvSlot::from_words(cnode, index, depth) else {
            break;
        };
        *slot = s;
        n += 1;
    }
    (out, n)
}

/// The status an operation returns in x0 (K30). The numbers are the test
/// build's until C17's private ABI numbers them; the names are the
/// kernel's internal ones, which C17 declares as the typed errors of each
/// `aspis.kernel.*` interface (ADR 0065, rule 8) and may rename.
///
/// The wait outcomes end a blocking operation; the errors refuse one at
/// once, with nothing changed. C15 adds the word waits' errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u64)]
pub enum Status {
    /// Done: the message came, or the call was replied to, or the count was
    /// reached.
    Ok = 0,
    /// The wait was canceled (ADR 0054, rule 6).
    Canceled = 1,
    /// The deadline passed first (ADR 0054, rule 5).
    TimedOut = 2,
    /// The wait's object was destroyed: its endpoint, eventcount or wait
    /// set, its reply object, or the server its call donated to.
    ObjectDestroyed = 3,
    /// No capability at the address, or a lookup failed.
    InvalidCapability = 4,
    /// A capability of the wrong kind for the operation. A zombie, a
    /// deletion a preemption point stopped, is of no kind but delete's and
    /// revoke's, so naming one to any other operation is "wrong kind",
    /// where seL4 reports an invalid capability.
    WrongKind = 5,
    /// A capability without a right the operation needs.
    MissingRight = 6,
    /// An argument out of range: a length over 960, a receive-only bit
    /// set, an index past a wait set's entries, a misaligned address or one
    /// outside the user half, a buffer page outside the frame presented, a
    /// source capability at the deepest level, whose copy couldn't be made;
    /// canceling a thread that waits on nothing, which changes nothing; and
    /// canceling badged sends on an unbadged endpoint capability, where
    /// seL4 does nothing.
    InvalidArgument = 7,
    /// The object is in use: a reply object already given out, which a
    /// call still waits on or another thread receives with (where seL4
    /// cancels that thread's IPC), a wait set already waited on, a slot
    /// already holding a binding.
    Busy = 8,
    /// The reply has no caller any more, or never had one.
    NoCaller = 9,
    /// The replier doesn't hold the donated context of the call it
    /// answers.
    NotHolder = 10,
    /// An advance would pass 2^64 - 1, and the count stays at its maximum
    /// (ADR 0053, rule 3).
    CountAtMaximum = 11,
    /// IPC buffer registration: no mapping at the address, or the thread
    /// has no address space.
    NotMapped = 12,
    /// IPC buffer registration: the frame isn't RAM.
    NotRam = 13,
}

/// Set in x0 when a call that ended canceled, timed out or "object
/// destroyed" had been delivered (ADR 0054, rules 5 and 6; K30).
pub const DELIVERED: u64 = 1 << 8;
/// What x0 holds after a call number the kernel doesn't know.
pub const UNKNOWN_CALL: u64 = u64::MAX;

impl Status {
    /// Every status, in number order.
    pub const ALL: [Status; 14] = [
        Status::Ok,
        Status::Canceled,
        Status::TimedOut,
        Status::ObjectDestroyed,
        Status::InvalidCapability,
        Status::WrongKind,
        Status::MissingRight,
        Status::InvalidArgument,
        Status::Busy,
        Status::NoCaller,
        Status::NotHolder,
        Status::CountAtMaximum,
        Status::NotMapped,
        Status::NotRam,
    ];

    /// The kernel's internal name (K30).
    pub const fn name(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Canceled => "canceled",
            Status::TimedOut => "timed_out",
            Status::ObjectDestroyed => "object_destroyed",
            Status::InvalidCapability => "invalid_capability",
            Status::WrongKind => "wrong_kind",
            Status::MissingRight => "missing_right",
            Status::InvalidArgument => "invalid_argument",
            Status::Busy => "busy",
            Status::NoCaller => "no_caller",
            Status::NotHolder => "not_holder",
            Status::CountAtMaximum => "count_at_maximum",
            Status::NotMapped => "not_mapped",
            Status::NotRam => "not_ram",
        }
    }

    /// Whether this ends a blocking wait, rather than refusing a call.
    pub const fn is_wait_outcome(self) -> bool {
        matches!(
            self,
            Status::Canceled | Status::TimedOut | Status::ObjectDestroyed
        )
    }

    /// x0: the status, with [`DELIVERED`] when `delivered` and this is a
    /// wait outcome. Only those say whether a call was delivered.
    pub const fn word(self, delivered: bool) -> u64 {
        let d = if delivered && self.is_wait_outcome() {
            DELIVERED
        } else {
            0
        };
        self as u64 | d
    }

    /// The status and delivered bit in x0; `None` for a word that holds
    /// neither.
    pub const fn from_word(w: u64) -> Option<(Status, bool)> {
        let delivered = w & DELIVERED != 0;
        let n = w & !DELIVERED;
        if n >= Status::ALL.len() as u64 {
            return None;
        }
        let s = Status::ALL[n as usize];
        if delivered && !s.is_wait_outcome() {
            return None;
        }
        Some((s, delivered))
    }

    /// The status a wait's result gives (`ksched::donation::Res`): a reply,
    /// a message or a restart is [`Status::Ok`].
    pub const fn of_res(r: Res) -> Status {
        match r {
            Res::None | Res::Replied => Status::Ok,
            Res::Canceled => Status::Canceled,
            Res::TimedOut => Status::TimedOut,
            Res::Destroyed => Status::ObjectDestroyed,
        }
    }
}

/// The fault message the kernel composes, provisional until C15 writes
/// `aspis.kernel.fault/1` in the IDL and generated encoders replace this
/// (kernel specification, "Fault delivery"; ADR 0064, rule 9).
///
/// A request on the common call header: word 0, a deadline of 0 and an
/// all-zero request ID in the four register words; then a body of four
/// words, which the kernel writes into the handler's IPC buffer as
/// big-endian octets ([`body_octets`]). Length 64, label 0, no
/// capabilities. Without a handler buffer, the handler gets the header
/// alone, cut to 32 octets.
pub mod fault {
    use super::Info;

    /// The call header's protocol version.
    pub const VERSION: u64 = 1;
    /// The message type: a request.
    pub const TYPE_REQUEST: u64 = 1;
    /// The header's length in words: an IPC request's four.
    pub const HEADER_WORDS: u64 = 4;
    /// The message's words: the header and a body of four.
    pub const WORDS: usize = 8;
    /// The message's length in octets.
    pub const LEN: u64 = WORDS as u64 * super::WORD;

    /// The fields the kernel keeps in a thread's fault record.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Fields {
        /// The method: the fault kind's number in the record.
        pub method: u16,
        pub pc: u64,
        /// The raw `ESR_EL1` (K49 is open).
        pub syndrome: u64,
        /// The faulting address, the call's number, or a context's badge.
        pub addr: u64,
        /// The time used, for a timeout fault, in counts.
        pub extra: u64,
    }

    /// Word 0, as a register value: `version << 56 | type << 48 | flags
    /// << 32 | method << 16 | header_words << 8`, flags 0 (call-language
    /// specification, "Word 0").
    pub const fn word0(method: u16) -> u64 {
        VERSION << 56 | TYPE_REQUEST << 48 | (method as u64) << 16 | HEADER_WORDS << 8
    }

    /// The message's eight words, as values: words 0 to 3 travel in
    /// registers, words 4 to 7 in the handler's buffer.
    pub const fn encode(f: &Fields) -> [u64; WORDS] {
        [word0(f.method), 0, 0, 0, f.pc, f.syndrome, f.addr, f.extra]
    }

    /// The info word the handler receives.
    pub const fn info() -> Info {
        Info {
            label: 0,
            len: LEN as u16,
            caps: 0,
            unwrapped: 0,
            advance: false,
        }
    }

    /// A body word as the octets the kernel writes into the buffer: its
    /// big-endian encoding (ADR 0062, rule 2).
    pub const fn body_octets(w: u64) -> [u8; 8] {
        w.to_be_bytes()
    }
}
