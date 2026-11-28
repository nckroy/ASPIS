// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The message layout (kernel specification K28) and the results (K30):
//! the info word, the buffer's offsets, the receive slots' checks, the
//! status words and the provisional fault message.

use kipc::msg::{
    DELIVERED, Info, MAX_WORDS, REG_OCTETS, RecvSlot, Status, UNKNOWN_CALL, buffer, cap_count,
    fault, recv_slots, regs,
};
use kipc::{MAX_CAPS, MAX_LEN};
use ksched::donation::Res;

#[test]
fn info_round_trips() {
    for label in [0, 1, 0x1234_5678, Info::MAX_LABEL] {
        for len in [0u16, 1, 7, 8, 32, 33, 959, 960] {
            for caps in 0..=3u8 {
                for unwrapped in 0..8u8 {
                    for advance in [false, true] {
                        let i = Info {
                            label,
                            len,
                            caps,
                            unwrapped,
                            advance,
                        };
                        assert_eq!(Info::decode(i.encode()), i, "{i:?}");
                    }
                }
            }
        }
    }
    // The fields sit where K28 puts them.
    let i = Info {
        label: 0xabc,
        len: 960,
        caps: 3,
        unwrapped: 5,
        advance: true,
    };
    assert_eq!(i.encode(), 0xabc << 16 | 1 << 15 | 5 << 12 | 3 << 10 | 960);
    // A label past 48 bits is cut, never spilled into other fields.
    let big = Info {
        label: u64::MAX,
        ..Info::default()
    };
    assert_eq!(Info::decode(big.encode()).label, Info::MAX_LABEL);
    assert_eq!(big.encode() & 0xffff, 0);
}

#[test]
fn info_refuses_long_many_caps_and_receive_bits() {
    // Every length up to 960 is accepted, with any label and count.
    for len in 0..=960u64 {
        let w = 0x77 << 16 | 3 << 10 | len;
        assert_eq!(Info::for_send(w).map(|i| i.len as u64), Ok(len));
    }
    // 961 to 1023 are refused: nothing is sent, and nothing is clamped.
    for len in 961..=1023u64 {
        assert_eq!(Info::for_send(len), Err(Status::InvalidArgument));
    }
    // The receive-only bits: the unwrapped mask and the advance flag.
    for bit in 12..=15 {
        assert_eq!(Info::for_send(1 << bit), Err(Status::InvalidArgument));
    }
    // The count's two bits hold at most three capabilities: no word asks
    // for more.
    for w in [0u64, 1 << 10, 2 << 10, 3 << 10, !(0xf << 12) & !0x3ff] {
        let i = Info::for_send(w).unwrap();
        assert!(i.caps as usize <= MAX_CAPS);
    }
}

#[test]
fn word_counts() {
    let at = |len: u16| Info {
        len,
        ..Info::default()
    };
    assert_eq!((at(0).words(), at(0).buffer_words()), (0, 0));
    assert_eq!((at(1).words(), at(1).buffer_words()), (1, 0));
    assert_eq!((at(32).words(), at(32).buffer_words()), (4, 0));
    assert_eq!((at(33).words(), at(33).buffer_words()), (5, 1));
    assert_eq!((at(960).words(), at(960).buffer_words()), (MAX_WORDS, 116));
    assert_eq!(MAX_WORDS, 120);
    // Without both buffers a message is cut to its register words and
    // carries no capabilities; with them it travels whole.
    let m = Info {
        label: 9,
        len: 500,
        caps: 3,
        unwrapped: 0,
        advance: false,
    };
    assert_eq!(m.as_sent(true), m);
    let cut = m.as_sent(false);
    assert_eq!((cut.len as u64, cut.caps, cut.label), (REG_OCTETS, 0, 9));
    assert_eq!(at(20).as_sent(false).len, 20);
    // What a receiver is told.
    let r = m.received(2, 0b10);
    assert_eq!(
        (r.label, r.len, r.caps, r.unwrapped, r.advance),
        (9, 500, 2, 2, false)
    );
    let a = Info::advance();
    assert!(a.advance && a.len == 0 && a.label == 0);
}

#[test]
fn buffer_layout_fits_a_page_without_overlap() {
    // (offset, size) of each region, in order.
    let regions = [
        (buffer::MSG, MAX_LEN),
        (buffer::USER_DATA, 8),
        (buffer::CAPS, 8 * MAX_CAPS as u64),
        (buffer::BADGES, 8 * MAX_CAPS as u64),
        (buffer::RECV_SLOTS, 8 * buffer::RECV_SLOT_WORDS as u64),
        (buffer::KEPT, buffer::SIZE - buffer::KEPT),
    ];
    let mut at = 0;
    for (off, size) in regions {
        assert_eq!(off, at, "regions are contiguous");
        assert_eq!(off % 8, 0, "every region is word-aligned");
        at = off + size;
    }
    assert_eq!(at, buffer::SIZE);
    assert_eq!(buffer::SIZE, 4096);
    // The register words' mirror, then the words the kernel copies.
    assert_eq!(buffer::BUFFER_WORDS, REG_OCTETS);
    assert_eq!(buffer::word(4), buffer::BUFFER_WORDS);
    assert_eq!(buffer::word(MAX_WORDS), buffer::USER_DATA);
    assert_eq!(buffer::RECV_SLOT_WORDS, 3 * MAX_CAPS);
    // seL4's AArch64 registers, with x6 the reply object and x7 the
    // deadline.
    assert_eq!(
        (
            regs::CAP,
            regs::INFO,
            regs::MSG,
            regs::REPLY,
            regs::DEADLINE
        ),
        (0, 1, [2, 3, 4, 5], 6, 7)
    );
    assert_eq!((regs::STATUS, regs::BADGE, regs::TEST_CALL), (0, 6, 8));
}

#[test]
fn fault_header_word0_bits() {
    let w = fault::word0(8);
    // Octet 0 the version, octet 1 the type, octets 2-3 the flags, 4-5 the
    // method, 6 the header's words, 7 reserved: the big-endian reading.
    assert_eq!(w.to_be_bytes(), [1, 1, 0, 0, 0, 8, 4, 0]);
    let f = fault::Fields {
        method: 2,
        pc: 0x40_1000,
        syndrome: 0x9200_0047,
        addr: 0xdead_0000,
        extra: 7,
    };
    let m = fault::encode(&f);
    assert_eq!(m[0], fault::word0(2));
    assert_eq!(&m[1..4], &[0, 0, 0], "deadline 0, an all-zero request ID");
    assert_eq!(&m[4..], &[0x40_1000, 0x9200_0047, 0xdead_0000, 7]);
    let i = fault::info();
    assert_eq!((i.len as u64, i.caps, i.label), (fault::LEN, 0, 0));
    assert_eq!(fault::LEN, 64);
    assert_eq!(
        fault::body_octets(0x0102_0304_0506_0708),
        [1, 2, 3, 4, 5, 6, 7, 8]
    );
}

#[test]
fn status_and_delivered_bit() {
    for (n, s) in Status::ALL.iter().enumerate() {
        assert_eq!(*s as u64, n as u64);
        assert_eq!(Status::from_word(s.word(false)), Some((*s, false)));
        if s.is_wait_outcome() {
            assert_eq!(s.word(true), n as u64 | DELIVERED);
            assert_eq!(Status::from_word(s.word(true)), Some((*s, true)));
        } else {
            // Only a wait's outcome says whether a call was delivered.
            assert_eq!(s.word(true), n as u64);
            assert_eq!(Status::from_word(n as u64 | DELIVERED), None);
        }
    }
    assert_eq!(DELIVERED, 0x100);
    assert_eq!(Status::from_word(Status::ALL.len() as u64), None);
    assert_eq!(Status::from_word(UNKNOWN_CALL), None);
    let names: Vec<&str> = Status::ALL.iter().map(|s| s.name()).collect();
    assert_eq!(
        names,
        [
            "ok",
            "canceled",
            "timed_out",
            "object_destroyed",
            "invalid_capability",
            "wrong_kind",
            "missing_right",
            "invalid_argument",
            "busy",
            "no_caller",
            "not_holder",
            "count_at_maximum",
            "not_mapped",
            "not_ram"
        ]
    );
    assert_eq!(Status::of_res(Res::None), Status::Ok);
    assert_eq!(Status::of_res(Res::Replied), Status::Ok);
    assert_eq!(Status::of_res(Res::Canceled), Status::Canceled);
    assert_eq!(Status::of_res(Res::TimedOut), Status::TimedOut);
    assert_eq!(Status::of_res(Res::Destroyed), Status::ObjectDestroyed);
}

#[test]
fn recv_slot_depth_2_pow_32_plus_5_refused() {
    // A depth is checked as the 64-bit value the receiver wrote: 2^32 + 5
    // is no depth, not 5.
    assert_eq!(RecvSlot::from_words(0x10, 3, (1 << 32) + 5), None);
    assert_eq!(RecvSlot::from_words(0x10, 3, u64::MAX), None);
    assert_eq!(
        RecvSlot::from_words(0x10, 3, 5),
        Some(RecvSlot {
            cnode: 0x10,
            index: 3,
            depth: 5
        })
    );
}

#[test]
fn recv_slot_depth_65_ends_list() {
    let mut w = [0u64; 9];
    w[..3].copy_from_slice(&[0x10, 1, 8]);
    w[3..6].copy_from_slice(&[0x20, 2, 65]);
    w[6..].copy_from_slice(&[0x30, 3, 8]);
    let (slots, n) = recv_slots(&w);
    assert_eq!(n, 1, "the second names no slot, which ends the list");
    assert_eq!(slots[0].cnode, 0x10);
    // Depth 0 ends it too; depth 64 is the widest.
    w[3..6].copy_from_slice(&[0x20, 2, 0]);
    assert_eq!(recv_slots(&w).1, 1);
    w[3..6].copy_from_slice(&[0x20, u64::MAX, 64]);
    let (slots, n) = recv_slots(&w);
    assert_eq!(n, 3);
    assert_eq!((slots[1].index, slots[1].depth), (u64::MAX, 64));
    assert_eq!(recv_slots(&[0; 9]).1, 0);
}

#[test]
fn recv_slot_index_bits_above_depth_refused() {
    assert_eq!(RecvSlot::from_words(0, 0x100, 8), None);
    assert_eq!(
        RecvSlot::from_words(0, 0xff, 8).map(|s| s.index),
        Some(0xff)
    );
    assert_eq!(RecvSlot::from_words(0, 1 << 63, 63), None);
    assert!(RecvSlot::from_words(0, 1 << 62, 63).is_some());
    assert_eq!(RecvSlot::from_words(0, 2, 1), None);
}

#[test]
fn cap_count_min_3_and_0_without_buffer() {
    for caps in 0..=3u8 {
        let i = Info {
            caps,
            ..Info::default()
        };
        assert_eq!(cap_count(&i, true), caps as usize);
        assert_eq!(cap_count(&i, false), 0);
    }
    // A count beyond three, which no info word can hold, is still cut.
    let i = Info {
        caps: 200,
        ..Info::default()
    };
    assert_eq!(cap_count(&i, true), MAX_CAPS);
}
