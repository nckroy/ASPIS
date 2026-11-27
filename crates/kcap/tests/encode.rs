// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The encoding of capabilities and slots: every field round-trips at its
//! extremes, and anything that isn't a valid capability is refused.

mod common;

use common::Lcg;
use kcap::SlotRef;
use kcap::cap::{
    Binding, Cap, FrameSize, Kind, Mapping, RECORD_SLOTS, SlotArray, THREAD_SLOTS, ZombieKind,
};
use kcap::rights::Rights;
use kcap::slot::{MAX_DEPTH, Slot};

const TOP: u64 = 1 << 48;

fn round_trip(c: Cap) {
    assert!(c.is_valid(), "{c:x?} should be valid");
    let w = c.encode();
    assert_eq!(Cap::decode(w), Some(c), "{c:x?} encodes as {w:x?}");
}

fn all_rights() -> impl Iterator<Item = Rights> {
    (0..16).map(Rights::from_bits)
}

#[test]
fn zero_is_null_and_an_empty_slot_is_all_zero() {
    assert_eq!(Cap::decode([0, 0]), Some(Cap::Null));
    assert_eq!(Cap::Null.encode(), [0, 0]);
    assert_eq!(Slot::EMPTY.encode(), [0; 4]);
    assert_eq!(Slot::decode([0; 4]), Some(Slot::EMPTY));
    // An empty capability with links or a depth is corrupt.
    assert_eq!(Slot::decode([0, 0, 1, 0]), None);
    assert_eq!(Slot::decode([0, 0, 1 << 48, 0]), None);
    assert_eq!(Slot::decode([0, 1, 0, 0]), None);
}

#[test]
fn untyped_fields_round_trip() {
    for bits in [12u8, 13, 30, 47] {
        for base in [0, 1 << bits, TOP - (1 << bits)] {
            for device in [false, true] {
                for watermark in [0, 1, (1 << bits) - 1, 1 << bits] {
                    round_trip(Cap::Untyped {
                        base,
                        bits,
                        device,
                        watermark,
                    });
                }
            }
        }
    }
    // Out of range: a watermark past the end, a size of 11 or 48, a
    // misaligned base.
    let bad = |base, bits, watermark| {
        let c = Cap::Untyped {
            base,
            bits,
            device: false,
            watermark,
        };
        assert!(!c.is_valid());
        assert_eq!(Cap::decode(c.encode()), None, "{c:x?}");
    };
    bad(0, 12, 4097);
    bad(0, 11, 0);
    bad(0, 48, 0);
    bad(0x1000, 13, 0);
}

#[test]
fn cnode_fields_round_trip() {
    for radix in [1u8, 7, 42] {
        let size = 1u64 << (radix + 5);
        for ptr in [0, size, TOP - size] {
            for (guard_size, guard) in [(0u8, 0u64), (5, 0x15), (63 - radix.min(63), 0)] {
                if guard_size as u32 + radix as u32 > 64 {
                    continue;
                }
                round_trip(Cap::CNode {
                    ptr,
                    radix,
                    guard_size,
                    guard,
                });
            }
        }
    }
    // The extremes of the guard: 63 bits with a radix of 1, all ones, and a
    // guard and radix that use all 64 bits.
    round_trip(Cap::CNode {
        ptr: 64,
        radix: 1,
        guard_size: 63,
        guard: (1 << 63) - 1,
    });
    round_trip(Cap::CNode {
        ptr: 1 << 12,
        radix: 7,
        guard_size: 57,
        guard: 1 << 56,
    });
    // A 64-bit guard can't be encoded; a guard wider than its size, or a
    // guard and radix over 64 bits, is invalid.
    for (radix, guard_size, guard) in [(1u8, 64u8, 0u64), (1, 3, 8), (2, 63, 0), (42, 23, 0)] {
        let c = Cap::CNode {
            ptr: 1 << 47,
            radix,
            guard_size,
            guard,
        };
        assert!(!c.is_valid(), "{c:x?}");
        assert_ne!(Cap::decode(c.encode()), Some(c));
    }
    // Radix 0 and 43 are out of range.
    for radix in [0u8, 43] {
        let c = Cap::CNode {
            ptr: 0,
            radix,
            guard_size: 0,
            guard: 0,
        };
        assert_eq!(Cap::decode(c.encode()), None);
    }
}

#[test]
fn frame_fields_round_trip() {
    let mut rng = Lcg(0xf4a3);
    for size in [FrameSize::Small, FrameSize::Large, FrameSize::Huge] {
        let n = size.bytes();
        // A base with bit 12 set, which must not touch any other field.
        let mut bases = vec![0, n, TOP - n];
        if size == FrameSize::Small {
            bases.push(0x1000);
            bases.push(0x4000_1000);
            bases.push(TOP - 0x1000);
        }
        for base in bases {
            for device in [false, true] {
                for rights in all_rights() {
                    let mut mappings = vec![None];
                    for _ in 0..3 {
                        let va = (rng.below(TOP / n)) * n;
                        let write = rng.below(2) == 0;
                        mappings.push(Some(Mapping {
                            va,
                            write,
                            exec: !write && rng.below(2) == 0,
                        }));
                    }
                    mappings.push(Some(Mapping {
                        va: 0,
                        write: false,
                        exec: false,
                    }));
                    mappings.push(Some(Mapping {
                        va: TOP - n,
                        write: true,
                        exec: false,
                    }));
                    for mapping in mappings {
                        let c = Cap::Frame {
                            base,
                            size,
                            device,
                            rights,
                            mapping,
                        };
                        round_trip(c);
                        // The decoded fields are the ones put in.
                        let Some(Cap::Frame {
                            base: b, rights: r, ..
                        }) = Cap::decode(c.encode())
                        else {
                            panic!()
                        };
                        assert_eq!((b, r), (base, rights));
                    }
                }
            }
        }
    }
    // A writable and executable mapping, or one past the top, is invalid.
    let wx = Cap::Frame {
        base: 0,
        size: FrameSize::Small,
        device: false,
        rights: Rights::ALL,
        mapping: Some(Mapping {
            va: 0x1000,
            write: true,
            exec: true,
        }),
    };
    assert_eq!(Cap::decode(wx.encode()), None);
    let unaligned = Cap::Frame {
        base: 0,
        size: FrameSize::Large,
        device: false,
        rights: Rights::ALL,
        mapping: Some(Mapping {
            va: 0x1000,
            write: false,
            exec: false,
        }),
    };
    assert_eq!(Cap::decode(unaligned.encode()), None);
    // Size code 3 is unknown.
    assert_eq!(Cap::decode([3 | 3 << 6, 0]), None);
}

#[test]
fn address_space_endpoint_and_zombie_fields_round_trip() {
    for rights in all_rights() {
        for base in [0, 1 << 13, TOP - (1 << 13)] {
            round_trip(Cap::AddressSpace { base, rights });
        }
        for ptr in [0, 64, TOP - 64] {
            for badge in [0, 1, u64::MAX] {
                for binding in [
                    None,
                    Some(Binding::FaultEndpoint),
                    Some(Binding::TimeoutEndpoint),
                ] {
                    round_trip(Cap::Endpoint {
                        ptr,
                        rights,
                        badge,
                        binding,
                    });
                }
            }
        }
    }
    for radix in [1u8, 42] {
        let size = 1u64 << (radix + 5);
        for ptr in [0, TOP - size] {
            for n in [0, 1, 1 << radix] {
                round_trip(Cap::Zombie {
                    kind: ZombieKind::CNode { radix },
                    ptr,
                    n,
                });
            }
        }
    }
    for n in [0, RECORD_SLOTS] {
        round_trip(Cap::Zombie {
            kind: ZombieKind::AddressSpace,
            ptr: TOP - (1 << 13),
            n,
        });
    }
    // n past the slot count is invalid.
    let z = Cap::Zombie {
        kind: ZombieKind::AddressSpace,
        ptr: 0,
        n: RECORD_SLOTS + 1,
    };
    assert_eq!(Cap::decode(z.encode()), None);
}

#[test]
fn unknown_tags_and_stray_bits_are_refused() {
    for tag in 11..32 {
        assert_eq!(Cap::decode([tag, 0]), None, "tag {tag}");
    }
    // An unknown zombie kind.
    assert_eq!(Cap::decode([6 | 3 << 5 | 1 << 8, 0]), None);
    // A stray bit above each kind's fields.
    let caps = [
        Cap::Untyped {
            base: 0x4000_0000,
            bits: 20,
            device: false,
            watermark: 0,
        },
        Cap::CNode {
            ptr: 0x1000,
            radix: 7,
            guard_size: 0,
            guard: 0,
        },
        Cap::Frame {
            base: 0x1000,
            size: FrameSize::Small,
            device: false,
            rights: Rights::ALL,
            mapping: None,
        },
        Cap::AddressSpace {
            base: 0x2000,
            rights: Rights::ALL,
        },
        Cap::Endpoint {
            ptr: 0x40,
            rights: Rights::ALL,
            badge: 0,
            binding: None,
        },
        Cap::Thread {
            ptr: 0x800,
            rights: Rights::ALL,
        },
        Cap::SchedContext {
            ptr: 0x100,
            bits: 8,
            binding: None,
        },
        Cap::SchedControl { core: 3 },
        Cap::Reply {
            ptr: 0x80,
            rights: Rights::ALL,
        },
    ];
    for c in caps {
        let [w0, w1] = c.encode();
        assert_eq!(Cap::decode([w0 | 1 << 63, w1]), None, "{c:x?}");
    }
    // An address space has nothing in word 1; a frame without a mapping
    // nothing either.
    let [w0, _] = caps[3].encode();
    assert_eq!(Cap::decode([w0, 8]), None);
    let [w0, _] = caps[2].encode();
    assert_eq!(Cap::decode([w0, 0x1000]), None);
}

#[test]
fn slot_links_and_depths_round_trip() {
    for prev in [
        None,
        Some(SlotRef(0)),
        Some(SlotRef(32)),
        Some(SlotRef(TOP - 32)),
    ] {
        for next in [None, Some(SlotRef(0)), Some(SlotRef(TOP - 32))] {
            for depth in [0, 1, MAX_DEPTH] {
                for barrier in [None, Some(0), Some(depth.saturating_sub(1))] {
                    if barrier.is_some_and(|b| b >= depth) {
                        continue;
                    }
                    let s = Slot {
                        cap: Cap::Endpoint {
                            ptr: 64,
                            rights: Rights::READ,
                            badge: 7,
                            binding: None,
                        },
                        prev,
                        next,
                        depth,
                        barrier,
                    };
                    assert_eq!(Slot::decode(s.encode()), Some(s));
                }
            }
        }
    }
    // A slot at physical address 0 is a link, not the end of the list.
    let s = Slot {
        cap: Cap::Endpoint {
            ptr: 64,
            rights: Rights::NONE,
            badge: 0,
            binding: None,
        },
        prev: Some(SlotRef(0)),
        next: None,
        depth: 0,
        barrier: None,
    };
    assert_ne!(s.encode()[2], 0);
    // A barrier sits above the slot's depth: a barrier word larger than the
    // depth, or a stray bit beside the next link, is corrupt.
    let s = Slot {
        depth: 3,
        barrier: Some(1),
        ..s
    };
    let w = s.encode();
    assert_eq!(w[3] >> 48, 2);
    assert_eq!(Slot::decode([w[0], w[1], w[2], w[3] | 4 << 48]), None);
    assert_eq!(Slot::decode([w[0], w[1], w[2], w[3] | 1 << 44]), None);
}

#[test]
fn identify_reports_kind_and_rights_only() {
    use kcap::ops::identify;
    let r = Rights::READ.union(Rights::GRANT);
    let cases = [
        (Cap::Null, Kind::Null, Rights::NONE),
        (
            Cap::Zombie {
                kind: ZombieKind::AddressSpace,
                ptr: 0,
                n: 3,
            },
            Kind::Null,
            Rights::NONE,
        ),
        (
            Cap::Untyped {
                base: 0,
                bits: 12,
                device: false,
                watermark: 0,
            },
            Kind::Untyped,
            Rights::NONE,
        ),
        (
            Cap::CNode {
                ptr: 0,
                radix: 1,
                guard_size: 0,
                guard: 0,
            },
            Kind::CNode,
            Rights::NONE,
        ),
        (
            Cap::Frame {
                base: 0,
                size: FrameSize::Small,
                device: false,
                rights: r,
                mapping: None,
            },
            Kind::Frame,
            r,
        ),
        (
            Cap::AddressSpace { base: 0, rights: r },
            Kind::AddressSpace,
            r,
        ),
        (
            Cap::Endpoint {
                ptr: 0,
                rights: r,
                badge: 99,
                binding: Some(Binding::FaultEndpoint),
            },
            Kind::Endpoint,
            r,
        ),
        (Cap::Thread { ptr: 0, rights: r }, Kind::Thread, r),
        (
            Cap::SchedContext {
                ptr: 0,
                bits: 8,
                binding: Some(Binding::Context),
            },
            Kind::SchedContext,
            Rights::NONE,
        ),
        (
            Cap::SchedControl { core: 0 },
            Kind::SchedControl,
            Rights::NONE,
        ),
        (Cap::Reply { ptr: 0, rights: r }, Kind::Reply, r),
    ];
    for (c, kind, rights) in cases {
        assert_eq!(identify(&c), (kind, rights), "{c:x?}");
    }
}

#[test]
fn slot_arrays_have_their_geometry() {
    let a = SlotArray::of(ZombieKind::CNode { radix: 3 }, 0x1000);
    assert_eq!((a.base, a.count), (0x1000, 8));
    assert_eq!(a.park(), SlotRef(0x1000));
    assert!(a.contains(SlotRef(0x10e0)) && !a.contains(SlotRef(0x1100)));
    // An address space's slots fill its record after a 32-byte header.
    let s = SlotArray::of_address_space(0x4000_2000);
    assert_eq!(s.base, 0x4000_3020);
    assert_eq!(s.count, 127);
    assert_eq!(s.slot(126).0 + 32, 0x4000_4000);
}

#[test]
fn thread_context_control_and_reply_fields_round_trip() {
    // C12's kinds, at their extremes.
    for rights in all_rights() {
        for ptr in [0, 1 << 11, TOP - (1 << 11)] {
            round_trip(Cap::Thread { ptr, rights });
        }
        for ptr in [0, 128, TOP - 128] {
            round_trip(Cap::Reply { ptr, rights });
        }
    }
    for bits in 8u8..=12 {
        for ptr in [0, 1 << bits, TOP - (1 << bits)] {
            for binding in [None, Some(Binding::Context)] {
                round_trip(Cap::SchedContext { ptr, bits, binding });
            }
        }
    }
    for core in [0u8, 1, 7, u8::MAX] {
        round_trip(Cap::SchedControl { core });
    }
    for n in [0, 1, THREAD_SLOTS] {
        round_trip(Cap::Zombie {
            kind: ZombieKind::Thread,
            ptr: TOP - (1 << 11),
            n,
        });
    }
    // Out of range: a misaligned thread, reply or context, a context's
    // size outside 2^8 to 2^12, a thread zombie past its eight slots.
    let bad = [
        Cap::Thread {
            ptr: 0x400,
            rights: Rights::ALL,
        },
        Cap::Reply {
            ptr: 0x40,
            rights: Rights::ALL,
        },
        Cap::SchedContext {
            ptr: 0x80,
            bits: 8,
            binding: None,
        },
        Cap::SchedContext {
            ptr: 0,
            bits: 7,
            binding: None,
        },
        Cap::SchedContext {
            ptr: 0,
            bits: 13,
            binding: None,
        },
        Cap::Zombie {
            kind: ZombieKind::Thread,
            ptr: 0,
            n: THREAD_SLOTS + 1,
        },
    ];
    for c in bad {
        assert!(!c.is_valid(), "{c:x?}");
    }
    // Where the words can hold the bad value, decode refuses it.
    for c in &bad[3..] {
        assert_eq!(Cap::decode(c.encode()), None, "{c:x?}");
    }
    // Every role's code round-trips, and none fits the other kind: an
    // endpoint can't carry the context's role, nor a context an endpoint's.
    let ep = Cap::Endpoint {
        ptr: 64,
        rights: Rights::ALL,
        badge: 5,
        binding: None,
    };
    let sc = Cap::SchedContext {
        ptr: 256,
        bits: 8,
        binding: None,
    };
    for role in [Binding::FaultEndpoint, Binding::TimeoutEndpoint] {
        let b = ep.with_binding(role).unwrap();
        assert!(b.is_binding());
        assert_eq!(b.binding(), Some(role));
        round_trip(b);
        assert_eq!(sc.with_binding(role), None);
    }
    let b = sc.with_binding(Binding::Context).unwrap();
    assert_eq!(b.binding(), Some(Binding::Context));
    round_trip(b);
    assert_eq!(ep.with_binding(Binding::Context), None);
    // A raw context role in an endpoint's word is refused.
    let [w0, w1] = ep.encode();
    assert_eq!(Cap::decode([w0 | 3 << 51, w1]), None);
    assert_eq!(
        (
            Binding::FaultEndpoint.thread_slot(),
            Binding::TimeoutEndpoint.thread_slot(),
            Binding::Context.thread_slot()
        ),
        (3, 4, 5)
    );
    // Neither kind without a role, nor a thread, is a binding.
    assert!(!ep.is_binding() && !sc.is_binding());
    assert!(
        !Cap::Thread {
            ptr: 0,
            rights: Rights::ALL
        }
        .is_binding()
    );
    // Two scheduling controls are one object when they name one core.
    let c = |core| Cap::SchedControl { core };
    assert!(c(1).same_object(&c(1)) && !c(1).same_object(&c(2)));
    assert_eq!(c(1).object(), None);
    // A thread has its eight slots, and a zombie when its last capability
    // goes.
    let t = Cap::Thread {
        ptr: 0x4000_0800,
        rights: Rights::ALL,
    };
    assert!(t.has_slots());
    assert_eq!(
        t.zombie(),
        Some(Cap::Zombie {
            kind: ZombieKind::Thread,
            ptr: 0x4000_0800,
            n: 8
        })
    );
    let a = SlotArray::of_thread(0x4000_0800);
    assert_eq!((a.base, a.count), (0x4000_0800, 8));
    assert_eq!(a.slot(7).0 + 32, 0x4000_0900);
}
