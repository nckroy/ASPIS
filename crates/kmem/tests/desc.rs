// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The descriptor encoders and decoder, and W^X (ADR 0048, rule 6).

use kmem::desc::{
    DEVICE_BIT, Entry, Half, KernelPerm, LeafError, MAIR_DEVICE, MAIR_NC, MAIR_NORMAL, MemType,
    UserPerm, decode, kernel_leaf, level_size, table_desc, user_leaf, violates_wx,
};

const LEVELS: [u8; 3] = [1, 2, 3];
const MEMS: [MemType; 3] = [MemType::Normal, MemType::Device, MemType::NonCacheable];

fn perms() -> impl Iterator<Item = (bool, bool)> {
    [(false, false), (false, true), (true, false), (true, true)].into_iter()
}

#[test]
fn kernel_leaves_round_trip() {
    for level in LEVELS {
        let pa = 3 * level_size(level);
        for mem in MEMS {
            for (write, exec) in perms() {
                let Ok(d) = kernel_leaf(pa, level, mem, KernelPerm { write, exec }) else {
                    continue;
                };
                let Entry::Leaf(l) = decode(d, level) else {
                    panic!("{d:#x} at level {level} didn't decode as a leaf");
                };
                assert_eq!(l.pa, pa);
                assert_eq!(l.level, level);
                assert_eq!(l.attr_index, mem.attr_index());
                assert_eq!(l.el1_write, write);
                assert!(!l.el0_read && !l.el0_write, "kernel leaf open to EL0");
                assert_eq!(l.pxn, !exec);
                assert!(l.uxn, "kernel leaf without UXN");
                assert!(l.global);
                assert!(l.access_flag);
                assert_eq!(l.device_bit, mem != MemType::Normal);
                assert!(!violates_wx(&l));
            }
        }
    }
}

#[test]
fn user_leaves_round_trip() {
    for level in LEVELS {
        let pa = 5 * level_size(level);
        for device in [false, true] {
            for (write, exec) in perms() {
                let Ok(d) = user_leaf(pa, level, UserPerm { write, exec }, device) else {
                    continue;
                };
                let Entry::Leaf(l) = decode(d, level) else {
                    panic!("{d:#x} at level {level} didn't decode as a leaf");
                };
                assert_eq!(l.pa, pa);
                assert!(l.el0_read);
                assert_eq!(l.el0_write, write);
                assert!(l.pxn, "user leaf without PXN");
                assert_eq!(l.uxn, !exec);
                assert!(!l.global, "user leaf is global");
                assert!(l.access_flag);
                assert_eq!(l.device_bit, device);
                // The memory type follows the frame's kind.
                let want = if device { MAIR_DEVICE } else { MAIR_NORMAL };
                assert_eq!(l.attr_index, want);
                assert!(!violates_wx(&l));
            }
        }
    }
}

#[test]
fn no_encoder_makes_a_writable_executable_leaf() {
    for level in LEVELS {
        for mem in MEMS {
            assert_eq!(
                kernel_leaf(
                    0,
                    level,
                    mem,
                    KernelPerm {
                        write: true,
                        exec: true
                    }
                ),
                Err(LeafError::WriteExecute)
            );
        }
        for device in [false, true] {
            assert_eq!(
                user_leaf(
                    0,
                    level,
                    UserPerm {
                        write: true,
                        exec: true
                    },
                    device
                ),
                Err(LeafError::WriteExecute)
            );
        }
    }
}

#[test]
fn device_memory_is_never_executable() {
    for level in LEVELS {
        let rx = UserPerm {
            write: false,
            exec: true,
        };
        assert_eq!(user_leaf(0, level, rx, true), Err(LeafError::DeviceExecute));
        assert!(user_leaf(0, level, rx, false).is_ok());
        for mem in [MemType::Device, MemType::NonCacheable] {
            let x = KernelPerm {
                write: false,
                exec: true,
            };
            assert_eq!(kernel_leaf(0, level, mem, x), Err(LeafError::DeviceExecute));
        }
    }
    // A device leaf is execute-never at both levels and marked not-RAM.
    let d = user_leaf(
        0x900_0000,
        3,
        UserPerm {
            write: true,
            exec: false,
        },
        true,
    )
    .unwrap();
    assert_ne!(d & DEVICE_BIT, 0);
    let Entry::Leaf(l) = decode(d, 3) else {
        panic!()
    };
    assert!(l.pxn && l.uxn);
}

#[test]
fn bad_levels_and_misaligned_addresses_are_refused() {
    let rw = KernelPerm {
        write: true,
        exec: false,
    };
    let user = UserPerm {
        write: true,
        exec: false,
    };
    for level in [0, 4, 9] {
        assert_eq!(
            kernel_leaf(0, level, MemType::Normal, rw),
            Err(LeafError::BadLevel)
        );
        assert_eq!(user_leaf(0, level, user, false), Err(LeafError::BadLevel));
    }
    assert_eq!(
        kernel_leaf(0x1000, 2, MemType::Normal, rw),
        Err(LeafError::Misaligned)
    );
    assert_eq!(
        kernel_leaf(0x20_0000, 1, MemType::Normal, rw),
        Err(LeafError::Misaligned)
    );
    assert_eq!(user_leaf(0x800, 3, user, false), Err(LeafError::Misaligned));
    assert_eq!(
        user_leaf(1 << 48, 3, user, false),
        Err(LeafError::Misaligned)
    );
}

#[test]
fn decoding_follows_the_level() {
    let page = 0x4000_1000u64;
    // 0b01 is a block at levels 1 and 2 only.
    assert_eq!(decode(page | 0b01, 0), Entry::Invalid);
    assert_eq!(decode(page | 0b01, 3), Entry::Invalid);
    assert!(matches!(decode(0x4000_0000 | 0b01, 1), Entry::Leaf(_)));
    assert!(matches!(decode(0x4000_0000 | 0b01, 2), Entry::Leaf(_)));
    // 0b11 is a table at levels 0 to 2, and a page at level 3.
    for level in 0..=2 {
        assert!(matches!(decode(page | 0b11, level), Entry::Table { .. }));
    }
    assert!(matches!(decode(page | 0b11, 3), Entry::Leaf(_)));
    // Bit 0 clear is invalid everywhere.
    for level in 0..=3 {
        assert_eq!(decode(page | 0b10, level), Entry::Invalid);
    }
}

#[test]
fn table_descriptors_carry_the_halfs_execute_never() {
    let Entry::Table { pa, pxn, uxn } = decode(table_desc(0x8000_1000, Half::Kernel), 0) else {
        panic!()
    };
    assert_eq!((pa, pxn, uxn), (0x8000_1000, false, true));
    let Entry::Table { pa, pxn, uxn } = decode(table_desc(0x8000_2000, Half::User), 1) else {
        panic!()
    };
    assert_eq!((pa, pxn, uxn), (0x8000_2000, true, false));
}

#[test]
fn the_framebuffer_type_is_non_cacheable() {
    let d = kernel_leaf(
        0x8000_0000,
        3,
        MemType::NonCacheable,
        KernelPerm {
            write: true,
            exec: false,
        },
    )
    .unwrap();
    let Entry::Leaf(l) = decode(d, 3) else {
        panic!()
    };
    assert_eq!(l.attr_index, MAIR_NC);
    assert!(l.device_bit && l.pxn && l.uxn && l.el1_write);
}

#[test]
fn violates_wx_catches_every_writable_executable_combination() {
    let d = kernel_leaf(
        0,
        3,
        MemType::Normal,
        KernelPerm {
            write: true,
            exec: false,
        },
    )
    .unwrap();
    let Entry::Leaf(mut l) = decode(d, 3) else {
        panic!()
    };
    assert!(!violates_wx(&l));
    l.pxn = false;
    assert!(violates_wx(&l), "EL1-writable and EL1-executable");
    l.pxn = true;
    l.uxn = false;
    assert!(violates_wx(&l), "EL1-writable and EL0-executable");
    l.el1_write = false;
    assert!(!violates_wx(&l));
    l.el0_write = true;
    assert!(violates_wx(&l), "EL0-writable and EL0-executable");
}
