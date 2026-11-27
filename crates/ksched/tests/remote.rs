// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Remote calls reach every target, which serves them while it spins, and
//! the panic stop ends a requester's wait.

use ksched::smp::remote::{Outcome, Remote};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[test]
fn targets_serve_and_the_requester_waits() {
    let remote = Arc::new(Remote::new());
    let seen = Arc::new([const { AtomicU64::new(0) }; 4]);
    let quit = Arc::new(AtomicBool::new(false));
    let targets: Vec<_> = (1..4)
        .map(|core| {
            let (remote, seen, quit) = (remote.clone(), seen.clone(), quit.clone());
            std::thread::spawn(move || {
                // A core spinning for the lock: it serves requests.
                while !quit.load(Ordering::Acquire) {
                    remote.serve(core, |op, arg| {
                        seen[core].fetch_add(op * 1000 + arg, Ordering::Relaxed);
                    });
                    std::hint::spin_loop();
                }
            })
        })
        .collect();
    for i in 0..100u64 {
        let mut sent = vec![];
        let out = remote.request(0b1110, 7, i, |c| sent.push(c), || {});
        assert_eq!(out, Outcome::Served);
        assert_eq!(sent, vec![1, 2, 3]);
    }
    quit.store(true, Ordering::Release);
    for t in targets {
        t.join().unwrap();
    }
    let want: u64 = (0..100u64).map(|i| 7000 + i).sum();
    for c in 1..4 {
        assert_eq!(seen[c].load(Ordering::Relaxed), want);
    }
    assert!(!remote.serve(1, |_, _| panic!("nothing pending")));
}

#[test]
fn the_stop_ends_a_wait_for_a_halted_target() {
    let remote = Arc::new(Remote::new());
    let r2 = remote.clone();
    // Core 2 has halted: it never serves. The panic path sets the stop.
    let panicker = std::thread::spawn(move || {
        while !r2.is_pending(2) {
            std::hint::spin_loop();
        }
        r2.stop();
    });
    let out = remote.request(0b100, 1, 0, |_| {}, || {});
    assert_eq!(out, Outcome::Stopped);
    assert!(remote.stopping());
    panicker.join().unwrap();
}
