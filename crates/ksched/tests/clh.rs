// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The CLH lock: mutual exclusion among eight threads, and first come,
//! first served: each holder's predecessor is the node its previous holder
//! released.

use ksched::smp::MAX_CORES;
use ksched::smp::clh::Clh;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[test]
fn exclusion_and_fifo() {
    let lock = Arc::new(Clh::new());
    let inside = Arc::new(AtomicBool::new(false));
    let count = Arc::new(AtomicUsize::new(0));
    // (holder's node, predecessor's node), in the order they held it.
    let order = Arc::new(Mutex::new(Vec::new()));
    let rounds = 2000;
    let handles: Vec<_> = (0..MAX_CORES)
        .map(|core| {
            let (lock, inside, count, order) =
                (lock.clone(), inside.clone(), count.clone(), order.clone());
            std::thread::spawn(move || {
                let mut node = Clh::node(core).unwrap();
                for _ in 0..rounds {
                    let held = lock.acquire(&mut node, || {});
                    assert!(!inside.swap(true, Ordering::Relaxed), "two holders");
                    count.fetch_add(1, Ordering::Relaxed);
                    order.lock().unwrap().push((held.node(), held.predecessor));
                    inside.store(false, Ordering::Relaxed);
                    lock.release(held);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(count.load(Ordering::Relaxed), MAX_CORES * rounds);
    let order = order.lock().unwrap();
    // The first holder's predecessor is the spare node.
    assert_eq!(order[0].1, MAX_CORES);
    for w in order.windows(2) {
        assert_eq!(w[1].1, w[0].0, "a core took the lock out of turn");
    }
    assert!(!lock.is_held());
}

#[test]
fn the_spin_hook_runs_while_waiting() {
    let lock = Arc::new(Clh::new());
    let mut a = Clh::node(0).unwrap();
    let held = lock.acquire(&mut a, || panic!("no wait when free"));
    assert!(lock.is_held());
    let spins = Arc::new(AtomicUsize::new(0));
    let l2 = lock.clone();
    let s2 = spins.clone();
    let waiter = std::thread::spawn(move || {
        let mut b = Clh::node(1).unwrap();
        let h = l2.acquire(&mut b, || {
            s2.fetch_add(1, Ordering::Relaxed);
        });
        l2.release(h);
    });
    while spins.load(Ordering::Relaxed) == 0 {
        std::hint::spin_loop();
    }
    lock.release(held);
    waiter.join().unwrap();
    assert!(Clh::node(MAX_CORES).is_none());
}
