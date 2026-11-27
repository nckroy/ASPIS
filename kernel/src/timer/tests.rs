// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! In-QEMU tests of the clock and the virtual timer (ADR 0036, rule 5;
//! ADR 0051, rules 4 and 5).
//!
//! Each test leaves the timer disarmed and nothing pending. None waits with
//! WFI: they take interrupts in windows, for a bounded count of the clock,
//! so a timer that never fires fails the test instead of hanging it. No test
//! assumes a frequency: QEMU's `max` CPU counts at 1 GHz, its Cortex-A72 at
//! 62.5 MHz, and the Pi 4 at 54 MHz.

use super::*;
use crate::irq::{self, Sgi, Target, spin_until, stats};
use kcap::preempt::Pending;
use kirq::regs::cntkctl;

/// `n` milliseconds of the clock.
fn ms(n: u64) -> u64 {
    frequency() * n / 1000
}

/// Opens windows until `cond` holds, for at most `counts` of the clock.
fn take_until(mut cond: impl FnMut() -> bool, counts: u64) -> bool {
    let start = now();
    loop {
        irq::window();
        if cond() {
            return true;
        }
        if now() - start > counts {
            return false;
        }
    }
}

/// Opens windows for `counts` of the clock.
fn take_for(counts: u64) {
    take_until(|| false, counts);
}

/// Waits, masked and for at most 10 ms, for the timer's level line to drop
/// at the core after a disarm: on hardware it may drop late.
fn line_dropped() -> bool {
    spin_until(|| !irq::pending(), ms(10))
}

/// Arms `deadline`, takes interrupts until the timer fires or 5 s pass, and
/// checks that it fired once, never early, and disarmed itself.
fn fire_once(deadline: u64) {
    let before = stats();
    set_deadline(deadline);
    assert!(
        take_until(|| stats().timer > before.timer, ms(5000)),
        "the timer didn't fire within 5 s of its deadline"
    );
    assert_eq!(stats().timer, before.timer + 1, "the timer fired twice");
    // On hardware the line may drop after the end of interrupt, and the
    // same window take it once more, as a stale entry. TCG drops it at once.
    assert!(
        stats().stale_timer - before.stale_timer <= 1,
        "more than one stale timer entry"
    );
    assert!(
        last_fire() >= deadline,
        "the timer fired early: at {}, deadline {deadline}",
        last_fire()
    );
    assert_eq!(compare_value(), CVAL_DISARMED, "the fire didn't disarm it");
    assert!(
        line_dropped(),
        "the timer's line stayed up after the disarm"
    );
}

crate::kernel_test!(timer_runs_at_cntfrq, {
    let f = frequency();
    assert_ne!(f, 0);
    assert_eq!(f, cntfrq());
    let i = intid().expect("timer::init didn't run");
    assert!(i.is_ppi(), "the timer's INTID {} isn't a PPI", i.0);
    assert!(
        irq::get().unwrap().is_enabled(i),
        "the timer's PPI is disabled"
    );
    // Enabled, unmasked, and armed for nothing.
    assert_eq!(
        control() & (cntv_ctl::ENABLE | cntv_ctl::IMASK),
        cntv_ctl::ENABLE
    );
    assert_eq!(compare_value(), CVAL_DISARMED);
    // EL0 can read the virtual count (K19), and reach neither timer, the
    // physical count, nor the event stream.
    let k = kernel_control();
    assert_eq!(
        k & cntkctl::EL0_ANY,
        cntkctl::EL0VCTEN,
        "CNTKCTL_EL1 {k:#x}"
    );
    assert_eq!(k, CNTKCTL);
    // The boot record ("timer: virtual, INTID 27, ... Hz") isn't checked
    // here: the log ring's wrap test may have overwritten it.
});

crate::kernel_test!(clock_is_monotonic, {
    // Including across delivered interrupts.
    let me = irq::get().unwrap().this_core();
    let mut last = now();
    for n in 0..100_000 {
        if n % 10_000 == 0 {
            irq::send_sgi(Sgi::Reschedule, Target::Core(me)).unwrap();
            assert!(take_until(irq::take_reschedule, ms(500)));
        }
        let t = now();
        assert!(t >= last, "the clock went back from {last} to {t}");
        last = t;
    }
    assert!(!irq::pending());
});

crate::kernel_test!(clock_starts_near_zero, {
    // The count is the time since the counter started (ADR 0051, rule 5),
    // with no offset. Under TCG it starts with the machine.
    let secs = now() / frequency();
    assert!(secs < 3600, "the clock reads {secs} s after boot");
});

crate::kernel_test!(virtual_count_has_no_offset, {
    // The kernel's clock is the virtual count (ADR 0051, rule 4). When the
    // stub is entered at EL2 it zeroes CNTVOFF_EL2 and lets EL1 read the
    // physical counter, so the virtual count read between two physical
    // reads must fall between them. Tests run under QEMU's TCG, with no
    // hypervisor of their own to set an offset.
    fn physical() -> u64 {
        let t: u64;
        // SAFETY: reading the physical counter has no side effects; the ISB
        // keeps the read in program order.
        unsafe { asm!("isb", "mrs {}, cntpct_el0", out(reg) t, options(nomem, nostack)) };
        t
    }
    let before = physical();
    let virtual_count = now();
    let after = physical();
    assert!(
        before <= virtual_count && virtual_count <= after,
        "virtual count {virtual_count} outside [{before}, {after}]: CNTVOFF_EL2 isn't zero"
    );
});

crate::kernel_test!(timer_fires_at_its_deadline, {
    fire_once(now() + ms(10));
});

crate::kernel_test!(the_timer_is_tickless, {
    // Nothing armed: no interrupt, however long the windows stay open.
    assert_eq!(compare_value(), CVAL_DISARMED);
    let before = stats();
    take_for(ms(50));
    assert_eq!(stats().timer, before.timer, "a tick with nothing armed");
    // One deadline, one fire, then nothing again.
    fire_once(now() + ms(1));
    let after = stats();
    take_for(ms(50));
    assert_eq!(stats().timer, after.timer, "a tick after the deadline");
});

crate::kernel_test!(a_passed_deadline_fires_at_once, {
    let before = stats();
    let deadline = now() - 1;
    set_deadline(deadline);
    // The timer compares "at or after", so it asserts at once. Under TCG
    // the first window takes it; on hardware the PPI reaches the core a
    // little later, so the windows are bounded at 100 ms.
    assert!(
        kirq::timer::asserts(control()),
        "a passed deadline doesn't assert"
    );
    assert!(
        take_until(|| stats().timer > before.timer, ms(100)),
        "a passed deadline waited"
    );
    assert_eq!(stats().timer, before.timer + 1);
    assert!(last_fire() >= deadline);
    assert_eq!(compare_value(), CVAL_DISARMED);
});

crate::kernel_test!(a_new_deadline_replaces_the_old, {
    let far = now() + ms(10_000);
    set_deadline(far);
    let near = now() + ms(5);
    fire_once(near);
    assert!(last_fire() < far, "the earlier deadline didn't replace it");
    // Arm, then disarm: nothing fires.
    let before = stats();
    set_deadline(now() + ms(5));
    disarm();
    take_for(ms(20));
    assert_eq!(stats().timer, before.timer, "a disarmed deadline fired");
});

crate::kernel_test!(a_deadline_waits_while_masked, {
    let before = stats();
    let deadline = now() + ms(1);
    set_deadline(deadline);
    // Masked, the deadline passes, and the core sees the interrupt pending
    // without taking it.
    let limit = deadline + ms(500);
    while !(now() >= deadline && irq::pending()) && now() < limit {
        core::hint::spin_loop();
    }
    assert!(now() >= deadline);
    assert!(irq::pending(), "ISR_EL1.I is clear after the deadline");
    assert!(irq::IrqPending.pending());
    assert_eq!(stats().timer, before.timer, "taken while masked");
    assert!(kirq::timer::asserts(control()));
    irq::window();
    assert_eq!(stats().timer, before.timer + 1);
    assert!(line_dropped());
    assert_eq!(compare_value(), CVAL_DISARMED);
});
