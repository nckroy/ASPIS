// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The test trap: how EL0 test programs reach the kernel until C17's
//! system-call ABI exists (test builds only; kernel specification, "Until C17: the
//! test trap").
//!
//! A program executes `svc #0x7e57` with the call's number in x8 and its
//! arguments in x0 to x2; the result comes back in x0, and a message word
//! in x1. In production every SVC is an unknown-system-call fault
//! (`crate::sched::entry`), and `cargo xtask check-production` checks that
//! production images hold neither this file's marker nor the trap's `svc`
//! instruction. C17's entry table and private ABI replace it.
//!
//! Capabilities are named by their address in the calling thread's root
//! CNode, its slot 1, as C17's calls will name them.
//!
//! | x8 | Call | Arguments | x0 after |
//! |---|---|---|---|
//! | 0 | END: the program is done; the thread suspends itself | — | — |
//! | 1 | YIELD | — | 0 |
//! | 2 | REPORT a value into the test log | x0 the value | 0 |
//! | 3 | SLEEP_UNTIL a deadline, a value of the virtual count, or 0 for none | x0 the deadline | 0, canceled (1) or timed out (2) |
//! | 4 | CALL a thread waiting to receive, the stand-in for C14's endpoint | x0 the thread, x1 a deadline or 0, x2 a message word | the call's end; x1 the reply's word |
//! | 5 | RECV with a reply object | x0 the reply object, x1 a deadline or 0 | 0 and x1 the caller's word, or canceled or timed out |
//! | 6 | REPLY on a reply object | x0 the reply object, x1 a message word | 0, or an error |
//! | 7 | REVOKE a capability | x0 its address | 0, or an error |
//! | 8 | DELETE a capability | x0 its address | 0 |
//! | 9 | CANCEL a thread's wait | x0 the thread | 0, or an error |
//! | 10 | REPLY_RECV: REPLY, then RECV with the same reply object | x0 the reply object, x1 a message word | as RECV |
//!
//! REVOKE and DELETE are long operations with preemption points: one
//! stopped there is made again when the thread next runs, picking up the
//! progress recorded in the objects (the restart, `crate::sched::entry`).
//! CANCEL has no long part to restart: a take-back's walk runs in batches.

use crate::cap::DirectSlots;
use crate::sched::donation;
use crate::sched::entry::restart;
use crate::sched::object::{Ended, Rp, Tcb, Wait, flag};
use crate::sched::percore::this_core;
use crate::sched::run::{self, Stop};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use kcap::SlotRef;
use kcap::cap::Cap;
use kcap::preempt::{Budget, Pending};

/// The SVC immediate of the test trap.
pub const IMM: u64 = 0x7e57;

/// Marks the trap's code; production images must not hold it.
#[used]
#[unsafe(link_section = ".aspis_test_marker")]
static TRAP_MARKER: [u8; 16] = *b"ASPIS-TEST-TRAP!";

pub const END: u64 = 0;
pub const YIELD: u64 = 1;
pub const REPORT: u64 = 2;
pub const SLEEP_UNTIL: u64 = 3;
pub const CALL: u64 = 4;
pub const RECV: u64 = 5;
pub const REPLY: u64 = 6;
pub const REVOKE: u64 = 7;
pub const DELETE: u64 = 8;
pub const CANCEL: u64 = 9;
pub const REPLY_RECV: u64 = 10;

/// What an unknown call number returns.
pub const UNKNOWN: u64 = u64::MAX;
/// What a call returns when a capability is missing or of the wrong kind.
pub const BAD_CAP: u64 = 0x100;
/// What a call returns when `ksched::donation` refuses it: this plus the
/// error's number.
pub const REFUSED: u64 = 0x200;

/// `DAIF` at the last trap, for the SError test (K77).
pub static LAST_DAIF: AtomicU64 = AtomicU64::new(u64::MAX);
/// Makes every preemption point of REVOKE and DELETE find an interrupt
/// pending, so a test sees the restart at every check.
pub static FORCE_PREEMPT: AtomicBool = AtomicBool::new(false);

/// The pending check of a trapped long operation: an interrupt pending, or
/// [`FORCE_PREEMPT`].
struct TrapPending;

impl Pending for TrapPending {
    fn pending(&mut self) -> bool {
        FORCE_PREEMPT.load(Ordering::Relaxed) || crate::irq::pending()
    }
}

fn set_x0(t: Tcb, v: u64) {
    t.with(|b| b.ctx.x[0] = v);
}

fn refused(e: ksched::donation::Error) -> u64 {
    use ksched::donation::Error as E;
    REFUSED
        + match e {
            E::NotReceiving => 1,
            E::NotWaiting => 2,
            E::Busy => 3,
            E::NoCaller => 4,
            E::NotHolder => 5,
            E::Bound => 6,
            E::NotBound => 7,
            E::NoContext => 8,
        }
}

/// The capability at `addr` in `t`'s root CNode, with its slot.
fn lookup(t: Tcb, addr: u64) -> Option<(SlotRef, Cap)> {
    kcap::lookup::lookup_cap(&DirectSlots, t.slot_cap(1), addr).ok()
}

fn thread_at(t: Tcb, addr: u64) -> Option<Tcb> {
    match lookup(t, addr)? {
        (_, Cap::Thread { ptr, .. }) => Some(Tcb(ptr)),
        _ => None,
    }
}

fn reply_at(t: Tcb, addr: u64) -> Option<Rp> {
    lookup(t, addr).and_then(|(_, c)| Rp::of(&c))
}

/// Handles the trap for the running thread `t`.
pub fn handle(t: Tcb) {
    LAST_DAIF.store(crate::sched::boot::daif(), Ordering::Relaxed);
    let (num, a) = t.with(|b| (b.ctx.x[8], [b.ctx.x[0], b.ctx.x[1], b.ctx.x[2]]));
    match num {
        END => {
            t.update(|s| s.flags = (s.flags | flag::DONE) & !flag::RESUMED);
            run::place(t);
        }
        YIELD => {
            set_x0(t, Ended::Done as u64);
            run::stop_current(Stop::Yield);
        }
        REPORT => {
            super::report::push(this_core().index, t.0, a[0]);
            set_x0(t, Ended::Done as u64);
        }
        SLEEP_UNTIL => sleep(t, a[0]),
        CALL => call(t, a[0], a[1], a[2]),
        RECV => recv(t, a[0], a[1], false, 0),
        REPLY => match reply_at(t, a[0]) {
            None => set_x0(t, BAD_CAP),
            Some(r) => {
                let v = match donation::reply(t, r, a[1]) {
                    Ok(()) => Ended::Done as u64,
                    Err(e) => refused(e),
                };
                set_x0(t, v);
            }
        },
        REPLY_RECV => recv(t, a[0], 0, true, a[1]),
        REVOKE | DELETE => long(t, num, a[0]),
        CANCEL => {
            let v = match thread_at(t, a[0]) {
                None => BAD_CAP,
                Some(x) => match donation::cancel(x) {
                    Ok(()) => Ended::Done as u64,
                    Err(e) => refused(e),
                },
            };
            // Canceling its own caller only takes this thread's context
            // away: it is still ready, and sees the result when it next runs.
            set_x0(t, v);
        }
        _ => set_x0(t, UNKNOWN),
    }
}

/// Sleeps until `deadline`, or until canceled with none. A deadline that
/// has passed returns "timed out" at once, since the sleep would block
/// (K19).
fn sleep(t: Tcb, deadline: u64) {
    if deadline != 0 && deadline <= crate::timer::now() {
        set_x0(t, Ended::TimedOut as u64);
        return;
    }
    t.update(|s| s.wait = Wait::TestSleep as u8);
    if deadline != 0 {
        run::deadline_insert(t, deadline);
    }
    donation::wait_other(t);
}

/// CALL: a call blocks for its reply, so a deadline already passed times
/// out at once, and nothing is delivered (K19).
fn call(t: Tcb, server: u64, deadline: u64, msg: u64) {
    let Some(v) = thread_at(t, server) else {
        return set_x0(t, BAD_CAP);
    };
    if deadline != 0 && deadline <= crate::timer::now() {
        return set_x0(t, Ended::TimedOut as u64);
    }
    match donation::call(t, v, msg) {
        Ok(_) => {
            if deadline != 0 {
                run::deadline_insert(t, deadline);
            }
        }
        Err(e) => set_x0(t, refused(e)),
    }
}

/// RECV, and REPLY_RECV's reply first.
fn recv(t: Tcb, reply: u64, deadline: u64, reply_first: bool, msg: u64) {
    let Some(r) = reply_at(t, reply) else {
        return set_x0(t, BAD_CAP);
    };
    if deadline != 0 && deadline <= crate::timer::now() {
        return set_x0(t, Ended::TimedOut as u64);
    }
    let out = if reply_first {
        match donation::reply_recv(t, r, msg) {
            // Nothing to answer is no error for a server's loop.
            Err(ksched::donation::Error::NoCaller) | Ok(()) => Ok(()),
            Err(e) => Err(e),
        }
    } else {
        donation::recv(t, r)
    };
    match out {
        Ok(()) if t.wait() == Wait::Receive => {
            if deadline != 0 {
                run::deadline_insert(t, deadline);
            }
        }
        Ok(()) => {}
        Err(e) => set_x0(t, refused(e)),
    }
}

/// REVOKE and DELETE, stopped at a preemption point when an interrupt is
/// pending, and then made again (module docs).
fn long(t: Tcb, num: u64, addr: u64) {
    let Some((slot, _)) = lookup(t, addr) else {
        return set_x0(t, BAD_CAP);
    };
    let mut budget = Budget::new(TrapPending);
    let r = if num == REVOKE {
        crate::cap::revoke_with(slot, &mut budget)
    } else {
        crate::cap::delete_with(slot, &mut budget)
    };
    match r {
        Ok(()) => set_x0(t, Ended::Done as u64),
        Err(_) => restart(t),
    }
}
