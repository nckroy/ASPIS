// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The test trap: how EL0 test programs reach the kernel until C17's
//! system-call ABI exists (test builds only; kernel specification, "Until C17: the
//! test trap").
//!
//! A program executes `svc #0x7e57` with the call's number in x8. The IPC
//! calls take their arguments in K28's registers (`kipc::msg::regs`): x0
//! the capability, x1 the info word, x2 to x5 the message's first words,
//! x6 the reply object, x7 the deadline; the rest take theirs in x0 to x3,
//! and a wait's deadline in x7.
//! The status comes back in x0 (`kipc::msg::Status`, with its delivered
//! bit), and a message in x1 to x6. In production every SVC is an
//! unknown-system-call fault (`crate::sched::entry`), and `cargo xtask
//! check-production` checks that production images hold neither this
//! file's marker nor the trap's `svc` instruction. C17's entry table and
//! private ABI replace it, calling the same decoded calls
//! (`crate::ipc::syscall`).
//!
//! Capabilities are named by their address in the calling thread's root
//! CNode, its slot 1, as C17's calls will name them.
//!
//! | x8 | Call | Arguments | After |
//! |---|---|---|---|
//! | 0 | END: the program is done; the thread suspends itself | — | — |
//! | 1 | YIELD | — | x0 0 |
//! | 2 | REPORT a value into the test log | x0 the value | x0 0 |
//! | 3 | SLEEP_UNTIL a deadline, a value of the virtual count, or 0 for none | x0 the deadline | x0 0, canceled (1) or timed out (2) |
//! | 4 | CALL | x0 endpoint, x1 info, x2-x5, x7 deadline | x0 status, x1 info, x2-x5 the reply, x6 0 |
//! | 5 | RECV | x0 endpoint, x6 reply object, x7 deadline | x0 status, x1 info, x2-x5, x6 badge or count |
//! | 6 | REPLY | x6 reply object, x1 info, x2-x5 | x0 status |
//! | 7 | REVOKE a capability | x0 its address | x0 status |
//! | 8 | DELETE a capability | x0 its address | x0 status |
//! | 9 | CANCEL a thread's wait | x0 the thread, with the write right | x0 status |
//! | 10 | REPLY_RECV | x0 endpoint, x1 info, x2-x5, x6 reply object, x7 deadline | as RECV |
//! | 11 | SEND | x0 endpoint, x1 info, x2-x5, x7 deadline | x0 status |
//! | 12 | NBSEND | x0 endpoint, x1 info, x2-x5 | x0 status |
//! | 13 | CANCEL_BADGED_SENDS | x0 the badged endpoint capability, with all four rights | x0 status |
//! | 14 | EC_ADVANCE | x0 eventcount | x0 status, x1 the count |
//! | 15 | EC_READ | x0 eventcount | x0 status, x1 the count |
//! | 16 | EC_WAIT | x0 eventcount, x1 target, x7 deadline | x0 status; on ok, x1 the count |
//! | 17 | WS_ADD | x0 wait set, x1 entry, x2 eventcount, x3 target | x0 status |
//! | 18 | WS_REMOVE | x0 wait set, x1 entry | x0 status |
//! | 19 | WS_WAIT | x0 wait set, x7 deadline | x0 status; on ok, x1 the mask |
//! | 20 | BIND_EC | x0 thread, x1 eventcount | x0 status |
//! | 21 | UNBIND_EC | x0 thread | x0 status |
//! | 22 | SET_IPC_BUFFER | x0 thread, x1 frame, x2 the buffer's address, 0 to unregister | x0 status |
//!
//! REVOKE, DELETE, CANCEL_BADGED_SENDS, WS_REMOVE, UNBIND_EC and
//! SET_IPC_BUFFER are long operations with preemption points: one stopped
//! there is made again when the thread next runs, picking up the progress
//! recorded in the objects (the restart, `crate::sched::entry`). CANCEL has
//! no long part to restart: a take-back's walk runs in batches. Nor has
//! EC_ADVANCE: its wakes past a preemption point go to the core's work list
//! (K31).

use crate::ipc::endpoint::set_status;
use crate::ipc::syscall::{self, Args};
use crate::sched::donation;
use crate::sched::entry::restart;
use crate::sched::object::{Ended, Tcb, Wait, flag};
use crate::sched::percore::this_core;
use crate::sched::run::{self, Stop};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use kcap::preempt::{Budget, Pending};
use kipc::msg::{Status, UNKNOWN_CALL};

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
pub const SEND: u64 = 11;
pub const NBSEND: u64 = 12;
pub const CANCEL_BADGED_SENDS: u64 = 13;
pub const EC_ADVANCE: u64 = 14;
pub const EC_READ: u64 = 15;
pub const EC_WAIT: u64 = 16;
pub const WS_ADD: u64 = 17;
pub const WS_REMOVE: u64 = 18;
pub const WS_WAIT: u64 = 19;
pub const BIND_EC: u64 = 20;
pub const UNBIND_EC: u64 = 21;
pub const SET_IPC_BUFFER: u64 = 22;

/// `DAIF` at the last trap, for the SError test (K77).
pub static LAST_DAIF: AtomicU64 = AtomicU64::new(u64::MAX);
/// Makes every preemption point of the long calls find an interrupt
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

/// A trapped long operation's budget, with [`TrapPending`].
fn budget() -> Budget<TrapPending> {
    Budget::new(TrapPending)
}

/// Handles the trap for the running thread `t`.
pub fn handle(t: Tcb) {
    LAST_DAIF.store(crate::sched::boot::daif(), Ordering::Relaxed);
    let (num, a) = t.with(|b| (b.ctx.x[8], [b.ctx.x[0], b.ctx.x[1], b.ctx.x[2], b.ctx.x[3]]));
    let args = Args::of(t);
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
        CALL => {
            let _ = syscall::call(t, &args);
        }
        RECV => {
            let _ = syscall::recv(t, &args);
        }
        REPLY => {
            let _ = syscall::reply(t, &args);
        }
        REPLY_RECV => {
            let _ = syscall::reply_recv(t, &args);
        }
        SEND | NBSEND => {
            let _ = syscall::send(t, &args, num == SEND);
        }
        REVOKE | DELETE => long(t, num, a[0]),
        CANCEL => syscall::cancel(t, a[0]),
        CANCEL_BADGED_SENDS => {
            if syscall::cancel_badged_sends(t, &args, &mut budget()).is_err() {
                restart(t);
            }
        }
        EC_ADVANCE => syscall::ec_advance(t, a[0], &mut budget()),
        EC_READ => syscall::ec_read(t, a[0]),
        EC_WAIT => {
            let _ = syscall::ec_wait(t, a[0], a[1], args.deadline);
        }
        WS_ADD => syscall::ws_add(t, a[0], a[1], a[2], a[3]),
        WS_REMOVE => {
            if syscall::ws_remove(t, a[0], a[1], &mut budget()).is_err() {
                restart(t);
            }
        }
        WS_WAIT => {
            let _ = syscall::ws_wait(t, a[0], args.deadline);
        }
        BIND_EC => syscall::bind_eventcount(t, a[0], a[1]),
        UNBIND_EC => {
            if syscall::unbind_eventcount(t, a[0], &mut budget()).is_err() {
                restart(t);
            }
        }
        SET_IPC_BUFFER => {
            if syscall::set_ipc_buffer(t, a[0], a[1], a[2], &mut budget()).is_err() {
                restart(t);
            }
        }
        _ => set_x0(t, UNKNOWN_CALL),
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

/// REVOKE and DELETE, stopped at a preemption point when an interrupt is
/// pending, and then made again (module docs).
fn long(t: Tcb, num: u64, addr: u64) {
    let slot = match syscall::lookup(t, addr) {
        Ok((slot, _)) => slot,
        Err(s) => return set_status(t, s),
    };
    let r = if num == REVOKE {
        crate::cap::revoke_with(slot, &mut budget())
    } else {
        crate::cap::delete_with(slot, &mut budget())
    };
    match r {
        Ok(()) => set_status(t, Status::Ok),
        Err(_) => restart(t),
    }
}
