// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! What the scheduler's in-QEMU tests share (test builds only): making EL0
//! threads in a [`Scratch`], and checking that a test leaves the scheduler
//! as it found it.
//!
//! The first thread's context takes the whole boot core (K13), so
//! [`make_room`] reconfigures it to 1 ms in 10 ms, as the root server's
//! manifest would, leaving nine tenths of the core to the tests.

use super::object::{Tcb, UserContext, Wait, flag};
use super::percore::this_core;
use super::{boot, context, thread};
use crate::cap::boot as cboot;
use crate::cap::testkit::Scratch;
use crate::cap::{self, map};
use crate::mm::phys::{DirectMem, Window};
use crate::testing::user::{Program, blob};
use crate::testing::{driver, report};
use kcap::SlotRef;
use kcap::cap::Cap;
use kmem::desc::UserPerm;
use kmem::untyped::ObjectType;

/// Where the test programs are mapped, read-only and executable.
pub const CODE_VA: u64 = 0x40_0000;
/// Where each address space's stack page is mapped, read-write.
pub const STACK_VA: u64 = 0x80_0000;
/// An address nothing is mapped at.
pub const UNMAPPED_VA: u64 = 0x1000_0000;

/// `n` milliseconds in counts.
pub fn ms(n: u64) -> u64 {
    crate::timer::frequency() * n / 1000
}

/// The boot core's scheduling control.
pub fn control() -> SlotRef {
    boot::control_slot(this_core().index)
}

/// Core `k`'s scheduling control.
pub fn control_of(k: usize) -> SlotRef {
    boot::control_slot(k)
}

/// The first thread's capability, the authority for priorities: its
/// maximum controlled priority is 255.
pub fn first_thread() -> SlotRef {
    cboot::root_slot(cboot::FIRST_THREAD)
}

/// The first thread's context.
pub fn first_context() -> SlotRef {
    cboot::root_slot(cboot::FIRST_CONTEXT)
}

/// The share the first thread's context keeps once [`make_room`] has run.
pub const FIRST_ROOM: (u64, u64) = (1_000, 10_000);

/// Reconfigures the first thread's context to 1 ms in 10 ms (module docs).
pub fn make_room() {
    let (b, p) = FIRST_ROOM;
    context::configure(control(), first_context(), b, p, 0, 0)
        .unwrap_or_else(|e| panic!("can't make room on the boot core: {e:?}"));
}

/// What [`spawn`] makes.
#[derive(Clone, Copy, Debug)]
pub struct Spec {
    pub program: Program,
    pub args: [u64; 3],
    pub priority: u8,
    pub budget_us: u64,
    pub period_us: u64,
    pub extra_refills: u32,
    pub badge: u64,
    /// The core its context is on; the boot core if None.
    pub core: Option<usize>,
}

impl Spec {
    /// `program` at priority 10, with 200 µs in 1 ms, on the boot core.
    pub const fn of(program: Program) -> Spec {
        Spec {
            program,
            args: [0; 3],
            priority: 10,
            budget_us: 200,
            period_us: 1_000,
            extra_refills: 0,
            badge: 0,
            core: None,
        }
    }

    /// The same, on core `k`.
    pub const fn on(self, k: usize) -> Spec {
        Spec {
            core: Some(k),
            ..self
        }
    }
}

/// An EL0 thread a test made.
#[derive(Clone, Copy, Debug)]
pub struct User {
    pub thread: SlotRef,
    pub context: SlotRef,
    pub tcb: Tcb,
}

/// An address space with the test programs mapped at [`CODE_VA`] and a
/// stack page at [`STACK_VA`].
pub fn space(sc: &mut Scratch) -> SlotRef {
    let s = sc.make(ObjectType::AddressSpace);
    let code = sc.make(ObjectType::Frame4K);
    let stack = sc.make(ObjectType::Frame4K);
    let b = blob();
    assert!(b.len() <= 4096, "the test programs take {} bytes", b.len());
    let Some((pa, _)) = cap::cap(code).object() else {
        panic!("no code frame")
    };
    // SAFETY: a RAM frame the test just retyped, in the direct map, which
    // nothing else uses yet; the blob is read-only data of the kernel.
    unsafe {
        core::ptr::copy_nonoverlapping(b.as_ptr(), DirectMem.va(pa) as *mut u8, b.len());
    }
    let rx = UserPerm {
        write: false,
        exec: true,
    };
    let rw = UserPerm {
        write: true,
        exec: false,
    };
    map(code, s, CODE_VA, rx, sc.ram).unwrap_or_else(|e| panic!("can't map the code: {e:?}"));
    map(stack, s, STACK_VA, rw, sc.ram).unwrap_or_else(|e| panic!("can't map the stack: {e:?}"));
    s
}

/// A thread running `spec` in the address space `s`, resumed.
pub fn spawn_in(sc: &mut Scratch, s: SlotRef, spec: Spec) -> User {
    let t = sc.make(ObjectType::Thread);
    let c = sc.make(ObjectType::SchedContext(8));
    context::configure(
        spec.core.map_or_else(control, control_of),
        c,
        spec.budget_us,
        spec.period_us,
        spec.extra_refills,
        spec.badge,
    )
    .unwrap_or_else(|e| panic!("can't configure {spec:?}: {e:?}"));
    thread::configure_space(t, cboot::root_slot(cboot::ROOT_SELF), s).unwrap();
    thread::set_priority(t, first_thread(), spec.priority).unwrap();
    thread::bind_context(t, c).unwrap();
    let mut regs = UserContext {
        pc: CODE_VA + spec.program.offset(),
        sp: STACK_VA + 4096,
        ..UserContext::default()
    };
    regs.x[..3].copy_from_slice(&spec.args);
    thread::write_registers(t, &regs).unwrap();
    thread::resume(t).unwrap();
    User {
        thread: t,
        context: c,
        tcb: Tcb::of(&cap::cap(t)).unwrap(),
    }
}

/// [`spawn_in`] a new address space.
pub fn spawn(sc: &mut Scratch, spec: Spec) -> User {
    let s = space(sc);
    spawn_in(sc, s, spec)
}

/// An endpoint with every right, for a fault or timeout endpoint.
pub fn endpoint(sc: &mut Scratch) -> SlotRef {
    sc.make(ObjectType::Endpoint)
}

/// Runs threads for `n` milliseconds.
pub fn run_ms(n: u64) {
    fn never() -> bool {
        false
    }
    driver::run_until(never, ms(n));
}

/// Destroys what the test made, and checks the scheduler is as the test
/// found it: nothing running, queued, waiting for a refill or a deadline,
/// and the boot core's share back to the first thread's alone.
pub fn finish(sc: Scratch) {
    sc.finish();
    // Every online core: the others are waiting for the kernel lock, which
    // the test body holds, so their data holds still.
    for k in (0..kirq::MAX_CORES).filter(|&k| crate::smp::is_online(k)) {
        let c = super::percore::core(k);
        assert_eq!(c.current, 0, "a thread is still running on core {k}");
        assert!(c.runq.is_empty(), "a thread is still queued on core {k}");
        assert_eq!(
            c.release_root, 0,
            "a context is still in core {k}'s release tree"
        );
        assert_eq!(c.deadline_root, 0, "a deadline is still queued on core {k}");
        assert!(c.work.is_empty(), "a walk is still on core {k}'s work list");
        assert_eq!(c.stats.idle_with_work, 0, "core {k} idled with work left");
        if k != this_core().index {
            assert_eq!(
                context::used(k).fraction(),
                ksched::share::Used::EMPTY.fraction(),
                "core {k}'s share wasn't released"
            );
        }
    }
    let c = this_core();
    assert!(
        super::donation::no_walks(),
        "a walk is still in the walk tree"
    );
    assert_eq!(c.stats.idle_with_work, 0, "the core idled with work left");
    assert!(!crate::testing::trap::FORCE_PREEMPT.load(core::sync::atomic::Ordering::Relaxed));
    let (b, p) = FIRST_ROOM;
    let want = ksched::share::Used::EMPTY
        .admit(context::ROOT_SHARE, b, p)
        .unwrap();
    assert_eq!(
        context::used(c.index).fraction(),
        want.fraction(),
        "the boot core's share wasn't released"
    );
    let first = Tcb(boot::first_thread());
    assert!(!first.has(flag::RESUMED) && first.wait() == Wait::None);
    assert!(matches!(
        cap::cap(first_context()),
        Cap::SchedContext { bits: 12, .. }
    ));
    report::clear();
}
