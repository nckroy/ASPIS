// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! What the IPC in-QEMU tests share (test builds only): threads that stay
//! suspended while a test drives them through the kernel's operations, so
//! long queues are built in the kernel without running each thread at EL0;
//! reply objects, endpoints, eventcounts, wait sets and IPC buffers; fault
//! handlers; and the invariants' checks.

use super::endpoint::{self, ep_cap, reply_cap};
use super::eventcount::ec_cap;
use super::object;
use super::waitset::ws_cap;
use crate::cap::testkit::Scratch;
use crate::cap::{self, boot as cboot, map};
use crate::sched::object::{Rp, Tcb};
use crate::sched::percore::this_core;
use crate::sched::testkit::{first_thread, make_room};
use crate::sched::{donation, thread};
use crate::testing::report;
use kcap::SlotRef;
use kcap::cap::Cap;
use kipc::endpoint::EpCap;
use kipc::msg::{Info, Status};
use kipc::{Ec, Outcome, Ws};
use kmem::PAGE_SIZE;
use kmem::desc::UserPerm;
use kmem::untyped::ObjectType;
use ksched::donation::Reply;

/// Where the IPC buffers are mapped, one page each from here, read-write.
pub const BUF_VA: u64 = 0xa0_0000;

/// The thread a capability in `s` names.
pub fn tcb(s: SlotRef) -> Tcb {
    match Tcb::of(&cap::cap(s)) {
        Some(t) => t,
        None => panic!("slot {:#x} holds no thread", s.0),
    }
}

/// The endpoint capability in `s`.
pub fn epc(s: SlotRef) -> EpCap {
    ep_cap(&cap::cap(s)).unwrap_or_else(|e| panic!("slot {:#x}: {e:?}", s.0))
}

/// The reply object in `s`, and its grant right.
pub fn rpc(s: SlotRef) -> (Reply, bool) {
    reply_cap(&cap::cap(s)).unwrap_or_else(|e| panic!("slot {:#x}: {e:?}", s.0))
}

/// A thread in the boot capability space, at priority `prio`, with no
/// context and no address space: suspended, it never runs, and a test
/// drives it through the kernel's operations.
pub fn idle_thread(sc: &mut Scratch, prio: u8) -> (SlotRef, Tcb) {
    let s = sc.make(ObjectType::Thread);
    let t = tcb(s);
    on_this_core(t);
    // Its root CNode, so capability transfer resolves its receive slots,
    // and its addresses match the test's (`Scratch::addr_of`).
    cap::copy(cboot::root_slot(cboot::ROOT_SELF), t.slot(1)).unwrap();
    thread::set_priority(s, first_thread(), prio).unwrap();
    (s, t)
}

/// A thread like [`idle_thread`], with address space `space`, so it can
/// register an IPC buffer.
pub fn idle_thread_in(sc: &mut Scratch, space: SlotRef, prio: u8) -> (SlotRef, Tcb) {
    let s = sc.make(ObjectType::Thread);
    on_this_core(tcb(s));
    thread::configure_space(s, cboot::root_slot(cboot::ROOT_SELF), space).unwrap();
    thread::set_priority(s, first_thread(), prio).unwrap();
    (s, tcb(s))
}

/// Makes this core the one whose deadline tree a thread with no context
/// uses (K18).
pub fn on_this_core(t: Tcb) {
    let core = crate::sched::percore::this_core().index as u8;
    t.update(|s| s.core = core);
}

/// A thread with its own context, 50 µs in 1 ms with `badge`, on the boot
/// core, suspended, so it never runs: it can call, which needs a context.
pub fn caller_thread(sc: &mut Scratch, space: SlotRef, prio: u8, badge: u64) -> (SlotRef, Tcb) {
    let (s, t) = idle_thread_in(sc, space, prio);
    let c = sc.make(ObjectType::SchedContext(8));
    crate::sched::context::configure(crate::sched::testkit::control(), c, 50, 1_000, 0, badge)
        .unwrap();
    thread::bind_context(s, c).unwrap();
    (s, t)
}

/// A reply object.
pub fn reply_obj(sc: &mut Scratch) -> (SlotRef, Reply) {
    let r = sc.make(ObjectType::Reply);
    (r, rpc(r).0)
}

/// An endpoint, and its capability, with every right and no badge.
pub fn endpoint_obj(sc: &mut Scratch) -> (SlotRef, EpCap) {
    let e = sc.make(ObjectType::Endpoint);
    (e, epc(e))
}

/// A badged copy of the endpoint capability in `e`, with `rights`.
pub fn badged(sc: &mut Scratch, e: SlotRef, badge: u64, rights: kcap::rights::Rights) -> SlotRef {
    let s = sc.take();
    cap::mint(e, s, rights, kcap::ops::MintData::Badge(badge)).unwrap();
    s
}

/// Maps a new frame at `BUF_VA + i` pages of the address space in `space`,
/// and registers it as the IPC buffer of the thread in `thread`. Returns
/// the frame's slot and its physical address.
pub fn give_buffer(sc: &mut Scratch, space: SlotRef, thread: SlotRef, i: u64) -> (SlotRef, u64) {
    let f = sc.make(ObjectType::Frame4K);
    let va = BUF_VA + i * PAGE_SIZE;
    let rw = UserPerm {
        write: true,
        exec: false,
    };
    map(f, space, va, rw, sc.ram).unwrap_or_else(|e| panic!("can't map a buffer: {e:?}"));
    let t = tcb(thread);
    let r = super::buffer::set(t, Some(f), va, &mut cap::budget());
    assert_eq!(r, Ok(Ok(())), "can't register the buffer");
    let Some((pa, _)) = cap::cap(f).object() else {
        panic!("no frame")
    };
    assert_eq!(object::ipc(t).buf_pa, pa);
    (f, pa)
}

/// Word `off` of the buffer page at `pa`.
pub fn buf(pa: u64, off: u64) -> u64 {
    use crate::mm::phys::{DirectMem, Window};
    // SAFETY: a test's buffer page, RAM in the direct map, which no user
    // thread runs on while the test reads it.
    unsafe { core::ptr::read_volatile(DirectMem.va(pa + off) as *const u64) }
}

/// Writes word `off` of the buffer page at `pa`.
pub fn set_buf(pa: u64, off: u64, v: u64) {
    use crate::mm::phys::{DirectMem, Window};
    // SAFETY: as for `buf`.
    unsafe { core::ptr::write_volatile(DirectMem.va(pa + off) as *mut u64, v) }
}

/// Register `i` of `t`.
pub fn x(t: Tcb, i: usize) -> u64 {
    t.with(|b| b.ctx.x[i])
}

/// An info word with `label`, `len` octets and `caps` capabilities.
pub const fn info(label: u64, len: u16, caps: u8) -> u64 {
    Info {
        label,
        len,
        caps,
        unwrapped: 0,
        advance: false,
    }
    .encode()
}

/// Sets `t`'s message registers: words 0 to 3 in x2 to x5.
pub fn set_words(t: Tcb, w: [u64; 4]) {
    t.with(|b| b.ctx.x[2..6].copy_from_slice(&w));
}

/// `t`'s message registers.
pub fn words(t: Tcb) -> [u64; 4] {
    t.with(|b| [b.ctx.x[2], b.ctx.x[3], b.ctx.x[4], b.ctx.x[5]])
}

/// The status in `t`'s x0, with its delivered bit.
pub fn status(t: Tcb) -> (Status, bool) {
    let w = x(t, 0);
    Status::from_word(w).unwrap_or_else(|| panic!("x0 holds {w:#x}, no status"))
}

/// The caller of the call `r` holds, if any.
pub fn caller_of(r: Reply) -> Option<Tcb> {
    match Rp(r.0).get().caller {
        0 => None,
        c => Some(Tcb(c)),
    }
}

/// A handler, a new idle thread with a new reply object, receives on the
/// endpoint in `ep`: it must get a fault at once. It replies with nothing,
/// so the faulting thread resumes. Returns the thread whose fault it
/// answered.
pub fn answer_fault(sc: &mut Scratch, ep: SlotRef) -> Tcb {
    let (_, h) = idle_thread(sc, 0);
    let (_, r) = reply_obj(sc);
    assert_eq!(endpoint::recv(h, epc(ep), r, 0), Ok(Outcome::Done));
    let Some(t) = caller_of(r) else {
        panic!("the handler got no fault")
    };
    assert_eq!(endpoint::reply(h, r, false, 0), Ok(()));
    t
}

/// An eventcount, and its capability's slot, with every right.
pub fn ec_obj(sc: &mut Scratch) -> (SlotRef, Ec) {
    let s = sc.make(ObjectType::Eventcount);
    (s, ecc(s))
}

/// The eventcount the capability in `s` names.
pub fn ecc(s: SlotRef) -> Ec {
    ec_cap(&cap::cap(s))
        .unwrap_or_else(|e| panic!("slot {:#x}: {e:?}", s.0))
        .0
}

/// A wait set of `2^bits` bytes, and its capability's slot, with every
/// right.
pub fn ws_obj(sc: &mut Scratch, bits: u8) -> (SlotRef, Ws) {
    let s = sc.make(ObjectType::WaitSet(bits));
    (s, wsc(s))
}

/// The wait set the capability in `s` names, by `kipc`'s name for it.
pub fn wsc(s: SlotRef) -> Ws {
    ws_cap(&cap::cap(s))
        .unwrap_or_else(|e| panic!("slot {:#x}: {e:?}", s.0))
        .0
}

/// A copy of the capability in `s`, with only `rights`.
pub fn copy_with(sc: &mut Scratch, s: SlotRef, rights: kcap::rights::Rights) -> SlotRef {
    let c = sc.take();
    cap::mint(s, c, rights, kcap::ops::MintData::None).unwrap();
    c
}

/// Checks the eventcount invariants over the eventcounts and wait sets in
/// the slots given and the threads, and donation's over the threads
/// (test builds).
pub fn check_ec(ecs: &[SlotRef], sets: &[SlotRef], threads: &[Tcb]) {
    let mut es = [Ec(0); 16];
    for (i, &e) in ecs.iter().enumerate() {
        es[i] = ecc(e);
    }
    let mut ws = [Ws(0); 16];
    for (i, &w) in sets.iter().enumerate() {
        ws[i] = wsc(w);
    }
    if let Err(v) = super::eventcount::check(&es[..ecs.len()], &ws[..sets.len()], threads) {
        panic!("eventcount invariant broken: {v:?}");
    }
    if let Err(v) = donation::check(threads, &[], &[]) {
        panic!("donation invariant broken: {v:?}");
    }
}

/// The threads queued on the endpoint in `ep`, in the order they are
/// served: the first `n`, and how many there are.
pub fn queue<const N: usize>(ep: SlotRef) -> ([Tcb; N], usize) {
    let mut out = [Tcb(0); N];
    let n = endpoint::queued(epc(ep).ep.0, &mut out);
    (out, n)
}

/// How many threads are queued on the endpoint in `ep`.
pub fn queue_len(ep: SlotRef) -> usize {
    queue::<1>(ep).1
}

/// The `i`th thread queued on the endpoint in `ep`, if there are that many.
pub fn queued_at(ep: SlotRef, i: usize) -> Option<Tcb> {
    let (q, n) = queue::<512>(ep);
    (i < n).then(|| q[i])
}

/// Checks the endpoint invariants over the endpoints in `eps` and the
/// threads given, and donation's over the threads, the reply objects and
/// no context (test builds).
pub fn check(eps: &[SlotRef], threads: &[Tcb], replies: &[Reply]) {
    let mut es = [0u64; 16];
    for (i, &e) in eps.iter().enumerate() {
        es[i] = match cap::cap(e) {
            Cap::Endpoint { ptr, .. } => ptr,
            c => panic!("{c:x?} isn't an endpoint"),
        };
    }
    if let Err(v) = endpoint::check(&es[..eps.len()], threads) {
        panic!("endpoint invariant broken: {v:?}");
    }
    let mut rs = [Rp(0); 64];
    for (i, r) in replies.iter().enumerate() {
        rs[i] = Rp(r.0);
    }
    if let Err(v) = donation::check(threads, &rs[..replies.len()], &[]) {
        panic!("donation invariant broken: {v:?}");
    }
}

/// A scratch space of at least `2^bits` bytes, with room made on the boot
/// core and an empty log.
pub fn scratch(bits: u8) -> Scratch {
    make_room();
    report::clear();
    Scratch::new(bits)
}

/// `n` objects of type `ty` in a CNode of radix 9 made in the scratch
/// space, and the CNode's first slot.
pub fn many(sc: &mut Scratch, ty: ObjectType, n: u64) -> SlotRef {
    let cn = sc.make(ObjectType::CNode(9));
    let mut first = 0;
    while first < n {
        let k = (n - first).min(kcap::RETYPE_FAN_OUT);
        cap::retype(sc.ram, ty, cn, first, k)
            .unwrap_or_else(|e| panic!("can't make {n} {ty:?}: {e:?}"));
        first += k;
    }
    match cap::cap(cn) {
        Cap::CNode { ptr, .. } => SlotRef(ptr),
        c => panic!("{c:x?}"),
    }
}

/// The first slot of the CNode in `cn`.
pub fn slots_of(cn: SlotRef) -> SlotRef {
    match cap::cap(cn) {
        Cap::CNode { ptr, .. } => SlotRef(ptr),
        c => panic!("{c:x?} isn't a CNode"),
    }
}

/// The online cores other than this one; None, after the skip line, if
/// fewer than `need` other cores are online.
pub fn others(need: usize) -> Option<impl Iterator<Item = usize> + Clone> {
    let me = this_core().index;
    let it = (0..kirq::MAX_CORES).filter(move |&k| k != me && crate::smp::is_online(k));
    if it.clone().count() < need {
        crate::uart::write("  (too few cores: skipped)\n");
        return None;
    }
    Some(it)
}
