// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The kernel's interrupt controller (C13a; ADR 0007, rules 1 and 2;
//! ADR 0052, rule 4; ADR 0055, rule 1; kernel specification, "The kernel's
//! interrupt controller" and "Cross-core signals and TLB maintenance").
//!
//! [`init`] finds the GIC's version and frames in the device tree, through
//! the layout `mm` recorded and mapped, and each core's affinity in the
//! `/cpus` node. It sets up the distributor and the boot core's interface.
//! The kernel then takes IRQs at EL1 only inside two assembly windows,
//! [`window`] and [`wait`], and one interrupt per entry ([`handle`]): its
//! three SGIs ([`Sgi`]), the virtual timer, and anything else as unclaimed,
//! which is disabled and logged. An INTID beyond the distributor's lines
//! (an extended PPI or SPI, or an LPI) is logged and ended, never indexed
//! into the per-line registers. FIQs are never used: `PSTATE.F` stays set.
//!
//! The pure parts, register layouts, the device tree's GIC node, the
//! redistributor walk, the SGI encodings and the dispatch, are in the
//! `kirq` crate, which is tested on the host.
//!
//! [`init`] runs on the boot core before any other core starts, and each
//! secondary core calls [`Irq::init_cpu`] for itself as it starts (C12;
//! `crate::smp::start`). After [`init`], the static is only ever read,
//! through shared references, so the IRQ path and the panic path never meet
//! a mutable one, on any core. The interrupt counts are kept per core
//! ([`stats_of`]). On a GICv3, a core that panics before its own `init_cpu`
//! sends no stop ([`send_stop_to_others`]); the secondary entry sets
//! `ICC_SRE_EL2.Enable` on a core entered at EL2 before the kernel runs
//! there, as the stub does on the boot core.

mod arch;
mod gicv2;
mod gicv3;
#[cfg(aspis_test_build)]
mod tests;

use crate::mm::BootCell;
use arch::Mmio;
use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use gicv2::GicV2;
use gicv3::GicV3;
use kirq::MAX_CORES;
use kirq::affinity::Affinity;
use kirq::dispatch::{Action, classify};
use kirq::dt;
use kirq::intid::Intid;
use kirq::layout::{Frame, GicKind};
use kirq::redist::{self, RedistRegs};
use kirq::regs::{self, gicr};
use kirq::sgi::{SgiError, V2Target, V3Target};

pub use kirq::sgi::Sgi;

/// The cores the device tree names, by index, and which one booted.
pub struct Cores {
    affinity: [Affinity; MAX_CORES],
    len: usize,
    boot: usize,
}

impl Cores {
    pub fn len(&self) -> usize {
        self.len
    }

    /// The boot core's index: the core the stub ran on.
    pub fn boot(&self) -> usize {
        self.boot
    }

    pub fn affinity(&self, core: usize) -> Affinity {
        self.affinity[..self.len][core]
    }

    pub fn index_of(&self, a: Affinity) -> Option<usize> {
        self.affinity[..self.len].iter().position(|&x| x == a)
    }

    /// Every enabled cpu node under `/cpus` ([`is_cpu`]), in order. Each
    /// core's per-core data is by its index here (`crate::sched::percore`).
    fn from_device_tree(fdt: &fdt::Fdt<'_>) -> Cores {
        let Some(cpus) = fdt.find_node("/cpus") else {
            panic!("the device tree has no /cpus node");
        };
        let cells = cpus
            .property("#address-cells")
            .and_then(|p| dt::be_u32(p.value))
            .unwrap_or(2);
        let mut c = Cores {
            affinity: [Affinity::default(); MAX_CORES],
            len: 0,
            boot: 0,
        };
        for n in cpus.children() {
            if !is_cpu(&n) {
                continue;
            }
            let Some(a) = n
                .property("reg")
                .and_then(|p| dt::cpu_affinity(p.value, cells))
            else {
                panic!("cpu node {} has a reg the kernel can't read", n.name);
            };
            if c.len == MAX_CORES {
                panic!(
                    "the device tree has more than {MAX_CORES} enabled cpus, more than the kernel's core table holds"
                );
            }
            c.affinity[c.len] = a;
            c.len += 1;
        }
        let me = Affinity::from_mpidr(arch::mpidr());
        c.boot = c.index_of(me).unwrap_or_else(|| {
            panic!(
                "the boot core, affinity {:#x}, has no enabled cpu node",
                me.mpidr()
            )
        });
        c
    }
}

/// Whether a child of `/cpus` is an enabled core: `device_type` "cpu", and
/// a `status` that is absent or "okay".
pub fn is_cpu(n: &fdt::node::FdtNode<'_, '_>) -> bool {
    n.property("device_type").and_then(|p| p.as_str()) == Some("cpu")
        && dt::is_enabled(n.property("status").map(|p| p.value))
}

/// How many enabled cores the device tree names, at most [`MAX_CORES`]:
/// what `mm::init` maps per-core slots for, before the seal (kernel
/// specification, "Boot memory"). [`init`] builds the core table from the same nodes.
pub fn count_cores(fdt: &fdt::Fdt<'_>) -> usize {
    fdt.find_node("/cpus")
        .map_or(1, |cpus| cpus.children().filter(|n| is_cpu(n)).count())
        .clamp(1, MAX_CORES)
}

/// Whom an SGI goes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// The core with this index in the core table.
    Core(usize),
    /// Every core but this one.
    AllButSelf,
}

/// Why an SGI wasn't sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// [`init`] hasn't finished.
    NotReady,
    /// No core has that index.
    NoSuchCore,
    /// A GICv2 core that hasn't set up its interface yet, so its mask
    /// isn't known. Its `init_cpu` records it as the core starts.
    NotStarted,
    Sgi(SgiError),
}

enum Gic {
    V2(GicV2),
    V3(GicV3),
}

/// The interrupt controller and the cores it serves.
pub struct Irq {
    gic: Gic,
    cores: Cores,
}

/// Set once [`init`] has begun, and once it has finished.
static INIT: AtomicBool = AtomicBool::new(false);
static READY: AtomicBool = AtomicBool::new(false);
static IRQ: BootCell<Option<Irq>> = BootCell::new(None);

/// The interrupt controller, once [`init`] has finished.
pub fn get() -> Option<&'static Irq> {
    if !READY.load(Ordering::Acquire) {
        return None;
    }
    // SAFETY: `init` wrote the static before it set READY, and nothing
    // writes it again; every later reference is shared.
    unsafe { IRQ.get() }.as_ref()
}

/// The longest spin on a GIC status bit: far beyond the few register
/// accesses a write takes to complete, and bounded, so the kernel never
/// waits on hardware forever (kernel specification, "The kernel's interrupt
/// controller").
const WAIT_SPINS: u32 = 1 << 20;

/// Spins until `done`, at most [`WAIT_SPINS`] times, and panics naming the
/// bit `what` if it never is.
fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    for _ in 0..WAIT_SPINS {
        if done() {
            return;
        }
        core::hint::spin_loop();
    }
    panic!("the GIC's {what} didn't clear in time");
}

/// The redistributors' identification registers, at physical addresses
/// that the device window maps.
struct MappedRedists;

impl RedistRegs for MappedRedists {
    fn pidr2(&mut self, rd: u64) -> u32 {
        redist_frame(rd).read32(gicr::PIDR2)
    }
    fn typer(&mut self, rd: u64) -> u64 {
        redist_frame(rd).read64(gicr::TYPER)
    }
}

/// The redistributor at physical `RD_base` `rd`: its `RD_base` and
/// `SGI_base` frames.
fn redist_frame(rd: u64) -> Mmio {
    map(
        Frame {
            base: rd,
            size: gicr::SIZE,
        },
        "a redistributor",
    )
}

/// A frame of the GIC, as the device window maps it.
fn map(f: Frame, what: &str) -> Mmio {
    let Some(va) = crate::mm::device_va(f.base, f.size) else {
        panic!(
            "the interrupt controller's {what} at {:#x} isn't mapped",
            f.base
        );
    };
    // SAFETY: `mm::init` mapped the whole frame as device memory,
    // read-write, in the device window, which never changes.
    unsafe { Mmio::new(va, f.size as usize) }
}

/// Finds and sets up the interrupt controller (kernel specification, "The
/// kernel's interrupt controller"): checks its version, sets up the
/// distributor, then the boot core's redistributor and CPU interface. Any
/// failure stops the boot. Runs once, after `mm::init` and before anything
/// unmasks interrupts.
pub fn init(fdt: Option<&fdt::Fdt<'_>>) {
    assert!(!INIT.swap(true, Ordering::Relaxed), "irq::init runs twice");
    let (Some(fdt), Some(layout)) = (fdt, crate::mm::gic_layout()) else {
        // `mm::init` stops the boot first, without a device tree or a GIC.
        panic!("no interrupt controller");
    };
    let cores = Cores::from_device_tree(fdt);
    let sysregs = regs::cpu_has_gic_sysregs(arch::id_aa64pfr0());
    let gic = match (layout.kind, layout.cpu) {
        (GicKind::V2, Some(cpu)) => {
            let g = GicV2::new(map(layout.dist, "distributor"), map(cpu, "CPU interface"));
            // GICD_PIDR2 is implementation defined on a GICv2, and a CPU
            // may have the GIC system registers while wired to a GIC-400:
            // neither stops the boot.
            let rev = g.arch_rev();
            if !matches!(rev, 1 | 2) {
                crate::klog!(
                    Notice,
                    "interrupts",
                    "the GICv2's PIDR2 says architecture revision {rev}"
                );
            }
            Gic::V2(g)
        }
        (GicKind::V2, None) => panic!("the GICv2 has no CPU interface"),
        (GicKind::V3, _) => {
            if !sysregs {
                panic!("the device tree names a GICv3, but the CPU has no GIC system registers");
            }
            let dist = map(layout.dist, "distributor");
            let rev = regs::arch_rev(dist.read32(regs::gicd::PIDR2_V3));
            if !matches!(rev, 3 | 4) {
                panic!(
                    "the device tree names a GICv3, but its PIDR2 says architecture revision {rev}"
                );
            }
            let mut rd = [None; MAX_CORES];
            for (i, slot) in rd.iter_mut().enumerate().take(cores.len()) {
                let a = cores.affinity(i);
                let Some(pa) = redist::find(
                    layout.redistributor_regions(),
                    layout.stride,
                    &mut MappedRedists,
                    a,
                ) else {
                    panic!(
                        "the core with affinity {:#x} has no redistributor",
                        a.mpidr()
                    );
                };
                *slot = Some(redist_frame(pa));
            }
            Gic::V3(GicV3::new(dist, rd))
        }
    };
    let irq = Irq { gic, cores };
    irq.init_dist();
    let found = irq.init_cpu(irq.cores.boot());
    log_cpu_init(irq.cores.boot(), found);
    irq.prepare_stop();
    let (name, lines, n) = (
        match irq.gic {
            Gic::V2(_) => "GICv2",
            Gic::V3(_) => "GICv3",
        },
        irq.lines(),
        irq.cores.len(),
    );
    // SAFETY: once, at boot, before READY: nothing else holds a reference.
    unsafe { *IRQ.get_mut() = Some(irq) };
    READY.store(true, Ordering::Release);
    crate::klog!(
        Info,
        "interrupts",
        "{name}, {lines} lines, distributor at {:#x}; {n} {} in the device tree, booted on core {}",
        layout.dist.base,
        if n == 1 { "core" } else { "cores" },
        get().map_or(0, |i| i.cores.boot())
    );
}

/// What setting up one core's interface found, for [`log_cpu_init`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuInit {
    /// The GICv3 redistributor's LPIs stayed enabled when cleared: whether
    /// `GICR_CTLR.EnableLPIs` can be cleared is implementation defined.
    pub lpis_stuck: bool,
}

/// Logs what [`Irq::init_cpu`] found on core `core`. Called with the
/// kernel lock held, or on the boot core before any other core runs.
pub fn log_cpu_init(core: usize, found: CpuInit) {
    if found.lpis_stuck {
        crate::klog!(
            Notice,
            "interrupts",
            "core {core}'s redistributor has LPIs enabled, and won't disable them"
        );
    }
}

impl Irq {
    pub fn cores(&self) -> &Cores {
        &self.cores
    }

    pub fn is_v3(&self) -> bool {
        matches!(self.gic, Gic::V3(_))
    }

    /// The interrupt lines the distributor has, SGIs and PPIs included.
    pub fn lines(&self) -> u32 {
        match &self.gic {
            Gic::V2(g) => g.lines(),
            Gic::V3(g) => g.lines(),
        }
    }

    /// This core's index in the core table.
    pub fn this_core(&self) -> usize {
        let me = Affinity::from_mpidr(arch::mpidr());
        match self.cores.index_of(me) {
            Some(i) => i,
            None => panic!(
                "this core, affinity {:#x}, isn't in the core table",
                me.mpidr()
            ),
        }
    }

    fn init_dist(&self) {
        match &self.gic {
            Gic::V2(g) => g.init_dist(),
            Gic::V3(g) => g.init_dist(&self.cores),
        }
    }

    /// Sets up core `core`'s part of the GIC: on a GICv2 its banked
    /// distributor registers and CPU interface, recording its mask; on a
    /// GICv3 its redistributor, woken, and its system-register CPU
    /// interface. It runs on that core: the boot core in [`init`], and each
    /// secondary core as it starts, before it is online, so that the core's
    /// SGIs are Group 1 and enabled (`crate::smp::start`).
    ///
    /// It writes no log record: a secondary core doesn't hold the kernel
    /// lock yet, and every record but the panic path's is written under it.
    /// So it returns what the caller logs once it may, [`log_cpu_init`].
    #[must_use]
    pub fn init_cpu(&self, core: usize) -> CpuInit {
        assert_eq!(
            core,
            self.this_core(),
            "a core's interface is set up from that core"
        );
        match &self.gic {
            Gic::V2(g) => {
                g.init_cpu(core);
                CpuInit { lpis_stuck: false }
            }
            Gic::V3(g) => CpuInit {
                lpis_stuck: g.init_cpu(core),
            },
        }
    }

    /// Acknowledges the highest-priority pending interrupt: the raw value
    /// the end of interrupt repeats, and its INTID.
    fn ack(&self) -> (u32, Intid) {
        match &self.gic {
            Gic::V2(g) => {
                let raw = g.ack();
                (raw, GicV2::intid(raw))
            }
            Gic::V3(g) => {
                let raw = g.ack();
                (raw, Intid(raw))
            }
        }
    }

    fn eoi(&self, raw: u32) {
        match &self.gic {
            Gic::V2(g) => g.eoi(raw),
            Gic::V3(g) => g.eoi(raw),
        }
    }

    /// Enables interrupt `i`: an SGI or PPI at this core, or an SPI.
    pub fn enable(&self, i: Intid) {
        match &self.gic {
            Gic::V2(g) => g.enable(i),
            Gic::V3(g) => g.enable(i, self.this_core()),
        }
    }

    pub fn disable(&self, i: Intid) {
        match &self.gic {
            Gic::V2(g) => g.disable(i),
            Gic::V3(g) => g.disable(i, self.this_core()),
        }
    }

    pub fn is_enabled(&self, i: Intid) -> bool {
        match &self.gic {
            Gic::V2(g) => g.is_enabled(i),
            Gic::V3(g) => g.is_enabled(i, self.this_core()),
        }
    }

    pub fn is_pending(&self, i: Intid) -> bool {
        match &self.gic {
            Gic::V2(g) => g.is_pending(i),
            Gic::V3(g) => g.is_pending(i, self.this_core()),
        }
    }

    /// Sends `sgi` to `target`.
    pub fn send_sgi(&self, sgi: Sgi, target: Target) -> Result<(), SendError> {
        match &self.gic {
            Gic::V2(g) => g.send(g.sgir(sgi, target, self.this_core(), &self.cores)?),
            Gic::V3(g) => g.send(g.sgi1r(sgi, target, &self.cores)?),
        }
        Ok(())
    }
}

/// Sends `sgi` to `target`. Two register writes and a barrier: no lock, no
/// allocation.
pub fn send_sgi(sgi: Sgi, target: Target) -> Result<(), SendError> {
    get().ok_or(SendError::NotReady)?.send_sgi(sgi, target)
}

/// A core's interrupt counts (C12 keeps one set per core).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Acknowledges that returned a special INTID (1020 to 1023).
    pub spurious: u64,
    pub remote_call: u64,
    pub reschedule: u64,
    pub stop: u64,
    /// The virtual timer's interrupt, with the timer asserting it.
    pub timer: u64,
    /// The timer's interrupt taken after the timer stopped asserting it:
    /// its line dropped late, after an earlier end of interrupt. Nothing
    /// is done for it.
    pub stale_timer: u64,
    /// Interrupts with no use or handler, disabled and logged.
    pub unclaimed: u64,
    /// INTIDs beyond the distributor's lines, logged and ended.
    pub extended: u64,
}

struct Counters {
    spurious: AtomicU64,
    remote_call: AtomicU64,
    reschedule: AtomicU64,
    stop: AtomicU64,
    timer: AtomicU64,
    stale_timer: AtomicU64,
    unclaimed: AtomicU64,
    extended: AtomicU64,
}

static COUNTERS: [Counters; MAX_CORES] = [const {
    Counters {
        spurious: AtomicU64::new(0),
        remote_call: AtomicU64::new(0),
        reschedule: AtomicU64::new(0),
        stop: AtomicU64::new(0),
        timer: AtomicU64::new(0),
        stale_timer: AtomicU64::new(0),
        unclaimed: AtomicU64::new(0),
        extended: AtomicU64::new(0),
    }
}; MAX_CORES];

/// This core's index in the core table, from its affinity; 0 before
/// [`init`].
fn me() -> usize {
    get().map_or(0, |i| {
        i.cores
            .index_of(Affinity::from_mpidr(arch::mpidr()))
            .unwrap_or(0)
    })
}

/// This core's counts.
pub fn stats() -> Stats {
    stats_of(me())
}

/// Core `core`'s counts.
pub fn stats_of(core: usize) -> Stats {
    let c = &COUNTERS[core.min(MAX_CORES - 1)];
    let r = |a: &AtomicU64| a.load(Ordering::Relaxed);
    Stats {
        spurious: r(&c.spurious),
        remote_call: r(&c.remote_call),
        reschedule: r(&c.reschedule),
        stop: r(&c.stop),
        timer: r(&c.timer),
        stale_timer: r(&c.stale_timer),
        unclaimed: r(&c.unclaimed),
        extended: r(&c.extended),
    }
}

fn count(a: &AtomicU64) {
    a.fetch_add(1, Ordering::Relaxed);
}

/// Set by a reschedule SGI, per core. The exit path reschedules at every
/// kernel entry anyway, so only the tests take it.
static RESCHEDULE: [AtomicBool; MAX_CORES] = [const { AtomicBool::new(false) }; MAX_CORES];

/// Whether a reschedule SGI arrived at this core since the last call,
/// clearing it.
pub fn take_reschedule() -> bool {
    RESCHEDULE[me()].swap(false, Ordering::Relaxed)
}

/// The cores that took the stop and halted. The panic path waits for it,
/// with a bound, and reports it.
pub static STOPPED: AtomicU32 = AtomicU32::new(0);

/// One bit per INTID below 1024 that has been logged as unclaimed, so each
/// is logged once.
static LOGGED: [AtomicU32; 32] = [const { AtomicU32::new(0) }; 32];
/// Whether an INTID beyond the lines has been logged: only the first is.
static EXTENDED_LOGGED: AtomicBool = AtomicBool::new(false);

/// Takes the highest-priority pending interrupt, if any, and acts on it:
/// one interrupt per entry, as seL4's `getActiveIRQ`. If more are pending,
/// the IRQ is taken again after the exception returns. It runs with every
/// exception masked, from the IRQ vector, and from tests.
pub fn handle() -> Action {
    let Some(irq) = get() else {
        // Interrupts stay masked until `init` has finished.
        count(&COUNTERS[0].spurious);
        return Action::Spurious;
    };
    let me = me();
    let counters = &COUNTERS[me];
    let (raw, intid) = irq.ack();
    let action = classify(intid, crate::timer::intid(), irq.lines());
    match action {
        // Nothing was acknowledged: no end of interrupt.
        Action::Spurious => {
            count(&counters.spurious);
            return action;
        }
        // The request is served where the core waits for the kernel lock,
        // which every entry from EL0 and the idle loop take
        // (`crate::smp::remote`): the SGI only brings the core there.
        Action::RemoteCall => count(&counters.remote_call),
        Action::Reschedule => {
            count(&counters.reschedule);
            RESCHEDULE[me].store(true, Ordering::Relaxed);
        }
        Action::Stop => {
            count(&counters.stop);
            irq.eoi(raw);
            #[cfg(aspis_test_build)]
            if STOP_INTERCEPT.swap(false, Ordering::Relaxed) {
                // A test shows the stop's path on one core: everything
                // but the halt.
                STOPPED.fetch_add(1, Ordering::Relaxed);
                return action;
            }
            stop_this_core();
        }
        // The timer disarms itself before the end of interrupt below.
        Action::Timer => count(if crate::timer::on_fire() {
            &counters.timer
        } else {
            &counters.stale_timer
        }),
        Action::Unclaimed(i) => {
            // As seL4 masks an interrupt with no bound notification.
            irq.disable(i);
            count(&counters.unclaimed);
            let word = (i.0 / 32) as usize;
            if word < LOGGED.len()
                && LOGGED[word].fetch_or(1 << (i.0 % 32), Ordering::Relaxed) & 1 << (i.0 % 32) == 0
            {
                crate::klog!(
                    Warning,
                    "interrupts",
                    "INTID {} has no handler; disabled",
                    i.0
                );
            }
        }
        // Not disabled: the per-line arrays don't cover it, and the kernel
        // disabled what it could at setup. The end of interrupt still drops
        // the priority, for an LPI too.
        Action::Extended(i) => {
            count(&counters.extended);
            if !EXTENDED_LOGGED.swap(true, Ordering::Relaxed) {
                crate::klog!(
                    Warning,
                    "interrupts",
                    "INTID {} is beyond the distributor's lines; ended, not disabled",
                    i.0
                );
            }
        }
    }
    irq.eoi(raw);
    action
}

/// In test builds, makes the next stop SGI this core takes count as a stop
/// and return, instead of halting, so a test can follow the stop's path on
/// one core.
#[cfg(aspis_test_build)]
pub static STOP_INTERCEPT: AtomicBool = AtomicBool::new(false);

/// What the panic path writes to send the stop: set by [`Irq::prepare_stop`]
/// at the end of [`init`], and only read after. [`STOP_KIND`] is written
/// last, with `Release`, and read first, with `Acquire`.
static STOP_KIND: AtomicU8 = AtomicU8::new(STOP_NONE);
static STOP_AT: AtomicU64 = AtomicU64::new(0);
static STOP_VALUE: AtomicU64 = AtomicU64::new(0);
const STOP_NONE: u8 = 0;
/// A GICv2: [`STOP_VALUE`] is written to `GICD_SGIR`, whose device-window
/// address is [`STOP_AT`].
const STOP_V2: u8 = 2;
/// A GICv3: [`STOP_VALUE`] is written to `ICC_SGI1R_EL1`.
const STOP_V3: u8 = 3;

impl Irq {
    /// Works out the one write that sends the stop SGI to every core but
    /// the sender, so the panic path needs no borrow, no lookup and no
    /// result: on a GICv2, `GICD_SGIR` with the all-but-self filter; on a
    /// GICv3, `ICC_SGI1R_EL1` with `IRM` set.
    fn prepare_stop(&self) {
        match &self.gic {
            Gic::V2(g) => {
                let Ok(v) = kirq::sgi::gicd_sgir(Sgi::Stop, V2Target::AllButSelf) else {
                    panic!("the stop SGI can't be encoded for a GICv2");
                };
                STOP_AT.store(g.dist().va(regs::gicd::SGIR), Ordering::Relaxed);
                STOP_VALUE.store(v.into(), Ordering::Relaxed);
                STOP_KIND.store(STOP_V2, Ordering::Release);
            }
            Gic::V3(_) => {
                let Ok(v) = kirq::sgi::icc_sgi1r(Sgi::Stop, V3Target::AllButSelf, false) else {
                    panic!("the stop SGI can't be encoded for a GICv3");
                };
                STOP_VALUE.store(v, Ordering::Relaxed);
                STOP_KIND.store(STOP_V3, Ordering::Release);
            }
        }
    }
}

/// Sends the stop SGI to every core but this one: the panic path's, after
/// it has written its report to the UART (ADR 0052, rule 4; kernel
/// specification, "Cross-core signals and TLB maintenance"). One barrier
/// and one write, worked out at [`init`]; no lock, no borrow, nothing that
/// can fail. Returns whether it was sent: not before [`init`] has
/// finished, nor on a GICv3 from a core whose system-register interface
/// isn't enabled yet, where the write would be undefined. It doesn't wait
/// for the others to stop; [`STOPPED`] counts them.
pub fn send_stop_to_others() -> bool {
    // The kind first: its Acquire orders the value's loads after it.
    let kind = STOP_KIND.load(Ordering::Acquire);
    let value = STOP_VALUE.load(Ordering::Relaxed);
    match kind {
        STOP_V2 => {
            let at = STOP_AT.load(Ordering::Relaxed) as *mut u32;
            arch::dsb_ishst();
            // SAFETY: `GICD_SGIR`, in the distributor's frame, which
            // `mm::init` mapped as device memory and never unmaps.
            unsafe { core::ptr::write_volatile(at, value as u32) };
        }
        // ICC_SRE_EL1 can be read at EL1 once EL2 has set
        // ICC_SRE_EL2.Enable, which the stub does, and the secondary entry
        // on each other core; SRE is set by this core's `init_cpu`.
        STOP_V3 if arch::icc_sre() & regs::icc::SRE_SRE != 0 => {
            arch::dsb_ishst();
            // SAFETY: this core's system-register interface is enabled, and
            // the value names the kernel's stop SGI, as Group 1.
            unsafe { arch::set_icc_sgi1r(value) };
            arch::isb();
        }
        _ => return false,
    }
    true
}

/// Stops this core for good: another core panicked (ADR 0052, rule 4).
pub fn stop_this_core() -> ! {
    // SAFETY: masking every exception.
    unsafe {
        asm!(
            "msr daifset, #0xf",
            options(nomem, nostack, preserves_flags)
        )
    };
    STOPPED.fetch_add(1, Ordering::Relaxed);
    crate::halt()
}

/// Whether an IRQ is pending at this core: `ISR_EL1.I`, which shows an IRQ
/// the GIC signals to this core, past its priority mask and running
/// priority, whether or not `PSTATE.I` masks it. It works alike on GICv2
/// and GICv3, needs no MMIO, and is the virtual IRQ under a hypervisor. It
/// doesn't show an interrupt of the same priority while one is active, so
/// preemption points never run inside [`handle`] (kernel specification,
/// "The kernel lock and long operations").
pub fn pending() -> bool {
    arch::isr() & regs::ISR_I != 0
}

/// The pending-interrupt check for the capability system's preemption
/// points ([`kcap::preempt::Pending`]).
#[derive(Clone, Copy, Debug, Default)]
pub struct IrqPending;

impl kcap::preempt::Pending for IrqPending {
    fn pending(&mut self) -> bool {
        pending()
    }
}

/// A critical section with IRQs masked, which puts `DAIF` back as it was
/// when dropped. It nests. The kernel runs with IRQs masked anyway (ADR
/// 0052, rule 2), and takes them only in [`window`] and [`wait`].
#[must_use]
pub struct Masked {
    daif: u64,
}

/// Masks IRQs until the guard is dropped. IRQs must be masked already: no
/// Rust runs with them unmasked at EL1, since the IRQ path saves no FP or
/// SIMD state ([`window`]), so finding them unmasked is a kernel bug, and
/// panics. So the guard never unmasks IRQs when it is dropped.
pub fn masked() -> Masked {
    let daif = arch::daif();
    assert!(
        daif & regs::DAIF_I != 0,
        "IRQs are unmasked outside the kernel's windows"
    );
    // SAFETY: masking IRQs. Not `nomem`: memory accesses stay on their side
    // of the mask.
    unsafe { asm!("msr daifset, #2", options(nostack, preserves_flags)) };
    Masked { daif }
}

impl Drop for Masked {
    fn drop(&mut self) {
        // SAFETY: restores the masks `masked` found, with `I` set, as
        // `masked` checked: this never unmasks IRQs, so no Rust runs with
        // them unmasked.
        unsafe {
            asm!(
                "msr daif, {}",
                in(reg) self.daif | regs::DAIF_I,
                options(nostack, preserves_flags)
            )
        };
    }
}

/// Takes every IRQ pending now, then masks IRQs again: one of the two
/// places the kernel takes IRQs at EL1 (kernel specification, "The kernel's
/// interrupt controller"). The `ISB` is a context synchronization event, so
/// an IRQ pending and unmasked is taken before it completes.
pub fn window() {
    // SAFETY: the IRQ vector saves and restores x0 to x30, ELR and SPSR,
    // and runs Rust that keeps the callee-saved registers under the C ABI.
    // `clobber_abi("C")`, with neither `nomem`, `readonly`, `pure` nor
    // `nostack`, tells the compiler that every caller-saved register (x0 to
    // x17, x30 and all of v0 to v31) and all memory may change, and that
    // the stack is in use. So the IRQ path saves no FP or SIMD state.
    unsafe {
        asm!(
            "msr daifclr, #2",
            "isb",
            "msr daifset, #2",
            clobber_abi("C")
        )
    };
}

/// Waits for an interrupt, then takes it and masks IRQs again, for the
/// tests: the scheduler's idle loop instead handles what is pending with
/// IRQs masked (`crate::sched::run`). WFI wakes on a pending interrupt even
/// while `PSTATE.I` masks it, and unmasking only after it avoids the
/// lost-wakeup race.
pub fn wait() {
    // SAFETY: as for `window`.
    unsafe {
        asm!(
            "wfi",
            "msr daifclr, #2",
            "isb",
            "msr daifset, #2",
            clobber_abi("C")
        )
    };
}

/// `DAIF` now, for tests.
#[cfg(aspis_test_build)]
pub fn daif() -> u64 {
    arch::daif()
}

/// Spins, with IRQs masked, until `cond` holds, for at most `counts` of the
/// clock, and says whether it did; for tests. On hardware, the GIC makes an
/// interrupt pending, and signals it to the core, some time after the
/// write that generates it, and a level line drops some time after its
/// source stops asserting it. Under TCG both happen at once.
#[cfg(aspis_test_build)]
pub fn spin_until(mut cond: impl FnMut() -> bool, counts: u64) -> bool {
    let start = crate::timer::now();
    loop {
        if cond() {
            return true;
        }
        if crate::timer::now() - start > counts {
            return false;
        }
        core::hint::spin_loop();
    }
}
