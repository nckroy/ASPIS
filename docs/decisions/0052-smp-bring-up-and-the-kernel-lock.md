<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0052. SMP: PSCI bring-up and one kernel lock

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

The Pi 4 has four cores ([0007](0007-initial-hardware-targets.md), rule 2), and QEMU `virt` runs with several. No record covers how the secondary cores start or how the kernel locks. The [design backlog, D18](../design/design-backlog.md#m2-kernel-objects) names PSCI `CPU_ON` on both firmwares, a big kernel lock first, and run queues per core.

PSCI is Arm's firmware interface for starting and stopping cores, and for resetting and powering off the machine. QEMU's `virt` machine offers it. On the Pi 4, [0007](0007-initial-hardware-targets.md), rule 2 allows two firmwares. The pftf/RPi4 EDK2 firmware includes Trusted Firmware-A, which offers PSCI. U-Boot on the Raspberry Pi firmware's default armstub starts cores through a spin table instead. ASPIS uses no UEFI runtime services ([0039](0039-no-uefi-runtime-services.md), rule 1), so firmware without PSCI would also leave the kernel no way to reboot, short of a watchdog driver.

seL4's SMP kernel takes one big lock. Its FAQ says that this suits a few tightly coupled cores that share an L2 cache, not many cores. Microkernel system calls are short, so one lock costs less than it would in a large kernel. But seL4 inserts into some ordered queues in linear time, such as its release queue and endpoint queues, so the time it holds the lock grows with their length.

This record gives the decisions and what they guarantee. The mechanism is in the [kernel specification](../design/kernel-specification.md) ([0047](0047-the-kernel-follows-sel4.md), rule 5), which also lists what is still open.

Claude drafted this record from the project owner's choice of seL4 as the model, on 2026-11-25. The project owner chose PSCI only, without spin tables, the same day.

## Decision

1. **Secondary cores start through PSCI `CPU_ON`**, with the conduit the device tree's `psci` node names, or on ACPI platforms the FADT's flags (C65). The kernel doesn't use spin tables, so a Pi 4 needs firmware with PSCI: pftf/RPi4, or U-Boot with Trusted Firmware-A as its armstub ([kernel specification](../design/kernel-specification.md#starting-secondary-cores)).
2. **The kernel takes one lock**, as seL4's SMP kernel does.
   - Every system call, fault and interrupt takes the lock on entry and releases it on exit. The kernel runs with interrupts masked, and is preemptible only at preemption points.
   - **A core waiting for the lock serves cross-core requests while it spins**, as seL4's lock does, so two cores never wait on each other.
   - **The lock is never held for unbounded time.** Three rules make it so:
     - **Long operations have preemption points**, as in seL4. Such an operation keeps its progress in the objects it works on, lets a pending interrupt in, and restarts where it stopped. The [kernel specification](../design/kernel-specification.md#the-kernel-lock-and-long-operations) lists every one.
     - **Work the kernel starts from an interrupt, such as the timer's, runs in bounded batches**, since no calling thread can restart it. So no interrupt holds the lock for unbounded time. The [kernel specification](../design/kernel-specification.md#the-kernel-lock-and-long-operations) lists that work and says where the rest of it runs ([K24](../design/kernel-specification.md#k24-batches-of-interrupt-work)).
     - **Every queue the kernel keeps in order inserts and removes in bounded or logarithmic time**, and an advance or a wake visits only the waiters it wakes. This departs from seL4's code, not its design ([kernel specification](../design/kernel-specification.md#ordered-kernel-queues)).
   - The log ring and the panic path take no lock ([0042](0042-log-ring-and-panic-path.md), rules 3 and 7), so a panic on one core is reported even while another holds the lock.
   - Finer locks come only when measurements show the lock is a bottleneck, and through an edit to this record.
3. **Each core has its own run queues.**
   - A thread runs on the core of the scheduling context it is running on ([0051](0051-scheduling-timers-and-deadlines.md), rule 1).
   - The kernel moves a thread to another core only when a donated scheduling context takes it to that context's core, as in seL4 MCS. A passive server therefore runs on its caller's core for each call ([0051](0051-scheduling-timers-and-deadlines.md), rule 3).
   - Otherwise a thread moves only by an explicit call, such as configuring its scheduling context for another core. The kernel never migrates threads to balance load.
4. **Cores signal each other with software-generated interrupts, and TLB maintenance needs none.**
   - Software-generated interrupts are the kernel's alone. It uses them to make another core reschedule, for cross-core requests, and to stop every core at a panic.
   - TLB maintenance uses the broadcast inner-shareable `TLBI` instructions, which reach every core and complete before the following `DSB ISH` does ([kernel specification](../design/kernel-specification.md#cross-core-signals-and-tlb-maintenance)).

## Consequences

- **D18 is settled.** How the secondary cores start and the locking model are both decided here.
- **The kernel's code stays simple.** Most of it runs as if on one core, which suits a first kernel and the QEMU matrix.
- **Interrupt latency is bounded** by the work between preemption points and the size of a batch, not by the size of a capability tree, a job or a queue. A job that makes many waiting threads can't slow other threads' queue operations in proportion.
- **Passive servers move between cores with their callers**, as in seL4 MCS. That costs cache locality, but needs no placement policy in the kernel. Placing threads on cores is user space's job.
- **Contention grows with cores.** Four cores are within what seL4's design expects. Cloud VMs with many cores (C81) may need finer locking, or one kernel per cluster of cores, decided then from measurements.
- **The Pi 4's firmware choice narrows.** U-Boot on the default armstub would start only one core, and couldn't reboot. C63 documents the setups that work: pftf/RPi4, and U-Boot with Trusted Firmware-A as its armstub. Reboot and power-off come from PSCI on every platform ([0039](0039-no-uefi-runtime-services.md), rule 3).

## References

- [Arm Power State Coordination Interface 1.3 (DEN 0022), issue F.b](https://developer.arm.com/documentation/den0022/latest)
- [Arm Architecture Reference Manual for A-profile (DDI 0487), issue M.d](https://developer.arm.com/documentation/ddi0487/latest): TLB maintenance instructions and the inner-shareable domain
- [Trusted Firmware-A: Raspberry Pi 4](https://trustedfirmware-a.readthedocs.io/en/latest/plat/rpi4.html): the stock device tree's spin tables, and TF-A's PSCI
- [seL4 FAQ: multicore](https://docs.sel4.systems/projects/sel4/frequently-asked-questions)
- seL4 17.0.0 source: [`include/smp/lock.h`](https://github.com/seL4/seL4/blob/17.0.0/include/smp/lock.h), where a core waiting for the lock serves remote calls; [`src/object/schedcontext.c`](https://github.com/seL4/seL4/blob/17.0.0/src/object/schedcontext.c), where donating a scheduling context moves the thread to its core; [`src/object/tcb.c`](https://github.com/seL4/seL4/blob/17.0.0/src/object/tcb.c), where `tcbReleaseEnqueue` inserts into the release queue in linear time
- Peters, Danis, Elphinstone, Heiser, "For a microkernel, a big lock is fine", APSys 2015, [doi:10.1145/2797022.2797042](https://doi.org/10.1145/2797022.2797042)
- [Kernel specification](../design/kernel-specification.md): starting secondary cores, the kernel lock and long operations, ordered kernel queues, cross-core signals
- [0007. Initial hardware targets](0007-initial-hardware-targets.md); [0042. Log ring and panic path](0042-log-ring-and-panic-path.md)
