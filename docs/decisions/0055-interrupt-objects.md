<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0055. Interrupt objects for user-space drivers

- **Status:** Proposed
- **Date:** 2026-11-25

## Context

Interrupts are kernel objects ([0002](0002-capability-security-model.md), rule 1), and drivers run in user space ([kernel view](../design/kernel-components.md)). The Pi 4 adds a Broadcom second-level controller to its GIC-400 ([0007](0007-initial-hardware-targets.md), Consequences). virtio devices sit on PCIe ([0036](0036-qemu-configuration-and-test-builds.md), rule 2), and PCIe devices use MSI. On QEMU `virt`, MSIs go through a GICv2m frame with a GICv2, and through the ITS with a GICv3. The Pi 4's GIC-400 has no GICv2m frame. On the BCM2711, the PCIe root complex is its own MSI controller: it collects MSIs and raises one shared peripheral interrupt at the GIC.

The [design backlog, D21](../design/design-backlog.md#m2-kernel-objects) asks what an interrupt object signals, how a driver acknowledges it, how MSI works, and where the Pi 4's second-level controller is handled. Its options are an eventcount, or an endpoint notification as in seL4.

seL4 gives the root task an IRQ control capability, from which it makes a handler capability for each interrupt line. The handler is bound to a notification, which the kernel signals when the interrupt fires, with the line masked. The driver acknowledges through the handler, which unmasks the line. [0053](0053-eventcounts.md) replaces notifications with eventcounts, and rule 8 there has interrupts advance one.

The GICv3 ITS reads tables in memory: a command queue, device and collection tables, and a translation table for each device. The redistributors read LPI tables, which can't change while LPIs are enabled.

This record gives the decisions and what they guarantee. The mechanism is in the [kernel specification](../design/kernel-specification.md) ([0047](0047-the-kernel-follows-sel4.md), rule 5), which also lists what is still open.

Claude drafted this record from the project owner's choices of 2026-11-25.

## Decision

1. **The root server holds the interrupt control capability.** From it, a holder makes one handler capability for each interrupt: a shared peripheral interrupt, or an MSI (rule 4). The kernel keeps software-generated interrupts and the timer's private interrupt for itself ([0051](0051-scheduling-timers-and-deadlines.md), rule 4; [0052](0052-smp-bring-up-and-the-kernel-lock.md), rule 4).
2. **A handler signals an eventcount.** The driver binds the handler to an eventcount through a capability to it with the write right, because the kernel then advances it on the driver's behalf ([0049](0049-capability-spaces-rights-and-revocation.md), rule 2; [0053](0053-eventcounts.md), rule 8). When the interrupt fires, the kernel masks it, if it is level-triggered, and advances the eventcount by one. The waking runs in bounded batches, so a widely watched eventcount can't hold the kernel lock for long ([0052](0052-smp-bring-up-and-the-kernel-lock.md), rule 2). The [kernel specification](../design/kernel-specification.md#interrupt-handlers) gives the handler's operations.
3. **The driver acknowledges through the handler.** Acknowledging unmasks the interrupt. A driver usually waits on the eventcount, or has it bound to its thread ([0053](0053-eventcounts.md), rule 5), services the device, and then acknowledges.
4. **The kernel manages MSI where the GIC receives it.** With a GICv2, it uses the GICv2m frame the device tree describes. With a GICv3, it uses the ITS, and keeps the ITS's command queue and tables itself, because every MSI on the machine shares them. The kernel picks each MSI's vector and gives the driver the address and data to program; the PCIe driver (C20) programs the device. Four guarantees hold ([kernel specification](../design/kernel-specification.md#msi-and-the-gicv3-its)):
   - **The kernel allocates no memory for MSI after boot** ([0048](0048-kernel-memory-and-address-spaces.md), rule 1). The redistributors' LPI tables come from memory the kernel takes at boot, sized for a number of LPIs fixed at boot, and last until the node stops. The ITS's tables are kernel objects made from untyped memory the caller supplies. The root server supplies the shared tables from the root job's memory before the first MSI through the ITS. A request for a new device's MSIs supplies that device's translation table.
   - **Each ITS table belongs to the job whose untyped memory it is made from**, and counts against it ([0058](0058-jobs-and-budgets.md), rule 5).
   - **The hardware never reads memory that has become another object.** Before the kernel frees a device's translation table, whether it is deleted directly, or the memory it was made from is revoked, or its job ends, it unmaps the device in the ITS and waits for the ITS to finish. The device's handler capabilities then stop working.
   - **The ITS's shared tables can't be deleted while the ITS uses them.** A deletion of the command queue, the device table or the collection table fails, directly or through a revocation, so in practice they last until the node stops. This is an exception to a revocation that deletes every descendant ([0049](0049-capability-spaces-rights-and-revocation.md), rule 4). How such a revocation reports it is open in the kernel specification.
5. **Interrupt controllers beyond the GIC are handled in user space.**
   - **The Pi 4's second-level controller.** Its summary interrupt reaches the kernel through the GIC like any other. A user-space driver reads the controller, and advances an eventcount for each source that fired, which the drivers of those devices wait on. That driver comes with C63.
   - **MSI controllers outside the GIC**, such as the BCM2711's PCIe root complex, are handled the same way. The root complex's MSI interrupt is a shared peripheral interrupt with a handler like any other. The PCIe driver programs devices with the root complex's own MSI address and data, and advances an eventcount for each device's MSI.
   - **The kernel keeps every GIC frame it drives**: the GICv2 distributor and CPU interface, and the GICv2m frame; or the GICv3 distributor, redistributors and ITS. None of them is given out as device untyped memory ([0048](0048-kernel-memory-and-address-spaces.md), rules 1 and 4), so no user-space program can map them, raise an interrupt through a doorbell, or program the ITS.

## Consequences

- **D21 is settled.** Every item it asked for is decided here. The kernel specification lists the details still open: how the number of LPIs is chosen, the ITS's table sizes, how an MSI request names its device, which core an interrupt targets, what bounds a wait for the ITS, and how a revocation that meets an ITS table reports it.
- **Drivers use one primitive.** An interrupt is an eventcount, so a driver can wait on it with other eventcounts, or with its requests in one call. The count tells it how many interrupts fired since it last looked.
- **The kernel knows two controllers**, GICv2 and GICv3, with GICv2m and the ITS. On the Pi 4, a PCIe device's interrupt costs one more hop, through a user-space driver.
- **The ITS's memory is paid for by those who use it**, and ending a driver's job is safe for the ITS (rule 4).
- **The number of LPIs is fixed at boot.** Adding LPIs needs a reboot.
- **A shared interrupt line has one handler.** A driver that serves several devices on one line shares it among them itself.

## References

- [seL4 reference manual, 17.0.0: interrupts](https://docs.sel4.systems/releases/sel4/17.0.0)
- [Arm GIC architecture specification, GICv3 and GICv4 (IHI 0069), issue H.b](https://developer.arm.com/documentation/ihi0069/latest): the ITS
- [Arm GIC architecture specification, version 2.0 (IHI 0048), issue B.b](https://developer.arm.com/documentation/ihi0048/latest): the GICv2, which the GIC-400 implements
- [Arm Base System Architecture 1.2 (DEN 0094), issue E](https://developer.arm.com/documentation/den0094/latest), appendix I: GICv2m. GICv2m was earlier an appendix of the Server Base System Architecture (DEN 0029), which Arm has since split into the BSA and a slimmer SBSA.
- [Linux `bcm2711.dtsi`](https://github.com/torvalds/linux/blob/master/arch/arm/boot/dts/broadcom/bcm2711.dtsi): the PCIe root complex as its own MSI controller (`msi-controller`, and its `msi` interrupt, SPI 148)
- [Kernel specification](../design/kernel-specification.md): interrupt handlers, MSI and the GICv3 ITS
- [0053. Eventcounts](0053-eventcounts.md); [0007. Initial hardware targets](0007-initial-hardware-targets.md); [0048. Kernel memory](0048-kernel-memory-and-address-spaces.md); [0052. SMP and the kernel lock](0052-smp-bring-up-and-the-kernel-lock.md); [0058. Jobs and budgets](0058-jobs-and-budgets.md)
