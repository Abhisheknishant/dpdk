/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#ifndef _RTE_BPF_EVENTDEV_H_
#define _RTE_BPF_EVENTDEV_H_

/**
 * @file rte_bpf_eventdev.h
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * API to install BPF filter as Enqueue/Dequeue callbacks for event devices.
 * Note that right now:
 * - it is not MT safe, i.e. it is not allowed to do load/unload for the
 *   same device from different threads in parallel.
 * - though it allows to do load/unload at runtime
 *   (while Enqueue/Dequeue is ongoing on given device).
 * - allows only one BPF program per device,
 * i.e. new load will replace previously loaded for that device BPF program.
 * Filter behaviour - if BPF program returns zero value for a given event,
 * then it will be dropped inside callback and no further processing
 *   on Enqueue - it will be dropped inside callback and no further processing
 *   for that event will happen.
 *   on Dequeue - packet will remain unsent, and it is responsibility of the
 *   user to handle such situation (drop, try to send again, etc.).
 */

#include <rte_bpf.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	RTE_BPF_EVENT_F_NONE = 0,
	RTE_BPF_EVENT_F_JIT  = 0x1, /*< use compiled into native ISA code */
};

/**
 * Unload previously loaded BPF program (if any) from given event-port
 * and remove appropriate pre-enqueue event-port callback.
 *
 * @param device
 *  The identifier of the event device
 * @param port
 *  The identifier of the port for event device
 */
void __rte_experimental
rte_bpf_event_enq_unload(uint8_t device, uint8_t port);

/**
 * Unload previously loaded BPF program (if any) from given event-port
 * and remove appropriate post-dequeue event-port callback.
 *
 * @param device
 *  The identifier of the event device
 * @param port
 *  The identifier of the port for event device
 */
void __rte_experimental
rte_bpf_event_deq_unload(uint8_t device, uint8_t port);

/**
 * Load BPF program from the ELF file and install callback to execute it
 * on given event device-port for pre-enqueue.
 *
 * @param device
 *  The identifier of the event device
 * @param port
 *  The identifier of the event-port
 * @param prm
 *  Parameters used to create and initialise the BPF exeution context.
 * @param fname
 *  Pathname for a ELF file.
 * @param sname
 *  Name of the executable section within the file to load.
 * @param flags
 *  Flags that define expected behavior of the loaded filter
 *  (i.e. jited/non-jited version to use).
 * @return
 *   Zero on successful completion or negative error code otherwise.
 */
int __rte_experimental
rte_bpf_event_enq_elf_load(uint8_t device, uint8_t port,
	const struct rte_bpf_prm *prm, const char *fname, const char *sname,
	uint32_t flags);

/**
 * Load BPF program from the ELF file and install callback to execute it
 * on given device-port for post-dequeue.
 *
 * @param device
 *  The identifier of the event device.
 * @param port
 *  The identifier of the event-port
 * @param prm
 *  Parameters used to create and initialise the BPF exeution context.
 * @param fname
 *  Pathname for a ELF file.
 * @param sname
 *  Name of the executable section within the file to load.
 * @param flags
 *  Flags that define expected expected behavior of the loaded filter
 *  (i.e. jited/non-jited version to use).
 * @return
 *   Zero on successful completion or negative error code otherwise.
 */
int __rte_experimental
rte_bpf_event_deq_elf_load(uint8_t device, uint8_t port,
	const struct rte_bpf_prm *prm, const char *fname, const char *sname,
	uint32_t flags);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_BPF_EVENTDEV_H_ */
