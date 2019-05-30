/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#ifndef _RTE_IOAT_RAWDEV_H_
#define _RTE_IOAT_RAWDEV_H_

/**
 * @file rte_ioat_rawdev.h
 *
 * Definitions for using the ioat rawdev device driver
 *
 * @warning
 * @b EXPERIMENTAL: these structures and APIs may change without prior notice
 */

#include <x86intrin.h>

#include <rte_memory.h>
#include <rte_prefetch.h>
#include <rte_ioat_spec.h>

/** Name of the device driver */
#define IOAT_PMD_RAWDEV_NAME rawdev_ioat
/** String reported as the device driver name by rte_rawdev_info_get() */
#define IOAT_PMD_RAWDEV_NAME_STR "rawdev_ioat"
/** Name used to adjust the log level for this driver */
#define IOAT_PMD_LOG_NAME "rawdev.ioat"

/**
 * Configuration structure for an ioat rawdev instance
 *
 * This structure is to be passed as the ".dev_private" parameter when
 * calling the rte_rawdev_get_info() and rte_rawdev_configure() APIs on
 * an ioat rawdev instance.
 */
struct rte_ioat_rawdev_config {
	unsigned short ring_size;
};

/**
 * @internal
 * Structure representing a device instance
 */
struct rte_ioat_rawdev {
	struct rte_rawdev *rawdev;
	volatile struct rte_ioat_registers *regs;
	phys_addr_t status_addr;
	phys_addr_t ring_addr;

	unsigned short ring_size;
	struct rte_ioat_desc *desc_ring;
	__m128i *hdls; /* completion handles for returning to user */


	unsigned short next_read;
	unsigned short next_write;

	/* some statistics for tracking, if added/changed update xstats fns*/
	uint64_t enqueue_failed __rte_cache_aligned;
	uint64_t enqueued;
	uint64_t started;
	uint64_t completed;

	/* to report completions, the device will write status back here */
	volatile uint64_t status __rte_cache_aligned;
};

/**
 * @internal
 * Structure representing a descriptor for a copy operation
 */
struct rte_ioat_desc {
	uint32_t xfer_size __rte_cache_aligned;
	uint32_t desc_control;
	phys_addr_t src_addr; /* 64 bits */
	phys_addr_t dest_addr; /* 64 bits */
	phys_addr_t next_desc_addr; /* 64 bits */
	uint64_t op_type_specific[4];
};

/**
 * Enqueue a copy operation onto the ioat device
 *
 * This queues up a copy operation to be performed by hardware, but does not
 * trigger hardware to begin that operation.
 *
 * @param dev_id
 *   The rawdev device id of the ioat instance
 * @param src
 *   The physical address of the source buffer
 * @param dst
 *   The physical address of the destination buffer
 * @param length
 *   The length of the data to be copied
 * @param src_hdl
 *   An opaque handle for the source data, to be returned when this operation
 *   has been completed and the user polls for the completion details
 * @param dst_hdl
 *   An opaque handle for the destination data, to be returned when this
 *   operation has been completed and the user polls for the completion details
 * @param fence
 *   A flag parameter indicating that hardware should not begin to perform any
 *   subsequently enqueued copy operations until after this operation has
 *   completed
 * @return
 *   Number of operations enqueued, either 0 or 1
 */
static inline int
rte_ioat_enqueue_copy(int dev_id, phys_addr_t src, phys_addr_t dst,
		unsigned int length, uintptr_t src_hdl, uintptr_t dst_hdl,
		int fence)
{
	struct rte_ioat_rawdev *ioat = rte_rawdevs[dev_id].dev_private;
	unsigned short read = ioat->next_read;
	unsigned short write = ioat->next_write;
	unsigned short mask = ioat->ring_size - 1;
	unsigned short space = mask + read - write;

	if (space == 0) {
		ioat->enqueue_failed++;
		return 0;
	}

	ioat->next_write = write + 1;
	write &= mask;
	/* write transfer size and the descriptor control bits */
	*((uint64_t *)&ioat->desc_ring[write]) =
			length | (uint64_t)!!fence << 36 |
			(uint64_t)(!(write & 0xF)) << 35;
	ioat->desc_ring[write].src_addr = src;
	ioat->desc_ring[write].dest_addr = dst;
	ioat->hdls[write] = _mm_set_epi64((__m64)dst_hdl, (__m64)src_hdl);
	rte_prefetch0(&ioat->desc_ring[ioat->next_write & mask]);

	ioat->enqueued++;
	return 1;
}

/**
 * Trigger hardware to begin performing enqueued copy operations
 *
 * This API is used to write the "doorbell" to the hardware to trigger it
 * to begin the copy operations previously enqueued by rte_ioat_enqueue_copy()
 *
 * @param dev_id
 *   The rawdev device id of the ioat instance
 */
static inline void
rte_ioat_do_copies(int dev_id)
{
	struct rte_ioat_rawdev *ioat = rte_rawdevs[dev_id].dev_private;
	ioat->desc_ring[(ioat->next_write - 1) & (ioat->ring_size - 1)].desc_control = 8;
	rte_compiler_barrier();
	ioat->regs->dmacount = ioat->next_write;
	ioat->started = ioat->enqueued;
}

/**
 * @internal
 * Returns the index of the last completed operation.
 */
static inline int
rte_ioat_get_last_completed(struct rte_ioat_rawdev *ioat)
{
	uint64_t status = ioat->status;
	/* lower 3 bits indicate "transfer status" : active, idle, halted.. */
	if (status & 0x6)
		rte_panic("Error with cbdma: %u\n", (unsigned)status & 0x7);

	return (status - ioat->ring_addr) >> 6;
}

/**
 * Returns details of copy operations that have been completed
 *
 * Returns to the caller the user-provided "handles" for the copy operations
 * which have been completed by the hardware, and not already returned by
 * a previous call to this API.
 *
 * @param dev_id
 *   The rawdev device id of the ioat instance
 * @param max_copies
 *   The number of entries which can fit in the src_hdls and dst_hdls
 *   arrays, i.e. max number of completed operations to report
 * @param src_hdls
 *   Array to hold the source handle parameters of the completed copies
 * @param dst_hdls
 *   Array to hold the destination handle parameters of the completed copies
 * @return
 *   Number of completed operations i.e. number of entries written to the
 *   src_hdls and dst_hdls array parameters.
 */
static inline int
rte_ioat_completed_copies(int dev_id, uint8_t max_copies,
		uintptr_t *src_hdls, uintptr_t *dst_hdls)
{
	struct rte_ioat_rawdev *ioat = rte_rawdevs[dev_id].dev_private;
	unsigned short mask = (ioat->ring_size - 1);
	unsigned short read = ioat->next_read;
	unsigned short end_read = (rte_ioat_get_last_completed(ioat) + 1) & mask;
	unsigned short count = (end_read - (read & mask)) & mask;
	int i = 0;

	if (count > max_copies)
		count = max_copies;

	for (; i < count - 1; i += 2, read += 2) {
		__m128i hdls0 = _mm_load_si128(&ioat->hdls[read & mask]);
		__m128i hdls1 = _mm_load_si128(&ioat->hdls[(read + 1) & mask]);

		_mm_storeu_si128((void *)&src_hdls[i],
				_mm_unpacklo_epi64(hdls0, hdls1));
		_mm_storeu_si128((void *)&dst_hdls[i],
				_mm_unpackhi_epi64(hdls0, hdls1));
	}
	for (; i < count; i++, read++) {
		uintptr_t *hdls = (void *)&ioat->hdls[read & mask];
		src_hdls[i] = hdls[0];
		dst_hdls[i] = hdls[1];
	}

	ioat->next_read = read;
	ioat->completed += count;
	return count;
}

#endif /* _RTE_IOAT_RAWDEV_H_ */
