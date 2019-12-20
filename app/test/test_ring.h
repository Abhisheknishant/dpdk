/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Arm Limited
 */

#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_ring_elem.h>

/* API type to call
 * N - Calls default APIs
 * S - Calls SP or SC API
 * M - Calls MP or MC API
 */
#define TEST_RING_N 1
#define TEST_RING_S 2
#define TEST_RING_M 4

/* API type to call
 * SL - Calls single element APIs
 * BL - Calls bulk APIs
 * BR - Calls burst APIs
 */
#define TEST_RING_SL 8
#define TEST_RING_BL 16
#define TEST_RING_BR 32

#define TEST_RING_IGNORE_API_TYPE ~0U

#define TEST_RING_INCP(obj, esize, n) do { \
	/* Legacy queue APIs? */ \
	if ((esize) == -1) \
		obj = ((void **)obj) + n; \
	else \
		obj = (void **)(((uint32_t *)obj) + \
					(n * esize / sizeof(uint32_t))); \
} while (0)

#define TEST_RING_CREATE(name, esize, count, socket_id, flags, r) do { \
	/* Legacy queue APIs? */ \
	if ((esize) == -1) \
		r = rte_ring_create((name), (count), (socket_id), (flags)); \
	else \
		r = rte_ring_create_elem((name), (esize), (count), \
						(socket_id), (flags)); \
} while (0)

#define TEST_RING_ENQUEUE(r, obj, esize, n, ret, api_type) do { \
	/* Legacy queue APIs? */ \
	if ((esize) == -1) \
		switch (api_type) { \
		case (TEST_RING_N | TEST_RING_SL): \
			ret = rte_ring_enqueue(r, obj); \
			break; \
		case (TEST_RING_S | TEST_RING_SL): \
			ret = rte_ring_sp_enqueue(r, obj); \
			break; \
		case (TEST_RING_M | TEST_RING_SL): \
			ret = rte_ring_mp_enqueue(r, obj); \
			break; \
		case (TEST_RING_N | TEST_RING_BL): \
			ret = rte_ring_enqueue_bulk(r, obj, n, NULL); \
			break; \
		case (TEST_RING_S | TEST_RING_BL): \
			ret = rte_ring_sp_enqueue_bulk(r, obj, n, NULL); \
			break; \
		case (TEST_RING_M | TEST_RING_BL): \
			ret = rte_ring_mp_enqueue_bulk(r, obj, n, NULL); \
			break; \
		case (TEST_RING_N | TEST_RING_BR): \
			ret = rte_ring_enqueue_burst(r, obj, n, NULL); \
			break; \
		case (TEST_RING_S | TEST_RING_BR): \
			ret = rte_ring_sp_enqueue_burst(r, obj, n, NULL); \
			break; \
		case (TEST_RING_M | TEST_RING_BR): \
			ret = rte_ring_mp_enqueue_burst(r, obj, n, NULL); \
		} \
	else \
		switch (api_type) { \
		case (TEST_RING_N | TEST_RING_SL): \
			ret = rte_ring_enqueue_elem(r, obj, esize); \
			break; \
		case (TEST_RING_S | TEST_RING_SL): \
			ret = rte_ring_sp_enqueue_elem(r, obj, esize); \
			break; \
		case (TEST_RING_M | TEST_RING_SL): \
			ret = rte_ring_mp_enqueue_elem(r, obj, esize); \
			break; \
		case (TEST_RING_N | TEST_RING_BL): \
			ret = rte_ring_enqueue_bulk_elem(r, obj, esize, n, \
								NULL); \
			break; \
		case (TEST_RING_S | TEST_RING_BL): \
			ret = rte_ring_sp_enqueue_bulk_elem(r, obj, esize, n, \
								NULL); \
			break; \
		case (TEST_RING_M | TEST_RING_BL): \
			ret = rte_ring_mp_enqueue_bulk_elem(r, obj, esize, n, \
								NULL); \
			break; \
		case (TEST_RING_N | TEST_RING_BR): \
			ret = rte_ring_enqueue_burst_elem(r, obj, esize, n, \
								NULL); \
			break; \
		case (TEST_RING_S | TEST_RING_BR): \
			ret = rte_ring_sp_enqueue_burst_elem(r, obj, esize, n, \
								NULL); \
			break; \
		case (TEST_RING_M | TEST_RING_BR): \
			ret = rte_ring_mp_enqueue_burst_elem(r, obj, esize, n, \
								NULL); \
		} \
} while (0)

#define TEST_RING_DEQUEUE(r, obj, esize, n, ret, api_type) do { \
	/* Legacy queue APIs? */ \
	if ((esize) == -1) \
		switch (api_type) { \
		case (TEST_RING_N | TEST_RING_SL): \
			ret = rte_ring_dequeue(r, obj); \
			break; \
		case (TEST_RING_S | TEST_RING_SL): \
			ret = rte_ring_sc_dequeue(r, obj); \
			break; \
		case (TEST_RING_M | TEST_RING_SL): \
			ret = rte_ring_mc_dequeue(r, obj); \
			break; \
		case (TEST_RING_N | TEST_RING_BL): \
			ret = rte_ring_dequeue_bulk(r, obj, n, NULL); \
			break; \
		case (TEST_RING_S | TEST_RING_BL): \
			ret = rte_ring_sc_dequeue_bulk(r, obj, n, NULL); \
			break; \
		case (TEST_RING_M | TEST_RING_BL): \
			ret = rte_ring_mc_dequeue_bulk(r, obj, n, NULL); \
			break; \
		case (TEST_RING_N | TEST_RING_BR): \
			ret = rte_ring_dequeue_burst(r, obj, n, NULL); \
			break; \
		case (TEST_RING_S | TEST_RING_BR): \
			ret = rte_ring_sc_dequeue_burst(r, obj, n, NULL); \
			break; \
		case (TEST_RING_M | TEST_RING_BR): \
			ret = rte_ring_mc_dequeue_burst(r, obj, n, NULL); \
		} \
	else \
		switch (api_type) { \
		case (TEST_RING_N | TEST_RING_SL): \
			ret = rte_ring_dequeue_elem(r, obj, esize); \
			break; \
		case (TEST_RING_S | TEST_RING_SL): \
			ret = rte_ring_sc_dequeue_elem(r, obj, esize); \
			break; \
		case (TEST_RING_M | TEST_RING_SL): \
			ret = rte_ring_mc_dequeue_elem(r, obj, esize); \
			break; \
		case (TEST_RING_N | TEST_RING_BL): \
			ret = rte_ring_dequeue_bulk_elem(r, obj, esize, n, \
								NULL); \
			break; \
		case (TEST_RING_S | TEST_RING_BL): \
			ret = rte_ring_sc_dequeue_bulk_elem(r, obj, esize, n, \
								NULL); \
			break; \
		case (TEST_RING_M | TEST_RING_BL): \
			ret = rte_ring_mc_dequeue_bulk_elem(r, obj, esize, n, \
								NULL); \
			break; \
		case (TEST_RING_N | TEST_RING_BR): \
			ret = rte_ring_dequeue_burst_elem(r, obj, esize, n, \
								NULL); \
			break; \
		case (TEST_RING_S | TEST_RING_BR): \
			ret = rte_ring_sc_dequeue_burst_elem(r, obj, esize, n, \
								NULL); \
			break; \
		case (TEST_RING_M | TEST_RING_BR): \
			ret = rte_ring_mc_dequeue_burst_elem(r, obj, esize, n, \
								NULL); \
		} \
} while (0)

/* This function is placed here as it is required for both
 * performance and functional tests.
 */
static __rte_always_inline void *
test_ring_calloc(unsigned int rsize, int esize)
{
	unsigned int sz;
	void *p;

	/* Legacy queue APIs? */
	if (esize == -1)
		sz = sizeof(void *);
	else
		sz = esize;

	p = rte_zmalloc(NULL, rsize * sz, RTE_CACHE_LINE_SIZE);
	if (p == NULL)
		printf("Failed to allocate memory\n");

	return p;
}
