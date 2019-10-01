/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019 Arm Limited
 */

#ifndef _RTE_RCU_QSBR_PVT_H_
#define _RTE_RCU_QSBR_PVT_H_

/**
 * This file is private to the RCU library. It should not be included
 * by the user of this library.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "rte_rcu_qsbr.h"

/* RTE defer queue structure.
 * This structure holds the defer queue. The defer queue is used to
 * hold the deleted entries from the data structure that are not
 * yet freed.
 */
struct rte_rcu_qsbr_dq {
	struct rte_rcu_qsbr *v; /**< RCU QSBR variable used by this queue.*/
	struct rte_ring *r;     /**< RCU QSBR defer queue. */
	uint32_t size;
	/**< Number of elements in the defer queue */
	uint32_t esize;
	/**< Size (in bytes) of data stored on the defer queue */
	rte_rcu_qsbr_free_resource f;
	/**< Function to call to free the resource. */
	void *p;
	/**< Pointer passed to the free function. Typically, this is the
	 *   pointer to the data structure to which the resource to free
	 *   belongs.
	 */
	char e[0];
	/**< Temporary storage to copy the defer queue element. */
};

#ifdef __cplusplus
}
#endif

#endif /* _RTE_RCU_QSBR_PVT_H_ */
