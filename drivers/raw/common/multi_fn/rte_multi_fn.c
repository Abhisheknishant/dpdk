/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>

#include <rte_string_fns.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_dev.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_errno.h>
#include <rte_rawdev.h>

#include "rte_multi_fn_driver.h"
#include "rte_multi_fn.h"

/* Dynamic log identifier */
static int multi_fn_logtype;

/* Logging Macros */
#define MF_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, multi_fn_logtype, \
		"%s() line %u: " fmt "\n", \
		__func__, __LINE__, ##args)
#define MF_DEBUG(fmt, args...) \
	MF_LOG(DEBUG, fmt, ## args)
#define MF_INFO(fmt, args...) \
	MF_LOG(INFO, fmt, ## args)
#define MF_ERR(fmt, args...) \
	MF_LOG(ERR, fmt, ## args)
#define MF_WARN(fmt, args...) \
	MF_LOG(WARNING, fmt, ## args)

static void
multi_fn_op_init(struct rte_mempool *mempool,
		 __rte_unused void *opaque_arg,
		 void *op_data,
		 __rte_unused unsigned int i)
{
	struct rte_multi_fn_op *op = op_data;

	memset(op_data, 0, mempool->elt_size);

	op->overall_status = RTE_MULTI_FN_OP_STATUS_NOT_PROCESSED;
	op->mempool = mempool;
}

struct rte_multi_fn_session *
rte_multi_fn_session_create(uint16_t dev_id,
			    struct rte_multi_fn_xform *xform,
			    int socket_id)
{
	struct rte_rawdev *rawdev;
	struct rte_rawdev_info info = {0};
	struct rte_multi_fn_ops *mf_ops;

	if (xform == NULL) {
		MF_ERR("NULL xform for multi-function session create");
		return NULL;
	}

	if (rte_rawdev_info_get(dev_id, &info) < 0) {
		MF_ERR("Invalid dev_id=%d", dev_id);
		return NULL;
	}

	rawdev = &rte_rawdevs[dev_id];

	mf_ops = *((struct rte_multi_fn_ops **)(rawdev->dev_private));

	RTE_FUNC_PTR_OR_ERR_RET(*mf_ops->session_create, NULL);
	return (*mf_ops->session_create)(rawdev, xform, socket_id);
}

int
rte_multi_fn_session_destroy(uint16_t dev_id, struct rte_multi_fn_session *sess)
{
	struct rte_rawdev *rawdev;
	struct rte_rawdev_info info = {0};
	struct rte_multi_fn_ops *mf_ops;

	if (rte_rawdev_info_get(dev_id, &info) < 0) {
		MF_ERR("Invalid dev_id=%d", dev_id);
		return -EINVAL;
	}

	rawdev = &rte_rawdevs[dev_id];

	mf_ops = *((struct rte_multi_fn_ops **)(rawdev->dev_private));

	RTE_FUNC_PTR_OR_ERR_RET(*mf_ops->session_destroy, -ENOTSUP);
	return (*mf_ops->session_destroy)(rawdev, sess);
}

struct rte_mempool *
rte_multi_fn_op_pool_create(const char *name,
			    uint32_t nb_elts,
			    uint32_t cache_size,
			    uint16_t priv_size,
			    int socket_id)
{
	uint32_t elt_size = sizeof(struct rte_multi_fn_op) + priv_size;

	/* Lookup mempool in case already allocated */
	struct rte_mempool *mp = rte_mempool_lookup(name);

	if (mp != NULL) {
		if (mp->elt_size != elt_size ||
		    mp->cache_size < cache_size ||
		    mp->size < nb_elts) {
			mp = NULL;
			MF_ERR("Mempool %s already exists but with "
			       "incompatible parameters",
			       name);
			return NULL;
		}

		return mp;
	}

	mp = rte_mempool_create(name,
				nb_elts,
				elt_size,
				cache_size,
				0,
				NULL,
				NULL,
				multi_fn_op_init,
				NULL,
				socket_id,
				0);

	if (mp == NULL) {
		MF_ERR("Failed to create mempool %s", name);
		return NULL;
	}

	return mp;
}

RTE_INIT(rte_multi_fn_log_init)
{
	multi_fn_logtype = rte_log_register("pmd.raw.common.multi_fn");
	if (multi_fn_logtype >= 0)
		rte_log_set_level(multi_fn_logtype, RTE_LOG_INFO);
}
