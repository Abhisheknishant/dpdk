/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
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

#include "rte_rawdev.h"
#include "rte_rawdev_pmd.h"
#include "rte_multi_fn.h"

/* Dynamic log identifier */
static int librawmulti_fn_logtype;

/* Logging Macros */
#define MF_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, librawmulti_fn_logtype, "%s(): " fmt "\n", \
		__func__, ##args)

#define MF_ERR(fmt, args...) \
	MF_LOG(ERR, fmt, ## args)
#define MF_DEBUG(fmt, args...) \
	MF_LOG(DEBUG, fmt, ## args)
#define MF_INFO(fmt, args...) \
	MF_LOG(INFO, fmt, ## args)

struct rte_multi_fn_session *
rte_multi_fn_session_create(uint16_t dev_id,
				struct rte_rawdev_info *dev_info,
				struct rte_multi_fn_xform *xform,
				int socket_id)
{
	struct rte_rawdev *rawdev;
	struct rte_multi_fn_device_info *dev_priv;

	if (!rte_rawdev_pmd_is_valid_dev((dev_id))) {
		MF_ERR("Invalid rawdev dev_id=%d", dev_id);
		return NULL;
	}

	rawdev = &rte_rawdevs[dev_id];

	dev_priv = dev_info->dev_private;

	return dev_priv->create(rawdev, xform, socket_id);
}

int
rte_multi_fn_session_destroy(uint16_t dev_id,
				struct rte_rawdev_info *dev_info,
				struct rte_multi_fn_session *sess)
{
	struct rte_rawdev *rawdev;
	struct rte_multi_fn_device_info *dev_priv;

	if (!rte_rawdev_pmd_is_valid_dev((dev_id))) {
		MF_ERR("Invalid rawdev dev_id=%d", dev_id);
		return -EINVAL;
	}

	rawdev = &rte_rawdevs[dev_id];

	dev_priv = dev_info->dev_private;

	return dev_priv->destroy(rawdev, sess);
}

RTE_INIT(libmulti_fn_dev_init_log)
{
	librawmulti_fn_logtype = rte_log_register("lib.multi_fn");
	if (librawmulti_fn_logtype >= 0)
		rte_log_set_level(librawmulti_fn_logtype, RTE_LOG_INFO);
}
