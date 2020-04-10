/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation.
 */

#ifndef _RTE_MULTI_FN_DRIVER_H_
#define _RTE_MULTI_FN_DRIVER_H_

/**
 * @file rte_multi_fn_driver.h
 *
 * RTE Multi Function PMD APIs
 *
 * @note
 * These APIs are for rawdev PMDs only which support the multi-function
 * interface and user applications should not call them directly.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_rawdev.h>

#include "rte_multi_fn.h"

/** Multi-function device name prefix */
#define RTE_MULTI_FN_DEV_NAME_PREFIX rawdev_mfn_
/** Multi-function device name prefix string */
#define RTE_MULTI_FN_DEV_NAME_PREFIX_STR RTE_STR(RTE_MULTI_FN_DEV_NAME_PREFIX)

#define _CONCAT(x, y) x ## y
#define CONCAT(x, y) _CONCAT(x, y)

/** Create a full multi-function device name */
#define RTE_MULTI_FN_DEV_NAME(x) CONCAT(RTE_MULTI_FN_DEV_NAME_PREFIX, x)

/**
 * Multi-function xstat IDs
 */
enum rte_multi_fn_xtsat_id {
	RTE_MULTI_FN_XSTAT_ID_SUCCESSFUL_ENQUEUES = 0,
	/**< Successful enqueues */
	RTE_MULTI_FN_XSTAT_ID_SUCCESSFUL_DEQUEUES,
	/**< Successful dequeues */
	RTE_MULTI_FN_XSTAT_ID_FAILED_ENQUEUES,
	/**< Failed enqueues */
	RTE_MULTI_FN_XSTAT_ID_FAILED_DEQUEUES,
	/**< Failed dequeues */
	RTE_MULTI_FN_XSTAT_ID_NB
	/**< Number of stats */
};

/**
 * Multi-function xstat names
 */
extern const char *
rte_multi_fn_xstat_names[];

/**
 * Multi-function session data
 */
struct rte_multi_fn_session {
	void *sess_private_data;
};

/**
 * Session create function pointer type
 */
typedef struct rte_multi_fn_session *(*multi_fn_session_create_t)(
						struct rte_rawdev *,
						struct rte_multi_fn_xform *,
						int);

/**
 * Session destroy function pointer type
 */
typedef int (*multi_fn_session_destroy_t)(struct rte_rawdev *,
					  struct rte_multi_fn_session *);

/**
 * Structure containing multi-function ops to create and destroy a session.
 *
 * This structure MUST be the first element of the device's private data
 * structure pointed to by rte_rawdev->dev_private
 */
struct rte_multi_fn_ops {
	multi_fn_session_create_t session_create;
	/**< Create session function pointer */
	multi_fn_session_destroy_t session_destroy;
	/**< Destroy session function pointer */
};

#ifdef __cplusplus
}
#endif

#endif /* _RTE_MULTI_FN_DRIVER_H_ */
