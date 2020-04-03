/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation.
 */

#ifndef _RTE_MULTI_FN_DRIVER_H_
#define _RTE_MULTI_FN_DRIVER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_compat.h>
#include <rte_common.h>
#include <rte_rawdev.h>
#include <rte_multi_fn.h>

/**
 * Multi-function session
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
