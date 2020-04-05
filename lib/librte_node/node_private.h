/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#ifndef __NODE_PRIVATE_H__
#define __NODE_PRIVATE_H__

#include <rte_common.h>
#include <rte_crypto.h>
#include <rte_log.h>
#include <rte_mbuf.h>

extern int rte_node_logtype;
#define NODE_LOG(level, node_name, ...)                                        \
	rte_log(RTE_LOG_##level, rte_node_logtype,                             \
		RTE_FMT("NODE %s: %s():%u " RTE_FMT_HEAD(__VA_ARGS__, ) "\n",  \
			node_name, __func__, __LINE__,                         \
			RTE_FMT_TAIL(__VA_ARGS__, )))

#define node_err(node_name, ...) NODE_LOG(ERR, node_name, __VA_ARGS__)
#define node_info(node_name, ...) NODE_LOG(INFO, node_name, __VA_ARGS__)
#define node_dbg(node_name, ...) NODE_LOG(DEBUG, node_name, __VA_ARGS__)

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Node mbuf private data to store next hop, ttl and checksum.
 */
struct rte_node_mbuf_priv1 {
	union {
		/* IP4 rewrite */
		struct {
			uint16_t nh;
			uint16_t ttl;
			uint32_t cksum;
		};

		uint64_t u;
	};
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Node mbuf private data to store crypto operation.
 */
struct rte_node_mbuf_priv2 {
	union {
		/* Sym crypto */
		struct {
			struct rte_crypto_op op;
		};
	};
} __rte_cache_aligned;

#define RTE_NODE_MBUF_PRIV2_SIZE sizeof(struct rte_node_mbuf_priv2)

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Get mbuf_priv1 pointer from rte_mbuf.
 *
 * @param
 *   Pointer to the rte_mbuf.
 *
 * @return
 *   Pointer to the mbuf_priv1.
 */
static __rte_always_inline struct rte_node_mbuf_priv1 *
rte_node_mbuf_priv1(struct rte_mbuf *m)
{
	return (struct rte_node_mbuf_priv1 *)&m->udata64;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Get mbuf_priv2 pointer from rte_mbuf.
 *
 * @param
 *   Pointer to the rte_mbuf.
 *
 * @return
 *   Pointer to the mbuf_priv2.
 */
static __rte_always_inline struct rte_node_mbuf_priv2 *
rte_node_mbuf_priv2(struct rte_mbuf *m)
{
	return (struct rte_node_mbuf_priv2 *)rte_mbuf_to_priv(m);
}

#endif /* __NODE_PRIVATE_H__ */
