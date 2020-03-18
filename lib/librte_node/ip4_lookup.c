/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#include <arpa/inet.h>
#include <sys/socket.h>

#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_lpm.h>
#include <rte_mbuf.h>
#include <rte_node_ip4_api.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "node_private.h"

#define IPV4_L3FWD_LPM_MAX_RULES 1024
#define IPV4_L3FWD_LPM_NUMBER_TBL8S (1 << 8)

/* IP4 Lookup global data struct */
struct ip4_lookup_node_main {
	struct rte_lpm *lpm_tbl[RTE_MAX_NUMA_NODES];
};

#if defined(RTE_MACHINE_CPUFLAG_NEON)
/* ARM64 NEON */
static uint16_t
ip4_lookup_node_process(struct rte_graph *graph, struct rte_node *node,
			void **objs, uint16_t nb_objs)
{
	struct rte_mbuf *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ether_hdr *eth_hdr;
	void **to_next, **from;
	uint16_t last_spec = 0;
	rte_edge_t next_index;
	uint16_t n_left_from;
	struct rte_lpm *lpm;
	uint16_t held = 0;
	uint32_t drop_nh;
	rte_xmm_t result;
	rte_xmm_t priv01;
	rte_xmm_t priv23;
	int32x4_t dip;
	int rc, i;

	/* Speculative next */
	next_index = RTE_NODE_IP4_LOOKUP_NEXT_REWRITE;
	/* Drop node */
	drop_nh = ((uint32_t)RTE_NODE_IP4_LOOKUP_NEXT_PKT_DROP) << 16;

	/* Get socket specific LPM from ctx */
	lpm = *((struct rte_lpm **)node->ctx);

	pkts = (struct rte_mbuf **)objs;
	from = objs;
	n_left_from = nb_objs;

#define OBJS_PER_CLINE (RTE_CACHE_LINE_SIZE / sizeof(void *))
	for (i = OBJS_PER_CLINE; i < RTE_GRAPH_BURST_SIZE; i += OBJS_PER_CLINE)
		rte_prefetch0(&objs[i]);

	for (i = 0; i < 4 && i < n_left_from; i++) {
		rte_prefetch0(
			rte_pktmbuf_mtod(pkts[i], struct rte_ether_hdr *) + 1);
	}

	/* Get stream for the speculated next node */
	to_next = rte_node_next_stream_get(graph, node, next_index, nb_objs);
	while (n_left_from >= 4) {
#if RTE_GRAPH_BURST_SIZE > 64
		/* Prefetch next-next mbufs */
		if (likely(n_left_from >= 11)) {
			rte_prefetch0(pkts[8]);
			rte_prefetch0(pkts[9]);
			rte_prefetch0(pkts[10]);
			rte_prefetch0(pkts[11]);
		}
#endif
		/* Prefetch next mbuf data */
		if (likely(n_left_from >= 7)) {
			rte_prefetch0(rte_pktmbuf_mtod(pkts[4],
						       struct rte_ether_hdr *) +
				      1);
			rte_prefetch0(rte_pktmbuf_mtod(pkts[5],
						       struct rte_ether_hdr *) +
				      1);
			rte_prefetch0(rte_pktmbuf_mtod(pkts[6],
						       struct rte_ether_hdr *) +
				      1);
			rte_prefetch0(rte_pktmbuf_mtod(pkts[7],
						       struct rte_ether_hdr *) +
				      1);
		}

		mbuf0 = pkts[0];
		mbuf1 = pkts[1];
		mbuf2 = pkts[2];
		mbuf3 = pkts[3];

		pkts += 4;
		n_left_from -= 4;

		/* Extract DIP of mbuf0 */
		eth_hdr = rte_pktmbuf_mtod(mbuf0, struct rte_ether_hdr *);
		ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
		dip = vsetq_lane_s32(ipv4_hdr->dst_addr, dip, 0);
		/* Extract cksum, ttl as ipv4 hdr is in cache */
		priv01.u16[1] = ipv4_hdr->time_to_live;
		priv01.u32[1] = ipv4_hdr->hdr_checksum;

		/* Extract DIP of mbuf1 */
		eth_hdr = rte_pktmbuf_mtod(mbuf1, struct rte_ether_hdr *);
		ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
		dip = vsetq_lane_s32(ipv4_hdr->dst_addr, dip, 1);
		/* Extract cksum, ttl as ipv4 hdr is in cache */
		priv01.u16[5] = ipv4_hdr->time_to_live;
		priv01.u32[3] = ipv4_hdr->hdr_checksum;

		/* Extract DIP of mbuf2 */
		eth_hdr = rte_pktmbuf_mtod(mbuf2, struct rte_ether_hdr *);
		ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
		dip = vsetq_lane_s32(ipv4_hdr->dst_addr, dip, 2);
		/* Extract cksum, ttl as ipv4 hdr is in cache */
		priv23.u16[1] = ipv4_hdr->time_to_live;
		priv23.u32[1] = ipv4_hdr->hdr_checksum;

		/* Extract DIP of mbuf3 */
		eth_hdr = rte_pktmbuf_mtod(mbuf3, struct rte_ether_hdr *);
		ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
		dip = vsetq_lane_s32(ipv4_hdr->dst_addr, dip, 3);

		dip = vreinterpretq_s32_u8(
			vrev32q_u8(vreinterpretq_u8_s32(dip)));
		/* Extract cksum, ttl as ipv4 hdr is in cache */
		priv23.u16[5] = ipv4_hdr->time_to_live;
		priv23.u32[3] = ipv4_hdr->hdr_checksum;

		/* Perform LPM lookup to get NH and next node */
		rte_lpm_lookupx4(lpm, dip, result.u32, drop_nh);
		priv01.u16[0] = result.u16[0];
		priv01.u16[4] = result.u16[2];
		priv23.u16[0] = result.u16[4];
		priv23.u16[4] = result.u16[6];

		rte_node_mbuf_priv1(mbuf0)->u = priv01.u64[0];
		rte_node_mbuf_priv1(mbuf1)->u = priv01.u64[1];
		rte_node_mbuf_priv1(mbuf2)->u = priv23.u64[0];
		rte_node_mbuf_priv1(mbuf3)->u = priv23.u64[1];

		/* Enqueue four to next node */
		rte_edge_t fix_spec = ((next_index == result.u16[1]) &&
				       (result.u16[1] == result.u16[3]) &&
				       (result.u16[3] == result.u16[5]) &&
				       (result.u16[5] == result.u16[7]));

		if (unlikely(fix_spec == 0)) {
			/* Copy things successfully speculated till now */
			rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;

			/* Next0 */
			if (next_index == result.u16[1]) {
				to_next[0] = from[0];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node, result.u16[1],
						    from[0]);
			}

			/* Next1 */
			if (next_index == result.u16[3]) {
				to_next[0] = from[1];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node, result.u16[3],
						    from[1]);
			}

			/* Next2 */
			if (next_index == result.u16[5]) {
				to_next[0] = from[2];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node, result.u16[5],
						    from[2]);
			}

			/* Next3 */
			if (next_index == result.u16[7]) {
				to_next[0] = from[3];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node, result.u16[7],
						    from[3]);
			}

			from += 4;
		} else {
			last_spec += 4;
		}
	}

	while (n_left_from > 0) {
		uint32_t next_hop;
		uint16_t next0;

		mbuf0 = pkts[0];

		pkts += 1;
		n_left_from -= 1;

		/* Extract DIP of mbuf0 */
		eth_hdr = rte_pktmbuf_mtod(mbuf0, struct rte_ether_hdr *);
		ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
		/* Extract cksum, ttl as ipv4 hdr is in cache */
		rte_node_mbuf_priv1(mbuf0)->cksum = ipv4_hdr->hdr_checksum;
		rte_node_mbuf_priv1(mbuf0)->ttl = ipv4_hdr->time_to_live;

		rc = rte_lpm_lookup(lpm, rte_be_to_cpu_32(ipv4_hdr->dst_addr),
				    &next_hop);
		next_hop = (rc == 0) ? next_hop : drop_nh;

		rte_node_mbuf_priv1(mbuf0)->nh = (uint16_t)next_hop;
		next_hop = next_hop >> 16;
		next0 = (uint16_t)next_hop;

		if (unlikely(next_index ^ next0)) {
			/* Copy things successfully speculated till now */
			rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;

			rte_node_enqueue_x1(graph, node, next0, from[0]);
			from += 1;
		} else {
			last_spec += 1;
		}
	}

	/* !!! Home run !!! */
	if (likely(last_spec == nb_objs)) {
		rte_node_next_stream_move(graph, node, next_index);
		return nb_objs;
	}
	held += last_spec;
	rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
	rte_node_next_stream_put(graph, node, next_index, held);

	return nb_objs;
}

#elif defined(RTE_ARCH_X86)

/* X86 SSE */
static uint16_t
ip4_lookup_node_process(struct rte_graph *graph, struct rte_node *node,
			void **objs, uint16_t nb_objs)
{
	struct rte_mbuf *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
	rte_edge_t next0, next1, next2, next3, next_index;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ether_hdr *eth_hdr;
	uint32_t ip0, ip1, ip2, ip3;
	void **to_next, **from;
	uint16_t last_spec = 0;
	uint16_t n_left_from;
	struct rte_lpm *lpm;
	uint16_t held = 0;
	uint32_t drop_nh;
	rte_xmm_t dst;
	__m128i dip; /* SSE register */
	int rc, i;

	/* Speculative next */
	next_index = RTE_NODE_IP4_LOOKUP_NEXT_REWRITE;
	/* Drop node */
	drop_nh = ((uint32_t)RTE_NODE_IP4_LOOKUP_NEXT_PKT_DROP) << 16;

	/* Get socket specific LPM from ctx */
	lpm = *((struct rte_lpm **)node->ctx);

	pkts = (struct rte_mbuf **)objs;
	from = objs;
	n_left_from = nb_objs;

	if (n_left_from >= 4) {
		for (i = 0; i < 4; i++) {
			rte_prefetch0(rte_pktmbuf_mtod(pkts[i],
						       struct rte_ether_hdr *) +
				      1);
		}
	}

	/* Get stream for the speculated next node */
	to_next = rte_node_next_stream_get(graph, node, next_index, nb_objs);
	while (n_left_from >= 4) {
		/* Prefetch next-next mbufs */
		if (likely(n_left_from >= 11)) {
			rte_prefetch0(pkts[8]);
			rte_prefetch0(pkts[9]);
			rte_prefetch0(pkts[10]);
			rte_prefetch0(pkts[11]);
		}

		/* Prefetch next mbuf data */
		if (likely(n_left_from >= 7)) {
			rte_prefetch0(rte_pktmbuf_mtod(pkts[4],
						       struct rte_ether_hdr *) +
				      1);
			rte_prefetch0(rte_pktmbuf_mtod(pkts[5],
						       struct rte_ether_hdr *) +
				      1);
			rte_prefetch0(rte_pktmbuf_mtod(pkts[6],
						       struct rte_ether_hdr *) +
				      1);
			rte_prefetch0(rte_pktmbuf_mtod(pkts[7],
						       struct rte_ether_hdr *) +
				      1);
		}

		mbuf0 = pkts[0];
		mbuf1 = pkts[1];
		mbuf2 = pkts[2];
		mbuf3 = pkts[3];

		pkts += 4;
		n_left_from -= 4;

		/* Extract DIP of mbuf0 */
		eth_hdr = rte_pktmbuf_mtod(mbuf0, struct rte_ether_hdr *);
		ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
		ip0 = ipv4_hdr->dst_addr;
		/* Extract cksum, ttl as ipv4 hdr is in cache */
		rte_node_mbuf_priv1(mbuf0)->cksum = ipv4_hdr->hdr_checksum;
		rte_node_mbuf_priv1(mbuf0)->ttl = ipv4_hdr->time_to_live;

		/* Extract DIP of mbuf1 */
		eth_hdr = rte_pktmbuf_mtod(mbuf1, struct rte_ether_hdr *);
		ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
		ip1 = ipv4_hdr->dst_addr;
		/* Extract cksum, ttl as ipv4 hdr is in cache */
		rte_node_mbuf_priv1(mbuf1)->cksum = ipv4_hdr->hdr_checksum;
		rte_node_mbuf_priv1(mbuf1)->ttl = ipv4_hdr->time_to_live;

		/* Extract DIP of mbuf2 */
		eth_hdr = rte_pktmbuf_mtod(mbuf2, struct rte_ether_hdr *);
		ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
		ip2 = ipv4_hdr->dst_addr;
		/* Extract cksum, ttl as ipv4 hdr is in cache */
		rte_node_mbuf_priv1(mbuf2)->cksum = ipv4_hdr->hdr_checksum;
		rte_node_mbuf_priv1(mbuf2)->ttl = ipv4_hdr->time_to_live;

		/* Extract DIP of mbuf3 */
		eth_hdr = rte_pktmbuf_mtod(mbuf3, struct rte_ether_hdr *);
		ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
		ip3 = ipv4_hdr->dst_addr;

		/* Prepare for lookup x4 */
		dip = _mm_set_epi32(ip3, ip2, ip1, ip0);

		/* Byte swap 4 IPV4 addresses. */
		const __m128i bswap_mask = _mm_set_epi8(
			12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
		dip = _mm_shuffle_epi8(dip, bswap_mask);

		/* Extract cksum, ttl as ipv4 hdr is in cache */
		rte_node_mbuf_priv1(mbuf3)->cksum = ipv4_hdr->hdr_checksum;
		rte_node_mbuf_priv1(mbuf3)->ttl = ipv4_hdr->time_to_live;

		/* Perform LPM lookup to get NH and next node */
		rte_lpm_lookupx4(lpm, dip, dst.u32, drop_nh);

		/* Extract next node id and NH */
		rte_node_mbuf_priv1(mbuf0)->nh = dst.u32[0] & 0xFFFF;
		next0 = (dst.u32[0] >> 16);

		rte_node_mbuf_priv1(mbuf1)->nh = dst.u32[1] & 0xFFFF;
		next1 = (dst.u32[1] >> 16);

		rte_node_mbuf_priv1(mbuf2)->nh = dst.u32[2] & 0xFFFF;
		next2 = (dst.u32[2] >> 16);

		rte_node_mbuf_priv1(mbuf3)->nh = dst.u32[3] & 0xFFFF;
		next3 = (dst.u32[3] >> 16);

		/* Enqueue four to next node */
		rte_edge_t fix_spec =
			(next_index ^ next0) | (next_index ^ next1) |
			(next_index ^ next2) | (next_index ^ next3);

		if (unlikely(fix_spec)) {
			/* Copy things successfully speculated till now */
			rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;

			/* Next0 */
			if (next_index == next0) {
				to_next[0] = from[0];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node, next0,
						    from[0]);
			}

			/* Next1 */
			if (next_index == next1) {
				to_next[0] = from[1];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node, next1,
						    from[1]);
			}

			/* Next2 */
			if (next_index == next2) {
				to_next[0] = from[2];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node, next2,
						    from[2]);
			}

			/* Next3 */
			if (next_index == next3) {
				to_next[0] = from[3];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node, next3,
						    from[3]);
			}

			from += 4;

		} else {
			last_spec += 4;
		}
	}

	while (n_left_from > 0) {
		uint32_t next_hop;

		mbuf0 = pkts[0];

		pkts += 1;
		n_left_from -= 1;

		/* Extract DIP of mbuf0 */
		eth_hdr = rte_pktmbuf_mtod(mbuf0, struct rte_ether_hdr *);
		ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
		/* Extract cksum, ttl as ipv4 hdr is in cache */
		rte_node_mbuf_priv1(mbuf0)->cksum = ipv4_hdr->hdr_checksum;
		rte_node_mbuf_priv1(mbuf0)->ttl = ipv4_hdr->time_to_live;

		rc = rte_lpm_lookup(lpm, rte_be_to_cpu_32(ipv4_hdr->dst_addr),
				    &next_hop);
		next_hop = (rc == 0) ? next_hop : drop_nh;

		rte_node_mbuf_priv1(mbuf0)->nh = next_hop & 0xFFFF;
		next0 = (next_hop >> 16);

		if (unlikely(next_index ^ next0)) {
			/* Copy things successfully speculated till now */
			rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;

			rte_node_enqueue_x1(graph, node, next0, from[0]);
			from += 1;
		} else {
			last_spec += 1;
		}
	}

	/* !!! Home run !!! */
	if (likely(last_spec == nb_objs)) {
		rte_node_next_stream_move(graph, node, next_index);
		return nb_objs;
	}

	held += last_spec;
	/* Copy things successfully speculated till now */
	rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
	rte_node_next_stream_put(graph, node, next_index, held);

	return nb_objs;
}

#else

static uint16_t
ip4_lookup_node_process(struct rte_graph *graph, struct rte_node *node,
			void **objs, uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);
	return nb_objs;
}

#endif

static int
ip4_lookup_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);

	node_dbg("ip4_lookup", "Initialized ip4_lookup node");

	return 0;
}

static struct rte_node_register ip4_lookup_node = {
	.process = ip4_lookup_node_process,
	.name = "ip4_lookup",

	.init = ip4_lookup_node_init,

	.nb_edges = RTE_NODE_IP4_LOOKUP_NEXT_MAX,
	.next_nodes = {
		[RTE_NODE_IP4_LOOKUP_NEXT_REWRITE] = "ip4_rewrite",
		[RTE_NODE_IP4_LOOKUP_NEXT_PKT_DROP] = "pkt_drop",
	},
};

RTE_NODE_REGISTER(ip4_lookup_node);
