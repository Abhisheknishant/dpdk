/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Marvell International Ltd.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ip.h>

#ifndef USE_HASH_CRC
#include <rte_jhash.h>
#else
#include <rte_hash_crc.h>
#endif

#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_if_proxy.h>

#include "l3fwd.h"

#define DO_RFC_1812_CHECKS

#define IPV4_L3FWD_LPM_MAX_RULES	1024
#define IPV4_L3FWD_LPM_NUMBER_TBL8S	(1 << 8)
#define IPV6_L3FWD_LPM_MAX_RULES	1024
#define IPV6_L3FWD_LPM_NUMBER_TBL8S	(1 << 16)

static volatile bool ifpx_ready;

/* ethernet addresses of ports */
static
union lladdr_t port_mac[RTE_MAX_ETHPORTS];

static struct rte_lpm *ipv4_routes;
static struct rte_lpm6 *ipv6_routes;

static
struct ipv4_gateway {
	uint16_t port;
	union lladdr_t lladdr;
	uint32_t ip;
} ipv4_gateways[128];

static
struct ipv6_gateway {
	uint16_t port;
	union lladdr_t lladdr;
	uint8_t ip[16];
} ipv6_gateways[128];

/* The lowest 2 bits of next hop (which is 24/21 bit for IPv4/6) are reserved to
 * encode:
 * 00 -> host route: higher bits of next hop are port id and dst MAC should be
 *       based on dst IP
 * 01 -> gateway route: higher bits of next hop are index into gateway array and
 *       use port and MAC cached there (if no MAC cached yet then search for it
 *       based on gateway IP)
 * 10 -> proxy entry: packet directed to us, just take higher bits as port id of
 *       proxy and send packet there (without any modification)
 * The port id (16 bits) will always fit however this will not work if you
 * need more than 2^20 gateways.
 */
enum route_type {
	HOST_ROUTE = 0x00,
	GW_ROUTE   = 0x01,
	PROXY_ADDR = 0x02,
};

RTE_STD_C11
_Static_assert(RTE_DIM(ipv4_gateways) <= (1 << 22) &&
	       RTE_DIM(ipv6_gateways) <= (1 << 19),
	       "Gateway array index has to fit within next_hop with 2 bits reserved");

static
uint32_t find_add_gateway(uint16_t port, uint32_t ip)
{
	uint32_t i, idx = -1U;

	for (i = 0; i < RTE_DIM(ipv4_gateways); ++i) {
		/* Remember first free slot in case GW is not present. */
		if (idx == -1U && ipv4_gateways[i].ip == 0)
			idx = i;
		else if (ipv4_gateways[i].ip == ip)
			/* For now assume that given GW will be always at the
			 * same port, so no checking for that
			 */
			return i;
	}
	if (idx != -1U) {
		ipv4_gateways[idx].port = port;
		ipv4_gateways[idx].ip = ip;
		/* Since ARP tables are kept per lcore MAC will be updated
		 * during first lookup.
		 */
	}
	return idx;
}

static
void clear_gateway(uint32_t ip)
{
	uint32_t i;

	for (i = 0; i < RTE_DIM(ipv4_gateways); ++i) {
		if (ipv4_gateways[i].ip == ip) {
			ipv4_gateways[i].ip = 0;
			ipv4_gateways[i].lladdr.val = 0;
			ipv4_gateways[i].port = RTE_MAX_ETHPORTS;
			break;
		}
	}
}

static
uint32_t find_add_gateway6(uint16_t port, const uint8_t *ip)
{
	uint32_t i, idx = -1U;

	for (i = 0; i < RTE_DIM(ipv6_gateways); ++i) {
		/* Remember first free slot in case GW is not present. */
		if (idx == -1U && ipv6_gateways[i].ip[0] == 0)
			idx = i;
		else if (ipv6_gateways[i].ip[0])
			/* For now assume that given GW will be always at the
			 * same port, so no checking for that
			 */
			return i;
	}
	if (idx != -1U) {
		ipv6_gateways[idx].port = port;
		memcpy(ipv6_gateways[idx].ip, ip, 16);
		/* Since ARP tables are kept per lcore MAC will be updated
		 * during first lookup.
		 */
	}
	return idx;
}

static
void clear_gateway6(const uint8_t *ip)
{
	uint32_t i;

	for (i = 0; i < RTE_DIM(ipv6_gateways); ++i) {
		if (memcmp(ipv6_gateways[i].ip, ip, 16) == 0) {
			memset(&ipv6_gateways[i].ip, 0, 16);
			ipv6_gateways[i].lladdr.val = 0;
			ipv6_gateways[i].port = RTE_MAX_ETHPORTS;
			break;
		}
	}
}

/* Assumptions:
 * - Link related changes (MAC/MTU/...) need to be executed once, and it's OK
 *   to run them from the callback - if this is not the case (e.g. -EBUSY for
 *   MTU change, then event notification need to be used and more sophisticated
 *   coordination with lcore loops and stopping/starting of the ports: for
 *   example lcores not receiving on this port just mark it as inactive and stop
 *   transmitting to it and the one with RX stops the port sets the MAC starts
 *   it and notifies other lcores that it is back).
 * - LPM is safe to be modified by one writer, and read by many without any
 *   locks (it looks to me like this is the case), however upon routing change
 *   there might be a transient period during which packets are not directed
 *   according to new rule.
 * - Hash is unsafe to be used that way (and I don't want to turn on relevant
 *   flags just to excersize queued notifications) so every lcore keeps its
 *   copy of relevant data.
 * Therefore there are callbacks defined for the routing info/address changes
 * and remaining ones are handled via events on per lcore basis.
 */
static
int mac_change(const struct rte_ifpx_mac_change *ev)
{
	int i;
	struct rte_ether_addr mac_addr;
	char buf[RTE_ETHER_ADDR_FMT_SIZE];

	if (rte_log_get_level(RTE_LOGTYPE_L3FWD) >= (int)RTE_LOG_DEBUG) {
		rte_ether_format_addr(buf, sizeof(buf), &ev->mac);
		RTE_LOG(DEBUG, L3FWD, "MAC change for port %d: %s\n",
			ev->port_id, buf);
	}
	/* NOTE - use copy because RTE functions don't take const args */
	rte_ether_addr_copy(&ev->mac, &mac_addr);
	i = rte_eth_dev_default_mac_addr_set(ev->port_id, &mac_addr);
	if (i == -EOPNOTSUPP)
		i = rte_eth_dev_mac_addr_add(ev->port_id, &mac_addr, 0);
	if (i < 0)
		RTE_LOG(WARNING, L3FWD, "Failed to set MAC address\n");
	else {
		port_mac[ev->port_id].mac.addr = ev->mac;
		port_mac[ev->port_id].mac.valid = 1;
	}
	return 1;
}

static
int link_change(const struct rte_ifpx_link_change *ev)
{
	uint16_t proxy_id = rte_ifpx_proxy_get(ev->port_id);
	uint32_t mask;

	/* Mark the proxy too since we get only port notifications. */
	mask = 1U << ev->port_id | 1U << proxy_id;

	RTE_LOG(DEBUG, L3FWD, "Link change for port %d: %d\n",
		ev->port_id, ev->is_up);
	if (ev->is_up) {
		rte_eth_dev_set_link_up(ev->port_id);
		active_port_mask |= mask;
	} else {
		rte_eth_dev_set_link_down(ev->port_id);
		active_port_mask &= ~mask;
	}
	active_port_mask &= enabled_port_mask;
	return 1;
}

static
int addr_add(const struct rte_ifpx_addr_change *ev)
{
	char buf[INET_ADDRSTRLEN];
	uint32_t ip;

	if (rte_log_get_level(RTE_LOGTYPE_L3FWD) >= (int)RTE_LOG_DEBUG) {
		ip = rte_cpu_to_be_32(ev->ip);
		inet_ntop(AF_INET, &ip, buf, sizeof(buf));
		RTE_LOG(DEBUG, L3FWD, "IPv4 address for port %d: %s\n",
			ev->port_id, buf);
	}
	rte_lpm_add(ipv4_routes, ev->ip, 32,
		    ev->port_id << 2 | PROXY_ADDR);
	return 1;
}

static
int route_add(const struct rte_ifpx_route_change *ev)
{
	char buf[INET_ADDRSTRLEN];
	uint32_t nh, ip;

	if (rte_log_get_level(RTE_LOGTYPE_L3FWD) >= (int)RTE_LOG_DEBUG) {
		ip = rte_cpu_to_be_32(ev->ip);
		inet_ntop(AF_INET, &ip, buf, sizeof(buf));
		RTE_LOG(DEBUG, L3FWD, "IPv4 route for port %d: %s/%d\n",
			ev->port_id, buf, ev->depth);
	}

	/* On Linux upon changing of the IP we get notification for both addr
	 * and route, so just check if we already have addr entry and if so
	 * then ignore this notification.
	 */
	if (ev->depth == 32 &&
	    rte_lpm_lookup(ipv4_routes, ev->ip, &nh) == 0 && nh & PROXY_ADDR)
		return 1;

	if (ev->gateway) {
		nh = find_add_gateway(ev->port_id, ev->gateway);
		if (nh != -1U)
			rte_lpm_add(ipv4_routes, ev->ip, ev->depth,
				    nh << 2 | GW_ROUTE);
		else
			RTE_LOG(WARNING, L3FWD, "No free slot in GW array\n");
	} else
		rte_lpm_add(ipv4_routes, ev->ip, ev->depth,
			    ev->port_id << 2 | HOST_ROUTE);
	return 1;
}

static
int addr_del(const struct rte_ifpx_addr_change *ev)
{
	char buf[INET_ADDRSTRLEN];
	uint32_t ip;

	if (rte_log_get_level(RTE_LOGTYPE_L3FWD) >= (int)RTE_LOG_DEBUG) {
		ip = rte_cpu_to_be_32(ev->ip);
		inet_ntop(AF_INET, &ip, buf, sizeof(buf));
		RTE_LOG(DEBUG, L3FWD, "IPv4 address removed from port %d: %s\n",
			ev->port_id, buf);
	}
	rte_lpm_delete(ipv4_routes, ev->ip, 32);
	return 1;
}

static
int route_del(const struct rte_ifpx_route_change *ev)
{
	char buf[INET_ADDRSTRLEN];
	uint32_t ip;

	if (rte_log_get_level(RTE_LOGTYPE_L3FWD) >= (int)RTE_LOG_DEBUG) {
		ip = rte_cpu_to_be_32(ev->ip);
		inet_ntop(AF_INET, &ip, buf, sizeof(buf));
		RTE_LOG(DEBUG, L3FWD, "IPv4 route removed from port %d: %s/%d\n",
			ev->port_id, buf, ev->depth);
	}
	if (ev->gateway)
		clear_gateway(ev->gateway);
	rte_lpm_delete(ipv4_routes, ev->ip, ev->depth);
	return 1;
}

static
int addr6_add(const struct rte_ifpx_addr6_change *ev)
{
	char buf[INET6_ADDRSTRLEN];

	if (rte_log_get_level(RTE_LOGTYPE_L3FWD) >= (int)RTE_LOG_DEBUG) {
		inet_ntop(AF_INET6, ev->ip, buf, sizeof(buf));
		RTE_LOG(DEBUG, L3FWD, "IPv6 address for port %d: %s\n",
			ev->port_id, buf);
	}
	rte_lpm6_add(ipv6_routes, ev->ip, 128,
		     ev->port_id << 2 | PROXY_ADDR);
	return 1;
}

static
int route6_add(const struct rte_ifpx_route6_change *ev)
{
	char buf[INET6_ADDRSTRLEN];

	/* See comment in route_add(). */
	uint32_t nh;
	if (ev->depth == 128 &&
	    rte_lpm6_lookup(ipv6_routes, ev->ip, &nh) == 0 && nh & PROXY_ADDR)
		return 1;

	if (rte_log_get_level(RTE_LOGTYPE_L3FWD) >= (int)RTE_LOG_DEBUG) {
		inet_ntop(AF_INET6, ev->ip, buf, sizeof(buf));
		RTE_LOG(DEBUG, L3FWD, "IPv6 route for port %d: %s/%d\n",
			ev->port_id, buf, ev->depth);
	}
	/* no valid IPv6 address starts with 0x00 */
	if (ev->gateway[0]) {
		nh = find_add_gateway6(ev->port_id, ev->ip);
		if (nh != -1U)
			rte_lpm6_add(ipv6_routes, ev->ip, ev->depth,
				     nh << 2 | GW_ROUTE);
		else
			RTE_LOG(WARNING, L3FWD, "No free slot in GW6 array\n");
	} else
		rte_lpm6_add(ipv6_routes, ev->ip, ev->depth,
			     ev->port_id << 2 | HOST_ROUTE);
	return 1;
}

static
int addr6_del(const struct rte_ifpx_addr6_change *ev)
{
	char buf[INET6_ADDRSTRLEN];

	if (rte_log_get_level(RTE_LOGTYPE_L3FWD) >= (int)RTE_LOG_DEBUG) {
		inet_ntop(AF_INET6, ev->ip, buf, sizeof(buf));
		RTE_LOG(DEBUG, L3FWD, "IPv6 address removed from port %d: %s\n",
			ev->port_id, buf);
	}
	rte_lpm6_delete(ipv6_routes, ev->ip, 128);
	return 1;
}

static
int route6_del(const struct rte_ifpx_route6_change *ev)
{
	char buf[INET_ADDRSTRLEN];

	if (rte_log_get_level(RTE_LOGTYPE_L3FWD) >= (int)RTE_LOG_DEBUG) {
		inet_ntop(AF_INET6, ev->ip, buf, sizeof(buf));
		RTE_LOG(DEBUG, L3FWD, "IPv6 route removed from port %d: %s/%d\n",
			ev->port_id, buf, ev->depth);
	}
	if (ev->gateway[0])
		clear_gateway6(ev->gateway);
	rte_lpm6_delete(ipv6_routes, ev->ip, ev->depth);
	return 1;
}

static
int cfg_done(void)
{
	uint16_t port_id, px;
	const struct rte_ifpx_info *pinfo;

	RTE_LOG(DEBUG, L3FWD, "Proxy config finished\n");

	/* Copy MAC addresses of the proxies - to be used as src MAC during
	 * forwarding.
	 */
	RTE_ETH_FOREACH_DEV(port_id) {
		px = rte_ifpx_proxy_get(port_id);
		if (px != RTE_MAX_ETHPORTS && px != port_id) {
			pinfo = rte_ifpx_info_get(px);
			rte_ether_addr_copy(&pinfo->mac,
					    &port_mac[port_id].mac.addr);
			port_mac[port_id].mac.valid = 1;
		}
	}

	ifpx_ready = 1;
	return 1;
}

static
struct rte_ifpx_callback ifpx_callbacks[] = {
	{ RTE_IFPX_MAC_CHANGE,  {.mac_change  = mac_change} },
	{ RTE_IFPX_LINK_CHANGE, {.link_change = link_change} },
	{ RTE_IFPX_ADDR_ADD,    {.addr_add    = addr_add} },
	{ RTE_IFPX_ADDR_DEL,    {.addr_del    = addr_del} },
	{ RTE_IFPX_ADDR6_ADD,   {.addr6_add   = addr6_add} },
	{ RTE_IFPX_ADDR6_DEL,   {.addr6_del   = addr6_del} },
	{ RTE_IFPX_ROUTE_ADD,   {.route_add   = route_add} },
	{ RTE_IFPX_ROUTE_DEL,   {.route_del   = route_del} },
	{ RTE_IFPX_ROUTE6_ADD,  {.route6_add  = route6_add} },
	{ RTE_IFPX_ROUTE6_DEL,  {.route6_del  = route6_del} },
	{ RTE_IFPX_CFG_DONE,    {.cfg_done    = cfg_done} },
};

int init_if_proxy(void)
{
	char buf[16];
	unsigned int i;

	rte_ifpx_callbacks_register(RTE_DIM(ifpx_callbacks), ifpx_callbacks);

	RTE_LCORE_FOREACH(i) {
		if (lcore_conf[i].n_rx_queue == 0)
			continue;
		snprintf(buf, sizeof(buf), "IFPX-events_%d", i);
		lcore_conf[i].ev_queue = rte_ring_create(buf, 16, SOCKET_ID_ANY,
						 RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (!lcore_conf[i].ev_queue) {
			RTE_LOG(ERR, L3FWD,
				"Failed to create event queue for lcore %d\n",
				i);
			return -1;
		}
		rte_ifpx_queue_add(lcore_conf[i].ev_queue);
	}

	return rte_ifpx_listen();
}

void close_if_proxy(void)
{
	unsigned int i;

	RTE_LCORE_FOREACH(i) {
		if (lcore_conf[i].n_rx_queue == 0)
			continue;
		rte_ring_free(lcore_conf[i].ev_queue);
	}
	rte_ifpx_close();
}

void wait_for_config_done(void)
{
	while (!ifpx_ready)
		rte_delay_ms(100);
}

#ifdef DO_RFC_1812_CHECKS
static inline
int is_valid_ipv4_pkt(struct rte_ipv4_hdr *pkt, uint32_t link_len)
{
	/* From http://www.rfc-editor.org/rfc/rfc1812.txt section 5.2.2 */
	/*
	 * 1. The packet length reported by the Link Layer must be large
	 * enough to hold the minimum length legal IP datagram (20 bytes).
	 */
	if (link_len < sizeof(struct rte_ipv4_hdr))
		return -1;

	/* 2. The IP checksum must be correct. */
	/* this is checked in H/W */

	/*
	 * 3. The IP version number must be 4. If the version number is not 4
	 * then the packet may be another version of IP, such as IPng or
	 * ST-II.
	 */
	if (((pkt->version_ihl) >> 4) != 4)
		return -3;
	/*
	 * 4. The IP header length field must be large enough to hold the
	 * minimum length legal IP datagram (20 bytes = 5 words).
	 */
	if ((pkt->version_ihl & 0xf) < 5)
		return -4;

	/*
	 * 5. The IP total length field must be large enough to hold the IP
	 * datagram header, whose length is specified in the IP header length
	 * field.
	 */
	if (rte_cpu_to_be_16(pkt->total_length) < sizeof(struct rte_ipv4_hdr))
		return -5;

	return 0;
}
#endif

/* Send burst of packets on an output interface */
static inline
int send_burst(struct lcore_conf *lconf, uint16_t n, uint16_t port)
{
	struct rte_mbuf **m_table;
	int ret;
	uint16_t queueid;

	queueid = lconf->tx_queue_id[port];
	m_table = (struct rte_mbuf **)lconf->tx_mbufs[port].m_table;

	ret = rte_eth_tx_burst(port, queueid, m_table, n);
	if (unlikely(ret < n)) {
		do {
			rte_pktmbuf_free(m_table[ret]);
		} while (++ret < n);
	}

	return 0;
}

/* Enqueue a single packet, and send burst if queue is filled */
static inline
int send_single_packet(struct lcore_conf *lconf,
		       struct rte_mbuf *m, uint16_t port)
{
	uint16_t len;

	len = lconf->tx_mbufs[port].len;
	lconf->tx_mbufs[port].m_table[len] = m;
	len++;

	/* enough pkts to be sent */
	if (unlikely(len == MAX_PKT_BURST)) {
		send_burst(lconf, MAX_PKT_BURST, port);
		len = 0;
	}

	lconf->tx_mbufs[port].len = len;
	return 0;
}

static inline
int ipv4_get_destination(const struct rte_ipv4_hdr *ipv4_hdr,
			 struct rte_lpm *lpm, uint32_t *next_hop)
{
	return rte_lpm_lookup(lpm,
			      rte_be_to_cpu_32(ipv4_hdr->dst_addr),
			      next_hop);
}

static inline
int ipv6_get_destination(const struct rte_ipv6_hdr *ipv6_hdr,
			 struct rte_lpm6 *lpm, uint32_t *next_hop)
{
	return rte_lpm6_lookup(lpm, ipv6_hdr->dst_addr, next_hop);
}

static
uint16_t ipv4_process_pkt(struct lcore_conf *lconf,
			  struct rte_ether_hdr *eth_hdr,
			  struct rte_ipv4_hdr *ipv4_hdr, uint16_t portid)
{
	union lladdr_t lladdr = { 0 };
	int i;
	uint32_t ip, nh;

	/* Here we know that packet is not from proxy - this case is handled
	 * in the main loop - so if we fail to find destination we will direct
	 * it to the proxy.
	 */
	if (ipv4_get_destination(ipv4_hdr, ipv4_routes, &nh) < 0)
		return rte_ifpx_proxy_get(portid);

	if (nh & PROXY_ADDR)
		return nh >> 2;

	/* Packet not to us so update src/dst MAC. */
	if (nh & GW_ROUTE) {
		i = nh >> 2;
		if (ipv4_gateways[i].lladdr.mac.valid)
			lladdr = ipv4_gateways[i].lladdr;
		else {
			i = rte_hash_lookup(lconf->neigh_hash,
					    &ipv4_gateways[i].ip);
			if (i < 0)
				return rte_ifpx_proxy_get(portid);
			lladdr = lconf->neigh_map[i];
			ipv4_gateways[i].lladdr = lladdr;
		}
		nh = ipv4_gateways[i].port;
	} else {
		nh >>= 2;
		ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
		i = rte_hash_lookup(lconf->neigh_hash, &ip);
		if (i < 0)
			return rte_ifpx_proxy_get(portid);
		lladdr = lconf->neigh_map[i];
	}

	RTE_ASSERT(lladdr.mac.valid);
	RTE_ASSERT(port_mac[nh].mac.valid);
	/* dst addr */
	*(uint64_t *)&eth_hdr->d_addr = lladdr.val;
	/* src addr */
	rte_ether_addr_copy(&port_mac[nh].mac.addr, &eth_hdr->s_addr);

	return nh;
}

static
uint16_t ipv6_process_pkt(struct lcore_conf *lconf,
			  struct rte_ether_hdr *eth_hdr,
			  struct rte_ipv6_hdr *ipv6_hdr, uint16_t portid)
{
	union lladdr_t lladdr = { 0 };
	int i;
	uint32_t nh;

	/* Here we know that packet is not from proxy - this case is handled
	 * in the main loop - so if we fail to find destination we will direct
	 * it to the proxy.
	 */
	if (ipv6_get_destination(ipv6_hdr, ipv6_routes, &nh) < 0)
		return rte_ifpx_proxy_get(portid);

	if (nh & PROXY_ADDR)
		return nh >> 2;

	/* Packet not to us so update src/dst MAC. */
	if (nh & GW_ROUTE) {
		i = nh >> 2;
		if (ipv6_gateways[i].lladdr.mac.valid)
			lladdr = ipv6_gateways[i].lladdr;
		else {
			i = rte_hash_lookup(lconf->neigh6_hash,
					    ipv6_gateways[i].ip);
			if (i < 0)
				return rte_ifpx_proxy_get(portid);
			lladdr = lconf->neigh6_map[i];
			ipv6_gateways[i].lladdr = lladdr;
		}
		nh = ipv6_gateways[i].port;
	} else {
		nh >>= 2;
		i = rte_hash_lookup(lconf->neigh6_hash, ipv6_hdr->dst_addr);
		if (i < 0)
			return rte_ifpx_proxy_get(portid);
		lladdr = lconf->neigh6_map[i];
	}

	RTE_ASSERT(lladdr.mac.valid);
	/* dst addr */
	*(uint64_t *)&eth_hdr->d_addr = lladdr.val;
	/* src addr */
	rte_ether_addr_copy(&port_mac[nh].mac.addr, &eth_hdr->s_addr);

	return nh;
}

static __rte_always_inline
void l3fwd_lpm_simple_forward(struct rte_mbuf *m, uint16_t portid,
			      struct lcore_conf *lconf)
{
	struct rte_ether_hdr *eth_hdr;
	uint32_t nh;

	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	if (RTE_ETH_IS_IPV4_HDR(m->packet_type)) {
		/* Handle IPv4 headers.*/
		struct rte_ipv4_hdr *ipv4_hdr;

		ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,
						   sizeof(*eth_hdr));

#ifdef DO_RFC_1812_CHECKS
		/* Check to make sure the packet is valid (RFC1812) */
		if (is_valid_ipv4_pkt(ipv4_hdr, m->pkt_len) < 0) {
			rte_pktmbuf_free(m);
			return;
		}
#endif
		nh = ipv4_process_pkt(lconf, eth_hdr, ipv4_hdr, portid);

#ifdef DO_RFC_1812_CHECKS
		/* Update time to live and header checksum */
		--(ipv4_hdr->time_to_live);
		++(ipv4_hdr->hdr_checksum);
#endif
	} else if (RTE_ETH_IS_IPV6_HDR(m->packet_type)) {
		/* Handle IPv6 headers.*/
		struct rte_ipv6_hdr *ipv6_hdr;

		ipv6_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv6_hdr *,
						   sizeof(*eth_hdr));

		nh = ipv6_process_pkt(lconf, eth_hdr, ipv6_hdr, portid);
	} else
		/* Unhandled protocol */
		nh = rte_ifpx_proxy_get(portid);

	if (nh >= RTE_MAX_ETHPORTS || (active_port_mask & 1 << nh) == 0)
		rte_pktmbuf_free(m);
	else
		send_single_packet(lconf, m, nh);
}

static inline
void l3fwd_send_packets(int nb_rx, struct rte_mbuf **pkts_burst,
			uint16_t portid, struct lcore_conf *lconf)
{
	int32_t j;

	/* Prefetch first packets */
	for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++)
		rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));

	/* Prefetch and forward already prefetched packets. */
	for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
		rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[
				j + PREFETCH_OFFSET], void *));
		l3fwd_lpm_simple_forward(pkts_burst[j], portid, lconf);
	}

	/* Forward remaining prefetched packets */
	for (; j < nb_rx; j++)
		l3fwd_lpm_simple_forward(pkts_burst[j], portid, lconf);
}

static
void handle_neigh_add(struct lcore_conf *lconf,
		      const struct rte_ifpx_neigh_change *ev)
{
	char mac[RTE_ETHER_ADDR_FMT_SIZE];
	char ip[INET_ADDRSTRLEN];
	int32_t i, a;

	i = rte_hash_add_key(lconf->neigh_hash, &ev->ip);
	if (i < 0) {
		RTE_LOG(WARNING, L3FWD, "Failed to add IPv4 neighbour entry\n");
		return;
	}
	if (rte_log_get_level(RTE_LOGTYPE_L3FWD) >= (int)RTE_LOG_DEBUG) {
		rte_ether_format_addr(mac, sizeof(mac), &ev->mac);
		a = rte_cpu_to_be_32(ev->ip);
		inet_ntop(AF_INET, &a, ip, sizeof(ip));
		RTE_LOG(DEBUG, L3FWD, "Neighbour update for port %d: %s -> %s@%d\n",
			ev->port_id, ip, mac, i);
	}
	lconf->neigh_map[i].mac.addr = ev->mac;
	lconf->neigh_map[i].mac.valid = 1;
}

static
void handle_neigh_del(struct lcore_conf *lconf,
		      const struct rte_ifpx_neigh_change *ev)
{
	char ip[INET_ADDRSTRLEN];
	int32_t i, a;

	i = rte_hash_del_key(lconf->neigh_hash, &ev->ip);
	if (i < 0) {
		RTE_LOG(WARNING, L3FWD,
			"Failed to remove IPv4 neighbour entry\n");
		return;
	}
	if (rte_log_get_level(RTE_LOGTYPE_L3FWD) >= (int)RTE_LOG_DEBUG) {
		a = rte_cpu_to_be_32(ev->ip);
		inet_ntop(AF_INET, &a, ip, sizeof(ip));
		RTE_LOG(DEBUG, L3FWD, "Neighbour removal for port %d: %s\n",
			ev->port_id, ip);
	}
	lconf->neigh_map[i].val = 0;
}

static
void handle_neigh6_add(struct lcore_conf *lconf,
		       const struct rte_ifpx_neigh6_change *ev)
{
	char mac[RTE_ETHER_ADDR_FMT_SIZE];
	char ip[INET6_ADDRSTRLEN];
	int32_t i;

	i = rte_hash_add_key(lconf->neigh6_hash, ev->ip);
	if (i < 0) {
		RTE_LOG(WARNING, L3FWD, "Failed to add IPv4 neighbour entry\n");
		return;
	}
	if (rte_log_get_level(RTE_LOGTYPE_L3FWD) >= (int)RTE_LOG_DEBUG) {
		rte_ether_format_addr(mac, sizeof(mac), &ev->mac);
		inet_ntop(AF_INET6, ev->ip, ip, sizeof(ip));
		RTE_LOG(DEBUG, L3FWD, "Neighbour update for port %d: %s -> %s@%d\n",
			ev->port_id, ip, mac, i);
	}
	lconf->neigh6_map[i].mac.addr = ev->mac;
	lconf->neigh6_map[i].mac.valid = 1;
}

static
void handle_neigh6_del(struct lcore_conf *lconf,
		       const struct rte_ifpx_neigh6_change *ev)
{
	char ip[INET6_ADDRSTRLEN];
	int32_t i;

	i = rte_hash_del_key(lconf->neigh6_hash, ev->ip);
	if (i < 0) {
		RTE_LOG(WARNING, L3FWD, "Failed to remove IPv6 neighbour entry\n");
		return;
	}
	if (rte_log_get_level(RTE_LOGTYPE_L3FWD) >= (int)RTE_LOG_DEBUG) {
		inet_ntop(AF_INET6, ev->ip, ip, sizeof(ip));
		RTE_LOG(DEBUG, L3FWD, "Neighbour removal for port %d: %s\n",
			ev->port_id, ip);
	}
	lconf->neigh6_map[i].val = 0;
}

static
void handle_events(struct lcore_conf *lconf)
{
	struct rte_ifpx_event *ev;

	while (rte_ring_dequeue(lconf->ev_queue, (void **)&ev) == 0) {
		switch (ev->type) {
		case RTE_IFPX_NEIGH_ADD:
			handle_neigh_add(lconf, &ev->neigh_change);
			break;
		case RTE_IFPX_NEIGH_DEL:
			handle_neigh_del(lconf, &ev->neigh_change);
			break;
		case RTE_IFPX_NEIGH6_ADD:
			handle_neigh6_add(lconf, &ev->neigh6_change);
			break;
		case RTE_IFPX_NEIGH6_DEL:
			handle_neigh6_del(lconf, &ev->neigh6_change);
			break;
		default:
			RTE_LOG(WARNING, L3FWD,
				"Unexpected event: %d\n", ev->type);
		}
		free(ev);
	}
}

void setup_lpm(void)
{
	struct rte_lpm6_config cfg6;
	struct rte_lpm_config cfg4;

	/* create the LPM table */
	cfg4.max_rules = IPV4_L3FWD_LPM_MAX_RULES;
	cfg4.number_tbl8s = IPV4_L3FWD_LPM_NUMBER_TBL8S;
	cfg4.flags = 0;
	ipv4_routes = rte_lpm_create("IPV4_L3FWD_LPM", SOCKET_ID_ANY, &cfg4);
	if (ipv4_routes == NULL)
		rte_exit(EXIT_FAILURE, "Unable to create the l3fwd LPM table\n");

	/* create the LPM6 table */
	cfg6.max_rules = IPV6_L3FWD_LPM_MAX_RULES;
	cfg6.number_tbl8s = IPV6_L3FWD_LPM_NUMBER_TBL8S;
	cfg6.flags = 0;
	ipv6_routes = rte_lpm6_create("IPV6_L3FWD_LPM", SOCKET_ID_ANY, &cfg6);
	if (ipv6_routes == NULL)
		rte_exit(EXIT_FAILURE, "Unable to create the l3fwd LPM table\n");
}

static
uint32_t hash_ipv4(const void *key, uint32_t key_len __rte_unused,
		   uint32_t init_val)
{
#ifndef USE_HASH_CRC
	return rte_jhash_1word(*(const uint32_t *)key, init_val);
#else
	return rte_hash_crc_4byte(*(const uint32_t *)key, init_val);
#endif
}

static
uint32_t hash_ipv6(const void *key, uint32_t key_len __rte_unused,
		   uint32_t init_val)
{
#ifndef USE_HASH_CRC
	return rte_jhash_32b(key, 4, init_val);
#else
	const uint64_t *pk = key;
	init_val = rte_hash_crc_8byte(*pk, init_val);
	return rte_hash_crc_8byte(*(pk+1), init_val);
#endif
}

static
int setup_neigh(struct lcore_conf *lconf)
{
	char buf[16];
	struct rte_hash_parameters ipv4_hparams = {
		.name = buf,
		.entries = L3FWD_NEIGH_ENTRIES,
		.key_len = 4,
		.hash_func = hash_ipv4,
		.hash_func_init_val = 0,
	};
	struct rte_hash_parameters ipv6_hparams = {
		.name = buf,
		.entries = L3FWD_NEIGH_ENTRIES,
		.key_len = 16,
		.hash_func = hash_ipv6,
		.hash_func_init_val = 0,
	};

	snprintf(buf, sizeof(buf), "neigh_hash-%d", rte_lcore_id());
	lconf->neigh_hash = rte_hash_create(&ipv4_hparams);
	snprintf(buf, sizeof(buf), "neigh_map-%d", rte_lcore_id());
	lconf->neigh_map = rte_zmalloc(buf,
				L3FWD_NEIGH_ENTRIES*sizeof(*lconf->neigh_map),
				8);
	if (lconf->neigh_hash == NULL || lconf->neigh_map == NULL) {
		RTE_LOG(ERR, L3FWD,
			"Unable to create the l3fwd ARP/IPv4 table (lcore %d)\n",
			rte_lcore_id());
		return -1;
	}

	snprintf(buf, sizeof(buf), "neigh6_hash-%d", rte_lcore_id());
	lconf->neigh6_hash = rte_hash_create(&ipv6_hparams);
	snprintf(buf, sizeof(buf), "neigh6_map-%d", rte_lcore_id());
	lconf->neigh6_map = rte_zmalloc(buf,
				L3FWD_NEIGH_ENTRIES*sizeof(*lconf->neigh6_map),
				8);
	if (lconf->neigh6_hash == NULL || lconf->neigh6_map == NULL) {
		RTE_LOG(ERR, L3FWD,
			"Unable to create the l3fwd ARP/IPv6 table (lcore %d)\n",
			rte_lcore_id());
		return -1;
	}
	return 0;
}

int lpm_check_ptype(int portid)
{
	int i, ret;
	int ptype_l3_ipv4 = 0, ptype_l3_ipv6 = 0;
	uint32_t ptype_mask = RTE_PTYPE_L3_MASK;

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, NULL, 0);
	if (ret <= 0)
		return 0;

	uint32_t ptypes[ret];

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, ptypes, ret);
	for (i = 0; i < ret; ++i) {
		if (ptypes[i] & RTE_PTYPE_L3_IPV4)
			ptype_l3_ipv4 = 1;
		if (ptypes[i] & RTE_PTYPE_L3_IPV6)
			ptype_l3_ipv6 = 1;
	}

	if (ptype_l3_ipv4 == 0)
		RTE_LOG(WARNING, L3FWD,
			"port %d cannot parse RTE_PTYPE_L3_IPV4\n", portid);

	if (ptype_l3_ipv6 == 0)
		RTE_LOG(WARNING, L3FWD,
			"port %d cannot parse RTE_PTYPE_L3_IPV6\n", portid);

	if (ptype_l3_ipv4 && ptype_l3_ipv6)
		return 1;

	return 0;

}

static inline
void lpm_parse_ptype(struct rte_mbuf *m)
{
	struct rte_ether_hdr *eth_hdr;
	uint32_t packet_type = RTE_PTYPE_UNKNOWN;
	uint16_t ether_type;

	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	ether_type = eth_hdr->ether_type;
	if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
		packet_type |= RTE_PTYPE_L3_IPV4_EXT_UNKNOWN;
	else if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
		packet_type |= RTE_PTYPE_L3_IPV6_EXT_UNKNOWN;

	m->packet_type = packet_type;
}

uint16_t lpm_cb_parse_ptype(uint16_t port __rte_unused,
			    uint16_t queue __rte_unused,
			    struct rte_mbuf *pkts[], uint16_t nb_pkts,
			    uint16_t max_pkts __rte_unused,
			    void *user_param __rte_unused)
{
	unsigned int i;

	if (unlikely(nb_pkts == 0))
		return nb_pkts;
	rte_prefetch0(rte_pktmbuf_mtod(pkts[0], struct ether_hdr *));
	for (i = 0; i < (unsigned int) (nb_pkts - 1); ++i) {
		rte_prefetch0(rte_pktmbuf_mtod(pkts[i+1],
			struct ether_hdr *));
		lpm_parse_ptype(pkts[i]);
	}
	lpm_parse_ptype(pkts[i]);

	return nb_pkts;
}

/* main processing loop */
int lpm_main_loop(void *dummy __rte_unused)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	unsigned int lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc;
	int i, j, nb_rx;
	uint16_t portid;
	uint8_t queueid;
	struct lcore_conf *lconf;
	struct lcore_rx_queue *rxq;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
		US_PER_S * BURST_TX_DRAIN_US;

	prev_tsc = 0;

	lcore_id = rte_lcore_id();
	lconf = &lcore_conf[lcore_id];

	if (setup_neigh(lconf) < 0) {
		RTE_LOG(ERR, L3FWD, "lcore %u failed to setup its ARP tables\n",
			lcore_id);
		return 0;
	}

	if (lconf->n_rx_queue == 0) {
		RTE_LOG(INFO, L3FWD, "lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, L3FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < lconf->n_rx_queue; i++) {

		portid = lconf->rx_queue_list[i].port_id;
		queueid = lconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, L3FWD,
			" -- lcoreid=%u portid=%u rxqueueid=%hhu\n",
			lcore_id, portid, queueid);
	}

	while (!force_quit) {

		cur_tsc = rte_rdtsc();
		/*
		 * TX burst and event queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc % drain_tsc == 0)) {

			for (i = 0; i < lconf->n_tx_port; ++i) {
				portid = lconf->tx_port_id[i];
				if (lconf->tx_mbufs[portid].len == 0)
					continue;
				send_burst(lconf,
					lconf->tx_mbufs[portid].len,
					portid);
				lconf->tx_mbufs[portid].len = 0;
			}

			if (diff_tsc > EV_QUEUE_DRAIN * drain_tsc) {
				if (lconf->ev_queue &&
				    !rte_ring_empty(lconf->ev_queue))
					handle_events(lconf);
				prev_tsc = cur_tsc;
			}
		}

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < lconf->n_rx_queue; ++i) {
			rxq = &lconf->rx_queue_list[i];
			portid = rxq->port_id;
			queueid = rxq->queue_id;
			nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst,
				MAX_PKT_BURST);
			if (nb_rx == 0)
				continue;
			/* If current queue is from proxy interface then there
			 * is no need to figure out destination port - just
			 * forward it to the bound port.
			 */
			if (unlikely(rxq->dst_port != RTE_MAX_ETHPORTS)) {
				for (j = 0; j < nb_rx; ++j)
					send_single_packet(lconf, pkts_burst[j],
							   rxq->dst_port);
			} else
				l3fwd_send_packets(nb_rx, pkts_burst, portid,
						   lconf);
		}
	}

	return 0;
}
