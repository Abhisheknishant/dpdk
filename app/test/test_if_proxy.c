/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#include "test.h"

#include <rte_ethdev.h>
#include <rte_if_proxy.h>
#include <rte_cycles.h>

#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>

/* There are two types of event notifications - one using callbacks and one
 * using event queues (rings).  We'll test them both and this "bool" will govern
 * the type of API to use.
 */
static int use_callbacks = 1;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

static struct rte_ring *ev_queue;

enum net_event_mask {
	INITIALIZED	= 1U << RTE_IFPX_CFG_DONE,
	LINK_CHANGED	= 1U << RTE_IFPX_LINK_CHANGE,
	MAC_CHANGED	= 1U << RTE_IFPX_MAC_CHANGE,
	MTU_CHANGED	= 1U << RTE_IFPX_MTU_CHANGE,
	ADDR_ADD	= 1U << RTE_IFPX_ADDR_ADD,
	ADDR_DEL	= 1U << RTE_IFPX_ADDR_DEL,
	ROUTE_ADD	= 1U << RTE_IFPX_ROUTE_ADD,
	ROUTE_DEL	= 1U << RTE_IFPX_ROUTE_DEL,
	ADDR6_ADD	= 1U << RTE_IFPX_ADDR6_ADD,
	ADDR6_DEL	= 1U << RTE_IFPX_ADDR6_DEL,
	ROUTE6_ADD	= 1U << RTE_IFPX_ROUTE6_ADD,
	ROUTE6_DEL	= 1U << RTE_IFPX_ROUTE6_DEL,
	NEIGH_ADD	= 1U << RTE_IFPX_NEIGH_ADD,
	NEIGH_DEL	= 1U << RTE_IFPX_NEIGH_DEL,
	NEIGH6_ADD	= 1U << RTE_IFPX_NEIGH6_ADD,
	NEIGH6_DEL	= 1U << RTE_IFPX_NEIGH6_DEL,
};

static unsigned int state;

static struct {
	struct rte_ether_addr mac_addr;
	uint16_t port_id, mtu;
	struct in_addr ipv4, route4;
	struct in6_addr ipv6, route6;
	uint16_t depth4, depth6;
	int is_up;
} net_cfg;

static
int unlock_notify(unsigned int op)
{
	/* the mutex is expected to be locked on entry */
	RTE_VERIFY(pthread_mutex_trylock(&mutex) == EBUSY);
	state |= op;

	pthread_mutex_unlock(&mutex);
	return pthread_cond_signal(&cond);
}

static
void handle_event(struct rte_ifpx_event *ev);

static
int wait_for(unsigned int op_mask, unsigned int sec)
{
	int ec;

	if (use_callbacks) {
		struct timespec time;

		ec = pthread_mutex_trylock(&mutex);
		/* the mutex is expected to be locked on entry */
		RTE_VERIFY(ec == EBUSY);

		ec = 0;
		clock_gettime(CLOCK_REALTIME, &time);
		time.tv_sec += sec;

		while ((state & op_mask) != op_mask && ec == 0)
			ec = pthread_cond_timedwait(&cond, &mutex, &time);
	} else {
		uint64_t deadline;
		struct rte_ifpx_event *ev;

		ec = 0;
		deadline = rte_get_timer_cycles() + sec * rte_get_timer_hz();

		while ((state & op_mask) != op_mask) {
			if (rte_get_timer_cycles() >= deadline) {
				ec = ETIMEDOUT;
				break;
			}
			if (rte_ring_dequeue(ev_queue, (void **)&ev) == 0)
				handle_event(ev);
		}
	}

	return ec;
}

static
int expect(unsigned int op_mask, const char *fmt, ...)
#if __GNUC__
	__attribute__((format(printf, 2, 3)));
#endif

static
int expect(unsigned int op_mask, const char *fmt, ...)
{
	char cmd[128];
	va_list args;
	int ret;

	state &= ~op_mask;
	va_start(args, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, args);
	va_end(args);
	ret = system(cmd);
	if (ret == 0)
		/* IPv6 address notifications seem to need that long delay. */
		return wait_for(op_mask, 2);
	return ret;
}

static
int mac_change(const struct rte_ifpx_mac_change *ev)
{
	pthread_mutex_lock(&mutex);
	RTE_VERIFY(ev->port_id == net_cfg.port_id);
	if (memcmp(ev->mac.addr_bytes, net_cfg.mac_addr.addr_bytes,
		   RTE_ETHER_ADDR_LEN) == 0) {
		unlock_notify(MAC_CHANGED);
		return 1;
	}
	pthread_mutex_unlock(&mutex);
	return 0;
}

static
int mtu_change(const struct rte_ifpx_mtu_change *ev)
{
	pthread_mutex_lock(&mutex);
	RTE_VERIFY(ev->port_id == net_cfg.port_id);
	if (ev->mtu == net_cfg.mtu) {
		unlock_notify(MTU_CHANGED);
		return 1;
	}
	pthread_mutex_unlock(&mutex);
	return 0;
}

static
int link_change(const struct rte_ifpx_link_change *ev)
{
	pthread_mutex_lock(&mutex);
	RTE_VERIFY(ev->port_id == net_cfg.port_id);
	if (ev->is_up == net_cfg.is_up) {
		/* Special case for testing of callbacks modification from
		 * inside of callback: we catch putting link down (the last
		 * operation in test) and remove callbacks registered.
		 */
		if (!ev->is_up)
			rte_ifpx_callbacks_unregister_all();
		unlock_notify(LINK_CHANGED);
		return 1;
	}
	pthread_mutex_unlock(&mutex);
	return 0;
}

static
int addr_add(const struct rte_ifpx_addr_change *ev)
{
	pthread_mutex_lock(&mutex);
	RTE_VERIFY(ev->port_id == net_cfg.port_id);
	if (ev->ip == net_cfg.ipv4.s_addr) {
		unlock_notify(ADDR_ADD);
		return 1;
	}
	pthread_mutex_unlock(&mutex);
	return 0;
}

static
int addr_del(const struct rte_ifpx_addr_change *ev)
{
	pthread_mutex_lock(&mutex);
	RTE_VERIFY(ev->port_id == net_cfg.port_id);
	if (ev->ip == net_cfg.ipv4.s_addr) {
		unlock_notify(ADDR_DEL);
		return 1;
	}
	pthread_mutex_unlock(&mutex);
	return 0;
}

static
int addr6_add(const struct rte_ifpx_addr6_change *ev)
{
	pthread_mutex_lock(&mutex);
	RTE_VERIFY(ev->port_id == net_cfg.port_id);
	if (memcmp(ev->ip, net_cfg.ipv6.s6_addr, 16) == 0) {
		unlock_notify(ADDR6_ADD);
		return 1;
	}
	pthread_mutex_unlock(&mutex);
	return 0;
}

static
int addr6_del(const struct rte_ifpx_addr6_change *ev)
{
	pthread_mutex_lock(&mutex);
	RTE_VERIFY(ev->port_id == net_cfg.port_id);
	if (memcmp(ev->ip, net_cfg.ipv6.s6_addr, 16) == 0) {
		unlock_notify(ADDR6_DEL);
		return 1;
	}
	pthread_mutex_unlock(&mutex);
	return 0;
}

static
int route_add(const struct rte_ifpx_route_change *ev)
{
	pthread_mutex_lock(&mutex);
	RTE_VERIFY(ev->port_id == net_cfg.port_id);
	if (net_cfg.depth4 == ev->depth && net_cfg.route4.s_addr == ev->ip) {
		unlock_notify(ROUTE_ADD);
		return 1;
	}
	pthread_mutex_unlock(&mutex);
	return 0;
}

static
int route_del(const struct rte_ifpx_route_change *ev)
{
	pthread_mutex_lock(&mutex);
	RTE_VERIFY(ev->port_id == net_cfg.port_id);
	if (net_cfg.depth4 == ev->depth && net_cfg.route4.s_addr == ev->ip) {
		unlock_notify(ROUTE_DEL);
		return 1;
	}
	pthread_mutex_unlock(&mutex);
	return 0;
}

static
int route6_add(const struct rte_ifpx_route6_change *ev)
{
	pthread_mutex_lock(&mutex);
	RTE_VERIFY(ev->port_id == net_cfg.port_id);
	if (net_cfg.depth6 == ev->depth &&
	    /* don't check for trailing zeros */
	    memcmp(ev->ip, net_cfg.route6.s6_addr, ev->depth/8) == 0) {
		unlock_notify(ROUTE6_ADD);
		return 1;
	}
	pthread_mutex_unlock(&mutex);
	return 0;
}

static
int route6_del(const struct rte_ifpx_route6_change *ev)
{
	pthread_mutex_lock(&mutex);
	RTE_VERIFY(ev->port_id == net_cfg.port_id);
	if (net_cfg.depth6 == ev->depth &&
	    /* don't check for trailing zeros */
	    memcmp(ev->ip, net_cfg.route6.s6_addr, ev->depth/8) == 0) {
		unlock_notify(ROUTE6_DEL);
		return 1;
	}
	pthread_mutex_unlock(&mutex);
	return 0;
}

static
int neigh_add(const struct rte_ifpx_neigh_change *ev)
{
	pthread_mutex_lock(&mutex);
	RTE_VERIFY(ev->port_id == net_cfg.port_id);
	if (net_cfg.ipv4.s_addr == ev->ip &&
	    memcmp(ev->mac.addr_bytes, net_cfg.mac_addr.addr_bytes,
		   RTE_ETHER_ADDR_LEN) == 0) {
		unlock_notify(NEIGH_ADD);
		return 1;
	}
	pthread_mutex_unlock(&mutex);
	return 0;
}

static
int neigh_del(const struct rte_ifpx_neigh_change *ev)
{
	pthread_mutex_lock(&mutex);
	RTE_VERIFY(ev->port_id == net_cfg.port_id);
	if (net_cfg.ipv4.s_addr == ev->ip) {
		unlock_notify(NEIGH_DEL);
		return 1;
	}
	pthread_mutex_unlock(&mutex);
	return 0;
}

static
int neigh6_add(const struct rte_ifpx_neigh6_change *ev)
{
	pthread_mutex_lock(&mutex);
	RTE_VERIFY(ev->port_id == net_cfg.port_id);
	if (memcmp(ev->ip, net_cfg.ipv6.s6_addr, 16) == 0 &&
	    memcmp(ev->mac.addr_bytes, net_cfg.mac_addr.addr_bytes,
		   RTE_ETHER_ADDR_LEN) == 0) {
		unlock_notify(NEIGH6_ADD);
		return 1;
	}
	pthread_mutex_unlock(&mutex);
	return 0;
}

static
int neigh6_del(const struct rte_ifpx_neigh6_change *ev)
{
	pthread_mutex_lock(&mutex);
	RTE_VERIFY(ev->port_id == net_cfg.port_id);
	if (memcmp(ev->ip, net_cfg.ipv6.s6_addr, 16) == 0) {
		unlock_notify(NEIGH6_DEL);
		return 1;
	}
	pthread_mutex_unlock(&mutex);
	return 0;
}

static
int cfg_done(void)
{
	pthread_mutex_lock(&mutex);
	unlock_notify(INITIALIZED);
	return 1;
}

static
void handle_event(struct rte_ifpx_event *ev)
{
	if (ev->type != RTE_IFPX_CFG_DONE)
		RTE_VERIFY(ev->data.port_id == net_cfg.port_id);

	/* If params do not match what we expect just free the event. */
	switch (ev->type) {
	case RTE_IFPX_MAC_CHANGE:
		if (memcmp(ev->mac_change.mac.addr_bytes,
			   net_cfg.mac_addr.addr_bytes,
			   RTE_ETHER_ADDR_LEN) != 0)
			goto exit;
		break;
	case RTE_IFPX_MTU_CHANGE:
		if (ev->mtu_change.mtu != net_cfg.mtu)
			goto exit;
		break;
	case RTE_IFPX_LINK_CHANGE:
		if (ev->link_change.is_up != net_cfg.is_up)
			goto exit;
		break;
	case RTE_IFPX_ADDR_ADD:
		if (ev->addr_change.ip != net_cfg.ipv4.s_addr)
			goto exit;
		break;
	case RTE_IFPX_ADDR_DEL:
		if (ev->addr_change.ip != net_cfg.ipv4.s_addr)
			goto exit;
		break;
	case RTE_IFPX_ADDR6_ADD:
		if (memcmp(ev->addr6_change.ip, net_cfg.ipv6.s6_addr,
			   16) != 0)
			goto exit;
		break;
	case RTE_IFPX_ADDR6_DEL:
		if (memcmp(ev->addr6_change.ip, net_cfg.ipv6.s6_addr,
			   16) != 0)
			goto exit;
		break;
	case RTE_IFPX_ROUTE_ADD:
		if (net_cfg.depth4 != ev->route_change.depth ||
		    net_cfg.route4.s_addr != ev->route_change.ip)
			goto exit;
		break;
	case RTE_IFPX_ROUTE_DEL:
		if (net_cfg.depth4 != ev->route_change.depth ||
		    net_cfg.route4.s_addr != ev->route_change.ip)
			goto exit;
		break;
	case RTE_IFPX_ROUTE6_ADD:
		if (net_cfg.depth6 != ev->route6_change.depth ||
		    /* don't check for trailing zeros */
		    memcmp(ev->route6_change.ip, net_cfg.route6.s6_addr,
			   ev->route6_change.depth/8) != 0)
			goto exit;
		break;
	case RTE_IFPX_ROUTE6_DEL:
		if (net_cfg.depth6 != ev->route6_change.depth ||
		    /* don't check for trailing zeros */
		    memcmp(ev->route6_change.ip, net_cfg.route6.s6_addr,
			   ev->route6_change.depth/8) != 0)
			goto exit;
		break;
	case RTE_IFPX_NEIGH_ADD:
		if (net_cfg.ipv4.s_addr != ev->neigh_change.ip ||
		    memcmp(ev->neigh_change.mac.addr_bytes,
			   net_cfg.mac_addr.addr_bytes,
			   RTE_ETHER_ADDR_LEN) != 0)
			goto exit;
		break;
	case RTE_IFPX_NEIGH_DEL:
		if (net_cfg.ipv4.s_addr != ev->neigh_change.ip)
			goto exit;
		break;
	case RTE_IFPX_NEIGH6_ADD:
		if (memcmp(ev->neigh6_change.ip,
			   net_cfg.ipv6.s6_addr, 16) != 0 ||
		    memcmp(ev->neigh6_change.mac.addr_bytes,
			   net_cfg.mac_addr.addr_bytes,
			   RTE_ETHER_ADDR_LEN) != 0)
			goto exit;
		break;
	case RTE_IFPX_NEIGH6_DEL:
		if (memcmp(ev->neigh6_change.ip, net_cfg.ipv6.s6_addr, 16) != 0)
			goto exit;
		break;
	case RTE_IFPX_CFG_DONE:
		break;
	default:
		RTE_VERIFY(0 && "Unhandled event type");
	}

	state |= 1U << ev->type;
exit:
	free(ev);
}

static
struct rte_ifpx_callback cbs[] = {
	{ RTE_IFPX_MAC_CHANGE,  {.mac_change = mac_change} },
	{ RTE_IFPX_MTU_CHANGE,  {.mtu_change = mtu_change} },
	{ RTE_IFPX_LINK_CHANGE, {.link_change = link_change} },
	{ RTE_IFPX_ADDR_ADD,    {.addr_add = addr_add} },
	{ RTE_IFPX_ADDR_DEL,    {.addr_del = addr_del} },
	{ RTE_IFPX_ADDR6_ADD,   {.addr6_add = addr6_add} },
	{ RTE_IFPX_ADDR6_DEL,   {.addr6_del = addr6_del} },
	{ RTE_IFPX_ROUTE_ADD,   {.route_add = route_add} },
	{ RTE_IFPX_ROUTE_DEL,   {.route_del = route_del} },
	{ RTE_IFPX_ROUTE6_ADD,  {.route6_add = route6_add} },
	{ RTE_IFPX_ROUTE6_DEL,  {.route6_del = route6_del} },
	{ RTE_IFPX_NEIGH_ADD,   {.neigh_add = neigh_add} },
	{ RTE_IFPX_NEIGH_DEL,   {.neigh_del = neigh_del} },
	{ RTE_IFPX_NEIGH6_ADD,  {.neigh6_add = neigh6_add} },
	{ RTE_IFPX_NEIGH6_DEL,  {.neigh6_del = neigh6_del} },
	/* lib specific callback */
	{ RTE_IFPX_CFG_DONE,    {.cfg_done = cfg_done} },
};

static
int test_notifications(const struct rte_ifpx_info *pinfo)
{
	char mac_buf[RTE_ETHER_ADDR_FMT_SIZE];
	int ec;

	/* Test link up notification. */
	net_cfg.is_up = 1;
	ec = expect(LINK_CHANGED, "ip link set dev %s up", pinfo->if_name);
	if (ec != 0) {
		printf("Failed to notify about link going up\n");
		return ec;
	}

	/* Test for MAC changes notification. */
	rte_eth_random_addr(net_cfg.mac_addr.addr_bytes);
	rte_ether_format_addr(mac_buf, sizeof(mac_buf), &net_cfg.mac_addr);
	ec = expect(MAC_CHANGED, "ip link set dev %s address %s",
		    pinfo->if_name, mac_buf);
	if (ec != 0) {
		printf("Missing/wrong notification about mac change\n");
		return ec;
	}

	/* Test for MTU changes notification. */
	net_cfg.mtu = pinfo->mtu + 100;
	ec = expect(MTU_CHANGED, "ip link set dev %s mtu %d",
		    pinfo->if_name, net_cfg.mtu);
	if (ec != 0) {
		printf("Missing/wrong notification about mtu change\n");
		return ec;
	}

	/* Test for adding of IPv4 address - using address from TEST-2 pool.
	 * This test is specific to linux netlink behaviour - after adding
	 * address we get both notification about address being added and new
	 * route.  So I check both.
	 */
	net_cfg.ipv4.s_addr = RTE_IPV4(198, 51, 100, 14);
	net_cfg.route4.s_addr = net_cfg.ipv4.s_addr;
	net_cfg.depth4 = 32;
	ec = expect(ADDR_ADD | ROUTE_ADD, "ip addr add 198.51.100.14 dev %s",
		    pinfo->if_name);
	if (ec != 0) {
		printf("Missing/wrong notifications about IPv4 address add\n");
		return ec;
	}

	/* Test for IPv4 address removal.  See comment above for 'addr add'. */
	ec = expect(ADDR_DEL | ROUTE_DEL, "ip addr del 198.51.100.14/32 dev %s",
		    pinfo->if_name);
	if (ec != 0) {
		printf("Missing/wrong notifications about IPv4 address del\n");
		return ec;
	}

	/* Test for adding IPv4 route. */
	net_cfg.route4.s_addr = RTE_IPV4(198, 51, 100, 0);
	net_cfg.depth4 = 24;
	ec = expect(ROUTE_ADD, "ip route add 198.51.100.0/24 dev %s",
		    pinfo->if_name);
	if (ec != 0) {
		printf("Missing/wrong notifications about IPv4 route add\n");
		return ec;
	}

	/* Test for IPv4 route removal. */
	ec = expect(ROUTE_DEL, "ip route del 198.51.100.0/24 dev %s",
		    pinfo->if_name);
	if (ec != 0) {
		printf("Missing/wrong notifications about IPv4 route del\n");
		return ec;
	}

	/* Test for neighbour addresses notifications. */
	rte_eth_random_addr(net_cfg.mac_addr.addr_bytes);
	rte_ether_format_addr(mac_buf, sizeof(mac_buf), &net_cfg.mac_addr);

	ec = expect(NEIGH_ADD,
		    "ip neigh add 198.51.100.14 dev %s lladdr %s nud noarp",
		    pinfo->if_name, mac_buf);
	if (ec != 0) {
		printf("Missing/wrong notifications about IPv4 neighbour add\n");
		return ec;
	}

	ec = expect(NEIGH_DEL, "ip neigh del 198.51.100.14 dev %s",
		    pinfo->if_name);
	if (ec != 0) {
		printf("Missing/wrong notifications about IPv4 neighbour del\n");
		return ec;
	}

	/* Now the same for IPv6 - with address from "documentation pool". */
	inet_pton(AF_INET6, "2001:db8::dead:beef", net_cfg.ipv6.s6_addr);
	/* This is specific to linux netlink behaviour - after adding address
	 * we get both notification about address being added and new route.
	 * So I wait for both.
	 */
	memcpy(net_cfg.route6.s6_addr, net_cfg.ipv6.s6_addr, 16);
	net_cfg.depth6 = 128;
	ec = expect(ADDR6_ADD | ROUTE6_ADD,
		    "ip addr add 2001:db8::dead:beef dev %s",
		    pinfo->if_name);
	if (ec != 0) {
		printf("Missing/wrong notifications about IPv6 address add\n");
		return ec;
	}

	/* See comment above for 'addr6 add'. */
	ec = expect(ADDR6_DEL | ROUTE6_DEL,
		    "ip addr del 2001:db8::dead:beef/128 dev %s",
		    pinfo->if_name);
	if (ec != 0) {
		printf("Missing/wrong notifications about IPv6 address del\n");
		return ec;
	}

	net_cfg.depth6 = 96;
	ec = expect(ROUTE6_ADD, "ip route add 2001:db8::dead:0/96 dev %s",
		    pinfo->if_name);
	if (ec != 0) {
		printf("Missing/wrong notifications about IPv6 route add\n");
		return ec;
	}

	ec = expect(ROUTE6_DEL, "ip route del 2001:db8::dead:0/96 dev %s",
		    pinfo->if_name);
	if (ec != 0) {
		printf("Missing/wrong notifications about IPv6 route del\n");
		return ec;
	}

	ec = expect(NEIGH6_ADD,
		    "ip neigh add 2001:db8::dead:beef dev %s lladdr %s nud noarp",
		    pinfo->if_name, mac_buf);
	if (ec != 0) {
		printf("Missing/wrong notifications about IPv6 neighbour add\n");
		return ec;
	}

	ec = expect(NEIGH6_DEL, "ip neigh del 2001:db8::dead:beef dev %s",
		    pinfo->if_name);
	if (ec != 0) {
		printf("Missing/wrong notifications about IPv6 neighbour del\n");
		return ec;
	}

	/* Finally put link down and test for notification. */
	net_cfg.is_up = 0;
	ec = expect(LINK_CHANGED, "ip link set dev %s down", pinfo->if_name);
	if (ec != 0) {
		printf("Failed to notify about link going down\n");
		return ec;
	}

	return 0;
}

static
int test_if_proxy(void)
{
	int ec;
	const struct rte_ifpx_info *pinfo;
	uint16_t proxy_id;

	state = 0;
	memset(&net_cfg, 0, sizeof(net_cfg));

	if (rte_eth_dev_count_avail() == 0) {
		printf("Run this test with at least one port configured\n");
		return 1;
	}
	/* User the first port available. */
	RTE_ETH_FOREACH_DEV(net_cfg.port_id)
		break;
	proxy_id = rte_ifpx_proxy_create(RTE_IFPX_DEFAULT);
	RTE_VERIFY(proxy_id != RTE_MAX_ETHPORTS);
	rte_ifpx_port_bind(net_cfg.port_id, proxy_id);
	rte_ifpx_callbacks_register(RTE_DIM(cbs), cbs);
	rte_ifpx_listen();

	/* Let's start with callback based API. */
	use_callbacks = 1;
	pthread_mutex_lock(&mutex);
	ec = wait_for(INITIALIZED, 2);
	if (ec != 0) {
		printf("Failed to obtain network configuration\n");
		goto exit;
	}
	pinfo = rte_ifpx_info_get(net_cfg.port_id);
	RTE_VERIFY(pinfo);

	/* Make sure the link is down. */
	net_cfg.is_up = 0;
	ec = expect(LINK_CHANGED, "ip link set dev %s down", pinfo->if_name);
	RTE_VERIFY(ec == ETIMEDOUT || ec == 0);

	ec = test_notifications(pinfo);
	if (ec != 0) {
		printf("Failed test with callback based API\n");
		goto exit;
	}
	/* Switch to event queue based API and repeat tests. */
	use_callbacks = 0;
	ev_queue = rte_ring_create("IFPX-events", 16, SOCKET_ID_ANY,
				   RING_F_SP_ENQ | RING_F_SC_DEQ);
	ec = rte_ifpx_queue_add(ev_queue);
	if (ec != 0) {
		printf("Failed to add a notification queue\n");
		goto exit;
	}
	ec = test_notifications(pinfo);
	if (ec != 0) {
		printf("Failed test with event queue based API\n");
		goto exit;
	}

exit:
	pthread_mutex_unlock(&mutex);
	/* Proxy ports are not owned by the lib.  Internal references to them
	 * are cleared on close, but the ports are not destroyed so we need to
	 * do that explicitly.
	 */
	rte_ifpx_proxy_destroy(proxy_id);
	rte_ifpx_close();
	/* Queue is removed from the lib by rte_ifpx_close() - here we just
	 * free it.
	 */
	rte_ring_free(ev_queue);
	ev_queue = NULL;

	return ec;
}

REGISTER_TEST_COMMAND(if_proxy_autotest, test_if_proxy)
