/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#include "if_proxy_priv.h"
#include <rte_string_fns.h>

/* Definitions of data mentioned in if_proxy_priv.h and local ones. */
int ifpx_log_type;

/* Table keeping mapping between port and their proxies. */
static
uint16_t ifpx_ports[RTE_MAX_ETHPORTS];

rte_spinlock_t ifpx_lock = RTE_SPINLOCK_INITIALIZER;

struct ifpx_proxies_head ifpx_proxies = TAILQ_HEAD_INITIALIZER(ifpx_proxies);

struct ifpx_queue_node {
	TAILQ_ENTRY(ifpx_queue_node) elem;
	uint16_t state;
	struct rte_ring *r;
};
static
TAILQ_HEAD(ifpx_queues_head, ifpx_queue_node) ifpx_queues =
		TAILQ_HEAD_INITIALIZER(ifpx_queues);

/* All callbacks have similar signature (taking pointer to some event) so we'll
 * use this f_ptr to typecast and invoke them in a generic way.  There is one
 * exception though - notification about completed initial configuration - and
 * it is handled separately.
 */
union ifpx_cb_ptr {
	int (*f_ptr)(void *ev); /* type for normal event notification */
	union rte_ifpx_cb_ptr cb;
} ifpx_callbacks[RTE_IFPX_NUM_EVENTS];

uint64_t rte_ifpx_events_available(void)
{
	if (ifpx_platform.events)
		return ifpx_platform.events();

	/* If callback is not provided then all events are supported. */
	return (1ULL << RTE_IFPX_NUM_EVENTS) - 1;
}

uint16_t rte_ifpx_proxy_create(enum rte_ifpx_proxy_type type)
{
	char devargs[16] = { '\0' };
	int dev_cnt = 0, nlen;
	uint16_t port_id;

	switch (type) {
	case RTE_IFPX_DEFAULT:
	case RTE_IFPX_TAP:
		nlen = strlcpy(devargs, "net_tap", sizeof(devargs));
		break;
	case RTE_IFPX_KNI:
		nlen = strlcpy(devargs, "net_kni", sizeof(devargs));
		break;
	default:
		IFPX_LOG(ERR, "Unknown proxy type: %d", type);
		return RTE_MAX_ETHPORTS;
	}

	RTE_ETH_FOREACH_DEV(port_id) {
		if (strcmp(rte_eth_devices[port_id].device->driver->name,
			   devargs) == 0)
			++dev_cnt;
	}
	snprintf(devargs+nlen, sizeof(devargs)-nlen, "%d", dev_cnt);

	return rte_ifpx_proxy_create_by_devarg(devargs);
}

uint16_t rte_ifpx_proxy_create_by_devarg(const char *devarg)
{
	uint16_t port_id = RTE_MAX_ETHPORTS;
	struct rte_dev_iterator iter;

	if (rte_dev_probe(devarg) < 0) {
		IFPX_LOG(ERR, "Failed to create proxy port %s\n", devarg);
		return RTE_MAX_ETHPORTS;
	}

	if (rte_eth_iterator_init(&iter, devarg) == 0) {
		port_id = rte_eth_iterator_next(&iter);
		if (port_id != RTE_MAX_ETHPORTS)
			rte_eth_iterator_cleanup(&iter);
	}

	return port_id;
}

int ifpx_proxy_destroy(struct ifpx_proxy_node *px)
{
	unsigned int i;
	uint16_t proxy_id = px->proxy_id;

	/* This function is expected to be called with a lock held. */
	RTE_ASSERT(rte_spinlock_trylock(&ifpx_lock) == 0);

	if (px->state & IN_USE) {
		px->state |= DEL_PENDING;
		return 0;
	}

	TAILQ_REMOVE(&ifpx_proxies, px, elem);
	free(px);

	/* Clear any bindings for this proxy. */
	for (i = 0; i < RTE_DIM(ifpx_ports); ++i) {
		if (ifpx_ports[i] == proxy_id)
			ifpx_ports[i] = RTE_MAX_ETHPORTS;
	}

	return rte_dev_remove(rte_eth_devices[proxy_id].device);
}

int rte_ifpx_proxy_destroy(uint16_t proxy_id)
{
	struct ifpx_proxy_node *px;
	int ec;

	rte_spinlock_lock(&ifpx_lock);
	TAILQ_FOREACH(px, &ifpx_proxies, elem) {
		if (px->proxy_id == proxy_id)
			break;
	}
	if (!px) {
		ec = -EINVAL;
		goto exit;
	}

	ec = ifpx_proxy_destroy(px);
exit:
	rte_spinlock_unlock(&ifpx_lock);
	return ec;
}

int rte_ifpx_queue_add(struct rte_ring *r)
{
	struct ifpx_queue_node *node;
	int ec = 0;

	if (!r)
		return -EINVAL;

	rte_spinlock_lock(&ifpx_lock);
	TAILQ_FOREACH(node, &ifpx_queues, elem) {
		if (node->r == r) {
			ec = -EEXIST;
			goto exit;
		}
	}

	node = malloc(sizeof(*node));
	if (!node) {
		ec = -ENOMEM;
		goto exit;
	}

	node->r = r;
	TAILQ_INSERT_TAIL(&ifpx_queues, node, elem);
exit:
	rte_spinlock_unlock(&ifpx_lock);

	return ec;
}

int rte_ifpx_queue_remove(struct rte_ring *r)
{
	struct ifpx_queue_node *node, *next;
	int ec = -EINVAL;

	if (!r)
		return ec;

	rte_spinlock_lock(&ifpx_lock);
	for (node = TAILQ_FIRST(&ifpx_queues); node; node = next) {
		next = TAILQ_NEXT(node, elem);
		if (node->r != r)
			continue;
		TAILQ_REMOVE(&ifpx_queues, node, elem);
		free(node);
		ec = 0;
		break;
	}
	rte_spinlock_unlock(&ifpx_lock);

	return ec;
}

int rte_ifpx_port_bind(uint16_t port_id, uint16_t proxy_id)
{
	struct rte_eth_dev_info proxy_eth_info;
	struct ifpx_proxy_node *px;
	int ec;

	rte_spinlock_lock(&ifpx_lock);

	if (port_id >= RTE_MAX_ETHPORTS || proxy_id >= RTE_MAX_ETHPORTS ||
	    /* port is a proxy */
	    ifpx_ports[port_id] == port_id) {
		IFPX_LOG(ERR, "Invalid port_id: %d", port_id);
		ec = -EINVAL;
		goto error;
	}

	/* Do automatic rebinding but issue a warning since this is not
	 * considered to be a valid behaviour.
	 */
	if (ifpx_ports[port_id] != RTE_MAX_ETHPORTS) {
		IFPX_LOG(WARNING, "Port already bound: %d -> %d", port_id,
			 ifpx_ports[port_id]);
	}

	/* Search for existing proxy - if not found add one to the list. */
	TAILQ_FOREACH(px, &ifpx_proxies, elem) {
		if (px->proxy_id == proxy_id)
			break;
	}
	if (!px) {
		ec = rte_eth_dev_info_get(proxy_id, &proxy_eth_info);
		if (ec < 0 || proxy_eth_info.if_index == 0) {
			IFPX_LOG(ERR, "Invalid proxy: %d", proxy_id);
			if (ec >= 0)
				ec = -EINVAL;
			goto error;
		}
		px = malloc(sizeof(*px));
		if (!px) {
			ec = -ENOMEM;
			goto error;
		}
		px->proxy_id = proxy_id;
		px->info.if_index = proxy_eth_info.if_index;
		rte_eth_dev_get_mtu(proxy_id, &px->info.mtu);
		rte_eth_macaddr_get(proxy_id, &px->info.mac);
		memset(px->info.if_name, 0, sizeof(px->info.if_name));
		TAILQ_INSERT_TAIL(&ifpx_proxies, px, elem);
	}
	ifpx_ports[port_id] = proxy_id;
	rte_spinlock_unlock(&ifpx_lock);

	/* Add proxy MAC to the port - since port will often just forward
	 * packets from the proxy/system they will be sent with proxy MAC as
	 * src.  In order to pass communication in other direction we should be
	 * accepting packets with proxy MAC as dst.
	 */
	rte_eth_dev_mac_addr_add(port_id, &px->info.mac, 0);

	if (ifpx_platform.get_info)
		ifpx_platform.get_info(px->info.if_index);

	return 0;

error:
	rte_spinlock_unlock(&ifpx_lock);
	return ec;
}

int rte_ifpx_port_unbind(uint16_t port_id)
{
	unsigned int i, cnt;
	uint16_t proxy_id;
	struct ifpx_proxy_node *px;
	int ec = 0;

	rte_spinlock_lock(&ifpx_lock);
	if (port_id >= RTE_MAX_ETHPORTS ||
	    ifpx_ports[port_id] == RTE_MAX_ETHPORTS ||
	    /* port is a proxy */
	    ifpx_ports[port_id] == port_id) {
		ec = -EINVAL;
		goto exit;
	}

	proxy_id = ifpx_ports[port_id];
	ifpx_ports[port_id] = RTE_MAX_ETHPORTS;

	for (i = 0, cnt = 0; i < RTE_DIM(ifpx_ports); ++i) {
		if (ifpx_ports[i] == proxy_id)
			++cnt;
	}

	/* If there is no port bound to this proxy then remove it. */
	if (cnt == 0) {
		TAILQ_FOREACH(px, &ifpx_proxies, elem) {
			if (px->proxy_id == proxy_id)
				break;
		}
		RTE_ASSERT(px);
		ec = ifpx_proxy_destroy(px);
	}
exit:
	rte_spinlock_unlock(&ifpx_lock);
	return ec;
}

int rte_ifpx_callbacks_register(unsigned int len,
				const struct rte_ifpx_callback cbs[])
{
	unsigned int i;

	if (!cbs || len == 0)
		return -EINVAL;

	rte_spinlock_lock(&ifpx_lock);

	for (i = 0; i < len; ++i) {
		if (cbs[i].type < 0 || cbs[i].type > RTE_IFPX_LAST_EVENT) {
			IFPX_LOG(WARNING, "Invalid event type: %d",
				 cbs[i].type);
			continue;
		}
		ifpx_callbacks[i].cb = cbs[i].callback;
	}

	rte_spinlock_unlock(&ifpx_lock);

	return 0;
}

void rte_ifpx_callbacks_unregister_all(void)
{
	rte_spinlock_lock(&ifpx_lock);
	memset(&ifpx_callbacks, 0, sizeof(ifpx_callbacks));
	rte_spinlock_unlock(&ifpx_lock);
}

int rte_ifpx_callbacks_unregister(enum rte_ifpx_event_type ev)
{
	if (ev < 0 || ev > RTE_IFPX_CFG_DONE)
		return -EINVAL;

	rte_spinlock_lock(&ifpx_lock);
	ifpx_callbacks[ev].f_ptr = NULL;
	rte_spinlock_unlock(&ifpx_lock);

	return 0;
}

uint16_t rte_ifpx_proxy_get(uint16_t port_id)
{
	uint16_t p = RTE_MAX_ETHPORTS;

	if (port_id < RTE_MAX_ETHPORTS) {
		rte_spinlock_lock(&ifpx_lock);
		p = ifpx_ports[port_id];
		rte_spinlock_unlock(&ifpx_lock);
	}

	return p;
}

unsigned int rte_ifpx_port_get(uint16_t proxy_id,
			       uint16_t *ports, unsigned int num)
{
	unsigned int p, cnt = 0;

	rte_spinlock_lock(&ifpx_lock);
	for (p = 0; p < RTE_DIM(ifpx_ports); ++p) {
		if (ifpx_ports[p] == proxy_id && ifpx_ports[p] != p) {
			++cnt;
			if (ports && num > 0) {
				*ports++ = p;
				--num;
			}
		}
	}
	rte_spinlock_unlock(&ifpx_lock);

	return cnt;
}

const struct rte_ifpx_info *rte_ifpx_info_get(uint16_t port_id)
{
	struct ifpx_proxy_node *px;

	rte_spinlock_lock(&ifpx_lock);

	if (port_id >= RTE_MAX_ETHPORTS ||
	    ifpx_ports[port_id] == RTE_MAX_ETHPORTS) {
		rte_spinlock_unlock(&ifpx_lock);
		return NULL;
	}

	TAILQ_FOREACH(px, &ifpx_proxies, elem) {
		if (px->proxy_id == ifpx_ports[port_id])
			break;
	}
	rte_spinlock_unlock(&ifpx_lock);
	RTE_ASSERT(px && "Internal IF Proxy library error");

	return &px->info;
}

static
void queue_event(const struct rte_ifpx_event *ev, struct rte_ring *r)
{
	struct rte_ifpx_event *e = malloc(sizeof(*ev));

	if (!e) {
		IFPX_LOG(ERR, "Failed to allocate event!");
		return;
	}
	RTE_ASSERT(r);

	*e = *ev;
	rte_ring_sp_enqueue(r, e);
}

void ifpx_notify_event(struct rte_ifpx_event *ev, struct ifpx_proxy_node *px)
{
	struct ifpx_queue_node *q;
	int done = 0;
	uint16_t p, proxy_id;

	if (px) {
		if (px->state & DEL_PENDING)
			return;
		proxy_id = px->proxy_id;
		RTE_ASSERT(proxy_id != RTE_MAX_ETHPORTS);
		px->state |= IN_USE;
	} else
		proxy_id = RTE_MAX_ETHPORTS;

	RTE_ASSERT(ev && ev->type >= 0 && ev->type <= RTE_IFPX_LAST_EVENT);
	/* This function is expected to be called with a lock held. */
	RTE_ASSERT(rte_spinlock_trylock(&ifpx_lock) == 0);

	if (ifpx_callbacks[ev->type].f_ptr) {
		union ifpx_cb_ptr fun = ifpx_callbacks[ev->type];

		/* Below we drop the lock for the time of callback call to allow
		 * for calling of IF Proxy API.
		 */
		if (px) {
			for (p = 0; p < RTE_DIM(ifpx_ports); ++p) {
				if (ifpx_ports[p] != proxy_id ||
				    ifpx_ports[p] == p)
					continue;
				ev->data.port_id = p;
				rte_spinlock_unlock(&ifpx_lock);
				done = fun.f_ptr(&ev->data) || done;
				rte_spinlock_lock(&ifpx_lock);
			}
		} else {
			RTE_ASSERT(ev->type == RTE_IFPX_CFG_DONE);
			rte_spinlock_unlock(&ifpx_lock);
			done = fun.cb.cfg_done();
			rte_spinlock_lock(&ifpx_lock);
		}
	}
	if (done)
		goto exit;

	/* Event not "consumed" yet so try to notify via queues. */
	TAILQ_FOREACH(q, &ifpx_queues, elem) {
		if (px) {
			for (p = 0; p < RTE_DIM(ifpx_ports); ++p) {
				if (ifpx_ports[p] != proxy_id ||
				    ifpx_ports[p] == p)
					continue;
				/* Set the port_id - the remaining params should
				 * be filled before calling this function.
				 */
				ev->data.port_id = p;
				queue_event(ev, q->r);
			}
		} else
			queue_event(ev, q->r);
	}
exit:
	if (px)
		px->state &= ~IN_USE;
}

void ifpx_cleanup_proxies(void)
{
	struct ifpx_proxy_node *px, *next;
	for (px = TAILQ_FIRST(&ifpx_proxies); px; px = next) {
		next = TAILQ_NEXT(px, elem);
		if (px->state & DEL_PENDING)
			ifpx_proxy_destroy(px);
	}
}

int rte_ifpx_listen(void)
{
	int ec;

	if (!ifpx_platform.listen)
		return -ENOTSUP;

	ec = ifpx_platform.listen();
	if (ec == 0 && ifpx_platform.get_info)
		ifpx_platform.get_info(0);

	return ec;
}

int rte_ifpx_close(void)
{
	struct ifpx_proxy_node *px;
	struct ifpx_queue_node *q;
	unsigned int p;
	int ec = 0;

	rte_spinlock_lock(&ifpx_lock);

	if (ifpx_platform.close) {
		ec = ifpx_platform.close();
		if (ec != 0)
			IFPX_LOG(ERR, "Platform 'close' calback failed.");
	}

	/* Remove queues. */
	while (!TAILQ_EMPTY(&ifpx_queues)) {
		q = TAILQ_FIRST(&ifpx_queues);
		TAILQ_REMOVE(&ifpx_queues, q, elem);
		free(q);
	}

	/* Clear callbacks. */
	memset(&ifpx_callbacks, 0, sizeof(ifpx_callbacks));

	/* Unbind ports. */
	for (p = 0; p < RTE_DIM(ifpx_ports); ++p) {
		if (ifpx_ports[p] == RTE_MAX_ETHPORTS)
			continue;
		/* We don't need to call rte_ifpx_port_unbind() here since we
		 * clear proxies below anyway, just clearing the mapping is
		 * enough (and besides it would deadlock :)).
		 */
		ifpx_ports[p] = RTE_MAX_ETHPORTS;
	}

	/* Clear proxies. */
	while (!TAILQ_EMPTY(&ifpx_proxies)) {
		px = TAILQ_FIRST(&ifpx_proxies);
		TAILQ_REMOVE(&ifpx_proxies, px, elem);
		free(px);
	}

	rte_spinlock_unlock(&ifpx_lock);

	return ec;
}

RTE_INIT(if_proxy_init)
{
	unsigned int i;
	for (i = 0; i < RTE_DIM(ifpx_ports); ++i)
		ifpx_ports[i] = RTE_MAX_ETHPORTS;

	ifpx_log_type = rte_log_register("lib.if_proxy");
	if (ifpx_log_type >= 0)
		rte_log_set_level(ifpx_log_type, RTE_LOG_WARNING);

	if (ifpx_platform.init)
		ifpx_platform.init();
}
