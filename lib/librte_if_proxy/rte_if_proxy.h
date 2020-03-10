/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#ifndef _RTE_IF_PROXY_H_
#define _RTE_IF_PROXY_H_

/**
 * @file
 * RTE IF Proxy library
 *
 * The IF Proxy library allows for monitoring of system network configuration
 * and configuration of DPDK ports by using usual system utilities (like the
 * ones from iproute2 package).
 *
 * It is based on the notion of "proxy interface" which actually can be any DPDK
 * port which is also visible to the system - that is it has non-zero 'if_index'
 * field in 'rte_eth_dev_info' structure.
 *
 * If application doesn't have any such port (or doesn't want to use it for
 * proxy) it can create one by calling:
 *
 *   proxy_id = rte_ifpx_create(RTE_IFPX_DEFAULT);
 *
 * This function is just a wrapper that constructs valid 'devargs' string based
 * on the proxy type chosen (currently Tap or KNI) and creates the interface by
 * calling rte_ifpx_dev_create().
 *
 * Once one has DPDK port capable of being proxy one can bind target DPDK port
 * to it by calling.
 *
 *   rte_ifpx_port_bind(port_id, proxy_id);
 *
 * This binding is a logical one - there is no automatic packet forwarding
 * between port and it's proxy since the library doesn't know the structure of
 * application's packet processing.  It remains application responsibility to
 * forward the packets from/to proxy port (by calling the usual DPDK RX/TX burst
 * API).  However when the library notes some change to the proxy interface it
 * will simply call appropriate callback with 'port_id' of the DPDK port that is
 * bound to this proxy interface.  The binding can be 1 to many - that is many
 * ports can point to one proxy - in that case registered callbacks will be
 * called for every bound port.
 *
 * The callbacks that are used for notifications are described by the
 * 'rte_ifpx_callbacks' structure and they are registered by calling:
 *
 *   rte_ifpx_callbacks_register(&cbs);
 *
 * Finally the application should call:
 *
 *   rte_ifpx_listen();
 *
 * which will query system for present network configuration and start listening
 * to its changes.
 */

#include <rte_eal.h>
#include <rte_ethdev.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Enum naming the type of proxy to create.
 *
 * @see rte_ifpx_create()
 */
enum rte_ifpx_proxy_type {
	RTE_IFPX_DEFAULT,	/**< Use default proxy type for given arch. */
	RTE_IFPX_TAP,		/**< Use Tap based port for proxy. */
	RTE_IFPX_KNI		/**< Use KNI based port for proxy. */
};

/**
 * Create DPDK port that can serve as an interface proxy.
 *
 * This function is just a wrapper around rte_ifpx_create_by_devarg() that
 * constructs its 'devarg' argument based on type of proxy requested.
 *
 * @param type
 *   A type of proxy to create.
 *
 * @return
 *   DPDK port id on success, RTE_MAX_ETHPORTS otherwise.
 *
 * @see enum rte_ifpx_type
 * @see rte_ifpx_create_by_devarg()
 */
__rte_experimental
uint16_t rte_ifpx_proxy_create(enum rte_ifpx_proxy_type type);

/**
 * Create DPDK port that can serve as an interface proxy.
 *
 * @param devarg
 *   A string passed to rte_dev_probe() to create proxy port.
 *
 * @return
 *   DPDK port id on success, RTE_MAX_ETHPORTS otherwise.
 */
__rte_experimental
uint16_t rte_ifpx_proxy_create_by_devarg(const char *devarg);

/**
 * Remove DPDK proxy port.
 *
 * In addition to removing the proxy port the bindings (if any) are cleared.
 *
 * @param proxy_id
 *   Port id of the proxy that should be removed.
 *
 * @return
 *   0 on success, negative on error.
 */
__rte_experimental
int rte_ifpx_proxy_destroy(uint16_t proxy_id);

/**
 * The rte_ifpx_event_type enum lists all possible event types that can be
 * signaled by this library.  To learn what events are supported on your
 * platform call rte_ifpx_events_available().
 *
 * NOTE - do not reorder these enums freely, their values need to correspond to
 * the order of the callbacks in struct rte_ifpx_callbacks.
 */
enum rte_ifpx_event_type {
	RTE_IFPX_MAC_CHANGE,  /**< @see struct rte_ifpx_mac_change */
	RTE_IFPX_MTU_CHANGE,  /**< @see struct rte_ifpx_mtu_change */
	RTE_IFPX_LINK_CHANGE, /**< @see struct rte_ifpx_link_change */
	RTE_IFPX_ADDR_ADD,    /**< @see struct rte_ifpx_addr_change */
	RTE_IFPX_ADDR_DEL,    /**< @see struct rte_ifpx_addr_change */
	RTE_IFPX_ADDR6_ADD,   /**< @see struct rte_ifpx_addr6_change */
	RTE_IFPX_ADDR6_DEL,   /**< @see struct rte_ifpx_addr6_change */
	RTE_IFPX_ROUTE_ADD,   /**< @see struct rte_ifpx_route_change */
	RTE_IFPX_ROUTE_DEL,   /**< @see struct rte_ifpx_route_change */
	RTE_IFPX_ROUTE6_ADD,  /**< @see struct rte_ifpx_route6_change */
	RTE_IFPX_ROUTE6_DEL,  /**< @see struct rte_ifpx_route6_change */
	RTE_IFPX_NEIGH_ADD,   /**< @see struct rte_ifpx_neigh_change */
	RTE_IFPX_NEIGH_DEL,   /**< @see struct rte_ifpx_neigh_change */
	RTE_IFPX_NEIGH6_ADD,  /**< @see struct rte_ifpx_neigh6_change */
	RTE_IFPX_NEIGH6_DEL,  /**< @see struct rte_ifpx_neigh6_change */
	RTE_IFPX_CFG_DONE,    /**< This event is a lib specific event - it is
			       * signaled when initial network configuration
			       * query is finished and has no event data.
			       */
	RTE_IFPX_NUM_EVENTS,
};

/**
 * Get the bit mask of implemented events/callbacks for this platform.
 *
 * @return
 *   Bit mask of events/callbacks implemented: each event type can be tested by
 *   checking bit (1 << ev) where 'ev' is one of the rte_ifpx_event_type enum
 *   values.
 * @see enum rte_ifpx_event_type
 */
__rte_experimental
uint64_t rte_ifpx_events_available(void);

/**
 * The rte_ifpx_event defines structure used to pass notification event to
 * application.  Each event type has its own dedicated inner structure - these
 * structures are also used when using callbacks notifications.
 */
struct rte_ifpx_event {
	enum rte_ifpx_event_type type;
	union {
		/** Structure used to pass notification about MAC change of the
		 * proxy interface.
		 * @see RTE_IFPX_MAC_CHANGE
		 */
		struct rte_ifpx_mac_change {
			uint16_t port_id;
			struct rte_ether_addr mac;
		} mac_change;
		/** Structure used to pass notification about MTU change.
		 * @see RTE_IFPX_MTU_CHANGE
		 */
		struct rte_ifpx_mtu_change {
			uint16_t port_id;
			uint16_t mtu;
		} mtu_change;
		/** Structure used to pass notification about link going
		 * up/down.
		 * @see RTE_IFPX_LINK_CHANGE
		 */
		struct rte_ifpx_link_change {
			uint16_t port_id;
			int is_up;
		} link_change;
		/** Structure used to pass notification about IPv4 address being
		 * added/removed.  All IPv4 addresses reported by this library
		 * are in host order.
		 * @see RTE_IFPX_ADDR_ADD
		 * @see RTE_IFPX_ADDR_DEL
		 */
		struct rte_ifpx_addr_change {
			uint16_t port_id;
			uint32_t ip;
		} addr_change;
		/** Structure used to pass notification about IPv6 address being
		 * added/removed.
		 * @see RTE_IFPX_ADDR6_ADD
		 * @see RTE_IFPX_ADDR6_DEL
		 */
		struct rte_ifpx_addr6_change {
			uint16_t port_id;
			uint8_t ip[16];
		} addr6_change;
		/** Structure used to pass notification about IPv4 route being
		 * added/removed.
		 * @see RTE_IFPX_ROUTE_ADD
		 * @see RTE_IFPX_ROUTE_DEL
		 */
		struct rte_ifpx_route_change {
			uint16_t port_id;
			uint8_t depth;
			uint32_t ip;
			uint32_t gateway;
		} route_change;
		/** Structure used to pass notification about IPv6 route being
		 * added/removed.
		 * @see RTE_IFPX_ROUTE6_ADD
		 * @see RTE_IFPX_ROUTE6_DEL
		 */
		struct rte_ifpx_route6_change {
			uint16_t port_id;
			uint8_t depth;
			uint8_t ip[16];
			uint8_t gateway[16];
		} route6_change;
		/** Structure used to pass notification about IPv4 neighbour
		 * info changes.
		 * @see RTE_IFPX_NEIGH_ADD
		 * @see RTE_IFPX_NEIGH_DEL
		 */
		struct rte_ifpx_neigh_change {
			uint16_t port_id;
			struct rte_ether_addr mac;
			uint32_t ip;
		} neigh_change;
		/** Structure used to pass notification about IPv6 neighbour
		 * info changes.
		 * @see RTE_IFPX_NEIGH6_ADD
		 * @see RTE_IFPX_NEIGH6_DEL
		 */
		struct rte_ifpx_neigh6_change {
			uint16_t port_id;
			struct rte_ether_addr mac;
			uint8_t ip[16];
		} neigh6_change;
		/* This structure is used internally - to abstract common parts
		 * of proxy/port related events and to be able to refer to this
		 * union without giving it a name.
		 */
		struct {
			uint16_t port_id;
		} data;
	};
};

/**
 * This library can deliver notification about network configuration changes
 * either by the use of registered callbacks and/or by queueing change events to
 * configured notification queues.  The logic used is:
 * 1. If there is callback registered for given event type it is called.  In
 *   case of many ports to one proxy binding, this callback is called for every
 *   port bound.
 * 2. If this callback returns non-zero value (for any of ports in case of
 *   many-1 bindings) the handling of an event is considered as complete.
 * 3. Otherwise the event is added to each configured event queue.  The event is
 *   allocated with malloc() so after dequeueing and handling the application
 *   should deallocate it with free().
 *
 * This dual notification mechanism is meant to provide some flexibility to
 * application writer.  For example, if you store your data in a single writer/
 * many readers coherent data structure you could just update this structure
 * from the callback.  If you keep separate copy per lcore/port you could make
 * some common preparations (if applicable) in the callback, return 0 and use
 * notification queues to pick up the change and update data structures.  Or you
 * could skip the callbacks altogether and just use notification queues - and
 * configure them at the level appropriate for your application design (one
 * global / one per lcore / one per port ...).
 */

/**
 * Add notification queue to the list of queues.
 *
 * @param r
 *   Ring used for queueing of notification events - application can assume that
 *   there is only one producer.
 * @return
 *   0 on success, negative otherwise.
 */
int rte_ifpx_queue_add(struct rte_ring *r);

/**
 * Remove notification queue from the list of queues.
 *
 * @param r
 *   Notification ring used for queueing of notification events (previously
 *   added via rte_ifpx_queue_add()).
 * @return
 *   0 on success, negative otherwise.
 */
int rte_ifpx_queue_remove(struct rte_ring *r);

/**
 * This structure groups the callbacks that might be called as a notification
 * events for changing network configuration.  Not every platform might
 * implement all of them and you can query the availability with
 * rte_ifpx_callbacks_available() function.
 * @see rte_ifpx_events_available()
 * @see rte_ifpx_callbacks_register()
 */
struct rte_ifpx_callbacks {
	int (*mac_change)(const struct rte_ifpx_mac_change *event);
	/**< Callback for notification about MAC change of the proxy interface.
	 * This callback (as all other port related callbacks) is called for
	 * each port (with its port_id as a first argument) bound to the proxy
	 * interface for which change has been observed.
	 * @see struct rte_ifpx_mac_change
	 * @return non-zero if event handling is finished
	 */
	int (*mtu_change)(const struct rte_ifpx_mtu_change *event);
	/**< Callback for notification about MTU change.
	 * @see struct rte_ifpx_mtu_change
	 * @return non-zero if event handling is finished
	 */
	int (*link_change)(const struct rte_ifpx_link_change *event);
	/**< Callback for notification about link going up/down.
	 * @see struct rte_ifpx_link_change
	 * @return non-zero if event handling is finished
	 */
	int (*addr_add)(const struct rte_ifpx_addr_change *event);
	/**< Callback for notification about IPv4 address being added.
	 * @see struct rte_ifpx_addr_change
	 * @return non-zero if event handling is finished
	 */
	int (*addr_del)(const struct rte_ifpx_addr_change *event);
	/**< Callback for notification about IPv4 address removal.
	 * @see struct rte_ifpx_addr_change
	 * @return non-zero if event handling is finished
	 */
	int (*addr6_add)(const struct rte_ifpx_addr6_change *event);
	/**< Callback for notification about IPv6 address being added.
	 * @see struct rte_ifpx_addr6_change
	 */
	int (*addr6_del)(const struct rte_ifpx_addr6_change *event);
	/**< Callback for notification about IPv4 address removal.
	 * @see struct rte_ifpx_addr6_change
	 * @return non-zero if event handling is finished
	 */
	/* Please note that "route" callbacks might be also called when user
	 * adds address to the interface (that is in addition to address related
	 * callbacks).
	 */
	int (*route_add)(const struct rte_ifpx_route_change *event);
	/**< Callback for notification about IPv4 route being added.
	 * @see struct rte_ifpx_route_change
	 * @return non-zero if event handling is finished
	 */
	int (*route_del)(const struct rte_ifpx_route_change *event);
	/**< Callback for notification about IPv4 route removal.
	 * @see struct rte_ifpx_route_change
	 * @return non-zero if event handling is finished
	 */
	int (*route6_add)(const struct rte_ifpx_route6_change *event);
	/**< Callback for notification about IPv6 route being added.
	 * @see struct rte_ifpx_route6_change
	 * @return non-zero if event handling is finished
	 */
	int (*route6_del)(const struct rte_ifpx_route6_change *event);
	/**< Callback for notification about IPv6 route removal.
	 * @see struct rte_ifpx_route6_change
	 * @return non-zero if event handling is finished
	 */
	int (*neigh_add)(const struct rte_ifpx_neigh_change *event);
	/**< Callback for notification about IPv4 neighbour being added.
	 * @see struct rte_ifpx_neigh_change
	 * @return non-zero if event handling is finished
	 */
	int (*neigh_del)(const struct rte_ifpx_neigh_change *event);
	/**< Callback for notification about IPv4 neighbour removal.
	 * @see struct rte_ifpx_neigh_change
	 * @return non-zero if event handling is finished
	 */
	int (*neigh6_add)(const struct rte_ifpx_neigh6_change *event);
	/**< Callback for notification about IPv6 neighbour being added.
	 * @see struct rte_ifpx_neigh_change
	 */
	int (*neigh6_del)(const struct rte_ifpx_neigh6_change *event);
	/**< Callback for notification about IPv6 neighbour removal.
	 * @see struct rte_ifpx_neigh_change
	 * @return non-zero if event handling is finished
	 */
	int (*cfg_done)(void);
	/**< Lib specific callback - called when initial network configuration
	 * query is finished.
	 * @return non-zero if event handling is finished
	 */
};

/**
 * Register proxy callbacks.
 *
 * This function registers callbacks to be called upon appropriate network
 * event notification.
 *
 * @param cbs
 *   Set of callbacks that will be called.  The library does not take any
 *   ownership of the pointer passed - the callbacks are stored internally.
 *
 * @return
 *   0 on success, negative otherwise.
 */
__rte_experimental
int rte_ifpx_callbacks_register(const struct rte_ifpx_callbacks *cbs);

/**
 * Unregister proxy callbacks.
 *
 * This function unregisters callbacks previously registered with
 * rte_ifpx_callbacks_register().
 *
 * @param cbs
 *   Handle/pointer returned on previous callback registration.
 *
 * @return
 *   0 on success, negative otherwise.
 */
__rte_experimental
void rte_ifpx_callbacks_unregister(void);

/**
 * Bind the port to its proxy.
 *
 * After calling this function all network configuration of the proxy (and it's
 * changes) will be passed to given port by calling registered callbacks with
 * 'port_id' as an argument.
 *
 * Note: since both arguments are of the same type in order to not mix them and
 * ease remembering the order the first one is kept the same for bind/unbind.
 *
 * @param port_id
 *   Id of the port to be bound.
 * @param proxy_id
 *   Id of the proxy the port needs to be bound to.
 * @return
 *   0 on success, negative on error.
 */
__rte_experimental
int rte_ifpx_port_bind(uint16_t port_id, uint16_t proxy_id);

/**
 * Unbind the port from its proxy.
 *
 * After calling this function registered callbacks will no longer be called for
 * this port (but they might be called for other ports in one to many binding
 * scenario).
 *
 * @param port_id
 *   Id of the port to unbind.
 * @return
 *   0 on success, negative on error.
 */
__rte_experimental
int rte_ifpx_port_unbind(uint16_t port_id);

/**
 * Get the system network configuration and start listening to its changes.
 *
 * @return
 *   0 on success, negative otherwise.
 */
__rte_experimental
int rte_ifpx_listen(void);

/**
 * Remove all bindings/callbacks and stop listening to network configuration.
 *
 * @return
 *   0 on success, negative otherwise.
 */
__rte_experimental
int rte_ifpx_close(void);

/**
 * Get the id of the proxy the port is bound to.
 *
 * @param port_id
 *   Id of the port for which to get proxy.
 * @return
 *   Port id of the proxy on success, RTE_MAX_ETHPORTS on error.
 */
__rte_experimental
uint16_t rte_ifpx_proxy_get(uint16_t port_id);

/**
 * Test for port acting as a proxy.
 *
 * @param port_id
 *   Id of the port.
 * @return
 *   1 if port acts as a proxy, 0 otherwise.
 */
static inline
int rte_ifpx_is_proxy(uint16_t port_id)
{
	return rte_ifpx_proxy_get(port_id) == port_id;
}

/**
 * Get the ids of the ports bound to the proxy.
 *
 * @param proxy_id
 *   Id of the proxy for which to get ports.
 * @param ports
 *   Array where to store the port ids.
 * @param num
 *   Size of the 'ports' array.
 * @return
 *   The number of ports bound to given proxy.  Note that bound ports are filled
 *   in 'ports' array up to its size but the return value is always the total
 *   number of ports bound - so you can make call first with NULL/0 to query for
 *   the size of the buffer to create or call it with the buffer you have and
 *   later check if it was large enough.
 */
__rte_experimental
unsigned int rte_ifpx_port_get(uint16_t proxy_id,
			       uint16_t *ports, unsigned int num);

/**
 * The structure containing some properties of the proxy interface.
 */
struct rte_ifpx_info {
	unsigned int if_index; /* entry valid iff if_index != 0 */
	uint16_t mtu;
	struct rte_ether_addr mac;
	char if_name[RTE_ETH_NAME_MAX_LEN];
};

/**
 * Get the properties of the proxy interface.  Argument can be either id of the
 * proxy or an id of a port that is bound to it.
 *
 * @param port_id
 *   Id of the port (or proxy) for which to get proxy properties.
 * @return
 *   Pointer to the proxy information structure.
 */
__rte_experimental
const struct rte_ifpx_info *rte_ifpx_info_get(uint16_t port_id);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_IF_PROXY_H_ */
