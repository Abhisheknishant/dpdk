/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */
#ifndef _IF_PROXY_PRIV_H_
#define _IF_PROXY_PRIV_H_

#include "rte_if_proxy.h"
#include <rte_spinlock.h>

#define RTE_IFPX_LAST_EVENT     RTE_IFPX_CFG_DONE
#define RTE_IFPX_NUM_EVENTS     (RTE_IFPX_LAST_EVENT+1)
#define RTE_IFPX_EVENT_INVALID  RTE_IFPX_NUM_EVENTS

extern int ifpx_log_type;
#define IFPX_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, ifpx_log_type, "%s(): " fmt "\n", \
		__func__, ##args)

/* Since this library is really a slow/config path we guard all internal data
 * with a lock - and only one for all of them should be enough.
 */
extern rte_spinlock_t ifpx_lock;

enum ifpx_node_status {
	IN_USE		= 1U << 0,
	DEL_PENDING	= 1U << 1,
};

/* List of configured proxies */
struct ifpx_proxy_node {
	TAILQ_ENTRY(ifpx_proxy_node) elem;
	uint16_t proxy_id;
	uint16_t state;
	struct rte_ifpx_info info;
};
extern
TAILQ_HEAD(ifpx_proxies_head, ifpx_proxy_node) ifpx_proxies;

/* This function should be called by the implementation whenever it notices
 * change in the network configuration.  The arguments are:
 * - ev : pointer to filled event data structure (all fields are expected to be
 *     filled, with the exception of 'port_id' for all proxy/port related
 *     events: this function clones the event notification for each bound port
 *     and fills 'port_id' appropriately).
 * - px : proxy node when given event is proxy/port related, otherwise pass NULL
 */
void ifpx_notify_event(struct rte_ifpx_event *ev, struct ifpx_proxy_node *px);

/* This function should be called by the implementation whenever it is done with
 * notification about network configuration change.  It is only really needed
 * for the case of callback based API since from the callback user might attempt
 * to remove proxies.  Only implementation really knows when notification for
 * given proxy is finished so it is a duty of it to call this function to
 * cleanup all proxies that has been marked for deletion.
 */
void ifpx_cleanup_proxies(void);

/* This is the internal function removing the proxy from the list.  It is
 * related to the notification function above and intended to be used by the
 * platform implementation for the case of callback based API.
 * During notification via callback the internal lock is released so that
 * operation would not deadlock on an attempt to take a lock.  However
 * modification (destruction) is not really performed - instead the
 * callbacks/proxies are marked as "to be deleted".
 * Handling of callbacks that are "to be deleted" is done by the
 * ifpx_notify_event() function itself however it cannot delete the proxies (in
 * particular the proxy passed as an argument) since they might still be
 * referred by the calling function.  So it is a responsibility of the platform
 * implementation to check after calling notification function if there are any
 * proxies to be removed and use ifpx_proxy_destroy() to actually release them.
 */
int ifpx_proxy_destroy(struct ifpx_proxy_node *px);

/* Every implementation should provide definition of this structure:
 * - init : called during library initialization (NULL when not needed)
 * - events : this should return bitmask of supported events (can be NULL if all
 *     defined events are supported by the implementation)
 * - listen : this function should start service listening to the network
 *     configuration events/changes,
 * - close : this function should close the service started by listen()
 * - get_info : this function should query system for current configuration of
 *     interface with index 'if_index'.  After successful initialization of
 *     listening service this function is called with 0 as an argument.  In that
 *     case configuration of all ports should be obtained - and when this
 *     procedure completes a RTE_IFPX_CFG_DONE event should be signaled via
 *     ifpx_notify_event().
 */
extern
struct ifpx_platform_callbacks {
	void (*init)(void);
	uint64_t (*events)(void);
	int (*listen)(void);
	int (*close)(void);
	void (*get_info)(int if_index);
} ifpx_platform;

#endif /* _IF_PROXY_PRIV_H_ */
