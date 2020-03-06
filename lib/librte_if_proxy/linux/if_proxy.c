/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */
#include <if_proxy_priv.h>
#include <rte_interrupts.h>
#include <rte_string_fns.h>

#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>

static
struct rte_intr_handle ifpx_irq = {
	.type = RTE_INTR_HANDLE_NETLINK,
	.fd = -1,
};

static
unsigned int ifpx_pid;

static
int request_info(int type, int index)
{
	static rte_spinlock_t send_lock = RTE_SPINLOCK_INITIALIZER;
	struct info_get {
		struct nlmsghdr h;
		union {
			struct ifinfomsg ifm;
			struct ifaddrmsg ifa;
			struct rtmsg rtm;
			struct ndmsg ndm;
		} __rte_aligned(NLMSG_ALIGNTO);
	} info_req;
	int ret;

	memset(&info_req, 0, sizeof(info_req));
	/* First byte of these messages is family, so just make sure that this
	 * memset is enough to get all families.
	 */
	RTE_ASSERT(AF_UNSPEC == 0);

	info_req.h.nlmsg_pid = ifpx_pid;
	info_req.h.nlmsg_type = type;
	info_req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	info_req.h.nlmsg_len = offsetof(struct info_get, ifm);

	switch (type) {
	case RTM_GETLINK:
		info_req.h.nlmsg_len += sizeof(info_req.ifm);
		info_req.ifm.ifi_index = index;
		break;
	case RTM_GETADDR:
		info_req.h.nlmsg_len += sizeof(info_req.ifa);
		info_req.ifa.ifa_index = index;
		break;
	case RTM_GETROUTE:
		info_req.h.nlmsg_len += sizeof(info_req.rtm);
		break;
	case RTM_GETNEIGH:
		info_req.h.nlmsg_len += sizeof(info_req.ndm);
		break;
	default:
		IFPX_LOG(WARNING, "Unhandled message type: %d", type);
		return -EINVAL;
	}
	/* Store request type (and if it is global or link specific) in 'seq'.
	 * Later it is used during handling of reply to continue requesting of
	 * information dump from system - if needed.
	 */
	info_req.h.nlmsg_seq = index << 8 | type;

	IFPX_LOG(DEBUG, "\tRequesting msg %d for: %u", type, index);

	rte_spinlock_lock(&send_lock);
	ret = send(ifpx_irq.fd, &info_req, info_req.h.nlmsg_len, 0);
	if (ret < 0) {
		IFPX_LOG(ERR, "Failed to send netlink msg: %d", errno);
		rte_errno = errno;
	}
	rte_spinlock_unlock(&send_lock);

	return ret;
}

static
void handle_link(const struct nlmsghdr *h)
{
	const struct ifinfomsg *ifi = NLMSG_DATA(h);
	int alen = h->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
	const struct rtattr *attrs[IFLA_MAX+1] = { NULL };
	const struct rtattr *attr;
	struct ifpx_proxy_node *px;
	struct rte_ifpx_event ev;

	IFPX_LOG(DEBUG, "\tLink action (%u): %u, 0x%x/0x%x (flags/changed)",
		 ifi->ifi_index, h->nlmsg_type, ifi->ifi_flags,
		 ifi->ifi_change);

	rte_spinlock_lock(&ifpx_lock);
	TAILQ_FOREACH(px, &ifpx_proxies, elem) {
		if (px->info.if_index == (unsigned int)ifi->ifi_index)
			break;
	}

	/* Drop messages that are not associated with any proxy */
	if (!px)
		goto exit;
	/* When message is a reply to request for specific interface then keep
	 * it only when it contains info for this interface.
	 */
	if (h->nlmsg_pid == ifpx_pid && h->nlmsg_seq >> 8 &&
	    (h->nlmsg_seq >> 8) != (unsigned)ifi->ifi_index)
		goto exit;

	for (attr = IFLA_RTA(ifi); RTA_OK(attr, alen);
				   attr = RTA_NEXT(attr, alen)) {
		if (attr->rta_type > IFLA_MAX)
			continue;
		attrs[attr->rta_type] = attr;
	}

	if (ifi->ifi_change & IFF_UP) {
		ev.type = RTE_IFPX_LINK_CHANGE;
		ev.link_change.is_up = ifi->ifi_flags & IFF_UP;
		ifpx_notify_event(&ev, px);
	}
	if (attrs[IFLA_MTU]) {
		uint16_t mtu = *(const int *)RTA_DATA(attrs[IFLA_MTU]);
		if (mtu != px->info.mtu) {
			px->info.mtu = mtu;
			ev.type = RTE_IFPX_MTU_CHANGE;
			ev.mtu_change.mtu = mtu;
			ifpx_notify_event(&ev, px);
		}
	}
	if (attrs[IFLA_ADDRESS]) {
		const struct rte_ether_addr *mac =
				RTA_DATA(attrs[IFLA_ADDRESS]);

		RTE_ASSERT(RTA_PAYLOAD(attrs[IFLA_ADDRESS]) ==
			   RTE_ETHER_ADDR_LEN);
		if (memcmp(mac, &px->info.mac, RTE_ETHER_ADDR_LEN) != 0) {
			rte_ether_addr_copy(mac, &px->info.mac);
			ev.type = RTE_IFPX_MAC_CHANGE;
			rte_ether_addr_copy(mac, &ev.mac_change.mac);
			ifpx_notify_event(&ev, px);
		}
	}
	if (h->nlmsg_pid == ifpx_pid) {
		RTE_ASSERT((h->nlmsg_seq & 0xFF) == RTM_GETLINK);
		/* If this is reply for specific link request (not initial
		 * global dump) then follow up with address request, otherwise
		 * just store the interface name.
		 */
		if (h->nlmsg_seq >> 8)
			request_info(RTM_GETADDR, ifi->ifi_index);
		else if (!px->info.if_name[0] && attrs[IFLA_IFNAME])
			strlcpy(px->info.if_name, RTA_DATA(attrs[IFLA_IFNAME]),
				sizeof(px->info.if_name));
	}

	ifpx_cleanup_proxies();
exit:
	rte_spinlock_unlock(&ifpx_lock);
}

static
void handle_addr(const struct nlmsghdr *h, bool needs_del)
{
	const struct ifaddrmsg *ifa = NLMSG_DATA(h);
	int alen = h->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa));
	const struct rtattr *attrs[IFA_MAX+1] = { NULL };
	const struct rtattr *attr;
	struct ifpx_proxy_node *px;
	struct rte_ifpx_event ev;
	const uint8_t *ip;

	IFPX_LOG(DEBUG, "\tAddr action (%u): %u, family: %u",
		 ifa->ifa_index, h->nlmsg_type, ifa->ifa_family);

	rte_spinlock_lock(&ifpx_lock);
	TAILQ_FOREACH(px, &ifpx_proxies, elem) {
		if (px->info.if_index == ifa->ifa_index)
			break;
	}

	/* Drop messages that are not associated with any proxy */
	if (!px)
		goto exit;
	/* When message is a reply to request for specific interface then keep
	 * it only when it contains info for this interface.
	 */
	if (h->nlmsg_pid == ifpx_pid && h->nlmsg_seq >> 8 &&
	    (h->nlmsg_seq >> 8) != ifa->ifa_index)
		goto exit;

	for (attr = IFA_RTA(ifa); RTA_OK(attr, alen);
				  attr = RTA_NEXT(attr, alen)) {
		if (attr->rta_type > IFA_MAX)
			continue;
		attrs[attr->rta_type] = attr;
	}

	if (attrs[IFA_ADDRESS]) {
		ip = RTA_DATA(attrs[IFA_ADDRESS]);
		if (ifa->ifa_family == AF_INET) {
			ev.type = needs_del ? RTE_IFPX_ADDR_DEL
					    : RTE_IFPX_ADDR_ADD;
			ev.addr_change.ip =
					RTE_IPV4(ip[0], ip[1], ip[2], ip[3]);
		} else {
			ev.type = needs_del ? RTE_IFPX_ADDR6_DEL
					    : RTE_IFPX_ADDR6_ADD;
			memcpy(ev.addr6_change.ip, ip, 16);
		}
		ifpx_notify_event(&ev, px);
		ifpx_cleanup_proxies();
	}
exit:
	rte_spinlock_unlock(&ifpx_lock);
}

static
void handle_route(const struct nlmsghdr *h, bool needs_del)
{
	const struct rtmsg *r = NLMSG_DATA(h);
	int alen = h->nlmsg_len - NLMSG_LENGTH(sizeof(*r));
	const struct rtattr *attrs[RTA_MAX+1] = { NULL };
	const struct rtattr *attr;
	struct rte_ifpx_event ev;
	struct ifpx_proxy_node *px = NULL;
	const uint8_t *ip;

	IFPX_LOG(DEBUG, "\tRoute action: %u, family: %u",
		 h->nlmsg_type, r->rtm_family);

	for (attr = RTM_RTA(r); RTA_OK(attr, alen);
				attr = RTA_NEXT(attr, alen)) {
		if (attr->rta_type > RTA_MAX)
			continue;
		attrs[attr->rta_type] = attr;
	}

	memset(&ev, 0, sizeof(ev));
	ev.type = RTE_IFPX_NUM_EVENTS;

	rte_spinlock_lock(&ifpx_lock);
	if (attrs[RTA_OIF]) {
		int if_index = *((int32_t*)RTA_DATA(attrs[RTA_OIF]));

		if (if_index > 0) {
			TAILQ_FOREACH(px, &ifpx_proxies, elem) {
				if (px->info.if_index == (uint32_t)if_index)
					break;
			}
		}
	}
	/* We are only interested in routes related to the proxy interfaces and
	 * we need to have dst - otherwise skip the message.
	 */
	if (!px || !attrs[RTA_DST])
		goto exit;

	ip = RTA_DATA(attrs[RTA_DST]);
	/* This is common to both IPv4/6. */
	ev.route_change.depth = r->rtm_dst_len;
	if (r->rtm_family == AF_INET) {
		ev.type = needs_del ? RTE_IFPX_ROUTE_DEL
		                    : RTE_IFPX_ROUTE_ADD;
		ev.route_change.ip =
		                RTE_IPV4(ip[0], ip[1], ip[2], ip[3]);
	} else {
		ev.type = needs_del ? RTE_IFPX_ROUTE6_DEL
		                    : RTE_IFPX_ROUTE6_ADD;
		memcpy(ev.route6_change.ip, ip, 16);
	}
	if (attrs[RTA_GATEWAY]) {
		ip = RTA_DATA(attrs[RTA_GATEWAY]);
		if (r->rtm_family == AF_INET)
			ev.route_change.gateway =
					RTE_IPV4(ip[0], ip[1], ip[2], ip[3]);
		else
			memcpy(ev.route6_change.gateway, ip, 16);
	}

	ifpx_notify_event(&ev, px);
	/* Let's check for proxies to remove here too - just in case somebody
	 * removed the non-proxy related callback.
	 */
	ifpx_cleanup_proxies();
exit:
	rte_spinlock_unlock(&ifpx_lock);
}

/* Link, addr and route related messages seem to have this macro defined but not
 * neighbour one.  Define one if it is missing - const qualifiers added just to
 * silence compiler - for some reason it is not needed in equivalent macros for
 * other messages and here compiler is complaining about (char*) cast on pointer
 * to const.
 */
#ifndef NDA_RTA
#define NDA_RTA(r) ((const struct rtattr*)(((const char*)(r)) + \
			NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif

static
void handle_neigh(const struct nlmsghdr *h, bool needs_del)
{
	const struct ndmsg *n = NLMSG_DATA(h);
	int alen = h->nlmsg_len - NLMSG_LENGTH(sizeof(*n));
	const struct rtattr *attrs[NDA_MAX+1] = { NULL };
	const struct rtattr *attr;
	struct ifpx_proxy_node *px;
	struct rte_ifpx_event ev;
	const uint8_t *ip;

	IFPX_LOG(DEBUG, "\tNeighbour action: %u, family: %u, state: %u, if: %d",
		 h->nlmsg_type, n->ndm_family, n->ndm_state, n->ndm_ifindex);

	for (attr = NDA_RTA(n); RTA_OK(attr, alen);
				attr = RTA_NEXT(attr, alen)) {
		if (attr->rta_type > NDA_MAX)
			continue;
		attrs[attr->rta_type] = attr;
	}

	memset(&ev, 0, sizeof(ev));
	ev.type = RTE_IFPX_NUM_EVENTS;

	rte_spinlock_lock(&ifpx_lock);
	TAILQ_FOREACH(px, &ifpx_proxies, elem) {
		if (px->info.if_index == (unsigned)n->ndm_ifindex)
			break;
	}
	/* We need only subset of neighbourhood related to proxy interfaces.
	 * lladdr seems to be needed only for adding new entry - modifications
	 * (also reported via RTM_NEWLINK) and deletion include only dst.
	 */
	if (!px || !attrs[NDA_DST] || (!needs_del && !attrs[NDA_LLADDR]))
		goto exit;

	ip = RTA_DATA(attrs[NDA_DST]);
	if (n->ndm_family == AF_INET) {
		ev.type = needs_del ? RTE_IFPX_NEIGH_DEL
		                    : RTE_IFPX_NEIGH_ADD;
		ev.neigh_change.ip =
		                RTE_IPV4(ip[0], ip[1], ip[2], ip[3]);
	} else {
		ev.type = needs_del ? RTE_IFPX_NEIGH6_DEL
		                    : RTE_IFPX_NEIGH6_ADD;
		memcpy(ev.neigh6_change.ip, ip, 16);
	}
	if (attrs[NDA_LLADDR])
		rte_ether_addr_copy(RTA_DATA(attrs[NDA_LLADDR]),
		                    &ev.neigh_change.mac);

	ifpx_notify_event(&ev, px);
	/* Let's check for proxies to remove here too - just in case somebody
	 * removed the non-proxy related callback.
	 */
	ifpx_cleanup_proxies();
exit:
	rte_spinlock_unlock(&ifpx_lock);
}

static
void if_proxy_intr_callback(void *arg __rte_unused)
{
	struct nlmsghdr *h;
	struct sockaddr_nl addr;
	socklen_t addr_len;
	char buf[8192];
	ssize_t len;

restart:
	len = recvfrom(ifpx_irq.fd, buf, sizeof(buf), 0,
		       (struct sockaddr *)&addr, &addr_len);
	if (len < 0) {
		if (errno == EINTR) {
			IFPX_LOG(DEBUG, "recvmsg() interrupted");
			goto restart;
		}
		IFPX_LOG(ERR, "Failed to read netlink msg: %ld (errno %d)",
			 len, errno);
		return;
	}
	if (addr_len != sizeof(addr)) {
		IFPX_LOG(ERR, "Invalid netlink addr size: %d", addr_len);
		return;
	}
	IFPX_LOG(DEBUG, "Read %lu bytes (buf %lu) from %u/%u", len,
		 sizeof(buf), addr.nl_pid, addr.nl_groups);

	for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, len);
					 h = NLMSG_NEXT(h, len)) {
		IFPX_LOG(DEBUG, "Recv msg: %u (%u/%u/%u seq/flags/pid)",
			 h->nlmsg_type, h->nlmsg_seq, h->nlmsg_flags,
			 h->nlmsg_pid);

		switch (h->nlmsg_type) {
		case RTM_NEWLINK:
		case RTM_DELLINK:
			handle_link(h);
			break;
		case RTM_NEWADDR:
		case RTM_DELADDR:
			handle_addr(h, h->nlmsg_type == RTM_DELADDR);
			break;
		case RTM_NEWROUTE:
		case RTM_DELROUTE:
			handle_route(h, h->nlmsg_type == RTM_DELROUTE);
			break;
		case RTM_NEWNEIGH:
		case RTM_DELNEIGH:
			handle_neigh(h, h->nlmsg_type == RTM_DELNEIGH);
			break;
		}

		/* If this is a reply for global request then follow up with
		 * additional requests and notify about finish.
		 */
		if (h->nlmsg_pid == ifpx_pid && (h->nlmsg_seq >> 8) == 0 &&
		    h->nlmsg_type == NLMSG_DONE) {
			if ((h->nlmsg_seq & 0xFF) == RTM_GETLINK)
				request_info(RTM_GETADDR, 0);
			else if ((h->nlmsg_seq & 0xFF) == RTM_GETADDR)
				request_info(RTM_GETROUTE, 0);
			else if ((h->nlmsg_seq & 0xFF) == RTM_GETROUTE)
				request_info(RTM_GETNEIGH, 0);
			else {
				struct rte_ifpx_event ev = {
					.type = RTE_IFPX_CFG_DONE
				};

				RTE_ASSERT((h->nlmsg_seq & 0xFF) ==
						RTM_GETNEIGH);
				rte_spinlock_lock(&ifpx_lock);
				ifpx_notify_event(&ev, NULL);
				rte_spinlock_unlock(&ifpx_lock);
			}
		}
	}
	IFPX_LOG(DEBUG, "Finished msg loop: %ld bytes left", len);
}

static
int nlink_listen(void)
{
	struct sockaddr_nl addr = {
		.nl_family = AF_NETLINK,
		.nl_pid = 0,
	};
	socklen_t addr_len = sizeof(addr);
	int ret;

	if (ifpx_irq.fd != -1) {
		rte_errno = EBUSY;
		return -1;
	}

	addr.nl_groups = 1 << (RTNLGRP_LINK-1)
			| 1 << (RTNLGRP_NEIGH-1)
			| 1 << (RTNLGRP_IPV4_IFADDR-1)
			| 1 << (RTNLGRP_IPV6_IFADDR-1)
			| 1 << (RTNLGRP_IPV4_ROUTE-1)
			| 1 << (RTNLGRP_IPV6_ROUTE-1);

	ifpx_irq.fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC,
				 NETLINK_ROUTE);
	if (ifpx_irq.fd == -1) {
		IFPX_LOG(ERR, "Failed to create netlink socket: %d", errno);
		goto error;
	}
	/* Starting with kernel 4.19 you can request dump for a specific
	 * interface and kernel will filter out and send only relevant info.
	 * Otherwise NLM_F_DUMP will generate info for all interfaces and you
	 * need to filter them yourself.
	 */
#ifdef NETLINK_DUMP_STRICT_CHK
	ret = 1; /* use this var also as an input param */
	ret = setsockopt(ifpx_irq.fd, SOL_SOCKET, NETLINK_DUMP_STRICT_CHK,
			 &ret, sizeof(ret));
	if (ret < 0) {
		IFPX_LOG(ERR, "Failed to set socket option: %d", errno);
		goto error;
	}
#endif

	ret = bind(ifpx_irq.fd, (struct sockaddr *)&addr, addr_len);
	if (ret < 0) {
		IFPX_LOG(ERR, "Failed to bind socket: %d", errno);
		goto error;
	}
	ret = getsockname(ifpx_irq.fd, (struct sockaddr *)&addr, &addr_len);
	if (ret < 0) {
		IFPX_LOG(ERR, "Failed to get socket addr: %d", errno);
		goto error;
	} else {
		ifpx_pid = addr.nl_pid;
		IFPX_LOG(DEBUG, "Assigned port ID: %u", addr.nl_pid);
	}

	ret = rte_intr_callback_register(&ifpx_irq, if_proxy_intr_callback,
					 NULL);
	if (ret == 0)
		return 0;

error:
	rte_errno = errno;
	if (ifpx_irq.fd != -1) {
		close(ifpx_irq.fd);
		ifpx_irq.fd = -1;
	}
	return -1;
}

static
int nlink_close(void)
{
	int ec;

	if (ifpx_irq.fd < 0)
		return -EBADFD;

	do
		ec = rte_intr_callback_unregister(&ifpx_irq,
		                                  if_proxy_intr_callback, NULL);
	while (ec == -EAGAIN); /* unlikely but possible - at least I think so */

	close(ifpx_irq.fd);
	ifpx_irq.fd = -1;
	ifpx_pid = 0;

	return 0;
}

static
void nlink_get_info(int if_index)
{
	if (ifpx_irq.fd != -1)
		request_info(RTM_GETLINK, if_index);
}

struct ifpx_platform_callbacks ifpx_platform = {
	.init = NULL,
	.listen = nlink_listen,
	.close = nlink_close,
	.get_info = nlink_get_info,
};
