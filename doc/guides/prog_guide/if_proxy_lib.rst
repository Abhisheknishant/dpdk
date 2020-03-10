..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(C) 2020 Marvell International Ltd.

.. _IF_Proxy_Library:

IF Proxy Library
================

When a network interface is assigned to DPDK it usually disappears from
the system and user looses ability to configure it via typical
configuration tools.
There are basically two options to deal with this situation:

- configure it via command line arguments and/or load configuration
  from some file,
- add support for live configuration via some IPC mechanism.

The first option is static and the second one requires some work to add
communication loop (e.g. separate thread listening/communicating on
a socket).

This library adds a possibility to configure DPDK ports by using normal
configuration utilities (e.g. from iproute2 suite).
It requires user to configure additional DPDK ports that are visible to
the system (such as Tap or KNI - actually any port that has valid
`if_index` in ``struct rte_eth_dev_info`` will do) and designate them as
a port representor (a proxy) in the system.

Let's see typical intended usage by an example.
Suppose that you have application that handles traffic on two ports (in
the white list below)::

    ./app -w 00:14.0 -w 00:16.0 --vdev=net_tap0 --vdev=net_tap1

So in addition to the "regular" ports you need to configure proxy ports.
These proxy ports can be created via a command line (like above) or from
within the application (e.g. by using `rte_ifpx_proxy_create()`
function).

When you have proxy ports you need to bind them to the "regular" ports::

    rte_ifpx_port_bind(port0, proxy0);
    rte_ifpx_port_bind(port1, proxy1);

This binding is a logical one - there is no automatic packet forwarding
configured.
This is because library cannot tell upfront what portion of the traffic
received on ports 0/1 should be redirected to the system via proxies and
also it does not know how the application is structured (what packet
processing engines it uses).
Therefore it is application writer responsibility to include proxy ports
into its packet processing and forward appropriate packets between
proxies and ports.
What the library actually does is that it gets network configuration
from the system and listens to its changes.
This information is then matched against `if_index` of the configured
proxies and passed to the application.

There are two mechanisms via which library passes notifications to the
application.
First is the set of global callbacks that user has
to register via::

    rte_ifpx_callbacks_register(&cbs);

Here `cbs` is a ``struct rte_ifpx_callbacks`` which has following
members::

    int (*mac_change)(const struct rte_ifpx_mac_change *event);
    int (*mtu_change)(const struct rte_ifpx_mtu_change *event);
    int (*link_change)(const struct rte_ifpx_link_change *event);
    int (*addr_add)(const struct rte_ifpx_addr_change *event);
    int (*addr_del)(const struct rte_ifpx_addr_change *event);
    int (*addr6_add)(const struct rte_ifpx_addr6_change *event);
    int (*addr6_del)(const struct rte_ifpx_addr6_change *event);
    int (*route_add)(const struct rte_ifpx_route_change *event);
    int (*route_del)(const struct rte_ifpx_route_change *event);
    int (*route6_add)(const struct rte_ifpx_route6_change *event);
    int (*route6_del)(const struct rte_ifpx_route6_change *event);
    int (*neigh_add)(const struct rte_ifpx_neigh_change *event);
    int (*neigh_del)(const struct rte_ifpx_neigh_change *event);
    int (*neigh6_add)(const struct rte_ifpx_neigh6_change *event);
    int (*neigh6_del)(const struct rte_ifpx_neigh6_change *event);
    int (*cfg_done)(void);

All of them should be self explanatory apart from the last one which is
library specific callback - called when initial network configuration
query is finished.

So for example when the user issues command::

    ip link set dev dtap0 mtu 1600

then library will call `mtu_change()` callback with MTU change event
having port_id equal to `port0` (id of the port bound to this proxy) and
`mtu` equal to 1600 (``dtap0`` is the default interface name for
``net_tap0``).
Application can simply use `rte_eth_dev_set_mtu()` in this callback.
The same way `rte_eth_dev_default_mac_addr_set()` can be used in
`mac_change()` and `rte_eth_dev_set_link_up/down()` inside the
`link_change()` callback that does dispatch based on `is_up` member of
its `event` argument.

Please note however that the context in which these callbacks are called
is most probably different from the one in which packets are handled and
it is application writer responsibility to use proper synchronization
mechanisms - if they are needed.

Second notification mechanism relies on queueing of event notifications
to the configured notification rings.
Application can add queue via::

    int rte_ifpx_queue_add(struct rte_ring *r);

This type of notification is used when there is no callback registered
for given type of event or when it is registered but it returns 0.
This way application has following choices:

- if the data structure that needs to be updated due to notification
  is safe to be modified by a single writer (while being used by other
  readers) then it can simply do that inside the callback and return
  non-zero value to signal end of the event handling

- otherwise, when there are some common preparation steps that needs
  to be done only once, application can register callback that will
  perform these steps and return 0 - library will then add an event to
  each registered notification queue

- if the data structures are replicated and there are no common steps
  then application can simply skip registering of the callbacks and
  configure notification queues (e.g. 1 per each lcore)

Once we have bindings in place and notification configured, the only
essential part that remains is to get the current network configuration
and start listening to its changes.
This is accomplished via a call to::

    int rte_ifpx_listen(void);

From that moment you should see notifications coming to your
application: first ones resulting from querying of current system
configurations and subsequent on the configuration changes.
