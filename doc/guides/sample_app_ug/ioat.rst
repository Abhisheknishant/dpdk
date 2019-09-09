..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2019 Intel Corporation.

Sample Application of packet copying using Intel\|reg| QuickData Technology
============================================================================

Overview
--------

This sample is intended as a demonstration of the basic components of a DPDK
forwarding application and example of how to use IOAT driver API to make
packets copies.

Also while forwarding, the MAC addresses are affected as follows:

*   The source MAC address is replaced by the TX port MAC address

*   The destination MAC address is replaced by  02:00:00:00:00:TX_PORT_ID

This application can be used to compare performance of using software packet
copy with copy done using a DMA device for different sizes of packets.
The example will print out statistics each second. The stats shows
received/send packets and packets dropped or failed to copy.

Compiling the Application
-------------------------

To compile the sample application see :doc:`compiling`.

The application is located in the ``ioat`` sub-directory.


Running the Application
-----------------------

In order to run the hardware copy application, the copying device
needs to be bound to user-space IO driver.

Refer to the *IOAT Rawdev Driver for Intel\ |reg| QuickData Technology*
guide for information on using the driver.

The application requires a number of command line options:

.. code-block:: console

    ./build/ioatfwd [EAL options] -- -p MASK [-C CT] [--[no-]mac-updating]

where,

*   p MASK: A hexadecimal bitmask of the ports to configure

*   c CT: Performed packet copy type: software (sw) or hardware using
    DMA (rawdev)

*   s RS: size of IOAT rawdev ring for hardware copy mode or rte_ring for
    software copy mode

*   --[no-]mac-updating: Whether MAC address of packets should be changed
    or not

The application can be launched in 2 different configurations:

*   Performing software packet copying

*   Performing hardware packet copying

Each port needs 2 lcores: one of them receives incoming traffic and makes
a copy of each packet. The second lcore then updates MAC address and sends
the copy. For each configuration an additional lcore is needed since
master lcore in use which is responsible for configuration, statistics
printing and safe deinitialization of all ports and devices.

The application can use a maximum of 8 ports.

To run the application in a Linux environment with 3 lcores (one of them
is master lcore), 1 port (port 0), software copying and MAC updating issue
the command:

.. code-block:: console

    $ ./build/ioatfwd -l 0-2 -n 2 -- -p 0x1 --mac-updating -c sw

To run the application in a Linux environment with 5 lcores (one of them
is master lcore), 2 ports (ports 0 and 1), hardware copying and no MAC
updating issue the command:

.. code-block:: console

    $ ./build/ioatfwd -l 0-4 -n 1 -- -p 0x3 --no-mac-updating -c rawdev

Refer to the *DPDK Getting Started Guide* for general information on
running applications and the Environment Abstraction Layer (EAL) options.

Explanation
-----------

The following sections provide an explanation of the main components of the
code.

All DPDK library functions used in the sample code are prefixed with
``rte_`` and are explained in detail in the *DPDK API Documentation*.


The Main Function
~~~~~~~~~~~~~~~~~

The ``main()`` function performs the initialization and calls the execution
threads for each lcore.

The first task is to initialize the Environment Abstraction Layer (EAL).
The ``argc`` and ``argv`` arguments are provided to the ``rte_eal_init()``
function. The value returned is the number of parsed arguments:

.. code-block:: c

    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");


The ``main()`` also allocates a mempool to hold the mbufs (Message Buffers)
used by the application:

.. code-block:: c

    nb_mbufs = RTE_MAX(rte_eth_dev_count_avail() * (nb_rxd + nb_txd
        + MAX_PKT_BURST + rte_lcore_count() * MEMPOOL_CACHE_SIZE),
        MIN_POOL_SIZE);

    /* Create the mbuf pool */
    ioat_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
        MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id());
    if (ioat_pktmbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

Mbufs are the packet buffer structure used by DPDK. They are explained in
detail in the "Mbuf Library" section of the *DPDK Programmer's Guide*.

The ``main()`` function also initializes the ports:

.. code-block:: c

    /* Initialise each port */
    RTE_ETH_FOREACH_DEV(portid) {
        port_init(portid, ioat_pktmbuf_pool);
    }

Each port is configured using ``port_init()``:

.. code-block:: c

    static inline void
    port_init(uint16_t portid, struct rte_mempool *mbuf_pool)
    {
        struct rte_eth_rxconf rxq_conf;
        struct rte_eth_txconf txq_conf;
        struct rte_eth_conf local_port_conf = port_conf;
        struct rte_eth_dev_info dev_info;
        int ret;

        /* Skip ports that are not enabled */
        if ((ioat_enabled_port_mask & (1 << portid)) == 0) {
            printf("Skipping disabled port %u\n", portid);
            return;
        }

        /* Init port */
        printf("Initializing port %u... ", portid);
        fflush(stdout);
        rte_eth_dev_info_get(portid, &dev_info);
        if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
            local_port_conf.txmode.offloads |=
                DEV_TX_OFFLOAD_MBUF_FAST_FREE;
        ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
                    ret, portid);

        ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
                            &nb_txd);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                    "Cannot adjust number of descriptors: err=%d, port=%u\n",
                    ret, portid);

        rte_eth_macaddr_get(portid, &ioat_ports_eth_addr[portid]);

        /* Init one RX queue */
        fflush(stdout);
        rxq_conf = dev_info.default_rxconf;
        rxq_conf.offloads = local_port_conf.rxmode.offloads;
        ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
                        rte_eth_dev_socket_id(portid),
                        &rxq_conf,
                        mbuf_pool);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
                    ret, portid);

        /* Init one TX queue on each port */
        fflush(stdout);
        txq_conf = dev_info.default_txconf;
        txq_conf.offloads = local_port_conf.txmode.offloads;
        ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
                rte_eth_dev_socket_id(portid),
                &txq_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
                ret, portid);

        /* Initialize TX buffers */
        tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
                RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
                rte_eth_dev_socket_id(portid));
        if (tx_buffer[portid] == NULL)
            rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx "
                    "on port %u\n", portid);

        rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);

        ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],
                rte_eth_tx_buffer_count_callback,
                &port_statistics[portid].tx_dropped);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
            "Cannot set error callback for tx buffer on port %u\n",
                    portid);

        /* Start device */
        ret = rte_eth_dev_start(portid);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
                    ret, portid);

        rte_eth_promiscuous_enable(portid);

        printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
                portid,
                ioat_ports_eth_addr[portid].addr_bytes[0],
                ioat_ports_eth_addr[portid].addr_bytes[1],
                ioat_ports_eth_addr[portid].addr_bytes[2],
                ioat_ports_eth_addr[portid].addr_bytes[3],
                ioat_ports_eth_addr[portid].addr_bytes[4],
                ioat_ports_eth_addr[portid].addr_bytes[5]);
    }

The Ethernet ports are configured with local settings using the
``rte_eth_dev_configure()`` function and the ``port_conf`` struct:

.. code-block:: c

    static struct rte_eth_conf port_conf = {
        .rxmode = {
            .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
        },
    };

For this example the ports are set up with 1 RX and 1 TX queue using the
``rte_eth_rx_queue_setup()`` and ``rte_eth_tx_queue_setup()`` functions.

The Ethernet port is then started:

.. code-block:: c

    ret = rte_eth_dev_start(portid);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
            ret, portid);


Finally the RX port is set in promiscuous mode:

.. code-block:: c

    rte_eth_promiscuous_enable(portid);


After that each port application assigns resources needed.

.. code-block:: c

    check_link_status(ioat_enabled_port_mask);

    if (!cfg.nb_ports) {
        rte_exit(EXIT_FAILURE,
            "All available ports are disabled. Please set portmask.\n");
    }

    /* Check if there is enough lcores for all ports. */
    cfg.nb_lcores = rte_lcore_count() - 1;
    if (cfg.nb_lcores < 1)
        rte_exit(EXIT_FAILURE,
            "There should be at least one slave lcore.\n");

    ret = 0;

    if (copy_mode == COPY_MODE_IOAT_NUM) {
        assign_rawdevs();
    } else /* copy_mode == COPY_MODE_SW_NUM */ {
        assign_rings();
    }

A link status is checked of each port enabled by port mask
using ``check_link_status()`` function.

.. code-block:: c

    /* Check the link status of all ports in up to 9s, and print them finally */
    static void
    check_link_status(uint32_t port_mask)
    {

        uint16_t portid;
        struct rte_eth_link link;

        cfg.nb_ports = 0;

        printf("\nChecking link status\n");
        fflush(stdout);
        RTE_ETH_FOREACH_DEV(portid) {
            if (force_quit)
                return;
            if ((port_mask & (1 << portid)) == 0)
                continue;

            store_port_nb(portid);

            memset(&link, 0, sizeof(link));
            rte_eth_link_get(portid, &link);

            /* Print link status */
            if (link.link_status) {
                printf(
                    "Port %d Link Up. Speed %u Mbps - %s\n",
                    portid, link.link_speed,
                    (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                    ("full-duplex") : ("half-duplex\n"));
            }
            else
                printf("Port %d Link Down\n", portid);
        }
    }

Depending on mode set (whether copy should be done by software or by hardware)
special structures are assigned to each port. If software copy was chosen,
application have to assign ring structures for packet exchanging between lcores
assigned to ports.

.. code-block:: c

    static void
    assign_rings(void)
    {
        uint32_t i;

        for (i = 0; i < cfg.nb_ports; i++) {
            char ring_name[20];

            snprintf(ring_name, 20, "rx_to_tx_ring_%u", i);
            /* Create ring for inter core communication */
            cfg.ports[i].rx_to_tx_ring = rte_ring_create(
                    ring_name, ring_size,
                    rte_socket_id(), RING_F_SP_ENQ);

            if (cfg.ports[i].rx_to_tx_ring == NULL)
                rte_exit(EXIT_FAILURE, "%s\n",
                        rte_strerror(rte_errno));
        }
    }


When using hardware copy each port is assigned an IOAT device
(``assign_rawdevs()``) using IOAT Rawdev Driver API functions:

.. code-block:: c

    static void
    assign_rawdevs(void)
    {
        uint16_t nb_rawdev = 0;
        uint32_t i;

        for (i = 0; i < cfg.nb_ports; i++) {
            struct rte_rawdev_info rdev_info = {0};
            rte_rawdev_info_get(0, &rdev_info);

            if (strcmp(rdev_info.driver_name, "rawdev_ioat") == 0) {
                configure_rawdev_queue(i);
                cfg.ports[i].dev_id = i;
                ++nb_rawdev;
            }
        }

        RTE_LOG(INFO, IOAT, "Number of used rawdevs: %u.\n", nb_rawdev);

        if (nb_rawdev < cfg.nb_ports)
            rte_exit(EXIT_FAILURE, "Not enough IOAT rawdevs (%u) for ports (%u).\n",
                    nb_rawdev, cfg.nb_ports);
    }


The initialization of hardware device is done by ``rte_rawdev_configure()``
function and ``rte_rawdev_info`` struct. After configuration the device is
started using ``rte_rawdev_start()`` function. Each of the above operations
is done in ``configure_rawdev_queue()``.

.. code-block:: c

    static void
    configure_rawdev_queue(uint32_t dev_id)
    {
        struct rte_rawdev_info info = { .dev_private = &dev_config };

        /* Configure hardware copy device */
        dev_config.ring_size = ring_size;

        if (rte_rawdev_configure(dev_id, &info) != 0) {
            rte_exit(EXIT_FAILURE,
                "Error with rte_rawdev_configure()\n");
        }
        rte_rawdev_info_get(dev_id, &info);
        if (dev_config.ring_size != ring_size) {
            rte_exit(EXIT_FAILURE,
                "Error, ring size is not %d (%d)\n",
                ring_size, (int)dev_config.ring_size);
        }
        if (rte_rawdev_start(dev_id) != 0) {
            rte_exit(EXIT_FAILURE,
                "Error with rte_rawdev_start()\n");
        }
    }

If initialization is successful memory for hardware device
statistics is allocated.

Finally ``main()`` functions starts all processing lcores and starts
printing stats in a loop on master lcore. The application can be
interrupted and closed using ``Ctrl-C``. The master lcore waits for
all slave processes to finish, deallocates resources and exits.

The processing lcores launching function are described below.

The Lcores Launching Functions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As described above ``main()`` function invokes ``run_transmission()``
function in order to start processing for each lcore:

.. code-block:: c

    static void run_transmission(void)
    {
        uint32_t lcore_id = rte_lcore_id();

        RTE_LOG(INFO, IOAT, "Entering %s on lcore %u\n",
                __func__, rte_lcore_id());

        if (cfg.nb_lcores == 1) {
            lcore_id = rte_get_next_lcore(lcore_id, true, true);
            rte_eal_remote_launch((lcore_function_t *)rxtx_main_loop, NULL, lcore_id);
        } else if (cfg.nb_lcores > 1) {
            lcore_id = rte_get_next_lcore(lcore_id, true, true);
            rte_eal_remote_launch((lcore_function_t *)rx_main_loop, NULL, lcore_id);

            lcore_id = rte_get_next_lcore(lcore_id, true, true);
            rte_eal_remote_launch((lcore_function_t *)tx_main_loop, NULL, lcore_id);
        }
    }

The function launches rx/tx processing functions on configured lcores
for each port using ``rte_eal_remote_launch()``. The configured ports,
their number and number of assigned lcores are stored in user-defined
``rxtx_transmission_config`` struct that is initialized before launching
tasks:

.. code-block:: c

    struct rxtx_transmission_config {
        struct rxtx_port_config ports[RTE_MAX_ETHPORTS];
        uint16_t nb_ports;
        uint16_t nb_lcores;
    };

The Lcores Processing Functions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For receiving packets on each port an ``ioat_rx_port()`` function is used.
Depending on mode the user chose, it will enqueue packets to IOAT rawdev
and then invoke copy process (hardware copy), or perform software copy
of each packet using ``pktmbuf_sw_copy()`` function and enqueue them to
rte_ring:

.. code-block:: c

    /* Receive packets on one port and enqueue to IOAT rawdev or rte_ring. */
    static void
    ioat_rx_port(struct rxtx_port_config *rx_config)
    {
        uint32_t nb_rx, nb_enq, i;
        struct rte_mbuf *pkts_burst[MAX_PKT_BURST];

        nb_rx = rte_eth_rx_burst(rx_config->rx_portId, 0,
            pkts_burst, MAX_PKT_BURST);

        if (nb_rx == 0)
            return;

        port_statistics[rx_config->rx_portId].rx += nb_rx;

        if (copy_mode == COPY_MODE_IOAT_NUM) {
            /* Perform packet hardware copy */
            nb_enq = ioat_enqueue_packets(rx_config,
                pkts_burst, nb_rx);

            if (nb_enq > 0)
                rte_ioat_do_copies(rx_config->dev_id);
        } else {
            /* Perform packet software copy, free source packets */
            int ret;
            struct rte_mbuf *pkts_burst_copy[MAX_PKT_BURST];

            ret = rte_pktmbuf_alloc_bulk(ioat_pktmbuf_pool,
                    pkts_burst_copy, nb_rx);

            if (unlikely(ret < 0))
                rte_exit(EXIT_FAILURE, "Unable to allocate memory.\n");

            for (i = 0; i < nb_rx; i++) {
                pktmbuf_sw_copy(pkts_burst[i], pkts_burst_copy[i]);
                rte_pktmbuf_free(pkts_burst[i]);
            }

            nb_enq = rte_ring_enqueue_burst(rx_config->rx_to_tx_ring,
                (void *)pkts_burst_copy, nb_rx, NULL);

            /* Free any not enqueued packets. */
            for (i = nb_enq; i < nb_rx; i++)
                rte_pktmbuf_free(pkts_burst_copy[i]);
        }

        port_statistics[rx_config->rx_portId].copy_dropped
            += (nb_rx - nb_enq);
    }

The packets are received in burst mode using ``rte_eth_rx_burst()``
function. When using hardware copy mode the packets are enqueued in
copying device's buffer using ``ioat_enqueue_packets()`` which calls
``rte_ioat_enqueue_copy()``. When all received packets are in the
buffer the copies are invoked by calling ``rte_ioat_do_copies()``.
Function ``rte_ioat_enqueue_copy()`` operates on physical address of
the packet. Structure ``rte_mbuf`` contains only physical address to
start of the data buffer (``buf_iova``). Thus the address is shifted
by ``addr_offset`` value in order to get pointer to ``rearm_data``
member of ``rte_mbuf``. That way the packet is copied all at once
(with data and metadata).

.. code-block:: c

    static uint32_t
    ioat_enqueue_packets(struct rxtx_port_config *rx_config,
        struct rte_mbuf **pkts, uint32_t nb_rx)
    {
        int ret;
        uint32_t i;
        struct rte_mbuf *pkts_copy[MAX_PKT_BURST];

        const uint64_t addr_offset = RTE_PTR_DIFF(pkts[0]->buf_addr,
            &pkts[0]->rearm_data);

        ret = rte_pktmbuf_alloc_bulk(ioat_pktmbuf_pool, pkts_copy, nb_rx);

        if (unlikely(ret < 0))
            rte_exit(EXIT_FAILURE, "Unable to allocate memory.\n");

        for (i = 0; i < nb_rx; i++) {
            /* Perform data copy */
            ret = rte_ioat_enqueue_copy(rx_config->dev_id,
                pkts[i]->buf_iova
                    - addr_offset,
                pkts_copy[i]->buf_iova
                    - addr_offset,
                rte_pktmbuf_data_len(pkts[i])
                    + addr_offset,
                (uintptr_t)pkts[i],
                (uintptr_t)pkts_copy[i],
                0 /* nofence */);

            if (ret != 1)
                break;
        }

        ret = i;
        /* Free any not enqueued packets. */
        for (; i < nb_rx; i++) {
            rte_pktmbuf_free(pkts[i]);
            rte_pktmbuf_free(pkts_copy[i]);
        }

        return ret;
    }


All done copies are processed by ``ioat_tx_port()`` function. When using
hardware copy mode the function invokes ``rte_ioat_completed_copies()``
to gather copied packets. If software copy mode is used the function
dequeues copied packets from rte_ring. Then each packet MAC address
is changed if it was enabled. After that copies are sent in burst mode
using `` rte_eth_tx_burst()``.


.. code-block:: c

    /* Transmit packets from IOAT rawdev/rte_ring for one port. */
    static void
    ioat_tx_port(struct rxtx_port_config *tx_config)
    {
        uint32_t i, nb_dq;
        struct rte_mbuf *mbufs_src[MAX_PKT_BURST];
        struct rte_mbuf *mbufs_dst[MAX_PKT_BURST];

        if (copy_mode == COPY_MODE_IOAT_NUM) {
            /* Deque the mbufs from IOAT device. */
            nb_dq = rte_ioat_completed_copies(tx_config->dev_id,
                MAX_PKT_BURST, (void *)mbufs_src, (void *)mbufs_dst);
        } else {
            /* Deque the mbufs from rx_to_tx_ring. */
            nb_dq = rte_ring_dequeue_burst(tx_config->rx_to_tx_ring,
                (void *)mbufs_dst, MAX_PKT_BURST, NULL);
        }

        if (nb_dq == 0)
            return;

        /* Free source packets */
        if (copy_mode == COPY_MODE_IOAT_NUM) {
            for (i = 0; i < nb_dq; i++)
                rte_pktmbuf_free(mbufs_src[i]);
        }

        /* Update macs if enabled */
        if (mac_updating) {
            for (i = 0; i < nb_dq; i++)
                update_mac_addrs(mbufs_dst[i],
                    tx_config->tx_portId);
        }

        const uint16_t nb_tx = rte_eth_tx_burst(tx_config->tx_portId,
            0, (void *)mbufs_dst, nb_dq);

        port_statistics[tx_config->tx_portId].tx += nb_tx;

        /* Free any unsent packets. */
        if (unlikely(nb_tx < nb_dq)) {
            for (i = nb_tx; i < nb_dq; i++)
                rte_pktmbuf_free(mbufs_dst[i]);
        }
    }

The Packet Copying Functions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In order to perform packet copy there is a user-defined function
``pktmbuf_sw_copy()`` used. It copies a whole packet by copying
metadata from source packet to new mbuf, and then copying a data
chunk of source packet. Both memory copies are done using
``rte_memcpy()``:

.. code-block:: c

    static inline void
    pktmbuf_sw_copy(struct rte_mbuf *src, struct rte_mbuf *dst)
    {
        /* Copy packet metadata */
        rte_memcpy(&dst->rearm_data,
            &src->rearm_data,
            offsetof(struct rte_mbuf, cacheline1)
                - offsetof(struct rte_mbuf, rearm_data));

        /* Copy packet data */
        rte_memcpy(rte_pktmbuf_mtod(dst, char *),
            rte_pktmbuf_mtod(src, char *), src->data_len);
    }

The metadata in this example is copied from ``rearm_data`` member of
``rte_mbuf`` struct up to ``cacheline1``.

In order to understand why software packet copying is done as shown
above please refer to the "Mbuf Library" section of the
*DPDK Programmer's Guide*.