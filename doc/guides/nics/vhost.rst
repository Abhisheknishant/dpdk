..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2016 IGEL Co., Ltd.

Poll Mode Driver that wraps vhost library
=========================================

This PMD is a thin wrapper of the DPDK vhost library.
The user can handle virtqueues as one of normal DPDK port.

Vhost Implementation in DPDK
----------------------------

Please refer to Chapter "Vhost Library" of *DPDK Programmer's Guide* to know detail of vhost.

Features and Limitations of vhost PMD
-------------------------------------

Currently, the vhost PMD provides the basic functionality of packet reception, transmission and event handling.

*   It has multiple queues support.

*   It supports ``RTE_ETH_EVENT_INTR_LSC`` and ``RTE_ETH_EVENT_QUEUE_STATE`` events.

*   It supports Port Hotplug functionality.

*   Don't need to stop RX/TX, when the user wants to stop a guest or a virtio-net driver on guest.

*   It supports to offload large data movement in Tx operations from the
    CPU to the I/OAT device for every queue. Note that I/OAT acceleration
    is just enabled for split rings. In addition, a queue can only use one
    I/OAT device, and I/OAT devices cannot be shared among vhost ports and
    queues. That is, an I/OAT device can only be used by one queue at a
    time. Moreover, users cannot enable I/OAT acceleration, if iommu or
    postcopy live-migration is enabled; when enabling I/OAT acceleration
    for a queue, Rx interrupt is not supported.

Vhost PMD arguments
-------------------

The user can specify below arguments in `--vdev` option.

#.  ``iface``:

    It is used to specify a path to connect to a QEMU virtio-net device.

#.  ``queues``:

    It is used to specify the number of queues virtio-net device has.
    (Default: 1)

#.  ``iommu-support``:

    It is used to enable iommu support in vhost library.
    (Default: 0 (disabled))

#.  ``postcopy-support``:

    It is used to enable postcopy live-migration support in vhost library.
    (Default: 0 (disabled))

#.  ``tso``:

    It is used to enable tso support in vhost library.
    (Default: 0 (disabled))

#.  ``dmas``:

    It is used to specify DMA engines used to accelerate data movement
    in Tx operations for queues.

Vhost PMD event handling
------------------------

This section describes how to handle vhost PMD events.

The user can register an event callback handler with ``rte_eth_dev_callback_register()``.
The registered callback handler will be invoked with one of below event types.

#.  ``RTE_ETH_EVENT_INTR_LSC``:

    It means link status of the port was changed.

#.  ``RTE_ETH_EVENT_QUEUE_STATE``:

    It means some of queue statuses were changed. Call ``rte_eth_vhost_get_queue_event()`` in the callback handler.
    Because changing multiple statuses may occur only one event, call the function repeatedly as long as it doesn't return negative value.

Vhost PMD with testpmd application
----------------------------------

This section demonstrates vhost PMD with testpmd DPDK sample application.

#.  Launch the testpmd with vhost PMD:

    .. code-block:: console

        ./testpmd -l 0-3 -n 4 --vdev 'net_vhost0,iface=/tmp/sock0,queues=1' -- -i

    Other basic DPDK preparations like hugepage enabling here.
    Please refer to the *DPDK Getting Started Guide* for detailed instructions.

#.  Launch the QEMU:

    .. code-block:: console

       qemu-system-x86_64 <snip>
                   -chardev socket,id=chr0,path=/tmp/sock0 \
                   -netdev vhost-user,id=net0,chardev=chr0,vhostforce,queues=1 \
                   -device virtio-net-pci,netdev=net0

    This command attaches one virtio-net device to QEMU guest.
    After initialization processes between QEMU and DPDK vhost library are done, status of the port will be linked up.
