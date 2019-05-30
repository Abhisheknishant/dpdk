..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2019 Intel Corporation.

.. include:: <isonum.txt>

IOAT Rawdev Driver for Intel\ |reg| QuickData Technology
======================================================================

The ``ioat`` rawdev driver provides a poll-mode driver (PMD) for Intel\ |reg|
QuickData Technology, part of Intel\ |reg| I/O Acceleration Technology
`(Intel I/OAT) <https://www.intel.com/content/www/us/en/wireless-network/accel-technology.html>`_.
This PMD allows data copies, for example, cloning packet data, to be
accelerated by hardware rather than having to be done by software, freeing
up CPU cycles for other tasks.

Compilation
------------

For builds done with ``make``, the driver compilation is enabled by the
``CONFIG_RTE_LIBRTE_PMD_IOAT_RAWDEV`` build configuration option. This is
enabled by default in builds for x86 platforms, and disabled in other
configurations.

For builds using ``meson`` and ``ninja``, the driver will be built when the
target platform is x86-based.

Device Setup
-------------

The Intel\ |reg| QuickData Technology HW devices will need to be bound to a
user-space IO driver for use. The script ``dpdk-devbind.py`` script
included with DPDK can be used to view the state of the devices and to bind
them to a suitable DPDK-supported kernel driver. When querying the
status of the devices, they will appear under the category of "dma
devices", i.e. the command ``dpdk-devbind.py --status-dev dma`` can be used
to see the state of those devices alone.

Device Probing and Initialization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once bound to a suitable kernel device driver, the HW devices will be found
as part of the PCI scan done at application initialization time. No vdev
parameters need to be passed to create or initialize the device.

Once probed successfully, the device will appear as a ``rawdev``, that is a
"raw device type" inside DPDK, and can be accessed using APIs from the
``rte_rawdev`` library.

Using IOAT Rawdev Devices
--------------------------

To use the devices from an application, the rawdev API can be used, along
with definitions taken from the device-specific header file
``rte_ioat_rawdev.h``. This header is needed to get the definition of
structure parameters used by some of the rawdev APIs for IOAT rawdev
devices, as well as providing key functions for using the device for memory
copies.

Getting Device Information
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Basic information about each rawdev device can be got using the
``rte_rawdev_info_get()`` API. For most applications, this API will be
needed to verify that the rawdev in question is of the expected type. For
example, the following code in ``test_ioat_rawdev.c`` is used to identify
the IOAT rawdev device for use for the tests:

.. code-block:: C

        for (i = 0; i < count && !found; i++) {
                struct rte_rawdev_info info = { .dev_private = NULL };
                found = (rte_rawdev_info_get(i, &info) == 0 &&
                                strcmp(info.driver_name,
                                                IOAT_PMD_RAWDEV_NAME_STR) == 0);
        }

When calling the ``rte_rawdev_info_get()`` API for an IOAT rawdev device,
the ``dev_private`` field in the ``rte_rawdev_info`` struct should either
be NULL, or else be set to point to a structure of type
``rte_ioat_rawdev_config``, in which case the size of the configured device
input ring will be returned in that structure.
