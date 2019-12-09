..  SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
    Copyright(c) 2018-2019 Pensando Systems, Inc. All rights reserved.

IONIC Driver
============

The ionic driver provides support for Pensando server adapters.
Please visit https://pensando.io for more information about the
adapters.

Identifying the Adapter
-----------------------

To find if one or more Pensando PCI Ethernet devices are installed
on the host, check for the PCI devices:

   .. code-block:: console

      lspci -d 1dd8:
      b5:00.0 Ethernet controller: Device 1dd8:1002
      b6:00.0 Ethernet controller: Device 1dd8:1002

Pre-Installation Configuration
------------------------------

The following options can be modified in the ``config`` file.

- ``CONFIG_RTE_LIBRTE_IONIC_PMD`` (default ``y``)

  Toggle compilation of ionic PMD.

Building DPDK
-------------

The ionic PMD driver supports UIO and VFIO, please refer to the
:ref:`DPDK documentation that comes with the DPDK suite <linux_gsg>`
for instructions on how to build DPDK.
