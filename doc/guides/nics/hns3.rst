..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2018-2019 Hisilicon Limited.

HNS3 Poll Mode Driver
===============================

The Hisilicon Network Subsystem is a long term evolution IP which is
supposed to be used in Hisilicon ICT SoCs such as Kunpeng 920.

The HNS3 PMD (librte_pmd_hns3) provides poll mode driver support
for hns3(Hisilicon Network Subsystem 3) network engine.

Features
--------

Features of the HNS3 PMD are:

- Arch support: ARMv8.
- Multiple queues for TX and RX
- Receive Side Scaling (RSS)
- Packet type information
- Checksum offload
- Promiscuous mode
- Multicast mode
- Port hardware statistics
- Jumbo frames
- Link state information
- VLAN stripping
- NUMA support

Prerequisites
-------------
- Follow the DPDK :ref:`Getting Started Guide for Linux <linux_gsg>` to setup the basic DPDK environment.

Pre-Installation Configuration
------------------------------

Config File Options
~~~~~~~~~~~~~~~~~~~

The following options can be modified in the ``config`` file.
Please note that enabling debugging options may affect system performance.

- ``CONFIG_RTE_LIBRTE_HNS3_PMD`` (default ``y``)

Driver compilation and testing
------------------------------

Refer to the document :ref:`compiling and testing a PMD for a NIC <pmd_build_and_test>`
for details.

Limitations or Known issues
---------------------------
Build with clang is not supported yet.
Currently, only ARMv8 architecture is supported.