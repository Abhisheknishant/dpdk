..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2017 Huawei Technologies Co., Ltd


Hinic Poll Mode Driver
======================

The hinic PMD (librte_pmd_hinic) provides poll mode driver support for
Huawei Intelligent PCIE Network Interface Card.

Prerequisites
-------------

- Follow the DPDK :ref:`Getting Started Guide for Linux <linux_gsg>` to setup the basic DPDK environment.

Requires firmware 1.6.2.5


Pre-Installation Configuration
------------------------------

Config File Options
~~~~~~~~~~~~~~~~~~~

The following options can be modified in the ``config`` file.

- ``CONFIG_RTE_LIBRTE_HINIC_PMD`` (default ``y``)



Runtime Config Options
~~~~~~~~~~~~~~~~~~~~~~

None

Driver compilation and testing
------------------------------

Refer to the document :ref:`compiling and testing a PMD for a NIC <pmd_build_and_test>`
for details.

Sample Application Notes
------------------------


Limitations or Known issues
---------------------------
Jumbo frames is not supported yet.
Build with ICC is not supported yet.
