..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2014 Intel Corporation.

Compiling the Application
=========================

The ``testpmd`` application is compiled as part of the main compilation of the DPDK libraries and tools.
Refer to the DPDK Getting Started Guides for details.
The basic compilation steps are:

#.  Set the required environmental variables and go to the source directory:

    .. code-block:: console

        export RTE_SDK=/path/to/rte_sdk
        cd $RTE_SDK

#.  Set the compilation target. For example:

    .. code-block:: console

        export RTE_TARGET=x86_64-native-linux-gcc

#.  If required, enable configuration options. For example:

    .. code-block:: console

        cd to the top-level DPDK directory
        sed -i 's,\(CONFIG_RTE_TEST_PMD_RECORD_CORE_CYCLES\)=n,\1=y,' build/.config
        sed -i 's,\(CONFIG_RTE_TEST_PMD_RECORD_BURST_STATS\)=n,\1=y,' build/.config

    Enabling CONFIG_RTE_TEST_PMD_RECORD_CORE_CYCLES enables measurement of CPU cycles.

    Enabling CONFIG_RTE_TEST_PMD_RECORD_BURST_STATS enables display of RX and TX bursts.

#.  Build the application:

    .. code-block:: console

        make install T=$RTE_TARGET

    The compiled application will be located at:

    .. code-block:: console

        $RTE_SDK/$RTE_TARGET/app/testpmd
