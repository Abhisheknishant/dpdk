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

#.  Edit the desired conditional options in $RTE_SDK/config/common_base (optional):

    *  ``CONFIG_RTE_TEST_PMD_RECORD_CORE_TX_CYCLES``

       Enables gathering profiling data for transmit datapath,
       counts the ticks spent within rte_eth_tx_burst() routine.

    *  ``CONFIG_RTE_TEST_PMD_RECORD_CORE_RX_CYCLES``

       Enables gathering profiling data for receive datapath,
       counts ticks spent within rte_eth_rx_burst() routine.

    *  ``CONFIG_RTE_TEST_PMD_RECORD_CORE_CYCLES``

       Enables gathering profiling data for forwarding routine
       in general.

#.  Build the application:

    .. code-block:: console

        make install T=$RTE_TARGET

    The compiled application will be located at:

    .. code-block:: console

        $RTE_SDK/$RTE_TARGET/app/testpmd
