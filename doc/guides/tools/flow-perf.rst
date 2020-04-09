..	SPDX-License-Identifier: BSD-3-Clause
	Copyright 2020 Mellanox Technologies, Ltd

RTE Flow performance tool
=========================

Application for rte_flow performance testing.


Compiling the Application
=========================
The ``test-flow-perf`` application is compiled as part of the main compilation
of the DPDK libraries and tools.

Refer to the DPDK Getting Started Guides for details.
The basic compilation steps are:

#. Set the required environmental variables and go to the source directory:

	.. code-block:: console

		export RTE_SDK=/path/to/rte_sdk
		cd $RTE_SDK

#. Set the compilation target. For example:

	.. code-block:: console

		export RTE_TARGET=x86_64-native-linux-gcc

#. Build the application:

	.. code-block:: console

		make install T=$RTE_TARGET

#. The compiled application will be located at:

	.. code-block:: console

		$RTE_SDK/$RTE_TARGET/app/flow-perf


Running the Application
=======================

EAL Command-line Options
------------------------

Please refer to :doc:`EAL parameters (Linux) <../linux_gsg/linux_eal_parameters>`
or :doc:`EAL parameters (FreeBSD) <../freebsd_gsg/freebsd_eal_parameters>` for
a list of available EAL command-line options.


Flow performance Options
------------------------

The following are the command-line options for the flow performance application.
They must be separated from the EAL options, shown in the previous section, with
a ``--`` separator:

.. code-block:: console

	sudo ./test-flow-perf -n 4 -w 08:00.0,dv_flow_en=1 --

The command line options are:

*	``--help``
	Display a help message and quit.
