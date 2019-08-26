.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2019 NXP

PPFE Poll Mode Driver
======================

The PPFE NIC PMD (**librte_pmd_ppfe**) provides poll mode driver
support for the inbuilt NIC found in the **NXP LS1012** SoC.

More information can be found at `NXP Official Website
<https://nxp.com/ls1012a>`_.

PPFE
-----

This section provides an overview of the NXP PPFE
and how it is integrated into the DPDK.

Contents summary

- PPFE overview
- PPFE features
- Supported PPFE SoCs
- Prerequisites
- Driver compilation and testing
- Limitations

PPFE Overview
~~~~~~~~~~~~~~

PPFE is a hardware programmable packet forwarding engine to provide
high performance Ethernet interfaces. The diagram below shows a
system level overview of PPFE:

.. code-block:: console

   ====================================================+===============
   US   +-----------------------------------------+    | Kernel Space
        |                                         |    |
        |          PPFE Ethernet Driver           |    |
        +-----------------------------------------+    |
                  ^   |          ^     |               |
   PPFE        RXQ|   |TXQ    RXQ|     |TXQ            |
   PMD            |   |          |     |               |
                  |   v          |     v               |   +----------+
               +---------+     +----------+            |   | pfe.ko   |
               | pfe_eth0|     | pfe_eth1 |            |   +----------+
               +---------+     +----------+            |
                  ^   |          ^     |               |
               TXQ|   |RXQ    TXQ|     |RXQ            |
                  |   |          |     |               |
                  |   v          |     v               |
                 +------------------------+            |
                 |                        |            |
                 |     PPFE HIF driver    |            |
                 +------------------------+            |
                       ^         |                     |
                    RX |      TX |                     |
                   RING|     RING|                     |
                       |         v                     |
                     +--------------+                  |
                     |              |                  |
   ==================|    HIF       |==================+===============
         +-----------+              +--------------+
         |           |              |              |        HW
         | PPFE      +--------------+              |
         |       +-----+                +-----+    |
         |       | MAC |                | MAC |    |
         |       |     |                |     |    |
         +-------+-----+----------------+-----+----+
                 | PHY |                | PHY |
                 +-----+                +-----+


The HIF, PPFE, MAC and PHY are the hardware blocks, the pfe.ko is a kernel
module, the PPFE HIF driver and the PPFE ethernet driver combined represent
as DPDK PPFE poll mode driver are running in the userspace.

The PPFE hardware supports one HIF (host interface) RX ring and one TX ring
to send and receive packets through packet forwarding engine. Both network
interface traffic is multiplexed and send over HIF queue.

pfe_eth0 and pfe_eth1 are logical ethernet interfaces, created by HIF client
driver. HIF driver is responsible for send and receive packets between
host interface and these logical interfaces. PPFE ethernet driver is a
hardware independent and register with the HIF client driver to transmit and
receive packets from HIF via logical interfaces.

pfe.ko is required for PHY initialisation.

PPFE Features
~~~~~~~~~~~~~~

- L3/L4 checksum offload
- Packet type parsing
- Basic stats
- MTU update
- Promiscuous mode
- Allmulticast mode
- ARMv8

Supported PPFE SoCs
~~~~~~~~~~~~~~~~~~~~

- LS1012

Prerequisites
~~~~~~~~~~~~~

Below are some pre-requisites for executing PPFE PMD on a PPFE
compatible board:

1. **ARM 64 Tool Chain**

   For example, the `*aarch64* Linaro Toolchain <https://releases.linaro.org/components/toolchain/binaries/7.3-2018.05/aarch64-linux-gnu/gcc-linaro-7.3.1-2018.05-i686_aarch64-linux-gnu.tar.xz>`_.

2. **Linux Kernel**

   It can be obtained from `NXP's Github hosting <https://source.codeaurora.org/external/qoriq/qoriq-components/linux>`_.

3. **Rootfile system**

   Any *aarch64* supporting filesystem can be used. For example,
   Ubuntu 16.04 LTS (Xenial) or 18.04 (Bionic) userland which can be obtained
   from `here <http://cdimage.ubuntu.com/ubuntu-base/releases/18.04/release/ubuntu-base-18.04.1-base-arm64.tar.gz>`_.

4. The ethernet device will be registered as virtual device, so ppfe has dependency on
   **rte_bus_vdev** library and it is mandatory to use `--vdev` with value `eth_pfe` to
   run DPDK application.

The following dependencies are not part of DPDK and must be installed
separately:

- **NXP Linux LSDK**

  NXP Layerscape software development kit (LSDK) includes support for family
  of QorIQ® ARM-Architecture-based system on chip (SoC) processors
  and corresponding boards.

  It includes the Linux board support packages (BSPs) for NXP SoCs,
  a fully operational tool chain, kernel and board specific modules.

  LSDK and related information can be obtained from:  `LSDK <https://www.nxp.com/support/developer-resources/run-time-software/linux-software-and-development-tools/layerscape-software-development-kit:LAYERSCAPE-SDK>`_

- **pfe kernel module**

  pfe kernel module can be obtained from NXP Layerscape software development kit at
  location `/lib/modules/<kernel version>/kernel/drivers/staging/fsl_ppfe` in rootfs.
  Module should be loaded using below command:

  .. code-block:: console

     insmod pfe.ko us=1


Driver compilation and testing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Follow instructions available in the document
:ref:`compiling and testing a PMD for a NIC <pmd_build_and_test>`
to launch **testpmd**

Additionally, PPFE driver need `--vdev` as an input with value `eth_pfe` to execute DPDK application,
see the command below:

 .. code-block:: console

    <dpdk app> <EAL args> --vdev="eth_pfe0" --vdev="eth_pfe1" -- ...


Limitations
~~~~~~~~~~~

- Multi buffer pool cannot be supported.
