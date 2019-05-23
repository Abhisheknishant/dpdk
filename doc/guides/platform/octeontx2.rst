..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2019 Marvell International Ltd.

Marvell OCTEON TX2 Platform Guide
=================================

This document gives an overview of **Marvell OCTEON TX2** RVU H/W block,
packet flow and procedure to build DPDK on OCTEON TX2 platform.

More information about OCTEON TX2 SoC can be found at `Marvell Official Website
<https://www.marvell.com/embedded-processors/infrastructure-processors/>`_.

Supported OCTEON TX2 SoCs
-------------------------

- CN96xx
- CN93xx

OCTEON TX2 Resource Virtualization Unit architecture
----------------------------------------------------

The :numref:`figure_octeontx2_resource_virtualization` diagram depicts the
RVU architecture and a resource provisioning example.

.. _figure_octeontx2_resource_virtualization:

.. figure:: img/octeontx2_resource_virtualization.*

    OCTEON TX2 Resource virtualization architecture and provisioning example


Resource Virtualization Unit (RVU) on Marvell's OCTEON TX2 SoC maps HW
resources belonging to the network, crypto and other functional blocks onto
PCI-compatible physical and virtual functions.

Each functional block has multiple local functions (LFs) for
provisioning to different PCIe devices. RVU supports multiple PCIe SRIOV
physical functions (PFs) and virtual functions (VFs).

The :numref:`table_octeontx2_rvu_dpdk_mapping` shows the various local
functions (LFs) provided by the RVU and its functional mapping to
DPDK subsystem.

.. _table_octeontx2_rvu_dpdk_mapping:

.. table:: RVU managed functional blocks and its mapping to DPDK subsystem

   +---+-----+--------------------------------------------------------------+
   | # | LF  | DPDK subsystem mapping                                       |
   +===+=====+==============================================================+
   | 1 | NIX | rte_ethdev, rte_tm, rte_event_eth_[rt]x_adapter, rte_security|
   +---+-----+--------------------------------------------------------------+
   | 2 | NPA | rte_mempool                                                  |
   +---+-----+--------------------------------------------------------------+
   | 3 | NPC | rte_flow                                                     |
   +---+-----+--------------------------------------------------------------+
   | 4 | CPT | rte_cryptodev, rte_event_crypto_adapter                      |
   +---+-----+--------------------------------------------------------------+
   | 5 | SSO | rte_eventdev                                                 |
   +---+-----+--------------------------------------------------------------+
   | 6 | TIM | rte_event_timer_adapter                                      |
   +---+-----+--------------------------------------------------------------+

PF0 is called the administrative / admin function (AF) and has exclusive
privileges to provision RVU functional block's LFs to each of the PF/VF.

PF/VFs communicates with AF via a shared memory region (mailbox).Upon receiving
requests from PF/VF, AF does resource provisioning and other HW configuration.

AF is always attached to host, but PF/VFs may be used by host kernel itself,
or attached to VMs or to userspace applications like DPDK, etc. So, AF has to
handle provisioning/configuration requests sent by any device from any domain.

The AF driver does not receive or process any data.
It is only a configuration driver used in control path.

The :numref:`figure_octeontx2_resource_virtualization` diagram also shows a
resource provisioning example where,

1. PFx and PFx-VF0 bound to Linux netdev driver.
2. PFx-VF1 ethdev driver bound to the first DPDK application.
3. PFy ethdev driver, PFy-VF0 ethdev driver, PFz eventdev driver, PFm-VF0 cryptodev driver bound to the second DPDK application.

OCTEON TX2 packet flow
----------------------

The :numref:`figure_octeontx2_packet_flow_hw_accelerators` diagram depicts
the packet flow on OCTEON TX2 SoC in conjunction with use of various HW accelerators.

.. _figure_octeontx2_packet_flow_hw_accelerators:

.. figure:: img/octeontx2_packet_flow_hw_accelerators.*

    OCTEON TX2 packet flow in conjunction with use of HW accelerators

HW Offload Drivers
------------------

This section lists dataplane H/W block(s) available in OCTEON TX2 SoC.

#. **Mempool Driver**
   See :doc:`../mempool/octeontx2` for NPA mempool driver information.

Procedure to Setup Platform
---------------------------

There are three main prerequisites for setting up DPDK on OCTEON TX2
compatible board:

1. **OCTEON TX2 Linux kernel driver**

   The dependent kernel drivers can be obtained from the
   `kernel.org <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/ethernet/marvell/octeontx2>`_.

   Alternatively, the Marvell SDK also provides the required kernel drivers.

   Linux kernel should be configured with the following features enabled:

.. code-block:: console

        # 64K pages enabled for better performance
        CONFIG_ARM64_64K_PAGES=y
        CONFIG_ARM64_VA_BITS_48=y
        # huge pages support enabled
        CONFIG_HUGETLBFS=y
        CONFIG_HUGETLB_PAGE=y
        # VFIO enabled with TYPE1 IOMMU at minimum
        CONFIG_VFIO_IOMMU_TYPE1=y
        CONFIG_VFIO_VIRQFD=y
        CONFIG_VFIO=y
        CONFIG_VFIO_NOIOMMU=y
        CONFIG_VFIO_PCI=y
        CONFIG_VFIO_PCI_MMAP=y
        # SMMUv3 driver
        CONFIG_ARM_SMMU_V3=y
        # ARMv8.1 LSE atomics
        CONFIG_ARM64_LSE_ATOMICS=y
        # OCTEONTX2 drivers
        CONFIG_OCTEONTX2_MBOX=y
        CONFIG_OCTEONTX2_AF=y
        # Enable if netdev PF driver required
        CONFIG_OCTEONTX2_PF=y
        # Enable if netdev VF driver required
        CONFIG_OCTEONTX2_VF=y
        CONFIG_CRYPTO_DEV_OCTEONTX2_CPT=y

2. **ARM64 Linux Tool Chain**

   For example, the *aarch64* Linaro Toolchain, which can be obtained from
   `here <https://releases.linaro.org/components/toolchain/binaries/7.4-2019.02/aarch64-linux-gnu/>`_.

   Alternatively, the Marvell SDK also provides GNU GCC toolchain, which is
   optimized for OCTEON TX2 CPU.

3. **Rootfile system**

   Any *aarch64* supporting filesystem may be used. For example,
   Ubuntu 15.10 (Wily) or 16.04 LTS (Xenial) userland which can be obtained
   from `<http://cdimage.ubuntu.com/ubuntu-base/releases/16.04/release/ubuntu-base-16.04.1-base-arm64.tar.gz>`_.

   Alternatively, the Marvell SDK provides the buildroot based root filesystem.
   The SDK includes all the above prerequisites necessary to bring up the OCTEON TX2 board.

- Follow the DPDK :doc:`../linux_gsg/index` to setup the basic DPDK environment.


Debugging Options
-----------------

.. _table_octeontx2_common_debug_options:

.. table:: OCTEON TX2 common debug options

   +---+------------+-------------------------------------------------------+
   | # | Component  | EAL log command                                       |
   +===+============+=======================================================+
   | 1 | Common     | --log-level='pmd\.octeontx2\.base,8'                  |
   +---+------------+-------------------------------------------------------+
   | 2 | Mailbox    | --log-level='pmd\.octeontx2\.mbox,8'                  |
   +---+------------+-------------------------------------------------------+


Compile DPDK
------------

DPDK may be compiled either natively on OCTEON TX2 platform or cross-compiled on
an x86 based platform.

Native Compilation
~~~~~~~~~~~~~~~~~~

make build
^^^^^^^^^^

.. code-block:: console

        make config T=arm64-octeontx2-linux-gcc
        make -j

The example applications can be compiled using the following:

.. code-block:: console

        cd <dpdk directory>
        export RTE_SDK=$PWD
        export RTE_TARGET=build
        cd examples/<application>
        make -j

meson build
^^^^^^^^^^^

.. code-block:: console

        meson build
        ninja -C build

Cross Compilation
~~~~~~~~~~~~~~~~~

Refer to :doc:`../linux_gsg/cross_build_dpdk_for_arm64` for generic arm64 details.

make build
^^^^^^^^^^

.. code-block:: console

        make config T=arm64-octeontx2-linux-gcc
        make -j CROSS=aarch64-marvell-linux-gnu- CONFIG_RTE_KNI_KMOD=n

meson build
^^^^^^^^^^^

.. code-block:: console

        meson build --cross-file config/arm/arm64_octeontx2_linux_gcc
        ninja -C build
