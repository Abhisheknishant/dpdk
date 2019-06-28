..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2018 Intel Corporation.

NTB Rawdev Driver
=================

The ``ntb`` rawdev driver provides a non-transparent bridge between two
separate hosts so that they can communicate with each other. Thus, many
user cases can benefit from this, such as fault tolerance and visual
acceleration.

This PMD allows two hosts to handshake for device start and stop, memory
allocation for the peer to access and read/write allocated memory from peer.
Also, the PMD allows to use doorbell registers to notify the peer and share
some information by using scratchpad registers.

But the PMD hasn't implemented FIFO. The FIFO will come in 19.11 release.
And this PMD only supports intel skylake platform.

BIOS setting on skylake platform
--------------------------------

Intel non-transparent bridge needs special BIOS setting. Since the PMD only
supports intel skylake platform, introduce BIOS setting here. The referencce
is https://www.intel.com/content/dam/support/us/en/documents/server-products/Intel_Xeon_Processor_Scalable_Family_BIOS_User_Guide.pdf

- Set the needed PCIe port as NTB to NTB mode on both hosts.
- Enable NTB bars and set bar size of bar 23 and bar 45 as 12-29 (2K-512M)
  on both hosts. Note that bar size on both hosts should be the same.
- Disable split bars for both hosts.
- Set crosslink control override as DSD/USP on one host, USD/DSP on
  another host.
- Disable PCIe PII SSC (Spread Spectrum Clocking) for both hosts. This
  is a hardware requirement.

Build options
-------------

- ``CONFIG_RTE_LIBRTE_IFPGA_RAWDEV`` (default ``y``)

   Toggle compilation of the ``ntb_rawdev`` driver.
