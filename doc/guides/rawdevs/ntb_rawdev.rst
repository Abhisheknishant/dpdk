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

Build options
-------------

- ``CONFIG_RTE_LIBRTE_IFPGA_RAWDEV`` (default ``y``)

   Toggle compilation of the ``ntb_rawdev`` driver.
