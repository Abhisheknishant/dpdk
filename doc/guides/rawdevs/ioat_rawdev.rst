..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2019 Intel Corporation.

.. include:: <isonum.txt>

IOAT Rawdev Driver for Intel\ |reg| QuickData Technology
======================================================================

The ``ioat`` rawdev driver provides a poll-mode driver (PMD) for Intel\ |reg|
QuickData Technology, part of Intel\ |reg| I/O Acceleration Technology
`(Intel I/OAT) <https://www.intel.com/content/www/us/en/wireless-network/accel-technology.html>`_.
This PMD allows data copies, for example, cloning packet data, to be
accelerated by hardware rather than having to be done by software, freeing
up CPU cycles for other tasks.

Compilation
------------

For builds done with ``make``, the driver compilation is enabled by the
``CONFIG_RTE_LIBRTE_PMD_IOAT_RAWDEV`` build configuration option. This is
enabled by default in builds for x86 platforms, and disabled in other
configurations.

For builds using ``meson`` and ``ninja``, the driver will be built when the
target platform is x86-based.
