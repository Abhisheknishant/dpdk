# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019 Intel Corporation

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

if not dpdk_conf.has('RTE_LIBRTE_PMD_IOAT_RAWDEV')
	build = false
	subdir_done()
endif

deps += ['pmd_ioat']

sources = files(
	'ioatfwd.c'
)
