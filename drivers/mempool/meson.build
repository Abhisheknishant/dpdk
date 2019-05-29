# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

drivers = ['bucket', 'dpaa', 'dpaa2', 'octeontx', 'ring', 'stack']

enabled_drivers = get_option('drivers_mempool')
if enabled_drivers != 'all'
	drivers = (enabled_drivers == 'none') ? [] : enabled_drivers.split(',')
endif

std_deps = ['mempool']
config_flag_fmt = 'RTE_LIBRTE_@0@_MEMPOOL'
driver_name_fmt = 'rte_mempool_@0@'
