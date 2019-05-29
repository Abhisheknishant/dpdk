# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

drivers = ['dpaa', 'fslmc', 'ifpga', 'pci', 'vdev', 'vmbus']

enabled_drivers = get_option('drivers_bus')
if enabled_drivers != 'all'
	drivers = (enabled_drivers == 'none') ? [] : enabled_drivers.split(',')
endif

std_deps = ['eal']
config_flag_fmt = 'RTE_LIBRTE_@0@_BUS'
driver_name_fmt = 'rte_bus_@0@'
