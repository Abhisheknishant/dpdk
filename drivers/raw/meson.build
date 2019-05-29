# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018 NXP

drivers = ['skeleton_rawdev', 'dpaa2_cmdif', 'dpaa2_qdma', 'ifpga_rawdev']

enabled_drivers = get_option('drivers_raw')
if enabled_drivers != 'all'
	drivers = (enabled_drivers == 'none') ? [] : enabled_drivers.split(',')
endif

std_deps = ['rawdev']
config_flag_fmt = 'RTE_LIBRTE_PMD_@0@_RAWDEV'
driver_name_fmt = 'rte_pmd_@0@'
