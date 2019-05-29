# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Luca Boccassi <bluca@debian.org>

drivers = ['null']

enabled_drivers = get_option('drivers_baseband')
if enabled_drivers != 'all'
	drivers = (enabled_drivers == 'none') ? [] : enabled_drivers.split(',')
endif

config_flag_fmt = 'RTE_LIBRTE_@0@_PMD'
driver_name_fmt = 'rte_pmd_@0@'
