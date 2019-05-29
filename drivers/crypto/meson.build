# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

drivers = ['aesni_gcm', 'aesni_mb', 'caam_jr', 'ccp', 'dpaa_sec', 'dpaa2_sec',
	'kasumi', 'mvsam', 'null', 'octeontx', 'openssl', 'qat', 'scheduler',
	'snow3g', 'virtio', 'zuc']

enabled_drivers = get_option('drivers_crypto')
if enabled_drivers != 'all'
	drivers = (enabled_drivers == 'none') ? [] : enabled_drivers.split(',')
endif

std_deps = ['cryptodev'] # cryptodev pulls in all other needed deps
config_flag_fmt = 'RTE_LIBRTE_@0@_PMD'
driver_name_fmt = 'rte_pmd_@0@'
