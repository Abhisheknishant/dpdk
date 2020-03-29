# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Advanced Micro Devices, Inc. All rights reserved.

if not is_linux
	build = false
	reason = 'only supported on linux'
endif

allow_experimental_apis = true
dep = dependency('libcrypto', required: false)
if not dep.found()
	build = false
	reason = 'missing dependency, "libcrypto"'
endif
deps += 'bus_vdev'
deps += 'bus_pci'

sources = files('rte_ccp_pmd.c',
		'ccp_crypto.c',
		'ccp_dev.c',
		'ccp_pci.c',
		'ccp_pmd_ops.c')

ext_deps += dep
