# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

headers = files('rte_crc_arm64.h',
	'rte_fbk_hash.h',
	'rte_k32v64_hash.h',
	'rte_hash_crc.h',
	'rte_hash.h',
	'rte_jhash.h',
	'rte_thash.h')

sources = files('rte_cuckoo_hash.c', 'rte_fbk_hash.c', 'rte_k32v64_hash.c')
deps += ['ring', 'mempool']

if dpdk_conf.has('RTE_ARCH_X86')
	if cc.has_argument('-mavx512vl')
		avx512_tmplib = static_library('avx512_tmp',
                                'k32v64_hash_avx512vl.c',
                                dependencies: static_rte_mempool,
                                c_args: cflags + ['-mavx512vl'])
                objs += avx512_tmplib.extract_objects('k32v64_hash_avx512vl.c')
                cflags += '-DCC_AVX512VL_SUPPORT'

	endif
endif
