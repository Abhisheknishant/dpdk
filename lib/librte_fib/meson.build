# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
# Copyright(c) 2019 Intel Corporation

sources = files('rte_fib.c', 'rte_fib6.c', 'dir24_8.c', 'trie.c')
headers = files('rte_fib.h', 'rte_fib6.h')
deps += ['rib']

if dpdk_conf.has('RTE_ARCH_X86') and cc.has_argument('-mavx512f')
	if cc.has_argument('-mavx512dq')
		dir24_8_avx512_tmp = static_library('dir24_8_avx512_tmp',
			'dir24_8_avx512.c',
			dependencies: static_rte_eal,
			c_args: cflags + ['-mavx512f'] + ['-mavx512dq'])
		objs += dir24_8_avx512_tmp.extract_objects('dir24_8_avx512.c')
		cflags += '-DCC_DIR24_8_AVX512_SUPPORT'
	endif
endif
