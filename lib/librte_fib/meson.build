# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
# Copyright(c) 2019 Intel Corporation

sources = files('rte_fib.c', 'rte_fib6.c', 'dir24_8.c', 'trie.c')
headers = files('rte_fib.h', 'rte_fib6.h')
deps += ['rib']

if dpdk_conf.has('RTE_ARCH_X86')
	if cc.has_argument('-mavx512f')
		cflags += '-DCC_AVX512_SUPPORT'
		cflags += '-mavx512f'
	endif
	if cc.has_argument('-mavx512dq')
		cflags += '-mavx512dq'
	endif
	if cc.has_argument('-mavx512bw')
		cflags += '-mavx512bw'
	endif
endif
