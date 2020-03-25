# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

extra_flags = []

foreach flag: extra_flags
	if cc.has_argument(flag)
		cflags += flag
	endif
endforeach

sources = files('rte_mempool.c', 'rte_mempool_ops.c',
		'rte_mempool_ops_default.c', 'mempool_trace_points.c')
headers = files('rte_mempool.h', 'rte_trace_mempool.h',
		'rte_trace_mempool_fp.h')
deps += ['ring']

# memseg walk is not yet part of stable API
allow_experimental_apis = true
