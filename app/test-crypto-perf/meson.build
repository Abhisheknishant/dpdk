# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

allow_experimental_apis = true
sources = files('cperf_ops.c',
		'cperf_options_parsing.c',
		'cperf_test_common.c',
		'cperf_test_latency.c',
		'cperf_test_pmd_cyclecount.c',
		'cperf_test_throughput.c',
		'cperf_test_vector_parsing.c',
		'cperf_test_vectors.c',
		'cperf_test_verify.c',
		'main.c')
deps += ['cryptodev', 'security']
#deps += ['cryptodev', 'security', 'rawdev', 'common_multi_fn']

if dpdk_conf.has('RTE_LIBRTE_MULTI_FN_COMMON') and dpdk_conf.has('RTE_LIBRTE_PMD_AESNI_MB_RAWDEV')
	deps += ['rawdev', 'common_multi_fn']
	cflags += ['-DMULTI_FN_SUPPORTED']
endif
