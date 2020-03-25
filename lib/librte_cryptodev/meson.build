# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017-2019 Intel Corporation

allow_experimental_apis = true
sources = files('rte_cryptodev.c', 'rte_cryptodev_pmd.c',
	'cryptodev_trace_points.c')
headers = files('rte_cryptodev.h',
	'rte_cryptodev_pmd.h',
	'rte_crypto.h',
	'rte_crypto_sym.h',
	'rte_crypto_asym.h',
	'rte_trace_cryptodev.h',
	'rte_trace_cryptodev_fp.h')
deps += ['kvargs', 'mbuf']
