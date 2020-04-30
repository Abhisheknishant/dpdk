# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Mellanox Technologies, Ltd

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'
name = 'flow_perf'
allow_experimental_apis = true
cflags += '-Wno-deprecated-declarations'
cflags += '-Wunused-function'

sources = files(
	'actions_gen.c',
	'flow_gen.c',
	'items_gen.c',
	'main.c',
)
deps += ['ethdev']
