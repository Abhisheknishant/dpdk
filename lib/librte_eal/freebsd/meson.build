# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

includes += include_directories('include')

headers += files(
		'include/rte_os.h',
)

sources += files('eal_alarm.c',
		'eal_cpuflags.c',
		'eal_debug.c',
		'eal_hugepage_info.c',
		'eal_interrupts.c',
		'eal_lcore.c',
		'eal_memalloc.c',
		'eal_thread.c',
		'eal_timer.c',
		'eal.c',
		'eal_memory.c',
		'eal_dev.c'
)

deps += ['kvargs']
