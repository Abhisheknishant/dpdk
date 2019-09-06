# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2019 Marvell International Ltd.

mkfile = custom_target('vfio_pf_makefile',
	output: 'Makefile',
	command: ['touch', '@OUTPUT@'])

custom_target('vfio_pf',
	input: ['vfio_pf.c', 'Kbuild'],
	output: 'vfio_pf.ko',
	command: ['make', '-C', kernel_dir + '/build',
		'M=' + meson.current_build_dir(),
		'src=' + meson.current_source_dir(),
		'EXTRA_CFLAGS=-I' + meson.current_source_dir() +
			'/../../../lib/librte_eal/common/include',
		'modules'],
	depends: mkfile,
	install: true,
	install_dir: kernel_dir + '/extra/dpdk',
	build_by_default: get_option('enable_kmods'))
