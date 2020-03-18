# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018 NXP

if not is_linux
	build = false
	reason = 'only supported on linux'
endif

allow_experimental_apis = true
deps += ['common_dpaax']
sources = files('enetc_ethdev.c',
		'enetc_rxtx.c')

includes += include_directories('base')
