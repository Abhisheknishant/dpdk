# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2019 NXP

if host_machine.system() != 'linux'
	build = false
endif
deps += ['bus_dpaa']

sources = files('ppfe_ethdev.c')

includes += include_directories('../../bus/dpaa/include/')
