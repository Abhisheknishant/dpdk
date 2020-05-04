# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2020 Marvell International Ltd.

# Currently only implemented on Linux
if not is_linux
	build = false
	reason = 'only supported on linux'
endif

version = 1
allow_experimental_apis = true

deps += ['ethdev']
sources = files('if_proxy_common.c')
headers = files('rte_if_proxy.h')

if is_linux
	sources += files('linux/if_proxy.c')
endif
