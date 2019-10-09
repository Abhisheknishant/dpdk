# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017-2018 Intel Corporation

if not is_linux
	build = false
	reason = 'only supported on linux'
endif
if has_libnuma == 1
	dpdk_conf.set10('RTE_LIBRTE_VHOST_NUMA', true)
endif
if (toolchain == 'gcc' and cc.version().version_compare('>=8.3.0'))
	cflags += '-DSUPPORT_GCC_UNROLL_PRAGMA'
elif (toolchain == 'clang' and cc.version().version_compare('>=3.7.0'))
	cflags += '-DSUPPORT_CLANG_UNROLL_PRAGMA'
elif (toolchain == 'icc' and cc.version().version_compare('>=16.0.0'))
	cflags += '-DSUPPORT_ICC_UNROLL_PRAGMA'
endif
r = run_command(toolchain, '-march=native', '-dM', '-E', '-', '</dev/null', '|', 'grep AVX512F')
if (r.stdout().strip() != '')
	cflags += '-DDISABLE_SWPREFETCH'
endif
dpdk_conf.set('RTE_LIBRTE_VHOST_POSTCOPY',
	      cc.has_header('linux/userfaultfd.h'))
version = 4
allow_experimental_apis = true
cflags += '-fno-strict-aliasing'
sources = files('fd_man.c', 'iotlb.c', 'socket.c', 'vdpa.c',
		'vhost.c', 'vhost_user.c',
		'virtio_net.c', 'vhost_crypto.c')
headers = files('rte_vhost.h', 'rte_vdpa.h', 'rte_vhost_crypto.h')
deps += ['ethdev', 'cryptodev', 'hash', 'pci']
