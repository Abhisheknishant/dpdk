# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

subdirs = ['igb_uio', 'kni']

# if we are cross-compiling we need kernel_version specified
if get_option('kernel_version') == '' and meson.is_cross_build()
	warning('Need "kernel_version" option for kmod compilation when cross-compiling')
	subdir_done()
endif

kernel_version = get_option('kernel_version')
if kernel_version == ''
	# use default version for native builds
	kernel_version = run_command('uname', '-r').stdout().strip()
endif

kernel_dir = '/lib/modules/' + kernel_version + '/build'
kernel_install_dir = '/lib/modules/' + kernel_version

# test running make in kernel directory, using "make kernelversion"
make_returncode = run_command('make', '-sC', kernel_dir,
		'kernelversion').returncode()
if make_returncode != 0
	warning('Cannot compile kernel modules as requested - are kernel headers installed?')
	subdir_done()
endif

# DO ACTUAL MODULE BUILDING
foreach d:subdirs
	subdir(d)
endforeach
