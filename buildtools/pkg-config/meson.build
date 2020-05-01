# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Intel Corporation

pkg = import('pkgconfig')
pkg_extra_cflags = ['-include', 'rte_config.h'] + machine_args
if is_freebsd
	pkg_extra_cflags += ['-D__BSD_VISIBLE']
endif

# When calling pkg-config --static --libs, pkg-config will always output the
# regular libs first, and then the extra libs from libraries.private field,
# since the assumption is that those are additional dependencies for building
# statically that the .a files depend upon. However, for DPDK, we only link
# the driver files for static builds, and those need to come *before* the
# regular libraries. To get this result, we need two pkgconfig files for DPDK,
# one for the shared libs, and a second for the static libs and drivers, which
# depends upon the first. Using a dependency means that the shared libs are
# printed only after the libraries.private field rather than before.
pkg.generate(name: 'dpdk-libs',
	filebase: 'libdpdk-libs',
	description: '''Internal-only DPDK pkgconfig file. Not for direct use.
Use libdpdk.pc instead of this file to query DPDK compile/link arguments''',
	version: meson.project_version(),
	subdirs: [get_option('include_subdir_arch'), '.'],
	extra_cflags: pkg_extra_cflags,
	libraries: ['-Wl,--as-needed'] + dpdk_libraries,
	libraries_private: dpdk_extra_ldflags)

pkg.generate(name: 'DPDK', # main DPDK pkgconfig file
	filebase: 'libdpdk',
	version: meson.project_version(),
	description: '''The Data Plane Development Kit (DPDK).
Note that CFLAGS might contain an -march flag higher than typical baseline.
This is required for a number of static inline functions in the public headers.''',
	requires: ['libdpdk-libs', libbsd], # may need libbsd for string funcs
	                  # if libbsd is not enabled, then this is blank
	libraries_private: ['-Wl,--whole-archive'] +
			dpdk_drivers + dpdk_static_libraries +
			['-Wl,--no-whole-archive']
)

# the pkg-config file generated is not best tuned for static linking so
# use a script to adjust the linker flags
run_command(py3, 'set-static-linker-flags.py', check: true)
