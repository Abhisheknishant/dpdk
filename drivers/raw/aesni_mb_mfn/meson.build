# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Intel Corporation.

IMB_required_ver = '0.54'
lib = cc.find_library('IPSec_MB', required: false)
if not lib.found()
	build = false
	reason = 'missing dependency, "libIPSec_MB"'
else
	ext_deps += lib

	# version comes with quotes, so we split based on " and take the middle
	imb_ver = cc.get_define('IMB_VERSION_STR',
		prefix : '#include<intel-ipsec-mb.h>').split('"')[1]

	if (imb_ver == '') or (imb_ver.version_compare('<' + IMB_required_ver))
		reason = 'IPSec_MB version >= @0@ is required, found version @1@'.format(
				IMB_required_ver, imb_ver)
		build = false
	endif

endif

sources = files('aesni_mb_mfn_rawdev.c', 'aesni_mb_mfn_rawdev_test.c')
allow_experimental_apis = true
deps += ['bus_vdev', 'net', 'rawdev', 'cryptodev', 'common_multi_fn']
