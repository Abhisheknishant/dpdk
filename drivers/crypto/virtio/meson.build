# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 HUAWEI TECHNOLOGIES CO., LTD.

includes += include_directories('../../../lib/librte_vhost')
deps += 'bus_pci'
name = 'virtio_crypto'
allow_experimental_apis = true
sources = files('virtio_cryptodev.c', 'virtio_pci.c',
		'virtio_rxtx.c', 'virtqueue.c')
