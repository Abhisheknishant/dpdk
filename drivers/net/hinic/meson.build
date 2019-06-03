# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Huawei Technologies Co., Ltd

subdir('base')
objs = [base_objs]

sources = files(
	'hinic_pmd_dpdev.c',
	'hinic_pmd_ethdev.c',
	'hinic_pmd_rx.c',
#	'hinic_pmd_tx.c'
	)

deps += 'ethdev'
deps += 'pci'
deps += 'hash'

includes += include_directories('base')
