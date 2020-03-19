# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

includes = [global_inc]
includes += include_directories('../librte_eal/common/include/arch/' + arch_subdir)

sources = files('telemetry.c', 'telemetry_legacy.c')
headers = files('rte_telemetry.h')
cflags += '-DALLOW_EXPERIMENTAL_API'
includes += include_directories('../librte_metrics')
