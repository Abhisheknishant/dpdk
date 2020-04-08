# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

includes = [global_inc]

sources = files('telemetry.c', 'telemetry_legacy.c')
headers = files('rte_telemetry.h', 'rte_telemetry_json.h')
cflags += '-DALLOW_EXPERIMENTAL_API'
includes += include_directories('../librte_metrics')
