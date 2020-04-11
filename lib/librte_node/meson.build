# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2020 Marvell International Ltd.

sources = files('null.c', 'log.c')
allow_experimental_apis = true
# Strict-aliasing rules are violated by uint8_t[] to context size casts.
cflags += '-fno-strict-aliasing'
deps += ['graph']
