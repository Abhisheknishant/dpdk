#! /bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020 Mellanox Technologies, Ltd

if [ "$(uname)" = "Linux" ] ; then
	cat /proc/sys/vm/nr_hugepages || echo 0
else
	echo 0
fi
