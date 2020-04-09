#! /bin/sh -e
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020 Mellanox Technologies, Ltd

linux_hugepages_number=/proc/sys/vm/nr_hugepages

if [ -r "$linux_hugepages_number" ] ; then
	cat /proc/sys/vm/nr_hugepages
else
	echo 0
fi
