#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019 Intel Corporation

abi_version=""
abi_version_file="./config/ABI_VERSION"
update_path="lib drivers"

if [ -z "$1" ]
then
      echo "\$provide ABI version"
fi

abi_version=$1
abi_version_with_prefix="DPDK_$abi_version"

if [ -n "$2" ]
then
      abi_version_file=$2
fi

if [ -n "$3" ]
then
      update_path=${@:3}
fi

echo "New ABI version:" $abi_version
echo "ABI_VERSION path:" $abi_version_file
echo "Path to update:" $update_path

echo $abi_version > $abi_version_file

grep --binary-files=without-match --recursive --files-with-matches \
--max-count=1 --include \*.c 'BIND_DEFAULT_SYMBOL\|VERSION_SYMBOL' \
$update_path | xargs --max-lines=1 --verbose -I {} \
./buildtools/update_default_symbol_abi.py {} \
$abi_version_with_prefix

find $update_path -name  \*version.map -exec \
./buildtools/update_version_map_abi.py {} \
$abi_version_with_prefix \; -print
