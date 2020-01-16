#! /bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020 Mellanox Technologies, Ltd
#
# Convert pkg-config link options for static linkage.
#
# Static flavour of provided libs are explicitly picked,
# thanks to the syntax -l:libfoo.a
# Other libs (dependencies) are unchanged, i.e. linked dynamically by default.
#
# Syntax: pkg-config-static.sh <libname>
#
# PKG_CONFIG_PATH may be required to be set if the .pc file is not installed.

ldflags=$(pkg-config --libs --static $1 | tr '[:space:]' '\n')
dir=$(echo "$ldflags" | sed -rn 's,^-L(.*),\1,p' | head -n1)
IFS='
'
for arg in $ldflags ; do
	prefix=$(echo $arg | sed -rn 's/^(-Wl,).*/\1/p')
	option=$(echo $arg | sed -rn "s/^$prefix-(.*=|.*,|.).*/\1/p")
	[ "$option" = 'l' -o "$option" = 'L' ] || continue
	value=$(echo $arg | sed "s/^$prefix-$option//")
	staticlib="lib$value.a"
	printf -- -$option
	if [ -f $dir/$staticlib ] ; then
		echo :$staticlib
	else
		echo $value
	fi
done | tr '\n' ' '
