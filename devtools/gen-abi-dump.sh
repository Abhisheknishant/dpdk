#!/bin/sh

builddir=$1

if [ -z "$builddir" ] ; then
	echo "Usage: $(basename $0) build_dir"
	exit 1
fi

if [ ! -d "$builddir" ] ; then
	echo "Error: build directory, '$builddir', doesn't exist"
	exit 1
fi

for d in lib drivers ; do
	mkdir -p $d/abi

	for f in $builddir/$d/*.so* ; do
		test -L "$f" && continue

		libname=$(basename $f)
		abidw --out-file $d/abi/${libname%.so*}.dump $f || exit 1
	done
done
