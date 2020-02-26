#! /bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020 Microsoft Corporation
#
# Produce a list of files with incorrect license tags

print_usage () {
    echo "usage: $(basename $0) [-q] [-v]"
    exit 1
}

check_spdx() {
    if  $verbose;  then
	echo "Files without SPDX License"
	echo "--------------------------"
    fi
    git grep -L SPDX-License-Identifier -- \
	':^.git*' ':^.ci/*' ':^.travis.yml' \
	':^README' ':^MAINTAINERS' ':^VERSION' ':^ABI_VERSION' \
	':^*/Kbuild' ':^*/README' \
	':^license/' ':^doc/' ':^config/' ':^buildtools/' \
	':^*.cocci' ':^*.abignore' \
	':^*.def' ':^*.map' ':^*.ini' ':^*.data' ':^*.cfg' ':^*.txt' \
	> $tmpfile

    errors=0
    while read -r line
    do $quiet || echo $line
       errors=$((errors + 1))
    done < $tmpfile
}

check_boilerplate() {
    if $verbose ; then
	echo
	echo "Files with redundant license text"
	echo "---------------------------------"
    fi

    git grep -l Redistribution -- \
	':^license/' ':^/devtools/check-spdx-tag.sh' > $tmpfile

    warnings=0
    while read -r line
    do $quiet || echo $line
       warnings=$((warnings + 1))
    done < $tmpfile
}

quiet=false
verbose=false

while getopts qvh ARG ; do
	case $ARG in
		q ) quiet=true ;;
		v ) verbose=true ;;
		h ) print_usage ; exit 0 ;;
		? ) print_usage ; exit 1 ;;
	esac
done
shift $(($OPTIND - 1))

tmpfile=$(mktemp)
trap 'rm -f -- "$tmpfile"' INT TERM HUP EXIT

check_spdx
$quiet || echo

check_boilerplate

$quiet || echo
echo "total: $errors errors, $warnings warnings"
exit $errors
