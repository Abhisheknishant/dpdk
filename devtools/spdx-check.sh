#! /bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019 Microsoft Corporation
#
# Produce a list of files with incorrect license
# information

echo "Files without SPDX License"
echo "--------------------------"

git grep -L SPDX-License-Identifier -- \
    ':^.git*' ':^.ci/*' ':^.travis.yml' \
    ':^README' ':^MAINTAINERS' ':^VERSION' ':^ABI_VERSION' \
    ':^*/Kbuild' ':^*/README' \
    ':^license/' ':^doc/' ':^config/' ':^buildtools/' \
    ':^*.cocci' ':^*.abignore' \
    ':^*.def' ':^*.map' ':^*.ini' ':^*.data' ':^*.cfg' ':^*.txt'

echo
echo "Files with additional license text"
echo "----------------------------------"

git grep -l Redistribution -- \
    ':^license/' ':^/devtools/spdx-check.sh'
