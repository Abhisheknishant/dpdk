#! /bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019 Microsoft Corporation
#
# Produce a list of files without SPDX license identifiers

echo "Files without SPDX License"
echo "--------------------------"

git grep -L SPDX-License-Identifier -- \
    ':^.git*' ':^.ci/*' ':^.travis.yml' \
    ':^README' ':^MAINTAINERS' ':^VERSION' \
    ':^*/Kbuild' ':^*/README' \
    ':^license/' ':^doc/' ':^config/' ':^buildtools/' \
    ':^*.def' ':^*.map' ':^*.ini' ':^*.data' ':^*.cfg' ':^*.txt'

echo
echo "Files with redundant BSD boilerplate"
echo "------------------------------------"

git grep -l SPDX-License-Identifier | \
    xargs grep -l 'Redistribution'
