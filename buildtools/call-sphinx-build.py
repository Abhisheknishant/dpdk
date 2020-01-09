#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019 Intel Corporation
#

import sys
import os
from os.path import join
from subprocess import run

(sphinx, src, dst) = sys.argv[1:]  # assign parameters to variables

# find all the files sphinx will process so we can write them as dependencies
srcfiles = []
for root, dirs, files in os.walk(src):
    srcfiles.extend([join(root, f) for f in files])

# run sphinx, putting the html output in a "html" directory
run([sphinx, '-j', 'auto', '-b', 'html', src, join(dst, 'html')], check=True)

# create a gcc format .d file giving all the dependencies of this doc build
with open(join(dst, '.html.d'), 'w') as d:
    d.write('html: ' + ' '.join(srcfiles) + '\n')
