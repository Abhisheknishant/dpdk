#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019 Intel Corporation
#

import sys
import os
import os.path
import subprocess

sphinx = sys.argv[1]
src = sys.argv[2]
dst = sys.argv[3]
depfile = os.path.join(dst,'.html.d')

# find all the files sphinx will process so we can write them as dependencies
srcfiles = []
for root, dirs, files in os.walk(src):
    for f in files:
        srcfiles.append(os.path.join(root, f))

# run sphinx, putting the html output in a "html" directory
subprocess.run([sphinx, '-j', 'auto', '-b', 'html', src,
                os.path.join(dst, 'html')], check = True)

# create a gcc format .d file giving all the dependencies of this doc build
with open(depfile, 'w') as d:
    d.write('html: ' + ' '.join(srcfiles) + '\n')
subprocess.run(['cp', '-f', depfile, '/tmp'])
