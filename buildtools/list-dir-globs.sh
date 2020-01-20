#! /usr/bin/env python
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Intel Corporation

from __future__ import print_function
from os import chdir, environ
from sys import argv
from glob import iglob # glob iterator
from os.path import isdir, join

chdir(join(environ['MESON_SOURCE_ROOT'], environ['MESON_SUBDIR']))
dirs = []
for path in argv[1].split(','):
  dirs.extend([entry for entry in iglob(path) if isdir(entry)])
print(",".join(dirs))
