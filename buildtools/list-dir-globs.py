#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Intel Corporation

import sys
import os
from glob import iglob
from os.path import join, relpath, isdir

if len(sys.argv) != 2:
  print("Usage: {0} <path-glob>[,<path-glob>[,...]]".format(sys.argv[0]))
  sys.exit(1)

root = '.'
if 'MESON_SOURCE_ROOT' in os.environ and 'MESON_SUBDIR' in os.environ:
  root = join(os.environ['MESON_SOURCE_ROOT'], os.environ['MESON_SUBDIR'])

for path in sys.argv[1].split(','):
  for p in iglob(join(root, path)):
    if isdir(p):
      print(relpath(p))
