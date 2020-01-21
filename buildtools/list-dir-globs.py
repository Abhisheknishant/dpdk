#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Intel Corporation

import sys
import os
from glob import iglob # glob iterator
from os.path import join, relpath, isdir

root = join(os.environ['MESON_SOURCE_ROOT'], os.environ['MESON_SUBDIR'])
for path in sys.argv[1].split(','):
  relpaths = [relpath(p, root) for p in iglob(join(root, path)) if isdir(p)]
  print("\n".join(relpaths))
