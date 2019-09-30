#!/usr/bin/env python
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019 Intel Corporation

from __future__ import print_function
import sys
import argparse
import re

def setup_options():
    arg_parser = argparse.ArgumentParser(description='Update default bind symbol abi version.')
    arg_parser.add_argument('map_file', metavar='map_file', type=str, nargs=1,
                    help='path to source file (pattern: *.c)')
    arg_parser.add_argument('dst_abi_version', metavar='dst_abi_version', type=str, nargs=1,
                    help='target ABI version (pattern: DPDK_*)')
    arg_parser.add_argument('-v', '--verbose', action='store_true', help='print changes')

    return arg_parser.parse_args()

def replace_abi(f_in, abi_version_number, verbose):
    source_file_content = []

    for ln_no, ln in enumerate(f_in, 1):
            if re.search("^BIND_DEFAULT_SYMBOL\(.*", ln):
                source_file_content += [re.sub(", [0-9]{1,2}\.[0-9]{1,2}\);$", ", " + abi_version_number + ");", ln)]
                if verbose:
                    print(f_in.name + ":" + str(ln_no) + ": " + ln[:-1] + " -> " + source_file_content[-1][:-1])
            elif re.search("^VERSION_SYMBOL\(.*", ln):
                if verbose:
                    print(f_in.name + ":" + str(ln_no) + ": " + ln[:-1] + " -> " + "[DELETED]")
            else:
                source_file_content += [ln]

    return source_file_content

def main(args):
    params = setup_options()

    if not params.map_file[0].endswith('.c') or \
            not params.dst_abi_version[0].startswith('DPDK_'):
        print('Wrong pattern for input files!\n')
        arg_parser.print_help()
        return 1

    abi_version_number = params.dst_abi_version[0][5:]
    source_file_content = []

    with open(params.map_file[0]) as f_in:
        source_file_content = replace_abi(f_in, abi_version_number, params.verbose)

    with open(params.map_file[0], 'w') as f_out:
        f_out.writelines(source_file_content)

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
