#!/usr/bin/env python
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019 Intel Corporation

from __future__ import print_function
import sys
import argparse

def setup_options():
    arg_parser = argparse.ArgumentParser(description='Merge versions in linker version script.')
    arg_parser.add_argument("map_file", metavar='map_file', type=str, nargs=1,
                    help='path to linker version script file (pattern: *version.map)')
    arg_parser.add_argument("dst_abi_version", metavar='dst_abi_version', type=str, nargs=1,
                    help='target ABI version (pattern: DPDK_*)')
    arg_parser.add_argument("src_abi_version", metavar='src_abi_version', default="DPDK_", type=str, nargs='?',
                    help='source ABI version (pattern: DPDK_*, default: DPDK_)')
    arg_parser.add_argument('-v', '--verbose', action='store_true', help='print changes')

    return arg_parser.parse_args()

def is_function_line(ln):
    return ln.startswith('\t') and ln.endswith(';\n') and ":" not in ln

def is_dpdk_version_start_line(ln, src_abi_version):
    return ln.startswith(src_abi_version) and ln.endswith('{\n') and ":" not in ln

def is_experimental_version_start_line(ln):
    return ln.startswith('EXPERIMENTAL {') and ln.endswith('\n') and ":" not in ln

def is_version_end_line(ln):
    return ln.startswith('}') and ln.endswith(';\n') and ":" not in ln

def is_global_line(ln):
    return ln.startswith('\tglobal:') and ln.endswith('\n')

def is_local_line(ln):
    return ln.startswith('\tlocal: ') and ln.endswith(';\n')

def store_functions(f_in):
    functions = []
    local_line = []

    for line in f_in:
        if is_version_end_line(line): break
        elif is_local_line(line):
            local_line = [line]
        elif is_function_line(line): functions += [line]

    return functions, local_line

def parse_linker_version_map_file(f_in, src_abi_version):
    dpdk_functions = []
    experimental_functions = []
    dpdk_local_line = []
    experimental_local_line = []

    for line in f_in:
        if is_dpdk_version_start_line(line, src_abi_version):
            dpdk_functions_tmp, dpdk_local_line_tmp = store_functions(f_in)
            dpdk_functions += dpdk_functions_tmp
            dpdk_local_line = dpdk_local_line_tmp if len(dpdk_local_line_tmp) > 0 else dpdk_local_line
        elif is_experimental_version_start_line(line):
            experimental_functions_tmp, experimental_local_line_tmp = store_functions(f_in)
            experimental_functions += experimental_functions_tmp
            experimental_local_line += experimental_local_line_tmp

    return list(set(dpdk_functions)), list(set(experimental_functions)), list(set(dpdk_local_line)), list(set(experimental_local_line))

def main(args):
    params = setup_options()

    if not params.map_file[0].endswith('version.map') or \
            not params.dst_abi_version[0].startswith('DPDK_'):
        print('Wrong pattern for input files!\n')
        arg_parser.print_help()
        return 1

    dpdk_functions = []
    experimental_functions = []
    dpdk_local_line = []
    experimental_local_line = []

    with open(params.map_file[0]) as f_in:
        dpdk_functions, experimental_functions, dpdk_local_line, experimental_local_line = parse_linker_version_map_file(f_in, params.src_abi_version)

    dpdk_functions.sort()
    experimental_functions.sort()

    with open(params.map_file[0], 'w') as f_out:
        if len(dpdk_functions) > 0:
            dpdk_functions = params.dst_abi_version + [" {\n"] + ["\tglobal:\n\n"] + dpdk_functions + dpdk_local_line + ["};\n\n"]
            if params.verbose:
                print(*dpdk_functions)
            f_out.writelines(dpdk_functions)
        elif len(dpdk_local_line) > 0:
            dpdk_functions = params.dst_abi_version + [" {\n"] + ["\n\tlocal: *;\n};\n"]
            if params.verbose:
                print(*dpdk_functions)
            f_out.writelines(dpdk_functions)

        if len(experimental_functions) > 0:
            experimental_functions = ["EXPERIMENTAL" + " {\n"] + ["\tglobal:\n\n"] + experimental_functions + experimental_local_line + ["};\n"]
            if params.verbose:
                print(*experimental_functions)
            f_out.writelines(experimental_functions)

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
