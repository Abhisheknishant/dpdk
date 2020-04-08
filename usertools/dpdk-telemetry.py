#! /usr/bin/python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Intel Corporation

import socket
import os
import glob
import json

telemetry_version = "v2"

def read_socket(buf_len):
    reply = fd.recv(buf_len).decode()
    try:
        print(json.dumps(json.loads(reply)))
        return json.loads(reply)
    except:
            print("Error in reply: ", reply)
            raise

def handle_socket(path):
    print("Connecting to " + path)
    try:
        fd.connect(path)
    except OSError:
        return
    json_reply = read_socket(1024)
    output_buf_len = json_reply["max_output_len"]
    text = input('--> ').strip()
    while (text != "quit"):
        if text.startswith('/'):
            fd.send(text.encode())
            read_socket(output_buf_len)
        text = input('--> ').strip()

    fd.close()

fd = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
# Path to sockets for processes run as a root user
for f in glob.glob('/var/run/dpdk/*/dpdk_telemetry.%s' % telemetry_version):
  handle_socket(f)
# Path to sockets for processes run as a regular user
for f in glob.glob('/run/user/%d/dpdk/*/dpdk_telemetry.%s' % (os.getuid(), telemetry_version)):
  handle_socket(f)
