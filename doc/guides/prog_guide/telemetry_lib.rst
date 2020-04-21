..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2020 Intel Corporation.

.. _telemetry_library:


Telemetry Library
=================

The Telemetry library provides an interface to retrieve information from a
variety of DPDK libraries. The library provides this information via socket
connection, taking requests from a connected client and replying with the JSON
response containing the requested telemetry information.

Telemetry is enabled to run by default when running a DPDK application, and the
telemetry information from enabled libraries is made available. Libraries are
responsible for registering their own commands, and providing the callback
function that will format the library specific stats into the correct JSON
response format, when requested.


Registering Commands
--------------------

Libraries and applications must register commands to make their information
available via the Telemetry library. This involves providing a string command
in the required format ("/library/command"), and the callback function that
will handle formatting the information when required. An example showing ethdev
commands being registered is shown below:

.. code-block:: c

    rte_telemetry_register_cmd("/ethdev/list", handle_port_list);
    rte_telemetry_register_cmd("/ethdev/xstats", handle_port_xstats);


Formatting JSON response
------------------------

The callback function provided by the library must format its telemetry
information in a valid JSON format. The Telemetry library provides a JSON
utilities API to build up the response. In the event of the output buffer being
too small to hold the telemetry information in full, the API functions maintain
correct JSON formatting regardless. For example, the ethdev library provides a
list of available ethdev ports in a JSON response, constructed using the
following functions to build up the list:

.. code-block:: c

    used = rte_tel_json_empty_array(buffer, buf_len, used);
    RTE_ETH_FOREACH_DEV(port_id)
        used = rte_tel_json_add_array_int(buffer, buf_len, used, port_id);

The resulting response that is returned to the client shows the list of ports
constructed above by the handler function in ethdev:

.. code-block:: console

    {"/ethdev/list": [0, 1]}

For more information on the range of JSON functions available in the API,
please refer to the docs.
