..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(C) 2020 Marvell International Ltd.

Trace Library
=============

DPDK provides a tracing library that gives the ability to add tracepoints
in application to get runtime trace/debug information for control and fast
APIs with minimum impact on fast path performance. Typical trace overhead is
~20 cycles and instrumentation overhead is 1 cycle.

Library mainly caters below mentioned use cases:

- The DPDK provider will not have access to the DPDK customer applications.
  Inbuilt tracer support will us enable to debug/analyze the slow path and
  fast path DPDK API usage.

- Provides a low overhead fast path multi-core PMD driver's debugging/analysis
  infrastructure to fix the functional and performance issue(s).

- Post trace analysis tools can provide various status across the system such
  as cpu_idle() using the timestamp added in the trace.

Below sections will provide detailed information about:

 - Trace a user application
 - View and analyze the recorded events

Trace a user application
------------------------

This section steps you through a simple example to trace an application.
A trace can be achieved using below mentioned steps:

Define and register a tracepoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The application can define and register tracepoints either existing C file or
create a new file (say xyz_app_trace_point.c). Also, all the tracepoints must be
resolved before rte_eal_init i.e. tracepoints must be registered as constructor
using RTE_INIT interface.

Following are the MACRO definition exposed by the trace Library to define and
register a tracepoint.

.. code-block:: c

 #define RTE_TRACE_POINT_DEFINE(tp)\
        uint64_t __attribute__((section("__rte_trace_point"))) __##tp

 #define RTE_TRACE_POINT_REGISTER(trace, name, level)\
       __rte_trace_point_register(&__##trace, RTE_STR(name), RTE_LOG_ ## level,\
                                  (void (*)(void)) trace)

Example tracepoint definition and registration

.. code-block:: c

 RTE_TRACE_POINT_DEFINE(rte_trace_lib_eal_generic_str); /* Definition */

 RTE_INIT(eal_trace_init)
 {
     /* Registration */
     RTE_TRACE_POINT_REGISTER(rte_trace_lib_eal_generic_str,
                              lib.eal.generic.str, INFO);
 }

For more details refer trace API documentation.
Defined tracepoint must be exported into corresponding .map file.

.. Note::

    A tracepoint is defined like __##tp i.e. __rte_trace_lib_eal_generic_str
    for above example. Same must be updated into corresponding .map file.

Define trace function to write events
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
After a successful tracepoint registration, the application must define a
trace function which solves three purposes:

 - Calculates the size of the event.
 - Generate CTF metadata field string for the event.
 - Emit the event to trace memory.

A tracepoint can be classified as either a data path or a slow path tracepoint.
So based on that, the application must define tracepoint function using one of
the mentioned MACRO

.. code-block:: c

 /* Define tracepoint function for slow path */
 #define RTE_TRACE_POINT(tp, args, ...)\
        __RTE_TRACE_POINT(generic, tp, args, __VA_ARGS__)

 /* Define tracepoint function for data path */
 #define RTE_TRACE_POINT_DP(tp, args, ...)\
        __RTE_TRACE_POINT(dp, tp, args, __VA_ARGS__)

RTE_TRACE_POINT_DP is compiled out by default and can be enabled using
CONFIG_RTE_ENABLE_TRACE_DP configuration parameter. Also application can use
``rte_trace_is_dp_enabled`` to get current status of RTE_TRACE_POINT_DP.
For more details, refer DPDK Trace API documentation.

Example tracepoint function definition

.. code-block:: c

 /* Slow path tracepoint */
 RTE_TRACE_POINT(
        rte_trace_lib_eal_generic_str,
        RTE_TRACE_POINT_ARGS(const char *str),
        rte_trace_ctf_string(str);
 )

 /* Data path tracepoint */
 RTE_TRACE_POINT_DP(
        rte_trace_lib_eal_generic_str,
        RTE_TRACE_POINT_ARGS(const char *str),
        rte_trace_ctf_string(str);
 )

Emit events to trace memory
~~~~~~~~~~~~~~~~~~~~~~~~~~~
After trace function definition is ready to emit tracepoints.
To emit the event application needs to invoke tracepoint function, as defined
in the above steps, at the desired location.

Below examples emit tracepoints in ``rte_eth_dev_configure`` to print a test
string:

.. code-block:: c

 int
 rte_eth_dev_configure(uint16_t port_id, uint16_t nb_rx_q, uint16_t nb_tx_q,
        const struct rte_eth_conf *dev_conf)
 {
        struct rte_eth_dev *dev;
        struct rte_eth_dev_info dev_info;
        struct rte_eth_conf orig_conf;
        int diag;
        int ret;

        RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -EINVAL);

        dev = &rte_eth_devices[port_id];

        RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->dev_configure, -ENOTSUP);

        ...

        rte_trace_lib_eal_generic_str("tp_test_string");
        return ret;
 }

Generate CTF formatted metadata
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
As of now emitted events just specify the debug information written by the
application but to view/analyze these events must be formatted into Common Trace
Format(CTF) so that any CTF compliant trace analysis tool can view those traces.

Trace library exposes below API to write events to CTF formatted metadata file.

.. code-block:: c

 int rte_trace_save(void);

Currently library invokes this API implicitly during tear down and metadata file
is generated at either ``/root/dpdk-traces/rte-yyyy-mm-dd-[AP]M-hh-mm-ss/`` or
at location if user has passed during command line(``say /tmp``) then
``/tmp/rte-yyyy-mm-dd-[AP]M-hh-mm-ss/``

For more information, refer :doc:`../linux_gsg/linux_eal_parameters` for trace.

View and analyze the recorded events
------------------------------------
Once ``Trace a user application`` is completed, the user can view/inspect the
recorded events.

There are many tools you can use to read DPDK traces:

 - ``babeltrace`` is a command-line utility that converts trace formats; it
   supports the format that DPDK trace library produces, CTF, as well as a
   basic text output that can be grep ed. The babeltrace command is part of the
   opensource ``Babeltrace`` project.

 - ``Trace Compass`` is a graphical user interface for viewing and analyzing any
   type of logs or traces, including DPDK traces.

.. Note::

   This section assumes that the trace library saved the traces, it recorded
   during the previous tutorials, to their specified location.


Use the babeltrace command-line tool
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The simplest way to list all the recorded events of a trace is to pass its path
to babeltrace with no options::

    babeltrace </path-to-trace-events/rte-yyyy-mm-dd-[AP]M-hh-mm-ss/>

``babeltrace`` finds all traces recursively within the given path and prints all
their events, merging them in chronological order.

You can pipe the output of the babeltrace into a tool like grep(1) for further
filtering. Below example grep the events for ``ethdev`` only::

    babeltrace /tmp/my-dpdk-trace | grep ethdev

You can pipe the output of babeltrace into a tool like wc(1) to count the
recorded events. Below example count the number of ``ethdev`` events::

    babeltrace /tmp/my-dpdk-trace | grep ethdev | wc --lines

Use the tracecompass GUI tool
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
``Tracecompass`` is another tool to view/analyze the DPDK traces which gives
a graphical view of events. Like ``babeltrace``, tracecompass also provides
an interface to search for a particular event. To use ``tracecompass``, following are
the minimum required steps:

 - Install ``tracecompass`` to the localhost. Variants are available for Linux,
   Windows, and OS-X.
 - Launch ``tracecompass`` which will open a graphical window with trace
   management interfaces.
 - Open a trace using ``File->Open Trace`` option and select metadata file
   which is to be viewed/analyzed.

For more details, refer `Trace Compass <https://www.eclipse.org/tracecompass/>`_

Core Concepts
-------------
As DPDK trace library is designed to generate traces that uses Common Trace
Format(CTF). CTF specification consist of following units to create a trace.

 - ``Stream`` Sequence of packets.
 - ``Packet`` Header and one or more events.
 - ``Event`` Header and payload.

For detailed information, refer `Common Trace Format <https://diamon.org/ctf/>`_

Channel and trace memory
~~~~~~~~~~~~~~~~~~~~~~~~
A channel is an object which is responsible for holding the trace memory.
The trace library creates the trace memory per thread to enable the lock-less
scheme to emit the event. When a DPDK tracer emits an event, it will be recorded
to the trace buffers that associated with that thread.

Event record mode
~~~~~~~~~~~~~~~~~
Event record mode is an attribute of trace buffers. Trace library exposes two
modes:

 - ``Overwrite`` This mode enables trace buffers to wrap around when trace buffer memory is full.
 - ``Discard`` This mode enables trace buffers to discard when trace buffer memory is full.

This mode can be enabled/disabled either using eal command line parameters or
DPDK trace library API to configure the mode.
Refer :doc:`../linux_gsg/linux_eal_parameters` and trace API documentation more
details.

Metadata
~~~~~~~~
Metadata defines the layout of event records so that trace analysis tool can
read the streams and show into the relevant format.
For more details, refer `Common Trace Format <https://diamon.org/ctf/>`_.
