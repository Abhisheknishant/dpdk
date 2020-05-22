.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2020 The DPDK contributors

.. include:: <isonum.txt>

DPDK Release 20.05
==================

.. **Read this first.**

   The text in the sections below explains how to update the release notes.

   Use proper spelling, capitalization and punctuation in all sections.

   Variable and config names should be quoted as fixed width text:
   ``LIKE_THIS``.

   Build the docs and view the output file to ensure the changes are correct::

      make doc-guides-html

      xdg-open build/doc/html/guides/rel_notes/release_20_05.html


New Features
------------

.. This section should contain new features added in this release.
   Sample format:

   * **Add a title in the past tense with a full stop.**

     Add a short 1-2 sentence description in the past tense.
     The description should be enough to allow someone scanning
     the release notes to understand the new feature.

     If the feature adds a lot of sub-features you can use a bullet list
     like this:

     * Added feature foo to do something.
     * Enhanced feature bar to do something else.

     Refer to the previous release notes for examples.

     Suggested order in release notes items:
     * Core libs (EAL, mempool, ring, mbuf, buses)
     * Device abstraction libs and PMDs
       - ethdev (lib, PMDs)
       - cryptodev (lib, PMDs)
       - eventdev (lib, PMDs)
       - etc
     * Other libs
     * Apps, Examples, Tools (if significant)

     This section is a comment. Do not overwrite or remove it.
     Also, make sure to start the actual text at the margin.
     =========================================================

* **Added Trace Library and Tracepoints.**

  A native implementation of "common trace format" (CTF) based trace library
  has been added to provide the ability to add tracepoints in an
  application/library to get runtime trace/debug information for control, and
  fast APIs with minimum impact on fast path performance.
  Typical trace overhead is ~20 cycles and instrumentation overhead is 1 cycle.
  Added tracepoints in ``EAL``, ``ethdev``, ``cryptodev``, ``eventdev`` and
  ``mempool`` libraries for important functions.

* **Added APIs for RCU defer queues.**

  Added APIs to create and delete defer queues. Additional APIs are provided
  to enqueue a deleted resource and reclaim the resource in the future.
  These APIs help an application use lock-free data structures with
  less effort.

* **Added new API for rte_ring.**

  * Introduced new synchronization modes for rte_ring.

    Introduced new optional MT synchronization modes for ``rte_ring``:
    Relaxed Tail Sync (RTS) mode and Head/Tail Sync (HTS) mode.
    With these modes selected, ``rte_ring`` shows significant improvements for
    average enqueue/dequeue times on overcommitted systems.

  * Added peek style API for ``rte_ring``.

    For rings with producer/consumer in ``RTE_RING_SYNC_ST``, ``RTE_RING_SYNC_MT_HTS``
    mode, provide the ability to split enqueue/dequeue operation into two phases
    (enqueue/dequeue start and enqueue/dequeue finish). This allows the user to inspect
    objects in the ring without removing them (aka MT safe peek).

* **Added flow aging support.**

  Added flow aging support to detect and report aged-out flows, including:

  * Added new action: ``RTE_FLOW_ACTION_TYPE_AGE`` to set the timeout
    and the application flow context for each flow.
  * Added new event: ``RTE_ETH_EVENT_FLOW_AGED`` for the driver to report
    that there are new aged-out flows.
  * Added new query: ``rte_flow_get_aged_flows`` to get the aged-out flows
    contexts from the port.

* **ethdev: Added a new value to link speed for 200Gbps.**

  Added a new ethdev value to for link speeds of 200Gbps.

* **Updated the Amazon ena driver.**

  Updated the ena PMD with new features and improvements, including:

  * Added support for large LLQ (Low-latency queue) headers.
  * Added Tx drops as a new extended driver statistic.
  * Added support for accelerated LLQ mode.
  * Handling of the 0 length descriptors on the Rx path.

* **Updated Hisilicon hns3 driver.**

  Updated Hisilicon hns3 driver with new features and improvements, including:

  * Added support for TSO.
  * Added support for configuring promiscuous and allmulticast mode for VF.

* **Updated Intel i40e driver.**

  Updated i40e PMD with new features and improvements, including:

  * Enabled MAC address as FDIR input set for ipv4-other, ipv4-udp and ipv4-tcp.
  * Added support for RSS using L3/L4 source/destination only.
  * Added support for setting hash function in rte flow.

* **Updated the Intel iavf driver.**

  Update the Intel iavf driver with new features and improvements, including:

  * Added generic filter support.
  * Added advanced iavf with FDIR capability.
  * Added advanced RSS configuration for VFs.

* **Updated the Intel ice driver.**

  Updated the Intel ice driver with new features and improvements, including:

  * Added support for DCF (Device Config Function) feature.
  * Added switch filter support for Intel DCF.

* **Updated Marvell OCTEON TX2 ethdev driver.**

  Updated Marvell OCTEON TX2 ethdev driver with traffic manager support,
  including:

  * Hierarchical Scheduling with DWRR and SP.
  * Single rate - Two color, Two rate - Three color shaping.

* **Updated Mellanox mlx5 driver.**

  Updated Mellanox mlx5 driver with new features and improvements, including:

  * Added support for matching on IPv4 Time To Live and IPv6 Hop Limit.
  * Added support for creating Relaxed Ordering Memory Regions.
  * Added support for configuring Hairpin queue data buffer size.
  * Added support for jumbo frame size (9K MTU) in Multi-Packet RQ mode.
  * Removed flow rules caching for memory saving and compliance with ethdev API.
  * Optimized the memory consumption of flows.
  * Added support for flow aging based on hardware counters.
  * Added support for flow pattern with wildcard VLAN items (without VID value).
  * Updated support for matching on GTP headers, added match on GTP flags.

* **Added additional algorithms to the Cryptodev API.**

  Added additional algorithms and updated support to the Cryptodev PMD and
  APIs, including:

  * Added support for intel-ipsec-mb version 0.54 to the following PMDs: AESNI
    MB, AESNI GCM, ZUC, KASUMI, SNOW 3G.

  * Added support for Chacha20-Poly1305 AEAD algorithm.

  * Updated the ZUC crypto PMD to support Multi-buffer ZUC-EIA3, improving
    performance significantly, when using intel-ipsec-mb version 0.54

  * AESNI MB crypto PMD:

    * Updated the AESNI MB PMD with AES-256 DOCSIS algorithm.
    * Added support for synchronous Crypto burst API.

* **Added handling of mixed crypto algorithms in QAT PMD for GEN2.**

  Enabled handling of mixed algorithms in encrypted digest hash-cipher
  (generation) and cipher-hash (verification) requests in QAT PMD
  when running on GEN2 QAT hardware with particular firmware versions
  (GEN3 support was added in DPDK 20.02).

* **Added plain SHA-1, 224, 256, 384, 512 support to QAT PMD.**

  Added support for plain SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 hashes
  to QAT PMD.

* **Added AES-GCM/GMAC J0 support to QAT PMD.**

  Added support for AES-GCM/GMAC J0 to Intel QuickAssist Technology PMD. User can
  use this feature by passing a zero length IV in the appropriate xform. For more
  info refer to the doxygen comments in ``rte_crypto_sym.h`` for ``J0``.

* **Updated the QAT PMD for AES-256 DOCSIS.**

  Added AES-256 DOCSIS algorithm support to the QAT PMD.

* **Added QAT intermediate undersized buffer handling in QAT compression PMD.**

  Added special buffer handling when the internal QAT intermediate buffer is
  too small for the Huffman dynamic compression operation. Instead of falling
  back to fixed compression, the operation is now split into multiple smaller
  dynamic compression requests (which are possible to execute on QAT) and
  their results are then combined and copied into the output buffer. This is
  not possible if any checksum calculation was requested - in such cases the
  code falls back to fixed compression as before.

* **Added a new driver for Intel Foxville I225 devices.**

  Added the new ``igc`` net driver for Intel Foxville I225 devices. See the
  :doc:`../nics/igc` NIC guide for more details on this new driver.

* **Updated Broadcom bnxt driver.**

  Updated the Broadcom bnxt driver with new features and improvements, including:

  * Added support for host based flow table management.
  * Added flow counters to extended stats.
  * Added PCI function stats to extended stats.

* **Updated the turbo_sw bbdev PMD.**

  Added support for large size code blocks which do not fit in one mbuf
  segment.

* **Added Intel FPGA_5GNR_FEC bbdev PMD.**

  Added a new ``fpga_5gnr_fec`` bbdev driver for the Intel\ |reg| FPGA PAC
  (Programmable  Acceleration Card) N3000.  See the
  :doc:`../bbdevs/fpga_5gnr_fec` BBDEV guide for more details on this new driver.

* **Updated the DSW event device.**

  Updated the DSW PMD with new features and improvements, including:

  * Improved flow migration mechanism, allowing faster and more
    accurate load balancing.
  * Improved behavior on high-core count systems.
  * Reduced latency in low-load situations.
  * Extended DSW xstats with migration and load-related statistics.

* **Updated ipsec-secgw sample application.**

  Updated ``ipsec-secgw`` sample application with following features:

  * Updated the application to add event based packet processing. The worker
    thread(s) would receive events and submit them back to the event device
    after the processing. This way, multicore scaling and HW assisted
    scheduling is achieved by making use of the event device capabilities. The
    event mode currently only supports inline IPsec protocol offload.

  * Updated the application to support key sizes for AES-192-CBC, AES-192-GCM,
    AES-256-GCM algorithms.

  * Added IPsec inbound load-distribution support for the application using
    NIC load distribution feature(Flow Director).

* **Updated Telemetry Library.**

  The updated Telemetry library has been significantly in relation to the
  original version to make it more accessible and scalable:

  * It now enables DPDK libraries and applications to provide their own
    specific telemetry information, rather than being limited to what could be
    reported through the metrics library.

  * It is no longer dependent on the external Jansson library, which allows
    Telemetry be enabled by default.

  * The socket handling has been simplified making it easier for clients to
    connect and retrieve information.

* **Added the rte_graph library.**

  The Graph architecture abstracts the data processing functions as a ``node``
  and ``links`` them together to create a complex ``graph`` to enable
  reusable/modular data processing functions. The graph library provides APIs
  to enable graph framework operations such as create, lookup, dump and
  destroy on graph and node operations such as clone, edge update, and edge
  shrink, etc.  The API also allows the creation of a stats cluster to monitor
  per graph and per node statistics.

* **Added the rte_node library.**

  Added the ``rte_node`` library that consists of nodes used by ``rte_graph``
  library. Each node performs a specific packet processing function based on
  the application configuration. The following nodes are added:

  * Null node: A skeleton node that defines the general structure of a node.
  * Ethernet device node: Consists of Ethernet Rx/Tx nodes as well as Ethernet
    control APIs.
  * IPv4 lookup node: Consists of IPv4 extract and LPM lookup node. Routes can
    be configured by the application through the ``rte_node_ip4_route_add``
    function.
  * IPv4 rewrite node: Consists of IPv4 and Ethernet header rewrite
    functionality that can be configured through the
    ``rte_node_ip4_rewrite_add`` function.
  * Packet drop node: Frees the packets received to their respective mempool.

* **Added new l3fwd-graph sample application.**

  Added an example application ``l3fwd-graph``. This demonstrates the usage of
  graph library and node library for packet processing. In addition to the
  library usage demonstration, this application can be used for performance
  comparison with existing ``l3fwd`` (The static code without any nodes) with
  the modular ``l3fwd-graph`` approach.

* **Updated the testpmd application.**

  * Added a new cmdline option ``--rx-mq-mode`` which can be used to test PMD's
    behaviour on handling Rx mq mode.


API Changes
-----------

.. This section should contain API changes. Sample format:

   * sample: Add a short 1-2 sentence description of the API change
     which was announced in the previous releases and made in this release.
     Start with a scope label like "ethdev:".
     Use fixed width quotes for ``function_names`` or ``struct_names``.
     Use the past tense.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =========================================================

* mempool: The API of ``rte_mempool_populate_iova()`` and
  ``rte_mempool_populate_virt()`` changed to return 0 instead of ``-EINVAL``
  when there is not enough room to store one object.


ABI Changes
-----------

.. This section should contain ABI changes. Sample format:

   * sample: Add a short 1-2 sentence description of the ABI change
     which was announced in the previous releases and made in this release.
     Start with a scope label like "ethdev:".
     Use fixed width quotes for ``function_names`` or ``struct_names``.
     Use the past tense.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =========================================================

* No ABI change that would break compatibility with DPDK 20.02 and 19.11.


Tested Platforms
----------------

.. This section should contain a list of platforms that were tested
   with this release.

   The format is:

   * <vendor> platform with <vendor> <type of devices> combinations

     * List of CPU
     * List of OS
     * List of devices
     * Other relevant details...

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =========================================================
