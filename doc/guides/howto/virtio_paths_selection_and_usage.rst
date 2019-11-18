..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2019 Intel Corporation.

Virtio paths Selection and Usage
================================

Logically virtio-PMD has 9 paths based on the virtio features (Rx mergeable,In-order,Packed virtqueue)
combinations, below are introduction of virtio three common features:

*   Rx mergeable: With this feature negotiated, device can receive larger packets by combining
    individual descriptors.
*   In-order: Some devices always use descriptors in the same order in which they have been made
    available, these devices can offer the VIRTIO_F_IN_ORDER feature. If this feature negotiated,
    driver will use descriptors in order. Meanwhile, this knowledge allows device operate used ring
    in batches and driver operate available ring in batches and such can decrease cache miss rate.
*   Packed virtqueue: The structure of packed virtqueue is different from split virtqueue，split
    virtqueue is composed of available ring, used ring and descriptor table, while packed virtqueue
    is composed of descriptor ring，driver event suppression and device event suppression. The idea
    behind this is to improve performance by avoiding cache misses and and make it easier for devices
    to implement.

Virtio paths Selection
----------------------

If packed virtqueue is not negotiated, below split virtqueue paths can be selected
according to below configuration:

#. Split virtqueue mergeable path: If Rx mergeable is negotiated, in-order feature is
   not negotiated, this path will be selected.
#. Split virtqueue non-mergeable path: If Rx mergeable and in-order feature are not
   negotiated, also Rx offload(s) are requested, this path can be selected.
#. Split virtqueue in-order mergeable path: If in-order feature and Rx mergeable are
   both negotiated, this path can be selected.
#. Split virtqueue in-order non-mergeable path: If in-order feature is negotiated and
   Rx mergeable is not negotiated, this path can be selected.
#. Split virtqueue vectorized RX path: If Rx mergeable is disabled and no Rx offload
   requested, this path can be selected.

If packed virtqueue is negotiated, below packed virtqueue paths can be selected
according to below configuration:

#. Packed virtqueue mergeable path: If Rx mergeable is negotiated, in-order feature
   is not negotiated, this path will be selected.
#. Packed virtqueue non-mergeable path: If Rx mergeable and in-order feature are not
   negotiated, also Rx offload(s) are requested, this path will be selected.
#. Packed virtqueue in-order mergeable path: If in-order feature and Rx mergeable are
   both negotiated, this path will be selected.
#. Packed virtqueue in-order non-mergeable path: If in-order feature is negotiated and
   Rx mergeable is not negotiated, this path will be selected.

Rx/Tx callbacks of each Virtio path
-----------------------------------

Refer to above descriptions,virtio path and Rx/TX callbacks are auto selected by different parameters of
vdev and workloads. Rx callbacks and Tx callbacks name for each Virtio Path are shown in following tables::

   +----------------------------------------------------------------------------------------------------------+
   |       Virtio path                          |   Rx callbacks                   |    TX callbacks          |
   +----------------------------------------------------------------------------------------------------------+
   |Split virtqueue mergeable path              |virtio_recv_mergeable_pkts        | virtio_xmit_pkts         |
   +----------------------------------------------------------------------------------------------------------+
   |Split virtqueue non-mergeable path          | virtio_recv_pkts                 |  virtio_xmit_pkts        |
   +----------------------------------------------------------------------------------------------------------+
   |Split virtqueue in-order mergeable path     | virtio_recv_pkts_inorder         |  virtio_xmit_pkts_inorder|
   +----------------------------------------------------------------------------------------------------------+
   |Split virtqueue in-order non-mergeable path | virtio_recv_pkts_inorder         |  virtio_xmit_pkts_inorder|
   +----------------------------------------------------------------------------------------------------------+
   |Split virtqueue vectorized RX path          | virtio_recv_pkts_vec             |  virtio_xmit_pkts        |
   +----------------------------------------------------------------------------------------------------------+
   |Packed virtqueue mergeable path             | virtio_recv_mergeable_pkts_packed|  virtio_xmit_pkts_packed |
   +----------------------------------------------------------------------------------------------------------+
   |Packed virtqueue normal path                | virtio_recv_pkts_packed          |  virtio_xmit_pkts_packed |
   +----------------------------------------------------------------------------------------------------------+
   |Packed virtqueue in-order mergeable path    | virtio_recv_mergeable_pkts_packed|  virtio_xmit_pkts_packed |
   +----------------------------------------------------------------------------------------------------------+
   |Packed virtqueue in-order normal path       | virtio_recv_pkts_packed          |  virtio_xmit_pkts_packed |
   +----------------------------------------------------------------------------------------------------------+

Virtio paths Support Status from Release to Release
---------------------------------------------------

Virtio feature implementation:

*   In-order feature implemented in DPDK 18.08 by adding new Rx/TX callbacks
    ``virtio_recv_pkts_inorder`` and ``virtio_xmit_pkts_inorder``.
*   Packed virtqueue implemented in DPDK 19.02 by adding new Rx/TX callbacks
    ``virtio_recv_pkts_packed`` , ``virtio_recv_mergeable_pkts_packed`` and ``virtio_xmit_pkts_packed``.

Virtio path number changes from release to release, all virtio paths support status are shown in below table::

   +--------------------------------------------------------------------------------------------------------------------------------------------------------+
   |Virtio path\ DPDK version                   | v16.11 | v17.02 | v17.05 | v17.08 | v17.11 | v18.02 | v18.05 | v18.08 | v18.11 | v19.02 | v19.05 | v19.08 |
   +--------------------------------------------------------------------------------------------------------------------------------------------------------+
   |Split virtqueue mergebale path              |   Y    |   Y    |    Y    |   Y   |   Y    |   Y    |   Y    |   Y    |   Y    |  Y     |   Y    |   Y    |
   +--------------------------------------------------------------------------------------------------------------------------------------------------------+
   |Split virtqueue non-mergeable path          |   Y    |   Y    |    Y    |   Y   |   Y    |   Y    |   Y    |   Y    |   Y    |  Y     |   Y    |   Y    |
   +--------------------------------------------------------------------------------------------------------------------------------------------------------+
   |Split virtqueue vectorized RX path          |   Y    |   Y    |    Y    |   Y   |   Y    |   Y    |   Y    |   Y    |   Y    |  Y     |   Y    |   Y    |
   ---------------------------------------------------------------------------------------------------------------------------------------------------------+
   |Split virtqueue simple TX path              |   Y    |   Y    |    Y    |   Y   |   Y    |   Y    |   Y    |   N    |   N    |  N     |   N    |   N    |
   ---------------------------------------------------------------------------------------------------------------------------------------------------------+
   |Split virtqueue in-order non-mergeable path |        |        |         |       |        |        |        |   Y    |   Y    |  Y     |   Y    |   Y    |
   ---------------------------------------------------------------------------------------------------------------------------------------------------------+
   |Split virtqueue in-order mergeable path     |        |        |         |       |        |        |        |   Y    |   Y    |  Y     |   Y    |   Y    |
   ---------------------------------------------------------------------------------------------------------------------------------------------------------+
   |Packed virtqueue mergeable path             |        |        |         |       |        |        |        |        |        |  Y     |   Y    |   Y    |
   ---------------------------------------------------------------------------------------------------------------------------------------------------------+
   |Packed virtqueue non-mergeable path         |        |        |         |       |        |        |        |        |        |  Y     |   Y    |   Y    |
   ---------------------------------------------------------------------------------------------------------------------------------------------------------+
   |Packed virtqueue in-order mergeable path    |        |        |         |       |        |        |        |        |        |  Y     |   Y    |   Y    |
   ---------------------------------------------------------------------------------------------------------------------------------------------------------+
   |Packed virtqueue in-order non-mergeable path|        |        |         |       |        |        |        |        |        |  Y     |   Y    |   Y    |
   ---------------------------------------------------------------------------------------------------------------------------------------------------------+

QEMU Support Status
-------------------

Qemu only support three path of Virtio-PMD: Split virtqueue mergebale path,
Split virtqueue no-mergeable path，Split virtqueue vectorized RX path.

How to Debug
------------

If you meet performance drop or some other issues after upgrading the driver
or configuration, below steps can help you identify which path you selected and
root cause faster.

#. Run vhost/virtio test case;
#. Run "perf top" and check virtio Rx/tx callback names;
#. Identify which virtio path is selected refer to above table.
