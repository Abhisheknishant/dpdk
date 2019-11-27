..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2019 Intel Corporation.

Virtio paths Selection and Usage
================================

Logically virtio-PMD has 9 paths based on the combination of virtio features
(Rx mergeable, In-order, Packed virtqueue), below is an introduction of these
features:

*   `Rx mergeable <https://docs.oasis-open.org/virtio/virtio/v1.1/cs01/
    virtio-v1.1-cs01.html#x1-2140004>`_: With this feature negotiated, device
    can receive large packets by combining individual descriptors.
*   `In-order <https://docs.oasis-open.org/virtio/virtio/v1.1/cs01/
    virtio-v1.1-cs01.html#x1-690008>`_: Some devices always use descriptors
    in the same order in which they have been made available, these
    devices can offer the VIRTIO_F_IN_ORDER feature. With this feature negotiated,
    driver will use descriptors in order.
*   `Packed virtqueue <https://docs.oasis-open.org/virtio/virtio/v1.1/cs01/
    virtio-v1.1-cs01.html#x1-610007>`_: The structure of packed virtqueue is
    different from split virtqueue, split virtqueue is composed of available ring,
    used ring and descriptor table, while packed virtqueue is composed of descriptor
    ring, driver event suppression and device event suppression. The idea behind
    this is to improve performance by avoiding cache misses and make it easier
    for hardware to implement.

Virtio paths Selection
----------------------

If packed virtqueue is not negotiated, below split virtqueue paths will be selected
according to below configuration:

#. Split virtqueue mergeable path: If Rx mergeable is negotiated, in-order feature is
   not negotiated, this path will be selected.
#. Split virtqueue non-mergeable path: If Rx mergeable and in-order feature are not
   negotiated, also Rx offload(s) are requested, this path will be selected.
#. Split virtqueue in-order mergeable path: If Rx mergeable and in-order feature are
   both negotiated, this path will be selected.
#. Split virtqueue in-order non-mergeable path: If in-order feature is negotiated and
   Rx mergeable is not negotiated, this path will be selected.
#. Split virtqueue vectorized Rx path: If Rx mergeable is disabled and no Rx offload
   requested, this path will be selected.

If packed virtqueue is negotiated, below packed virtqueue paths will be selected
according to below configuration:

#. Packed virtqueue mergeable path: If Rx mergeable is negotiated, in-order feature
   is not negotiated, this path will be selected.
#. Packed virtqueue non-mergeable path: If Rx mergeable and in-order feature are not
   negotiated, this path will be selected.
#. Packed virtqueue in-order mergeable path: If in-order and Rx mergeable feature are
   both negotiated, this path will be selected.
#. Packed virtqueue in-order non-mergeable path: If in-order feature is negotiated and
   Rx mergeable is not negotiated, this path will be selected.

Rx/Tx callbacks of each Virtio path
-----------------------------------

Refer to above description, virtio path and corresponding Rx/Tx callbacks will
be selected automatically. Rx callbacks and Tx callbacks for each virtio path
are shown in below table:

.. table:: Virtio Paths and Callbacks

   ============================================ ================================= ========================
                 Virtio paths                            Rx callbacks                   Tx callbacks
   ============================================ ================================= ========================
   Split virtqueue mergeable path               virtio_recv_mergeable_pkts        virtio_xmit_pkts
   Split virtqueue non-mergeable path           virtio_recv_pkts                  virtio_xmit_pkts
   Split virtqueue in-order mergeable path      virtio_recv_pkts_inorder          virtio_xmit_pkts_inorder
   Split virtqueue in-order non-mergeable path  virtio_recv_pkts_inorder          virtio_xmit_pkts_inorder
   Split virtqueue vectorized Rx path           virtio_recv_pkts_vec              virtio_xmit_pkts
   Packed virtqueue mergeable path              virtio_recv_mergeable_pkts_packed virtio_xmit_pkts_packed
   Packed virtqueue non-meregable path          virtio_recv_pkts_packed           virtio_xmit_pkts_packed
   Packed virtqueue in-order mergeable path     virtio_recv_mergeable_pkts_packed virtio_xmit_pkts_packed
   Packed virtqueue in-order non-mergeable path virtio_recv_pkts_packed           virtio_xmit_pkts_packed
   ============================================ ================================= ========================

Virtio paths Support Status from Release to Release
---------------------------------------------------

Virtio feature implementation:

*   In-order feature is supported since DPDK 18.08 by adding new Rx/Tx callbacks
    ``virtio_recv_pkts_inorder`` and ``virtio_xmit_pkts_inorder``.
*   Packed virtqueue is supported since DPDK 19.02 by adding new Rx/Tx callbacks
    ``virtio_recv_pkts_packed`` , ``virtio_recv_mergeable_pkts_packed`` and
    ``virtio_xmit_pkts_packed``.

All virtio paths support status are shown in below table:

.. table:: Virtio Paths and Releases

   ============================================ ============= ============= =============
                  Virtio paths                  16.11 ~ 18.05 18.08 ~ 18.11 19.02 ~ 19.11
   ============================================ ============= ============= =============
   Split virtqueue mergeable path                     Y             Y             Y
   Split virtqueue non-mergeable path                 Y             Y             Y
   Split virtqueue vectorized Rx path                 Y             Y             Y
   Split virtqueue simple Tx path                     Y             N             N
   Split virtqueue in-order mergeable path                          Y             Y
   Split virtqueue in-order non-mergeable path                      Y             Y
   Packed virtqueue mergeable path                                                Y
   Packed virtqueue non-mergeable path                                            Y
   Packed virtqueue in-order mergeable path                                       Y
   Packed virtqueue in-order non-mergeable path                                   Y
   ============================================ ============= ============= =============

QEMU Support Status
-------------------

*   Qemu now supports three paths of split virtqueue: Split virtqueue mergeable path,
    Split virtqueue non-mergeable path, Split virtqueue vectorized Rx path.
*   Since qemu 4.2.0, Packed virtqueue mergeable path and Packed virtqueue non-mergeable
    path can be supported.

How to Debug
------------

If you meet performance drop or some other issues after upgrading the driver
or configuration, below steps can help you identify which path you selected and
root cause faster.

#. Run vhost/virtio test case;
#. Run "perf top" and check virtio Rx/Tx callback names;
#. Identify which virtio path is selected refer to above table.
