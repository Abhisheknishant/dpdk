..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2020 Intel Corporation.

AES-NI Multi Buffer Multi-Function Rawdev Driver
================================================

The AES-NI MB Multi-Function Rawdev PMD is a poll mode driver which enables
utilization of new multi-function processing capabilities in the Intel IPSec
Multi Buffer library (see :doc:`../cryptodevs/aesni_mb` for more details on this
library).

This Rawdev PMD supports a new Multi-Function interface, which provides a way of
combining one or more packet-processing functions into a single operation,
thereby allowing these to be performed in parallel by the Intel IPSec Multi
Buffer library. Through the multi-function interface, the following use-cases
are supported by this PMD:

* DOCSIS MAC: Crypto-CRC
* GPON MAC: Crypto-CRC-BIP


Features
--------

AES-NI MB Multi-Function Rawdev PMD currently supports the following:

Cipher algorithms:

* RTE_CRYPTO_CIPHER_AES_CTR (128 bit)
* RTE_CRYPTO_CIPHER_AES_DOCSISBPI (128 bit)

Error Detection algorithms:

* RTE_MULTI_FN_ERR_DETECT_BIP32
* RTE_MULTI_FN_ERR_DETECT_CRC32_ETH

These algorithms may only be combined through the multi-function interface in
the following specific orders for use by this PMD:

* For DOCSIS Crypto-CRC (Encrypt direction)

  1. RTE_MULTI_FN_ERR_DETECT_CRC32_ETH (Generate)
  2. RTE_CRYPTO_CIPHER_AES_DOCSISBPI (Encrypt)


* For DOCSIS Crypto-CRC (Decrypt direction)

  1. RTE_CRYPTO_CIPHER_AES_DOCSISBPI (Decrypt)
  2. RTE_MULTI_FN_ERR_DETECT_CRC32_ETH (Verify)


* For GPON Crypto-CRC-BIP (Encrypt direction)

  1. RTE_MULTI_FN_ERR_DETECT_CRC32_ETH (Generate)
  2. RTE_CRYPTO_CIPHER_AES_CTR (Encrypt)
  3. RTE_MULTI_FN_ERR_DETECT_BIP32 (Generate)


* For GPON Crypto-CRC-BIP (Decrypt direction)

  1. RTE_MULTI_FN_ERR_DETECT_BIP32 (Generate)
  2. RTE_CRYPTO_CIPHER_AES_CTR (Decrypt)
  3. RTE_MULTI_FN_ERR_DETECT_CRC32_ETH (Verify)


Limitations
-----------

* Chained mbufs are not supported.
* Out of place operation is not supported.
* Only 128-bit keys for RTE_CRYPTO_CIPHER_AES_CTR and
  RTE_CRYPTO_CIPHER_AES_DOCSISBPI are supported.


Installation
------------

The AES-NI MB Multi-Function Rawdev PMD requires the Intel IPSec Multi Buffer
library be installed on the system. For details on how to install this library,
please see :doc:`../cryptodevs/aesni_mb`.

.. note::

   This PMD requires v0.54 or later of the Intel IPSec Multi Buffer library.


Initialization
--------------

In order to enable the AES-NI MB Multi-Function Rawdev PMD, the user must:

* Build the multi buffer library (as explained in Installation section).
* Set CONFIG_RTE_LIBRTE_MULTI_FN_COMMON=y in config/common_base.
* Set CONFIG_RTE_LIBRTE_PMD_AESNI_MB_MFN_RAWDEV=y in config/common_base.

To enabled extra debug features such as extra parameter checking, the user must:

* Set CONFIG_RTE_LIBRTE_PMD_AESNI_MB_RAWDEV_MFN_DEBUG=y in config/common_base.

Note, however, that doing so will impact performance.

To use the PMD in an application, the user must:

* Call rte_vdev_init("rawdev_mfn_aesni_mb") within the application.
* Use --vdev="rawdev_mfn_aesni_mb" in the EAL options, which will call
  rte_vdev_init() internally.

Example:

.. code-block:: console

    <application> -l 1 -n 4 --vdev="rawdev_mfn_aesni_mb" -- <application params>


Device Configuration
--------------------

Configuring the AES-NI MB Multi-Function Rawdev PMD is done through a
combination of the ``rte_rawdev_configure()`` API and the
``struct rte_multi_fn_dev_config``  structure of the multi-function interface.

The following code shows how the device is configured:

.. code-block:: c

    struct rte_multi_fn_dev_config mf_dev_conf = {
                    .nb_queues = 1,
                    .socket_id = 0
    };
    struct rte_rawdev_info rdev_info = {.dev_private = &mf_dev_conf};

    rte_rawdev_configure(dev_id, (rte_rawdev_obj_t)&rdev_info);


Queue Pair Configuration
------------------------

Configuring the queue pairs of the AES-NI MB Multi-Function Rawdev PMD is done
through a combination of the ``rte_rawdev_queue_setup()`` API and the
``struct rte_multi_fn_qp_config`` structure of the multi-function interface.

The following code shows how the queue pairs are configured:

.. code-block:: c

    struct rte_multi_fn_qp_config qp_conf = {
                    .nb_descriptors = 4096
    };

    rte_rawdev_queue_setup(dev_id, qp_id, (rte_rawdev_obj_t)&qp_conf);


Multi-Function Session Creation
-------------------------------

Multi-function sessions are created on the AES-NI MB Multi-Function Rawdev PMD
through the multi-function interface by chaining ``struct rte_multi_fn_xform``
transforms together and calling the ``rte_multi_fn_session_create()`` API.

The only transform chains supported by this PMD are listed in the Features
section.

The following code shows how a multi-function session is created, taking
Crypto-CRC chaining as an example:

.. code-block:: c

    struct rte_multi_fn_xform xform[2] = {0};

    xform[0].type = RTE_MULTI_FN_XFORM_TYPE_ERR_DETECT;
    xform[0].err_detect.algo = RTE_MULTI_FN_ERR_DETECT_CRC32_ETH;
    xform[0].err_detect.op = RTE_MULTI_FN_ERR_DETECT_OP_GENERATE;
    xform[0].next = &xform[1];

    xform[1].type = RTE_MULTI_FN_XFORM_TYPE_CRYPTO_SYM;
    xform[1].crypto_sym.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
    xform[1].next = NULL;
    /*
     * setup reaminder of xform[1].crypto_sym.cipher fields here, including
     * op, algo, key and iv
     */

    sess = rte_multi_fn_session_create(dev_id, &xform[0], rte_socket_id());


Performing Multi-Function Operations
------------------------------------

Multi-function operations are performed on the AES-NI MB Multi-Function Rawdev
PMD using the ``rte_rawdev_enqueue_buffers()`` and
``rte_rawdev_dequeue_buffers()`` APIs. Chains of multi-function operations
(``struct rte_multi_fn_op``) which are associated with an mbuf and a
multi-function session are passed to these APIs.

The following code shows how these APIs are used:


.. code-block:: c

    struct rte_multi_fn_op *ops[2];
    rte_multi_fn_op_bulk_alloc(op_pool, ops, 2);

    ops[0]->next = ops[1];
    ops[0]->m_src = src;
    ops[0]->sess = sess;
    ops[1]->next = NULL;
    /* setup remainder of ops here */

    rte_rawdev_enqueue_buffers(dev_id,
                               (struct rte_rawdev_buf **)ops,
                               1,
                               (rte_rawdev_obj_t)&qp_id);

    do {
        nb_deq = rte_rawdev_dequeue_buffers(dev_id,
                                            (struct rte_rawdev_buf **)ops,
                                            1,
                                            (rte_rawdev_obj_t)&qp_id);
    } while (nb_deq < 1);
