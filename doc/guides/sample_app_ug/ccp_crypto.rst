.. SPDX-License-Identifier: BSD-3-Clause
   Copyright(c) 2018 Advanced Micro Devices, Inc. All rights reserved.


.. _crypto_app:

Crypto Sample Application
============================================

The Crypto sample application is a simple example to test Crypto algorithm using
CCP, the Data Plane Development Kit (DPDK), in conjunction with the Cryptodev library.

Overview
--------

The Crypto sample application performs a Crypto operation (Cipher/Auth) specified by the user
from command line, with a Crypto device (like CCP) capable of doing that operation.

Compiling the Application
-------------------------

To compile the sample application see :doc:`compiling`.

The application is located in the `examples/crypto` sub-directory.

Running the Application
-----------------------

The application requires a number of command line options:

.. code-block:: console

	./build/crypto [EAL options] -- [-l core list] [-n number of channels] /
	[--vdev "crypto_ccp"] [--cdev_type HW/SW/ANY] [--cipher_op ENCRYPT / DECRYPT] /
	[--cipher_algo ALGO] [--plain_text ] [--cipher_key KEY] [--cipher_iv IV] /
	[--auth_op GENERATE / VERIFY] [ --auth_algo ALGO] [--auth_key KEY] /
	[--aead_algo ALGO] [--aead_op ENCRYPT / DECRYPT] [--aead_key KEY] [--aead_iv IV] /
	[--aad AAD] [ --digest]


where,

* l <core list>  	: List of cores to run on

* n NUM      		: Number of memory channels

* vdev             : Add a virtual device

* cdev_type: select preferred crypto device type: HW, SW or anything (ANY)

* cipher_op: select the ciphering operation to perform: ENCRYPT or DECRYPT

* cipher_algo: select the ciphering algorithm (EX: aes-cbc/aes-ecb/aes-ctr/)

* cipher_key: set the ciphering key to be used. Bytes has to be separated with ":"

* cipher_iv: set the cipher IV to be used. Bytes has to be separated with ":"

* plain_text: set the plain text to be operated. Bytes has to be separated with ":"

* auth_op: select the authentication operation to perform: GENERATE or VERIFY

* auth_algo: select the authentication algorithm

* auth_key: set the authentication key to be used. Bytes has to be separated with ":"

* aead_algo: select the AEAD algorithm

* aead_op: select the AEAD operation to perform: ENCRYPT or DECRYPT

* aead_key: set the AEAD key to be used. Bytes has to be separated with ":"

* aead_iv: set the AEAD IV to be used. Bytes has to be separated with ":"

* aad: set the AAD to be used. Bytes has to be separated with ":"

* digest : set the DIGEST values to be used. Bytes has to be separated with ":"


The application requires that crypto devices capable of performing
the specified crypto operation are available on application initialization.
This means that HW crypto device/s must be bound to a DPDK driver or
a SW crypto device/s (virtual crypto PMD) must be created (using --vdev).

Below are few example to run the application in linux environment with 2 lcores,
	4 Memory channel and 1 crypto device, issue the command:

.. code-block:: console

    Example 1:
	$sudo ./build/crypto -l1,2 -n 4 --vdev "crypto_ccp" -- --cipher_op ENCRYPT \
	--cipher_algo aes-cbc --plain_text f3:44:81:ec:3c:c6:27:ba:cd:5d:c3:fb:08:f2:73:e6 \
	--cipher_key 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00 \
	--cipher_iv 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00

    Example 2:
	$sudo ./build/crypto -l1,2 -n 4 --vdev "crypto_ccp" -- --auth_op GENERATE \
	--auth_algo sha3-224 --plain_text 01

    Example 3:
	$sudo ./build/crypto -l1,2 -n 4 --vdev "crypto_ccp" \
	-- --aead_op ENCRYPT --aead_algo aes-gcm \
	--plain_text c3:b3:c4:1f:11:3a:31:b7:3d:9a:5c:d4:32:10:30:69 \
	--aead_key c9:39:cc:13:39:7c:1d:37:de:6a:e0:e1:cb:7c:42:3c \
	--aead_iv 01:00:00:00:e2:67:0f:9e:b3:89:bb:7c:01:cc:d8:b3 \
	--aad 24:82:56:02:bd:12:a9:84:e0:09:2d:3e:44:8e:da:5f \
	--digest 00:00:00:00:00:00:00:80:00:00:00:00:00:00:00:80

Refer to the *DPDK Getting Started Guide* for general information on running applications
and the Environment Abstraction Layer (EAL) options.

.. Note::

    * All crypto devices shall use the same session.
