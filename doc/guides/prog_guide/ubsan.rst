..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2019 Marvell International Ltd.

The Undefined Behavior Sanitizer - UBSan
========================================

UndefinedBehaviorSanitizer (UBSan) is a runtime undefined behavior detector.
UBSan uses compile-time instrumentation and modifies the program by adding
some stubs which perform certain checks before operations that might cause
undefined behaviour. If some UB detected, respective _UBSan_handle_* handlers
(which are defined in libUBSan library) are called to prints the error message.

Some examples of undefined behaviour checks:

* Misaligned memory access
* Signed integer overflow
* Load from/store to an object with insufficient space.
* Integer divide by zero as well as INT_MIN / -1 division
* Out-of-bounds memory accesses.
* Null argument declared with nonnull attribute, returned null from function
  which never returns null, null ptr dereference
* Variable size array with non-positive length

GCC supports this feature since 4.9, however GCC 5.0 onwards has many more
checkers implemented.

Example UBSan error
--------------------

Following error was reported when UBSan was enabled:

.. code-block:: console

    drivers/net/octeontx2/otx2_stats.c:82:26: runtime error: left shift of
    1 by 31 places cannot be represented in type 'int'

Code responsible for this error:

.. code-block:: c

    if (dev->txmap[i] & (1 << 31)) {

To fix this error:

.. code-block:: c

    if (dev->txmap[i] & (1U << 31)) {

Usage
-----

make build
^^^^^^^^^^

To enable UBSan, enable following configuration:

.. code-block:: console

    CONFIG_RTE_UBSAN=y

UBSan framework supports three modes:

1. Enable UBSan on the entire DPDK source code - set following configuration:

.. code-block:: console

    CONFIG_RTE_UBSAN_SANITIZE_ALL=y

2. Enable UBSan on a particular library or PMD - add the following line to the
   respective Makefile of the library or PMD
   (make sure ``CONFIG_RTE_UBSAN_SANITIZE_ALL=n``). This will instrument only
   the library or PMD and not the entire repository.

.. code-block:: console

    UBSAN_SANITIZE := y

3. Disable UBSan for a particular library or PMD - add the following line to
   the respective Makefile of the library or PMD. Make sure
   ``CONFIG_RTE_UBSAN_SANITIZE_ALL=y`` config is set. This will instrument
   entire DPDK repository but not this specific library or PMD.

.. code-block:: console

    UBSAN_SANITIZE := n

.. Note::

  Standard DPDK applications like test, testpmd, etc. cannot be
  chosen explicitly for UBSan check, like libraries or PMD. The reason is,
  say UBSan is enabled for library X, and ``UBSAN_SANITIZE=y`` is not added
  in Makefile of app Y which uses X APIs. This will lead to undefined
  reference to _UBSan_handle_* handlers as Y is not compiled with UBSan flags.
  Hence UBSan check is enabled for all standard DPDK applications as soon as
  ``CONFIG_RTE_UBSAN=y`` is set.

meson build
^^^^^^^^^^^

To enable UBSan in meson build system, use following meson build command:

**Example usage:**

.. code-block:: console

 meson build -Denable_ubsan=true
 ninja -C build

.. Note::

  Meson build works only in one mode i.e. UBSan can be enabled for
  the entire DPDK sources and not individual libraries or PMD, like make build.
