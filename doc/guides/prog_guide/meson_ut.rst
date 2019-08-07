..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2018-2019 Intel Corporation.

Running DPDK Unit Tests with Meson
==================================

This section describes how to run test cases with the DPDK meson build system.

Steps to build and run unit test cases using meson can be referred
in :doc:`build-sdk-meson`

Grouping of test cases
----------------------

Testcases have been grouped into four different groups.

* Fast tests.
* Performance tests.
* Driver tests.
* Tests which produce lists of objects as output, and therefore that need
  manual checking.

Testcases can be run in parallel or non-parallel mode using the ``is_parallel`` argument
of ``test()`` in meson.build

These tests can be run using the argument to ``meson test`` as
``--suite project_name:label``.

For example::

    $ meson test --suite DPDK:fast-tests

The project name is optional so the following is equivalent to the previous
command::

    $ meson test --suite fast-tests

The meson command to list all available tests::

    $ meson test --list


Dealing with skipped test cases
-------------------------------

Some unit test cases have a dependency on external libraries, driver modules
or config flags, without which the test cases cannot be run. Such test cases
will be reported as skipped if they cannot run. To enable those test cases,
the user should ensure the required dependencies are met.  Below are a few
possible causes why tests may be skipped and how they may be resolved:

#. Optional external libraries are not found.
#. Config flags for the dependent library are not enabled.
#. Dependent driver modules are not installed on the system.

To help find missing libraries, the user can specify additional search paths
for those libraries as below:

* Single path::

      $ export LIBRARY_PATH=path

* Multiple paths::

      $ export LIBRARY_PATH=path1:path2:path3

Some functionality may be disabled due to library headers being missed as part
of the build. To specify an additional search path for headers at
configuration time, use one of the commands below:

*  Single path::

       $ CFLAGS=-I/path meson build

*  Multiple paths::

       $ CFLAGS=`-I/path1 -I/path2 meson build`

Below are some examples that show how to export libraries and their header
paths.

To specify a single library at a time::

    $ export LIBRARY_PATH=/root/wireless_libs/zuc/
    $ CFLAGS=-I/root/wireless_libs/zuc/include meson build

To specify multiple libraries at a time::

    $ export LIBRARY_PATH=/path/zuc/:/path/libsso_kasumi/build/
    $ CFLAGS=-I/path/zuc/include \
             -I/path/libsso_kasumi/include \
	     meson build
