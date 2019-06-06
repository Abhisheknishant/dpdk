..  SPDX-License-Identifier: BSD-3-Clause

    Copyright(c) 2018-2019 Intel Corporation.

.. _meson_unit_tests:

Running DPDK Unit Tests with Meson
==================================

This section describes how to run testcases with the DPDK meson build system.


Building and running the unit tests
-----------------------------------

* Create the meson build output folder using the following command::

      $ meson <build_dir>

* Enter into build output folder, which was created by above command::

      $ cd build

* Compile DPDK using command::

      $ ninja

The output file of the build will be available in meson build folder. After
a successful ninja command, the binary ``dpdk-test`` is created in
``build/test/test/``.

* Run the unit testcases::

      $ ninja test
      # or
      $ meson test

* To run specific test case via meson::

      $ meson test <test case>
      # or
      $ ninja test <test case>


Grouping of testcases
---------------------

Testcases have been grouped into four different groups based on conditions
of time duration and performance of the individual testcase.

* Fast tests which can be run in parallel.
* Fast tests which must run serially.
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


Running different test suites
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following commands are some examples of how to run testcases using option
``--suite``:

* Fast Tests should take less than 10 seconds. The meson command to run them
  is::

      $ meson test --suite DPDK:fast-tests

* Performance Tests should take less than 600 seconds. The meson command to
  run them is::

      $ meson test --suite DPDK:perf-tests

* Driver Tests should take less than 600 seconds. The meson command to run
  them is::

      $ meson test --suite DPDK:driver-tests

* The meson command to run Dump Tests is::

      $ meson test --suite DPDK:dump-tests


Dealing with skipped testcases
------------------------------

Some unit test cases have a dependency on external libraries, driver modules
or config flags, without which the test cases cannot be run. Such test cases
will be reported as skipped if they cannot run. To enable those test cases,
the user should ensure the required dependencies are met.  Below are a few
possible causes why tests may be skipped and how they may be resolved:

#. Optional external libraries are not found.
#. Config flags for the dependent library are not enabled.
#. Dependent driver modules are not installed on the system.

To help find missing libraries, the user can specify addition search paths
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

       $ CFLAGS=-I/path1 -I/path2 meson build

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
