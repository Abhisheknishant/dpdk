..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2019 Intel Corporation.

Enable DPDK on openwrt
======================

This document describes how to enable Data Plane Development Kit(DPDK) on
OpenWrt in both virtual and physical machine.

Introduction
------------

The OpenWrt project is a Linux operating system targeting embedded devices.
Instead of trying to create a single, static firmware, OpenWrt provides a fully
writable filesystem with package management. This frees user from the
application selection and configuration provided by the vendor and allows user
to customize the device through the use of packages to suit any application. For
developers, OpenWrt is the framework to build and application without having to
build a complete firmware around it, for users this means the ability for full
customization, to use the device in ways never envisioned.

Pre-requisites
~~~~~~~~~~~~~~

You need gcc, binutils, bzip2, flex, python3.5+, perl, make, find, grep, diff,
unzip, gawk, getopt, subversion, libz-dev and libc headers installed.

Build OpenWrt
-------------

You can obtain OpenWrt image through https://downloads.openwrt.org/releases. To
fully customize your own OpenWrt, it is highly recommended to build it through
the source code, you can clone the OpenWrt source code by:

.. code-block:: console

	git clone https://git.openwrt.org/openwrt/openwrt.git

OpenWrt configuration
~~~~~~~~~~~~~~~~~~~~~

You need to specify the Traget System & Subtarget through OpenWrt configuration,
take x86_64 for example, you need to:

* Select ``x86`` in ``Target System``
* Select ``x86_64`` in ``Subtarget``
* Select ``Build the OpenWrt SDK`` for cross-compilation environment
* Select ``Use glibc`` in ``Advanced configuration options (for developers)``
			   -> ``ToolChain Options``
			   -> ``C Library implementation``

Kernel configuration
~~~~~~~~~~~~~~~~~~~~

Below configurations need to be enabled:

* CONFIG_UIO=y
* CONFIG_HUGETLBFS=y
* CONFIG_HUGETLB_PAGE=y
* CONFIG_PAGE_MONITOR=y

Build steps
~~~~~~~~~~~

For detailed OpenWrt build steps, please refer to guide in its official site.

`OpenWrt build guide
<https://openwrt.org/docs/guide-developer/build-system/use-buildsystem>`_.

After build is done, you can find the images and sdk in ``<OpenWrt Root>/bin/targets/x86/64-glibc/``.

DPDK Cross Compilation for OpenWrt
----------------------------------

Pre-requisites
~~~~~~~~~~~~~~

NUMA is required to run dpdk in x86.

.. note::

	For compiling the NUMA lib, run libtool --version to ensure the libtool version >= 2.2,
otherwise the compilation will fail with errors.

.. code-block:: console

	git clone https://github.com/numactl/numactl.git
	cd numactl
	git checkout v2.0.13 -b v2.0.13
	./autogen.sh
	autoconf -i
	export PATH=<OpenWrt sdk>/glibc/openwrt-sdk-x86-64_gcc-8.3.0_glibc.Linux-x86_64/staging_dir/toolchain-x86_64_gcc-8.3.0_glibc/bin/:$PATH
	./configure CC=x86_64-openwrt-linux-gnu-gcc --prefix=<OpenWrt SDK toolchain dir>
	make install

The numa header files and lib file is generated in the include and lib folder respectively under <OpenWrt SDK toolchain dir>.

Build DPDK
~~~~~~~~~~

* meson build

To cross compile with meson build, you need to write customized cross file first.

.. code-block:: console

	[binaries]
	c = 'x86_64-openwrt-linux-gcc'
	cpp = 'x86_64-openwrt-linux-cpp'
	ar = 'x86_64-openwrt-linux-ar'
	strip = 'x86_64-openwrt-linux-strip'

	meson builddir --cross-file openwrt-cross
	ninja -C builddir

.. note::

	For compiling the igb_uio with the kernel version used in target machine, you need to explicitly specify kernel_dir in meson_options.txt.

* make

.. code-block:: console

	export STAGING_DIR=<OpenWrt sdk>/glibc/openwrt-sdk-x86-64_gcc-8.3.0_glibc.Linux-x86_64/staging_dir
	export RTE_SDK=`pwd`
	export RTE_KERNELDIR=<OpenWrt Root>/build_dir/target-x86_64_glibc/linux-x86_64/linux-4.19.81/
	make config T=x86_64-native-linuxapp-gcc
	make -j 100 CROSS=x86_64-openwrt-linux-gnu-

Running DPDK application on OpenWrt
-----------------------------------

Virtual machine
~~~~~~~~~~~~~~~

* Extract boot image

.. code-block:: console

	gzip -d openwrt-x86-64-combined-ext4.img.gz

* Launch Qemu

.. code-block:: console

	qemu-system-x86_64 \
	        -cpu host \
	        -smp 8 \
	        -enable-kvm \
	        -M q35 \
	        -m 2048M \
	        -object memory-backend-file,id=mem,size=2048M,mem-path=/tmp/hugepages,share=on \
	        -drive file=<Your OpenWrt images folder>/openwrt-x86-64-combined-ext4.img,id=d0,if=none,bus=0,unit=0 \
	        -device ide-hd,drive=d0,bus=ide.0 \
	        -net nic,vlan=0 \
	        -net nic,vlan=1 \
	        -net user,vlan=1 \
	        -display none \


Physical machine
~~~~~~~~~~~~~~~~

If you are using Windows PC, you can use some free and opensource raw disk image writer program such as
``Win32 Disk Imager`` and ``Etcher`` to write OpenWrt image (openwrt-x86-64-combined-ext4.img) to a USB
flash driver or USB SDcard with SDcard or a Sata hard drivre or SSD from your PC.

If you are using Linux, you can use old dd tool to write OpenWrt image to the drive you want to write the
image on.

.. code-block:: console

	dd if=openwrt-18.06.1-x86-64-combined-squashfs.img of=/dev/sdX

Where sdX is name of the drive. (You can find it though ``fdisk -l``)

Running DPDK
~~~~~~~~~~~~

More detailed info about how to run a DPDK application please refer to ``Running DPDK Applications`` section of :ref:`the DPDK documentation <linux_gsg>`.

.. note::

	You need to install pre-built numa libraries (including soft link) to /usr/lib64 in OpenWrt.
