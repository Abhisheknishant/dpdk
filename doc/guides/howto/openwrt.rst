..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2019 Intel Corporation.

Enable DPDK on openwrt
======================

This document describes how to enable Data Plane Development Kit(DPDK) on
Openwrt in both virtual and physical x86 environment.

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

1. Run ``./scripts/feeds update -a`` to obtain all the latest package definitions
defined in feeds.conf / feeds.conf.default

2. Run ``./scripts/feeds install -a`` to install symlinks for all obtained
packages into package/feeds/

3. Run ``make menuconfig`` to select preferred configuration mentioned above for
the toolchain, target system & firmware packages.

3. Run ``make kernel_menuconfig`` to select preferred kernel configurations.

4. Run ``make`` to build your firmware. This will download all sources, build
the cross-compile toolchain and then cross-compile the Linux kernel & all
chosen applications for your target system.

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

Installation

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

* Setup dpdk environment

  * Scp built numa libraries (including soft link) to /usr/lib64
  * Setup hugepages
  * insmod igb_uio.ko (scp the built igb_uio.ko first)
  * Bind the NIC to igb_uio.ko

* Launch testpmd

  * scp built testpmd to qemu
  * ./testpmd -c 0xf -- -i

 More detailed info about how to run a DPDK application refer to ``Running DPDK Applications`` section of :ref:`the DPDK documentation <linux_gsg>`.
