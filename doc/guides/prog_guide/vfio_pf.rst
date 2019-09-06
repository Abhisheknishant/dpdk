..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(C) 2019 Marvell International Ltd.

.. _vfio_pf:

The DPDK VFIO_PF Kernel Module
------------------------------

The VFIO_PF kernel loadable module ``vfio_pf`` provides sysfs way of enabling
PCI VF devices when the PCI PF is bound to VFIO driver.

DPDK use case such as VF representer or OVS offload etc would call for PF
and VF PCIe devices to bind vfio-pci module to enable IOMMU protection.

In addition to vSwitch use case, unlike, other PCI class of devices, Network
class of PCIe devices would have additional responsibility on the PF devices
such as promiscuous mode support etc. The above use cases demand VFIO needs
bound to PF and its VF devices.

These use case is not supported in Linux kernel, due to a security issue
where it is possible to have DoS in case if VF attached to guest over vfio-pci
and netdev kernel driver runs on it and which something VF representer would
like to enable it.

The igb_uio enables such PF and VF binding support for non-iommu devices to
make VF representer or OVS offload run on non-iommu devices with DoS
vulnerability for netdev driver as VF.

This kernel module facilitate to enable SRIOV on PF devices, therefore, to run
both PF and VF devices in VFIO mode knowing its impacts like igb_uio driver
functions of non-iommu devices.

Example usage
-------------

Following example demonstrates enabling vfs on Marvell's Octeontx2 platform.
RVU PF devices PF1 & PF2 are probed on BDFs "0002:02:00.0" and "0002:03:00.0"
respectively. 2 VFs of each PF are enabled after followng the below procedure.

.. code-block:: console

    # echo "177d a063" >  /sys/bus/pci/drivers/vfio-pci/new_id
    # echo 0002:02:00.0 > /sys/bus/pci/devices/0002:02:00.0/driver/unbind
    # echo 0002:02:00.0 > /sys/bus/pci/drivers/vfio-pci/bind
    # echo 0002:03:00.0 > /sys/bus/pci/devices/0002:03:00.0/driver/unbind
    # echo 0002:03:00.0 > /sys/bus/pci/drivers/vfio-pci/bind

    # lspci -k
     0002:02:00.0 Ethernet controller: Cavium, Inc. Device a063 (rev 01)
        Subsystem: Cavium, Inc. Device b200
        Kernel driver in use: vfio-pci
     0002:03:00.0 Ethernet controller: Cavium, Inc. Device a063 (rev 01)
        Subsystem: Cavium, Inc. Device b200
        Kernel driver in use: vfio-pci

    # insmod build/kernel/linux/vfio_pf/vfio_pf.ko

    # echo 0002:02:00.0 > /sys/vfio_pf/add_device
    # echo 2 > /sys/vfio_pf/0002\:02\:00.0/num_vfs
    # echo 0002:03:00.0 > /sys/vfio_pf/add_device
    # echo 2 > /sys/vfio_pf/0002\:03\:00.0/num_vfs

    # lspci -k
     0002:02:00.0 Ethernet controller: Cavium, Inc. Device a063 (rev 01)
        Subsystem: Cavium, Inc. Device b200
        Kernel driver in use: vfio-pci
     0002:02:00.1 Ethernet controller: Cavium, Inc. Device a064 (rev 01)
        Subsystem: Cavium, Inc. Device b200
     0002:02:00.2 Ethernet controller: Cavium, Inc. Device a064 (rev 01)
        Subsystem: Cavium, Inc. Device b200
     0002:03:00.0 Ethernet controller: Cavium, Inc. Device a063 (rev 01)
        Subsystem: Cavium, Inc. Device b200
        Kernel driver in use: vfio-pci
     0002:03:00.1 Ethernet controller: Cavium, Inc. Device a064 (rev 01)
        Subsystem: Cavium, Inc. Device b200
     0002:03:00.2 Ethernet controller: Cavium, Inc. Device a064 (rev 01)
        Subsystem: Cavium, Inc. Device b200

    # echo 0 > /sys/vfio_pf/0002\:02\:00.0/num_vfs
    # echo 0002:02:00.0 > /sys/vfio_pf/remove_device
    # echo 0 > /sys/vfio_pf/0002\:03\:00.0/num_vfs
    # echo 0002:03:00.0 > /sys/vfio_pf/remove_device

    # rmmod build/kernel/linux/vfio_pf/vfio_pf.ko

Prerequisite
-------------

PCI PF device needs to be bound to VFIO driver before enabling VFs using
vfio_pf kernel module.
