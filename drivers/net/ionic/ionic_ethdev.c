/* SPDX-License-Identifier: GPL-2.0
 * Copyright(c) 2018-2019 Pensando Systems, Inc. All rights reserved.
 */

#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_ethdev.h>
#include <rte_ethdev_driver.h>
#include <rte_malloc.h>
#include <rte_ethdev_pci.h>

#include "ionic_logs.h"
#include "ionic.h"
#include "ionic_dev.h"
#include "ionic_mac_api.h"
#include "ionic_lif.h"
#include "ionic_ethdev.h"

static int  eth_ionic_dev_init(struct rte_eth_dev *eth_dev, void *init_params);
static int  eth_ionic_dev_uninit(struct rte_eth_dev *eth_dev);

int ionic_logtype_init;
int ionic_logtype_driver;

static const struct rte_pci_id pci_id_ionic_map[] = {
	{ RTE_PCI_DEVICE(IONIC_PENSANDO_VENDOR_ID, IONIC_DEV_ID_ETH_PF) },
	{ RTE_PCI_DEVICE(IONIC_PENSANDO_VENDOR_ID, IONIC_DEV_ID_ETH_VF) },
	{ RTE_PCI_DEVICE(IONIC_PENSANDO_VENDOR_ID, IONIC_DEV_ID_ETH_MGMT) },
	{ .vendor_id = 0, /* sentinel */ },
};

static const struct eth_dev_ops ionic_eth_dev_ops = {
};

/*
 * There is no room in struct rte_pci_driver to keep a reference
 * to the adapter, using a static list for the time being.
 */
static LIST_HEAD(ionic_pci_adapters_list, ionic_adapter) ionic_pci_adapters =
		LIST_HEAD_INITIALIZER(ionic_pci_adapters);
static rte_spinlock_t ionic_pci_adapters_lock = RTE_SPINLOCK_INITIALIZER;

/**
 * Interrupt handler triggered by NIC for handling
 * specific interrupt.
 *
 * @param param
 *  The address of parameter regsitered before.
 *
 * @return
 *  void
 */
static void
ionic_dev_interrupt_handler(void *param)
{
	struct ionic_adapter *adapter = (struct ionic_adapter *)param;
	uint32_t i;

	ionic_drv_print(DEBUG, "->");

	for (i = 0; i < adapter->nlifs; i++) {
		if (adapter->lifs[i])
			ionic_notifyq_handler(adapter->lifs[i], -1);
	}
}

static int
eth_ionic_dev_init(struct rte_eth_dev *eth_dev, void *init_params)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct ionic_lif *lif = IONIC_ETH_DEV_TO_LIF(eth_dev);
	struct ionic_adapter *adapter = (struct ionic_adapter *)init_params;
	int err;

	ionic_init_print_call();

	eth_dev->dev_ops = &ionic_eth_dev_ops;

	/* Multi-process not supported, primary does initialization anyway */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	rte_eth_copy_pci_info(eth_dev, pci_dev);

	lif->index = adapter->nlifs;
	lif->eth_dev = eth_dev;
	lif->adapter = adapter;
	adapter->lifs[adapter->nlifs] = lif;

	err = ionic_lif_alloc(lif);

	if (err) {
		ionic_init_print(ERR, "Cannot allocate LIFs: %d, aborting",
				err);
		return err;
	}

	err = ionic_lif_init(lif);

	if (err) {
		ionic_init_print(ERR, "Cannot init LIFs: %d, aborting", err);
		return err;
	}

	ionic_init_print(DEBUG, "Port %u initialized", eth_dev->data->port_id);

	return 0;
}

static int
eth_ionic_dev_uninit(struct rte_eth_dev *eth_dev)
{
	struct ionic_lif *lif = IONIC_ETH_DEV_TO_LIF(eth_dev);
	struct ionic_adapter *adapter = lif->adapter;

	ionic_init_print_call();

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	adapter->lifs[lif->index] = NULL;

	ionic_lif_deinit(lif);
	ionic_lif_free(lif);

	eth_dev->dev_ops = NULL;

	return 0;
}

static int
ionic_configure_intr(struct ionic_adapter *adapter)
{
	struct rte_pci_device *pci_dev = adapter->pci_dev;
	struct rte_intr_handle *intr_handle = &pci_dev->intr_handle;
	int err;

	ionic_init_print(DEBUG, "Configuring %u intrs", adapter->nintrs);

	if (rte_intr_efd_enable(intr_handle, adapter->nintrs)) {
		ionic_init_print(ERR, "Fail to create eventfd");
		return -1;
	}

	if (rte_intr_dp_is_en(intr_handle))
		ionic_init_print(DEBUG,
				"Packet I/O interrupt on datapath is enabled");

	if (!intr_handle->intr_vec) {
		intr_handle->intr_vec = rte_zmalloc("intr_vec",
			adapter->nintrs * sizeof(int), 0);

		if (!intr_handle->intr_vec) {
			ionic_init_print(ERR, "Failed to allocate %u vectors",
				adapter->nintrs);
			return -ENOMEM;
		}
	}

	err = rte_intr_callback_register(intr_handle,
			ionic_dev_interrupt_handler,
			adapter);

	if (err) {
		ionic_init_print(ERR,
				"Failure registering interrupts handler (%d)",
				err);
		return err;
	}

	/* enable intr mapping */
	err = rte_intr_enable(intr_handle);

	if (err) {
		ionic_init_print(ERR, "Failure enabling interrupts (%d)", err);
		return err;
	}

	return 0;
}

static void
ionic_unconfigure_intr(struct ionic_adapter *adapter)
{
	struct rte_pci_device *pci_dev = adapter->pci_dev;
	struct rte_intr_handle *intr_handle = &pci_dev->intr_handle;

	rte_intr_disable(intr_handle);

	rte_intr_callback_unregister(intr_handle,
			ionic_dev_interrupt_handler,
			adapter);
}

static int
eth_ionic_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
		struct rte_pci_device *pci_dev)
{
	char name[RTE_ETH_NAME_MAX_LEN];
	struct rte_mem_resource *resource;
	struct ionic_adapter *adapter;
	struct ionic_hw *hw;
	unsigned long i;
	int err;

	/* Multi-process not supported */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return -EPERM;

	ionic_init_print(DEBUG, "Initializing device %s %s",
			pci_dev->device.name,
			rte_eal_process_type() == RTE_PROC_SECONDARY ?
			"[SECONDARY]" : "");

	adapter = rte_zmalloc("ionic", sizeof(*adapter), 0);

	if (!adapter) {
		ionic_init_print(ERR, "OOM");
		return -ENOMEM;
	}

	adapter->pci_dev = pci_dev;
	hw = &adapter->hw;

	hw->device_id = pci_dev->id.device_id;
	hw->vendor_id = pci_dev->id.vendor_id;

	err = ionic_init_mac(hw);
	if (err != 0) {
		ionic_init_print(ERR, "Mac init failed: %d", err);
		return -EIO;
	}

	adapter->is_mgmt_nic = (pci_dev->id.device_id == IONIC_DEV_ID_ETH_MGMT);

	adapter->num_bars = 0;
	for (i = 0; i < PCI_MAX_RESOURCE && i < IONIC_BARS_MAX; i++) {
		resource = &pci_dev->mem_resource[i];
		if (resource->phys_addr == 0 || resource->len == 0)
			continue;
		adapter->bars[adapter->num_bars].vaddr = resource->addr;
		adapter->bars[adapter->num_bars].bus_addr = resource->phys_addr;
		adapter->bars[adapter->num_bars].len = resource->len;
		adapter->num_bars++;
	}

	/* Discover ionic dev resources */

	err = ionic_setup(adapter);
	if (err) {
		ionic_init_print(ERR, "Cannot setup device: %d, aborting", err);
		return err;
	}

	err = ionic_identify(adapter);
	if (err) {
		ionic_init_print(ERR, "Cannot identify device: %d, aborting",
				err);
		return err;
	}

	err = ionic_init(adapter);
	if (err) {
		ionic_init_print(ERR, "Cannot init device: %d, aborting", err);
		return err;
	}

	/* Configure the ports */
	err = ionic_port_identify(adapter);

	if (err) {
		ionic_init_print(ERR, "Cannot identify port: %d, aborting\n",
				err);
		return err;
	}

	err = ionic_port_init(adapter);

	if (err) {
		ionic_init_print(ERR, "Cannot init port: %d, aborting\n", err);
		return err;
	}

	/* Configure LIFs */
	err = ionic_lif_identify(adapter);

	if (err) {
		ionic_init_print(ERR, "Cannot identify lif: %d, aborting", err);
		return err;
	}

	/* Allocate and init LIFs */
	err = ionic_lifs_size(adapter);

	if (err) {
		ionic_init_print(ERR, "Cannot size LIFs: %d, aborting", err);
		return err;
	}

	adapter->nlifs = 0;
	for (i = 0; i < adapter->ident.dev.nlifs; i++) {
		snprintf(name, sizeof(name), "net_%s_lif_%lu",
			pci_dev->device.name, i);

		err = rte_eth_dev_create(&pci_dev->device, name,
			sizeof(struct ionic_lif),
			NULL, NULL,
			eth_ionic_dev_init, adapter);

		if (err) {
			ionic_init_print(ERR, "Cannot create eth device for "
					"ionic lif %s", name);
			break;
		}

		adapter->nlifs++;
	}

	err = ionic_configure_intr(adapter);

	if (err) {
		ionic_init_print(ERR, "Failed to configure interrupts");
		return err;
	}

	rte_spinlock_lock(&ionic_pci_adapters_lock);
	LIST_INSERT_HEAD(&ionic_pci_adapters, adapter, pci_adapters);
	rte_spinlock_unlock(&ionic_pci_adapters_lock);

	return 0;
}

static int
eth_ionic_pci_remove(struct rte_pci_device *pci_dev)
{
	struct ionic_adapter *adapter = NULL;
	struct ionic_lif *lif;
	uint32_t i;

	rte_spinlock_lock(&ionic_pci_adapters_lock);
	LIST_FOREACH(adapter, &ionic_pci_adapters, pci_adapters) {
		if (adapter->pci_dev == pci_dev)
			break;

		adapter = NULL;
	}
	if (adapter)
		LIST_REMOVE(adapter, pci_adapters);
	rte_spinlock_unlock(&ionic_pci_adapters_lock);

	if (adapter) {
		ionic_unconfigure_intr(adapter);

		for (i = 0; i < adapter->nlifs; i++) {
			lif = adapter->lifs[i];
			rte_eth_dev_destroy(lif->eth_dev, eth_ionic_dev_uninit);
		}

		rte_free(adapter);
	}

	return 0;
}

static struct rte_pci_driver rte_ionic_pmd = {
	.id_table = pci_id_ionic_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe = eth_ionic_pci_probe,
	.remove = eth_ionic_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_ionic, rte_ionic_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_ionic, pci_id_ionic_map);
RTE_PMD_REGISTER_KMOD_DEP(net_ionic, "* igb_uio | uio_pci_generic | vfio-pci");

RTE_INIT(ionic_init_log)
{
	ionic_logtype_init = rte_log_register("pmd.net.ionic.init");

	if (ionic_logtype_init >= 0)
		rte_log_set_level(ionic_logtype_init, RTE_LOG_NOTICE);

	ionic_struct_size_checks();

	ionic_logtype_driver = rte_log_register("pmd.net.ionic.driver");

	if (ionic_logtype_driver >= 0)
		rte_log_set_level(ionic_logtype_driver, RTE_LOG_NOTICE);
}
