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
static int  ionic_dev_info_get(struct rte_eth_dev *eth_dev,
		struct rte_eth_dev_info *dev_info);
static int  ionic_dev_configure(struct rte_eth_dev *dev);
static int  ionic_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu);
static int  ionic_dev_start(struct rte_eth_dev *dev);
static void ionic_dev_stop(struct rte_eth_dev *dev);
static void ionic_dev_close(struct rte_eth_dev *dev);
static int  ionic_dev_set_link_up(struct rte_eth_dev *dev);
static int  ionic_dev_set_link_down(struct rte_eth_dev *dev);
static int  ionic_dev_link_update(struct rte_eth_dev *eth_dev,
		int wait_to_complete);

int ionic_logtype_init;
int ionic_logtype_driver;

static const struct rte_pci_id pci_id_ionic_map[] = {
	{ RTE_PCI_DEVICE(IONIC_PENSANDO_VENDOR_ID, IONIC_DEV_ID_ETH_PF) },
	{ RTE_PCI_DEVICE(IONIC_PENSANDO_VENDOR_ID, IONIC_DEV_ID_ETH_VF) },
	{ RTE_PCI_DEVICE(IONIC_PENSANDO_VENDOR_ID, IONIC_DEV_ID_ETH_MGMT) },
	{ .vendor_id = 0, /* sentinel */ },
};

static const struct eth_dev_ops ionic_eth_dev_ops = {
	.dev_infos_get          = ionic_dev_info_get,
	.dev_configure          = ionic_dev_configure,
	.mtu_set                = ionic_dev_mtu_set,
	.dev_start              = ionic_dev_start,
	.dev_stop               = ionic_dev_stop,
	.dev_close              = ionic_dev_close,
	.link_update            = ionic_dev_link_update,
	.dev_set_link_up        = ionic_dev_set_link_up,
	.dev_set_link_down      = ionic_dev_set_link_down,
};

/*
 * There is no room in struct rte_pci_driver to keep a reference
 * to the adapter, using a static list for the time being.
 */
static LIST_HEAD(ionic_pci_adapters_list, ionic_adapter) ionic_pci_adapters =
		LIST_HEAD_INITIALIZER(ionic_pci_adapters);
static rte_spinlock_t ionic_pci_adapters_lock = RTE_SPINLOCK_INITIALIZER;

/*
 * Set device link up, enable tx.
 */
static int
ionic_dev_set_link_up(struct rte_eth_dev *eth_dev)
{
	struct ionic_lif *lif = IONIC_ETH_DEV_TO_LIF(eth_dev);
	struct ionic_adapter *adapter = lif->adapter;
	struct ionic_dev *idev = &adapter->idev;
	int err;

	ionic_init_print_call();

	ionic_dev_cmd_port_state(idev, IONIC_PORT_ADMIN_STATE_UP);

	err = ionic_dev_cmd_wait_check(idev, IONIC_DEVCMD_TIMEOUT);

	if (err) {
		ionic_init_print(WARNING, "Failed to bring port UP\n");
		return err;
	}

	return 0;
}

/*
 * Set device link down, disable tx.
 */
static int
ionic_dev_set_link_down(struct rte_eth_dev *eth_dev)
{
	struct ionic_lif *lif = IONIC_ETH_DEV_TO_LIF(eth_dev);
	struct ionic_adapter *adapter = lif->adapter;
	struct ionic_dev *idev = &adapter->idev;
	int err;

	ionic_init_print_call();

	ionic_dev_cmd_port_state(idev, IONIC_PORT_ADMIN_STATE_DOWN);

	err = ionic_dev_cmd_wait_check(idev, IONIC_DEVCMD_TIMEOUT);

	if (err) {
		ionic_init_print(WARNING, "Failed to bring port DOWN\n");
		return err;
	}

	return 0;
}

static int
ionic_dev_link_update(struct rte_eth_dev *eth_dev,
		int wait_to_complete __rte_unused)
{
	struct ionic_lif *lif = IONIC_ETH_DEV_TO_LIF(eth_dev);
	struct ionic_adapter *adapter = lif->adapter;
	struct rte_eth_link link;

	ionic_init_print_call();

	/* Initialize */
	memset(&link, 0, sizeof(link));
	link.link_autoneg = ETH_LINK_AUTONEG;

	if (!adapter->link_up) {
		/* Interface is down */
		link.link_status = ETH_LINK_DOWN;
		link.link_duplex = ETH_LINK_HALF_DUPLEX;
		link.link_speed = ETH_SPEED_NUM_NONE;
	} else {
		/* Interface is up */
		link.link_status = ETH_LINK_UP;
		link.link_duplex = ETH_LINK_FULL_DUPLEX;
		switch (adapter->link_speed) {
		case  10000:
			link.link_speed = ETH_SPEED_NUM_10G;
			break;
		case  25000:
			link.link_speed = ETH_SPEED_NUM_25G;
			break;
		case  40000:
			link.link_speed = ETH_SPEED_NUM_40G;
			break;
		case  50000:
			link.link_speed = ETH_SPEED_NUM_50G;
			break;
		case 100000:
			link.link_speed = ETH_SPEED_NUM_100G;
			break;
		default:
			link.link_speed = ETH_SPEED_NUM_NONE;
			break;
		}
	}

	return rte_eth_linkstatus_set(eth_dev, &link);
}

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
	struct ionic_adapter *adapter = (struct ionic_adapter *) param;
	uint32_t i;

	ionic_drv_print(DEBUG, "->");

	for (i = 0; i < adapter->nlifs; i++) {
		if (adapter->lifs[i])
			ionic_notifyq_handler(adapter->lifs[i], -1);
	}
}

static int
ionic_dev_mtu_set(struct rte_eth_dev *eth_dev, uint16_t mtu)
{
	struct ionic_lif *lif = IONIC_ETH_DEV_TO_LIF(eth_dev);
	/*
	 * Size = MTU + Ethernet header + VLAN + QinQ
	 * Also add ETHER_CRC_LEN if the adapter is able to keep CRC
	 */
	uint32_t frame_size = mtu + RTE_ETHER_HDR_LEN + 4 + 4;
	int err;

	ionic_init_print_call();

	/* Check that mtu is within the allowed range */
	if (mtu < IONIC_MIN_MTU || mtu > IONIC_MAX_MTU)
		return -EINVAL;

	err = ionic_lif_change_mtu(lif, mtu);

	if (err)
		return err;

	/* Update max frame size */
	eth_dev->data->dev_conf.rxmode.max_rx_pkt_len = frame_size;

	return 0;
}

static int
ionic_dev_info_get(struct rte_eth_dev *eth_dev,
		struct rte_eth_dev_info *dev_info)
{
	struct ionic_lif *lif = IONIC_ETH_DEV_TO_LIF(eth_dev);
	struct ionic_adapter *adapter = lif->adapter;
	struct ionic_identity *ident = &adapter->ident;

	ionic_init_print_call();

	dev_info->max_rx_queues = (uint16_t)
		ident->lif.eth.config.queue_count[IONIC_QTYPE_RXQ];
	dev_info->max_tx_queues = (uint16_t)
		ident->lif.eth.config.queue_count[IONIC_QTYPE_TXQ];
	/* Also add ETHER_CRC_LEN if the adapter is able to keep CRC */
	dev_info->min_rx_bufsize = IONIC_MIN_MTU + RTE_ETHER_HDR_LEN;
	dev_info->max_rx_pktlen = IONIC_MAX_MTU + RTE_ETHER_HDR_LEN;
	dev_info->max_mac_addrs = adapter->max_mac_addrs;

	dev_info->speed_capa =
		ETH_LINK_SPEED_10G |
		ETH_LINK_SPEED_25G |
		ETH_LINK_SPEED_40G |
		ETH_LINK_SPEED_50G |
		ETH_LINK_SPEED_100G;

	return 0;
}

static int
ionic_dev_configure(struct rte_eth_dev *eth_dev)
{
	struct ionic_lif *lif = IONIC_ETH_DEV_TO_LIF(eth_dev);
	int err;

	ionic_init_print_call();

	err = ionic_lif_configure(lif);

	if (err) {
		ionic_drv_print(ERR, "Cannot configure LIF: %d", err);
		return err;
	}

	return 0;
}

static inline uint32_t
ionic_parse_link_speeds(uint16_t link_speeds)
{
	if (link_speeds & ETH_LINK_SPEED_100G)
		return 100000;
	else if (link_speeds & ETH_LINK_SPEED_50G)
		return 50000;
	else if (link_speeds & ETH_LINK_SPEED_40G)
		return 40000;
	else if (link_speeds & ETH_LINK_SPEED_25G)
		return 25000;
	else if (link_speeds & ETH_LINK_SPEED_10G)
		return 10000;
	else
		return 0;
}

/*
 * Configure device link speed and setup link.
 * It returns 0 on success.
 */
static int
ionic_dev_start(struct rte_eth_dev *eth_dev)
{
	struct ionic_lif *lif = IONIC_ETH_DEV_TO_LIF(eth_dev);
	struct ionic_adapter *adapter = lif->adapter;
	struct ionic_dev *idev = &adapter->idev;
	uint32_t allowed_speeds;
	int err;

	ionic_init_print_call();

	err = ionic_lif_start(lif);

	if (err) {
		ionic_drv_print(ERR, "Cannot start LIF: %d", err);
		return err;
	}

	if (eth_dev->data->dev_conf.link_speeds & ETH_LINK_SPEED_FIXED) {
		uint32_t speed = ionic_parse_link_speeds(eth_dev->data->dev_conf.link_speeds);

		if (speed)
			ionic_dev_cmd_port_speed(idev, speed);
	}

	allowed_speeds =
		ETH_LINK_SPEED_FIXED |
		ETH_LINK_SPEED_10G |
		ETH_LINK_SPEED_25G |
		ETH_LINK_SPEED_40G |
		ETH_LINK_SPEED_50G |
		ETH_LINK_SPEED_100G;

	if (eth_dev->data->dev_conf.link_speeds & ~allowed_speeds) {
		ionic_init_print(ERR, "Invalid link setting");
		return -EINVAL;
	}

	ionic_dev_link_update(eth_dev, 0);

	return 0;
}

/*
 * Stop device: disable rx and tx functions to allow for reconfiguring.
 */
static void
ionic_dev_stop(struct rte_eth_dev *eth_dev)
{
	struct ionic_lif *lif = IONIC_ETH_DEV_TO_LIF(eth_dev);
	int err;

	ionic_init_print_call();

	err = ionic_lif_stop(lif);

	if (err) {
		ionic_drv_print(ERR, "Cannot stop LIF: %d", err);
		return;
	}
}

/*
 * Reset and stop device.
 */
static void
ionic_dev_close(struct rte_eth_dev *eth_dev)
{
	struct ionic_lif *lif = IONIC_ETH_DEV_TO_LIF(eth_dev);
	int err;

	ionic_init_print_call();

	err = ionic_lif_stop(lif);

	if (err) {
		ionic_drv_print(ERR, "Cannot stop LIF: %d", err);
		return;
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

	ionic_init_print(DEBUG, "Up to %u MAC addresses supported",
			adapter->max_mac_addrs);

	/* Allocate memory for storing MAC addresses */
	eth_dev->data->mac_addrs = rte_zmalloc("ionic",
			RTE_ETHER_ADDR_LEN * adapter->max_mac_addrs, 0);

	if (eth_dev->data->mac_addrs == NULL) {
		ionic_init_print(ERR, "Failed to allocate %u bytes needed to "
				"store MAC addresses",
				RTE_ETHER_ADDR_LEN * adapter->max_mac_addrs);
		return -ENOMEM;
	}

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

	/* Copy the MAC address */
	rte_ether_addr_copy((struct rte_ether_addr *)lif->mac_addr,
			&eth_dev->data->mac_addrs[0]);

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

	adapter->max_mac_addrs = adapter->ident.lif.eth.max_ucast_filters;

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
