/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include <stdbool.h>

#include <rte_cryptodev_pmd.h>
#include <rte_crypto.h>

#include "nitrox_sym.h"
#include "nitrox_device.h"
#include "nitrox_logs.h"

#define CRYPTODEV_NAME_NITROX_PMD crypto_nitrox

struct nitrox_sym_device {
	struct rte_cryptodev *cdev;
	struct nitrox_device *ndev;
};

uint8_t nitrox_sym_drv_id;
static const char nitrox_sym_drv_name[] = RTE_STR(CRYPTODEV_NAME_NITROX_PMD);
static const struct rte_driver nitrox_rte_sym_drv = {
	.name = nitrox_sym_drv_name,
	.alias = nitrox_sym_drv_name
};

int
nitrox_sym_pmd_create(struct nitrox_device *ndev)
{
	char name[NITROX_DEV_NAME_MAX_LEN];
	struct rte_cryptodev_pmd_init_params init_params = {
			.name = "",
			.socket_id = ndev->pdev->device.numa_node,
			.private_data_size = sizeof(struct nitrox_sym_device)
	};
	struct rte_cryptodev *cdev;

	rte_pci_device_name(&ndev->pdev->addr, name, sizeof(name));
	snprintf(name + strlen(name), NITROX_DEV_NAME_MAX_LEN, "_n5sym");
	ndev->rte_sym_dev.driver = &nitrox_rte_sym_drv;
	ndev->rte_sym_dev.numa_node = ndev->pdev->device.numa_node;
	ndev->rte_sym_dev.devargs = NULL;
	cdev = rte_cryptodev_pmd_create(name, &ndev->rte_sym_dev,
					&init_params);
	if (!cdev) {
		NITROX_LOG(ERR, "Cryptodev '%s' creation failed\n", name);
		return -ENODEV;
	}

	ndev->rte_sym_dev.name = cdev->data->name;
	cdev->driver_id = nitrox_sym_drv_id;
	cdev->dev_ops = NULL;
	cdev->enqueue_burst = NULL;
	cdev->dequeue_burst = NULL;
	cdev->feature_flags = RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO |
		RTE_CRYPTODEV_FF_HW_ACCELERATED |
		RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING |
		RTE_CRYPTODEV_FF_IN_PLACE_SGL |
		RTE_CRYPTODEV_FF_OOP_SGL_IN_SGL_OUT |
		RTE_CRYPTODEV_FF_OOP_SGL_IN_LB_OUT |
		RTE_CRYPTODEV_FF_OOP_LB_IN_SGL_OUT |
		RTE_CRYPTODEV_FF_OOP_LB_IN_LB_OUT;

	ndev->sym_dev = cdev->data->dev_private;
	ndev->sym_dev->cdev = cdev;
	ndev->sym_dev->ndev = ndev;
	NITROX_LOG(DEBUG, "Created cryptodev '%s', dev_id %d, drv_id %d\n",
		   cdev->data->name, cdev->data->dev_id, nitrox_sym_drv_id);
	return 0;
}

int
nitrox_sym_pmd_destroy(struct nitrox_device *ndev)
{
	rte_cryptodev_pmd_destroy(ndev->sym_dev->cdev);
	return 0;
}

static struct cryptodev_driver nitrox_crypto_drv;
RTE_PMD_REGISTER_CRYPTO_DRIVER(nitrox_crypto_drv,
		nitrox_rte_sym_drv,
		nitrox_sym_drv_id);
