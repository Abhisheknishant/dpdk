/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include <rte_malloc.h>

#include "nitrox_device.h"
#include "nitrox_hal.h"

TAILQ_HEAD(ndev_list, nitrox_device);
static struct ndev_list ndev_list = TAILQ_HEAD_INITIALIZER(ndev_list);

static struct nitrox_device *
ndev_allocate(struct rte_pci_device *pdev)
{
	struct nitrox_device *ndev;

	ndev = rte_zmalloc_socket("nitrox device", sizeof(*ndev),
				   RTE_CACHE_LINE_SIZE,
				   pdev->device.numa_node);
	if (!ndev)
		return NULL;

	TAILQ_INSERT_TAIL(&ndev_list, ndev, next);
	return ndev;
}

static void
ndev_init(struct nitrox_device *ndev, struct rte_pci_device *pdev)
{
	enum nitrox_vf_mode vf_mode;

	ndev->pdev = pdev;
	ndev->bar_addr = pdev->mem_resource[0].addr;
	vf_mode = vf_get_vf_config_mode(ndev->bar_addr);
	ndev->nr_queues = vf_config_mode_to_nr_queues(vf_mode);
}

static struct nitrox_device *
find_ndev(struct rte_pci_device *pdev)
{
	struct nitrox_device *ndev;

	TAILQ_FOREACH(ndev, &ndev_list, next)
		if (ndev->pdev == pdev)
			return ndev;

	return NULL;
}

static void
ndev_release(struct nitrox_device *ndev)
{
	if (!ndev)
		return;

	TAILQ_REMOVE(&ndev_list, ndev, next);
	rte_free(ndev);
}

static int
nitrox_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
		struct rte_pci_device *pdev)
{
	struct nitrox_device *ndev;

	/* Nitrox CSR space */
	if (!pdev->mem_resource[0].addr)
		return -EINVAL;

	ndev = ndev_allocate(pdev);
	if (!ndev)
		return -ENOMEM;

	ndev_init(ndev, pdev);
	return 0;
}

static int
nitrox_pci_remove(struct rte_pci_device *pdev)
{
	struct nitrox_device *ndev;

	ndev = find_ndev(pdev);
	if (!ndev)
		return -ENODEV;

	ndev_release(ndev);
	return 0;
}

static struct rte_pci_id pci_id_nitrox_map[] = {
	{
		/* Nitrox 5 VF */
		RTE_PCI_DEVICE(0x177d, 0x13)
	},
	{.device_id = 0},
};

static struct rte_pci_driver nitrox_pmd = {
	.id_table       = pci_id_nitrox_map,
	.drv_flags      = RTE_PCI_DRV_NEED_MAPPING,
	.probe          = nitrox_pci_probe,
	.remove         = nitrox_pci_remove,
};

RTE_PMD_REGISTER_PCI(nitrox, nitrox_pmd);
RTE_PMD_REGISTER_PCI_TABLE(nitrox, pci_id_nitrox_map);
