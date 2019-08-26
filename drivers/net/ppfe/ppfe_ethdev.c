/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019 NXP
 */

#include <rte_kvargs.h>
#include <rte_ethdev_vdev.h>
#include <rte_bus_vdev.h>
#include <of.h>

#include "pfe_logs.h"
#include "pfe_mod.h"

#define PPFE_MAX_MACS 1 /*we can support upto 4 MACs per IF*/
#define PPFE_VDEV_GEM_ID_ARG	("intf")

struct pfe_vdev_init_params {
	int8_t	gem_id;
};
struct pfe *g_pfe;
unsigned int pfe_svr = SVR_LS1012A_REV1;

static void
pfe_soc_version_get(void)
{
	FILE *svr_file = NULL;
	unsigned int svr_ver = 0;

	PMD_INIT_FUNC_TRACE();

	svr_file = fopen(PFE_SOC_ID_FILE, "r");
	if (!svr_file) {
		PFE_PMD_ERR("Unable to open SoC device");
		return; /* Not supported on this infra */
	}

	if (fscanf(svr_file, "svr:%x", &svr_ver) > 0)
		pfe_svr = svr_ver;
	else
		PFE_PMD_ERR("Unable to read SoC device");

	fclose(svr_file);
}

static int
pfe_eth_open_cdev(struct pfe_eth_priv_s *priv)
{
	int pfe_cdev_fd;

	if (priv == NULL)
		return -1;

	pfe_cdev_fd = open(PFE_CDEV_PATH, O_RDONLY);
	if (pfe_cdev_fd < 0) {
		PFE_PMD_WARN("Unable to open PFE device file (%s).\n",
			     PFE_CDEV_PATH);
		PFE_PMD_WARN("Link status update will not be available.\n");
		priv->link_fd = PFE_CDEV_INVALID_FD;
		return -1;
	}

	priv->link_fd = pfe_cdev_fd;

	return 0;
}

static void
pfe_eth_close_cdev(struct pfe_eth_priv_s *priv)
{
	if (priv == NULL)
		return;

	if (priv->link_fd != PFE_CDEV_INVALID_FD) {
		close(priv->link_fd);
		priv->link_fd = PFE_CDEV_INVALID_FD;
	}
}

/* pfe_eth_exit
 */
static void
pfe_eth_exit(struct rte_eth_dev *dev, struct pfe *pfe)
{
	PMD_INIT_FUNC_TRACE();

	/* Close the device file for link status */
	pfe_eth_close_cdev(dev->data->dev_private);

	rte_eth_dev_release_port(dev);
	pfe->nb_devs--;
}

/* pfe_eth_init_one
 */
static int pfe_eth_init(struct rte_vdev_device *vdev, struct pfe *pfe, int id)
{
	struct rte_eth_dev_data *data = NULL;
	struct rte_eth_dev *eth_dev = NULL;
	struct pfe_eth_priv_s *priv = NULL;
	int err;

	if (id >= pfe->max_intf) {
		PFE_PMD_ERR("Requested intf (gemid) %d not supported Max is %d",
			id, pfe->max_intf);
		return -EINVAL;
	}

	data = rte_zmalloc(NULL, sizeof(*data), 64);
	if (data == NULL)
		return -ENOMEM;

	eth_dev = rte_eth_vdev_allocate(vdev, sizeof(*priv));
	if (eth_dev == NULL) {
		rte_free(data);
		return -ENOMEM;
	}

	priv = eth_dev->data->dev_private;
	rte_memcpy(data, eth_dev->data, sizeof(*data));

	priv->ndev = eth_dev;
	priv->pfe = pfe;

	pfe->eth.eth_priv[id] = priv;

#define HIF_GEMAC_TMUQ_BASE	6
	priv->low_tmu_q = HIF_GEMAC_TMUQ_BASE + (id * 2);
	priv->high_tmu_q = priv->low_tmu_q + 1;

	rte_spinlock_init(&priv->lock);

	/* Copy the station address into the dev structure, */
	eth_dev->data->mac_addrs = rte_zmalloc("mac_addr",
			ETHER_ADDR_LEN * PPFE_MAX_MACS, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		PFE_PMD_ERR("Failed to allocate mem %d to store MAC addresses",
			ETHER_ADDR_LEN * PPFE_MAX_MACS);
		err = -ENOMEM;
		goto err0;
	}

	eth_dev->data->mtu = 1500;

	eth_dev->data->nb_rx_queues = 1;
	eth_dev->data->nb_tx_queues = 1;

	/* For link status, open the PFE CDEV; Error from this function
	 * is silently ignored; In case of error, the link status will not
	 * be available.
	 */
	pfe_eth_open_cdev(priv);
	rte_eth_dev_probing_finish(eth_dev);

	return 0;
err0:
	rte_free(data);
	return err;
}

/* Parse integer from integer argument */
static int
parse_integer_arg(const char *key __rte_unused,
		const char *value, void *extra_args)
{
	int *i = (int *)extra_args;

	*i = atoi(value);
	if (*i < 0) {
		PFE_PMD_ERR("argument has to be positive.");
		return -1;
	}

	return 0;
}

static int
pfe_parse_vdev_init_params(struct pfe_vdev_init_params *params,
				struct rte_vdev_device *dev)
{
	struct rte_kvargs *kvlist = NULL;
	int ret = 0;

	static const char * const pfe_vdev_valid_params[] = {
		PPFE_VDEV_GEM_ID_ARG,
		NULL
	};

	const char *input_args = rte_vdev_device_args(dev);
	if (params == NULL)
		return -EINVAL;


	if (input_args) {
		kvlist = rte_kvargs_parse(input_args, pfe_vdev_valid_params);
		if (kvlist == NULL)
			return -1;

		ret = rte_kvargs_process(kvlist,
					PPFE_VDEV_GEM_ID_ARG,
					&parse_integer_arg,
					&params->gem_id);
		if (ret < 0)
			goto free_kvlist;
	}

free_kvlist:
	rte_kvargs_free(kvlist);
	return ret;
}

static int
pmd_pfe_probe(struct rte_vdev_device *vdev)
{
	const u32 *prop;
	const struct device_node *np;
	const char *name;
	const uint32_t *addr;
	uint64_t cbus_addr, ddr_size, cbus_size;
	int rc = -1, fd = -1, gem_id;
	unsigned int interface_count = 0;
	size_t size = 0;
	struct pfe_vdev_init_params init_params = {
		-1
	};

	name = rte_vdev_device_name(vdev);
	rc = pfe_parse_vdev_init_params(&init_params, vdev);
	if (rc < 0)
		return -EINVAL;

	RTE_LOG(INFO, PMD, "Initializing pmd_pfe for %s Given gem-id %d\n",
		name, init_params.gem_id);

	if (g_pfe) {
		if (g_pfe->nb_devs >= g_pfe->max_intf) {
			PFE_PMD_ERR("PPFE %d dev already created Max is %d",
				g_pfe->nb_devs, g_pfe->max_intf);
			return -EINVAL;
		}
		goto eth_init;
	}

	g_pfe = rte_zmalloc(NULL, sizeof(*g_pfe), 64);
	if (g_pfe == NULL)
		return  -EINVAL;

	/* Load the device-tree driver */
	rc = of_init();
	if (rc) {
		PFE_PMD_ERR("of_init failed with ret: %d", rc);
		goto err;
	}

	np = of_find_compatible_node(NULL, NULL, "fsl,pfe");
	if (!np) {
		PFE_PMD_ERR("Invalid device node");
		rc = -EINVAL;
		goto err;
	}

	addr = of_get_address(np, 0, &cbus_size, NULL);
	if (!addr) {
		PFE_PMD_ERR("of_get_address cannot return qman address\n");
		goto err;
	}
	cbus_addr = of_translate_address(np, addr);
	if (!cbus_addr) {
		PFE_PMD_ERR("of_translate_address failed\n");
		goto err;
	}

	addr = of_get_address(np, 1, &ddr_size, NULL);
	if (!addr) {
		PFE_PMD_ERR("of_get_address cannot return qman address\n");
		goto err;
	}

	g_pfe->ddr_phys_baseaddr = of_translate_address(np, addr);
	if (!g_pfe->ddr_phys_baseaddr) {
		PFE_PMD_ERR("of_translate_address failed\n");
		goto err;
	}

	g_pfe->ddr_size = ddr_size;

	fd = open("/dev/mem", O_RDWR);
	g_pfe->cbus_baseaddr = mmap(NULL, cbus_size, PROT_READ | PROT_WRITE,
					MAP_SHARED, fd, cbus_addr);
	if (g_pfe->cbus_baseaddr == MAP_FAILED) {
		PFE_PMD_ERR("Can not map cbus base");
		rc = -EINVAL;
		goto err;
	}

	/* Read interface count */
	prop = of_get_property(np, "fsl,pfe-num-interfaces", &size);
	if (!prop) {
		PFE_PMD_ERR("Failed to read number of interfaces");
		rc = -ENXIO;
		goto err_prop;
	}

	interface_count = rte_be_to_cpu_32((unsigned int)*prop);
	if (interface_count <= 0) {
		PFE_PMD_ERR("No ethernet interface count : %d",
				interface_count);
		rc = -ENXIO;
		goto err_prop;
	}
	PFE_PMD_INFO("num interfaces = %d ", interface_count);

	g_pfe->max_intf  = interface_count;
	pfe_soc_version_get();
eth_init:
	if (init_params.gem_id < 0)
		gem_id = g_pfe->nb_devs;
	else
		gem_id = init_params.gem_id;

	RTE_LOG(INFO, PMD, "Init pmd_pfe for %s gem-id %d(given =%d)\n",
		name, gem_id, init_params.gem_id);

	rc = pfe_eth_init(vdev, g_pfe, gem_id);
	if (rc < 0)
		goto err_eth;
	else
		g_pfe->nb_devs++;

	return 0;

err_eth:
err_prop:
err:
	rte_free(g_pfe);
	return rc;
}

static int
pmd_pfe_remove(struct rte_vdev_device *vdev)
{
	const char *name;
	struct rte_eth_dev *eth_dev = NULL;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	PFE_PMD_INFO("Closing eventdev sw device %s", name);

	if (!g_pfe)
		return 0;

	eth_dev = rte_eth_dev_allocated(name);
	if (eth_dev == NULL)
		return -ENODEV;

	pfe_eth_exit(eth_dev, g_pfe);

	return 0;
}

static struct rte_vdev_driver pmd_pfe_drv = {
	.probe = pmd_pfe_probe,
	.remove = pmd_pfe_remove,
};

RTE_PMD_REGISTER_VDEV(PFE_PMD, pmd_pfe_drv);
RTE_PMD_REGISTER_ALIAS(PFE_PMD, eth_pfe);
RTE_PMD_REGISTER_PARAM_STRING(PFE_PMD, "intf=<int> ");
