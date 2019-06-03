/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_bus_pci.h>
#include <rte_ethdev_driver.h>

#include "base/hinic_pmd_dpdev.h"
#include "hinic_pmd_ethdev.h"

#define DEFAULT_BASE_COS	(4)
#define NR_MAX_COS		(8)
#define HINIC_HASH_FUNC rte_jhash
#define HINIC_HASH_KEY_LEN (sizeof(dma_addr_t))
#define HINIC_HASH_FUNC_INIT_VAL	(0)
#define HINIC_SERVICE_MODE_OVS		(0)

/* dma pool */
struct dma_pool {
	u32 inuse;
	size_t elem_size;
	size_t align;
	size_t boundary;
	void *nic_dev;

	char name[32];
};

static int hinic_osdep_init(struct hinic_nic_dev *nic_dev)
{
	struct rte_hash_parameters dh_params = { 0 };
	struct rte_hash *paddr_hash = NULL;

	nic_dev->os_dep = &nic_dev->dumb_os_dep;

	rte_atomic32_set(&nic_dev->os_dep->dma_alloc_cnt, 0);
	rte_spinlock_init(&nic_dev->os_dep->dma_hash_lock);

	dh_params.name = nic_dev->proc_dev_name;
	dh_params.entries = HINIC_MAX_DMA_ENTRIES;
	dh_params.key_len = HINIC_HASH_KEY_LEN;
	dh_params.hash_func = HINIC_HASH_FUNC;
	dh_params.hash_func_init_val = HINIC_HASH_FUNC_INIT_VAL;
	dh_params.socket_id = SOCKET_ID_ANY;

	paddr_hash = rte_hash_find_existing(dh_params.name);
	if (paddr_hash == NULL) {
		paddr_hash = rte_hash_create(&dh_params);
		if (paddr_hash == NULL) {
			PMD_DRV_LOG(ERR, "Create nic_dev phys_addr hash table failed");
			return -ENOMEM;
		}
	} else {
		PMD_DRV_LOG(INFO, "Using existing dma hash table %s",
			    dh_params.name);
	}
	nic_dev->os_dep->dma_addr_hash = paddr_hash;

	return 0;
}

static void hinic_osdep_deinit(struct hinic_nic_dev *nic_dev)
{
	uint32_t iter = 0;
	dma_addr_t key_pa;
	struct rte_memzone *data_mz = NULL;
	struct rte_hash *paddr_hash = nic_dev->os_dep->dma_addr_hash;

	if (paddr_hash) {
		/* iterate through the hash table */
		while (rte_hash_iterate(paddr_hash, (const void **)&key_pa,
					(void **)&data_mz, &iter) >= 0) {
			if (data_mz) {
				PMD_DRV_LOG(WARNING, "Free leaked dma_addr: %p, mz: %s",
					(void *)key_pa, data_mz->name);
				(void)rte_memzone_free(data_mz);
			}
		}

		/* free phys_addr hash table */
		rte_hash_free(paddr_hash);
	}

	nic_dev->os_dep = NULL;
}

void *hinic_dma_mem_zalloc(void *dev, size_t size, dma_addr_t *dma_handle,
			   unsigned int flag, unsigned int align)
{
	int rc, alloc_cnt;
	const struct rte_memzone *mz;
	char z_name[RTE_MEMZONE_NAMESIZE];
	struct hinic_nic_dev *nic_dev = (struct hinic_nic_dev *)dev;
	hash_sig_t sig;
	rte_iova_t iova;

	HINIC_ASSERT((nic_dev != NULL) &&
		     (nic_dev->os_dep->dma_addr_hash != NULL));

	if (dma_handle == NULL || 0 == size)
		return NULL;

	alloc_cnt = rte_atomic32_add_return(&nic_dev->os_dep->dma_alloc_cnt, 1);
	snprintf(z_name, sizeof(z_name), "%s_%d",
		 nic_dev->proc_dev_name, alloc_cnt);

	mz = rte_memzone_reserve_aligned(z_name, size, SOCKET_ID_ANY,
					 flag, align);
	if (!mz) {
		PMD_DRV_LOG(ERR, "Alloc dma able memory failed, errno: %d, ma_name: %s, size: 0x%zx",
			    rte_errno, z_name, size);
		return NULL;
	}

	iova = mz->iova;

	/* check if phys_addr already exist */
	sig = HINIC_HASH_FUNC(&iova, HINIC_HASH_KEY_LEN,
			      HINIC_HASH_FUNC_INIT_VAL);
	rc = rte_hash_lookup_with_hash(nic_dev->os_dep->dma_addr_hash,
				       &iova, sig);
	if (rc >= 0) {
		PMD_DRV_LOG(ERR, "Dma addr: %p already in hash table, error: %d, mz_name: %s",
			(void *)iova, rc, z_name);
		goto phys_addr_hash_err;
	}

	/* record paddr in hash table */
	rte_spinlock_lock(&nic_dev->os_dep->dma_hash_lock);
	rc = rte_hash_add_key_with_hash_data(nic_dev->os_dep->dma_addr_hash,
					     &iova, sig,
					     (void *)(u64)mz);
	rte_spinlock_unlock(&nic_dev->os_dep->dma_hash_lock);
	if (rc) {
		PMD_DRV_LOG(ERR, "Insert dma addr: %p hash failed, error: %d, mz_name: %s",
			(void *)iova, rc, z_name);
		goto phys_addr_hash_err;
	}
	*dma_handle = iova;
	memset(mz->addr, 0, size);

	return mz->addr;

phys_addr_hash_err:
	(void)rte_memzone_free(mz);

	return NULL;
}

void hinic_dma_mem_free(void *dev, size_t size, void *virt, dma_addr_t phys)
{
	int rc;
	struct rte_memzone *mz = NULL;
	struct hinic_nic_dev *nic_dev = (struct hinic_nic_dev *)dev;
	struct rte_hash *hash;
	hash_sig_t sig;

	HINIC_ASSERT((nic_dev != NULL) &&
		     (nic_dev->os_dep->dma_addr_hash != NULL));

	if (virt == NULL || phys == 0)
		return;

	hash = nic_dev->os_dep->dma_addr_hash;
	sig = HINIC_HASH_FUNC(&phys, HINIC_HASH_KEY_LEN,
			      HINIC_HASH_FUNC_INIT_VAL);
	rc = rte_hash_lookup_with_hash_data(hash, &phys, sig, (void **)&mz);
	if (rc < 0) {
		PMD_DRV_LOG(ERR, "Can not find phys_addr: %p, error: %d",
			(void *)phys, rc);
		return;
	}

	HINIC_ASSERT(mz != NULL);
	if (virt != mz->addr || size > mz->len) {
		PMD_DRV_LOG(ERR, "Match mz_info failed: "
			"mz.name: %s, mz.phys: %p, mz.virt: %p, mz.len: %zu, "
			"phys: %p, virt: %p, size: %zu",
			mz->name, (void *)mz->iova, mz->addr, mz->len,
			(void *)phys, virt, size);
	}

	rte_spinlock_lock(&nic_dev->os_dep->dma_hash_lock);
	(void)rte_hash_del_key_with_hash(hash, &phys, sig);
	rte_spinlock_unlock(&nic_dev->os_dep->dma_hash_lock);

	(void)rte_memzone_free(mz);
}

void *dma_zalloc_coherent(void *dev, size_t size,
			  dma_addr_t *dma_handle, gfp_t flag)
{
	return hinic_dma_mem_zalloc(dev, size, dma_handle, flag,
				    RTE_CACHE_LINE_SIZE);
}

void *dma_zalloc_coherent_aligned(void *dev, size_t size,
				  dma_addr_t *dma_handle, gfp_t flag)
{
	return hinic_dma_mem_zalloc(dev, size, dma_handle, flag, PAGE_SIZE);
}

void *dma_zalloc_coherent_aligned256k(void *dev, size_t size,
				      dma_addr_t *dma_handle, gfp_t flag)
{
	return hinic_dma_mem_zalloc(dev, size, dma_handle,
				    flag, PAGE_SIZE * 64);
}

void dma_free_coherent(void *dev, size_t size, void *virt, dma_addr_t phys)
{
	hinic_dma_mem_free(dev, size, virt, phys);
}

void dma_free_coherent_volatile(void *dev, size_t size,
				volatile void *virt, dma_addr_t phys)
{
	int rc;
	struct rte_memzone *mz = NULL;
	struct hinic_nic_dev *nic_dev = (struct hinic_nic_dev *)dev;
	struct rte_hash *hash;
	hash_sig_t sig;

	HINIC_ASSERT((nic_dev != NULL) &&
		     (nic_dev->os_dep->dma_addr_hash != NULL));

	if (virt == NULL || phys == 0)
		return;

	hash = nic_dev->os_dep->dma_addr_hash;
	sig = HINIC_HASH_FUNC(&phys, HINIC_HASH_KEY_LEN,
			      HINIC_HASH_FUNC_INIT_VAL);
	rc = rte_hash_lookup_with_hash_data(hash, &phys, sig, (void **)&mz);
	if (rc < 0) {
		PMD_DRV_LOG(ERR, "Can not find phys_addr: %p, error: %d",
			(void *)phys, rc);
		return;
	}

	HINIC_ASSERT(mz != NULL);
	if (virt != mz->addr || size > mz->len) {
		PMD_DRV_LOG(ERR, "Match mz_info failed: "
			"mz.name:%s, mz.phys:%p, mz.virt:%p, mz.len:%zu, "
			"phys:%p, virt:%p, size:%zu",
			mz->name, (void *)mz->iova, mz->addr, mz->len,
			(void *)phys, virt, size);
	}

	rte_spinlock_lock(&nic_dev->os_dep->dma_hash_lock);
	(void)rte_hash_del_key_with_hash(hash, &phys, sig);
	rte_spinlock_unlock(&nic_dev->os_dep->dma_hash_lock);

	(void)rte_memzone_free(mz);
}

struct dma_pool *dma_pool_create(const char *name, void *dev,
				 size_t size, size_t align, size_t boundary)
{
	struct pci_pool *pool;

	pool = (struct pci_pool *)rte_zmalloc(NULL, sizeof(*pool),
					      HINIC_MEM_ALLOC_ALIGNE_MIN);
	if (!pool)
		return NULL;

	pool->inuse = 0;
	pool->elem_size = size;
	pool->align = align;
	pool->boundary = boundary;
	pool->nic_dev = dev;
	strncpy(pool->name, name, (sizeof(pool->name) - 1));

	return pool;
}

void dma_pool_destroy(struct dma_pool *pool)
{
	if (!pool)
		return;

	if (pool->inuse != 0) {
		PMD_DRV_LOG(ERR, "Leak memory, dma_pool:%s, inuse_count:%u",
			    pool->name, pool->inuse);
	}

	rte_free(pool);
}

void *dma_pool_alloc(struct pci_pool *pool, int flags, dma_addr_t *dma_addr)
{
	void *buf;

	buf = hinic_dma_mem_zalloc(pool->nic_dev, pool->elem_size,
				   dma_addr, flags, (u32)pool->align);
	if (buf)
		pool->inuse++;

	return buf;
}

void dma_pool_free(struct pci_pool *pool, void *vaddr, dma_addr_t dma)
{
	pool->inuse--;
	hinic_dma_mem_free(pool->nic_dev, pool->elem_size, vaddr, dma);
}

int hinic_link_event_process(struct rte_eth_dev *dev, u8 status)
{
	struct hinic_nic_dev *nic_dev = HINIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	uint32_t port_speed[LINK_SPEED_MAX] = {ETH_SPEED_NUM_10M,
					ETH_SPEED_NUM_100M, ETH_SPEED_NUM_1G,
					ETH_SPEED_NUM_10G, ETH_SPEED_NUM_25G,
					ETH_SPEED_NUM_40G, ETH_SPEED_NUM_100G};
	struct nic_port_info port_info;
	struct rte_eth_link link;
	int rc = HINIC_OK;

	nic_dev->link_status = status;
	if (!status) {
		link.link_status = ETH_LINK_DOWN;
		link.link_speed = 0;
		link.link_duplex = ETH_LINK_HALF_DUPLEX;
		link.link_autoneg = ETH_LINK_FIXED;
	} else {
		link.link_status = ETH_LINK_UP;

		memset(&port_info, 0, sizeof(port_info));
		rc = hinic_get_port_info(nic_dev->hwdev, &port_info);
		if (rc) {
			link.link_speed = ETH_SPEED_NUM_NONE;
			link.link_duplex = ETH_LINK_FULL_DUPLEX;
			link.link_autoneg = ETH_LINK_FIXED;
		} else {
			link.link_speed = port_speed[port_info.speed %
						LINK_SPEED_MAX];
			link.link_duplex = port_info.duplex;
			link.link_autoneg = port_info.autoneg_state;
		}
	}
	(void)rte_eth_linkstatus_set(dev, &link);

	return rc;
}

void hinic_lsc_process(struct rte_eth_dev *rte_dev, u8 status)
{
	int ret;

	ret = hinic_link_event_process(rte_dev, status);
	/* check if link has changed, notify callback */
	if (ret == 0)
		_rte_eth_dev_callback_process(rte_dev,
					      RTE_ETH_EVENT_INTR_LSC,
					      NULL);
}

static int hinic_set_default_pause_feature(struct hinic_nic_dev *nic_dev)
{
	struct nic_pause_config pause_config = {0};

	pause_config.auto_neg = 0;
	pause_config.rx_pause = HINIC_DEFAUT_PAUSE_CONFIG;
	pause_config.tx_pause = HINIC_DEFAUT_PAUSE_CONFIG;

	return hinic_set_pause_config(nic_dev->hwdev, pause_config);
}

static int hinic_set_default_dcb_feature(struct hinic_nic_dev *nic_dev)
{
	u8 up_tc[HINIC_DCB_UP_MAX] = {0};
	u8 up_pgid[HINIC_DCB_UP_MAX] = {0};
	u8 up_bw[HINIC_DCB_UP_MAX] = {0};
	u8 pg_bw[HINIC_DCB_UP_MAX] = {0};
	u8 up_strict[HINIC_DCB_UP_MAX] = {0};
	int i = 0;

	pg_bw[0] = 100;
	for (i = 0; i < HINIC_DCB_UP_MAX; i++)
		up_bw[i] = 100;

	return hinic_dcb_set_ets(nic_dev->hwdev, up_tc, pg_bw,
					up_pgid, up_bw, up_strict);
}

static void hinic_init_default_cos(struct hinic_nic_dev *nic_dev)
{
	nic_dev->default_cos =
			(hinic_global_func_id(nic_dev->hwdev) +
			 DEFAULT_BASE_COS) % NR_MAX_COS;
}

static int hinic_set_default_hw_feature(struct hinic_nic_dev *nic_dev)
{
	int err;

	hinic_init_default_cos(nic_dev);

	/* Restore DCB configure to default status */
	err = hinic_set_default_dcb_feature(nic_dev);
	if (err)
		return err;

	/* disable LRO */
	err = hinic_set_rx_lro(nic_dev->hwdev, 0, 0, (u8)0);
	if (err)
		return err;

	/* Set pause enable, and up will disable pfc. */
	err = hinic_set_default_pause_feature(nic_dev);
	if (err)
		return err;

	err = hinic_reset_port_link_cfg(nic_dev->hwdev);
	if (err)
		return err;

	err = hinic_set_link_status_follow(nic_dev->hwdev,
					   HINIC_LINK_FOLLOW_PORT);
	if (err == HINIC_MGMT_CMD_UNSUPPORTED)
		PMD_DRV_LOG(WARNING, "Don't support to set link status follow phy port status");
	else if (err)
		return err;

	return hinic_set_anti_attack(nic_dev->hwdev, true);
}

static int32_t hinic_card_workmode_check(struct hinic_nic_dev *nic_dev)
{
	struct hinic_board_info info = { 0 };
	int rc;

	rc = hinic_get_board_info(nic_dev->hwdev, &info);
	if (rc)
		return rc;

	/*pf can not run dpdk in ovs mode*/
	return (info.service_mode != HINIC_SERVICE_MODE_OVS ? HINIC_OK :
						HINIC_ERROR);
}

static int hinic_copy_mempool_init(struct hinic_nic_dev *nic_dev)
{
	nic_dev->cpy_mpool = rte_mempool_lookup(nic_dev->proc_dev_name);
	if (nic_dev->cpy_mpool == NULL) {
		nic_dev->cpy_mpool =
		rte_pktmbuf_pool_create(nic_dev->proc_dev_name,
					HINIC_COPY_MEMPOOL_DEPTH,
					RTE_CACHE_LINE_SIZE, 0,
					HINIC_COPY_MBUF_SIZE,
					rte_socket_id());
		if (!nic_dev->cpy_mpool) {
			PMD_DRV_LOG(ERR, "Create copy mempool failed, errno: %d, dev_name: %s",
				    rte_errno, nic_dev->proc_dev_name);
			return -ENOMEM;
		}
	}

	return 0;
}

static void hinic_copy_mempool_uninit(struct hinic_nic_dev *nic_dev)
{
	if (nic_dev->cpy_mpool != NULL)
		rte_mempool_free(nic_dev->cpy_mpool);
}

int hinic_init_sw_rxtxqs(struct hinic_nic_dev *nic_dev)
{
	u32 txq_size;
	u32 rxq_size;

	/* allocate software txq array */
	txq_size = nic_dev->nic_cap.max_sqs * sizeof(*nic_dev->txqs);
	nic_dev->txqs = kzalloc_aligned(txq_size, GFP_KERNEL);
	if (!nic_dev->txqs) {
		PMD_DRV_LOG(ERR, "Allocate txqs failed");
		return -ENOMEM;
	}

	/* allocate software rxq array */
	rxq_size = nic_dev->nic_cap.max_rqs * sizeof(*nic_dev->rxqs);
	nic_dev->rxqs = kzalloc_aligned(rxq_size, GFP_KERNEL);
	if (!nic_dev->rxqs) {
		/* free txqs */
		kfree(nic_dev->txqs);
		nic_dev->txqs = NULL;

		PMD_DRV_LOG(ERR, "Allocate rxqs failed");
		return -ENOMEM;
	}

	return HINIC_OK;
}

void hinic_deinit_sw_rxtxqs(struct hinic_nic_dev *nic_dev)
{
	kfree(nic_dev->txqs);
	nic_dev->txqs = NULL;

	kfree(nic_dev->rxqs);
	nic_dev->rxqs = NULL;
}

int32_t hinic_nic_dev_create(struct rte_eth_dev *eth_dev)
{
	struct hinic_nic_dev *nic_dev =
				HINIC_ETH_DEV_TO_PRIVATE_NIC_DEV(eth_dev);
	int rc;

	nic_dev->hwdev =
		(struct hinic_hwdev *)rte_zmalloc("hinic_hwdev",
						  sizeof(*nic_dev->hwdev),
						  RTE_CACHE_LINE_SIZE);
	if (!nic_dev->hwdev) {
		PMD_DRV_LOG(ERR, "Allocate hinic hwdev memory failed, dev_name: %s",
			    eth_dev->data->name);
		return -ENOMEM;
	}

	nic_dev->hwdev->pcidev_hdl =
			(struct rte_pci_device *)RTE_ETH_DEV_TO_PCI(eth_dev);
	nic_dev->hwdev->dev_hdl = nic_dev;

	/* init osdep*/
	rc = hinic_osdep_init(nic_dev);
	if (rc) {
		PMD_DRV_LOG(ERR, "Initialize os_dep failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_osdep_fail;
	}

	/* init_hwif */
	rc = hinic_hwif_res_init(nic_dev);
	if (rc) {
		PMD_DRV_LOG(ERR, "Initialize hwif failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_hwif_fail;
	}

	/* init_cfg_mgmt */
	rc = init_cfg_mgmt(nic_dev->hwdev);
	if (rc) {
		PMD_DRV_LOG(ERR, "Initialize cfg_mgmt failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_cfgmgnt_fail;
	}

	/* init_aeqs */
	rc = hinic_comm_aeqs_init(nic_dev);
	if (rc) {
		PMD_DRV_LOG(ERR, "Initialize aeqs failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_aeqs_fail;
	}

	/* init_pf_to_mgnt */
	rc = hinic_comm_pf_to_mgmt_init(nic_dev);
	if (rc) {
		PMD_DRV_LOG(ERR, "Initialize pf_to_mgmt failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_pf_to_mgmt_fail;
	}

	rc = hinic_card_workmode_check(nic_dev);
	if (rc) {
		PMD_DRV_LOG(ERR, "Check card workmode failed, dev_name: %s",
			    eth_dev->data->name);
		goto workmode_check_fail;
	}

	/* do l2nic reset to make chip clear */
	rc = hinic_l2nic_reset(nic_dev->hwdev);
	if (rc) {
		PMD_DRV_LOG(ERR, "Do l2nic reset failed, dev_name: %s",
			    eth_dev->data->name);
		goto l2nic_reset_fail;
	}

	/* init dma and aeq msix attribute table */
	(void)hinic_init_attr_table(nic_dev->hwdev);

	/* init_cmdqs */
	rc = hinic_comm_cmdqs_init(nic_dev->hwdev);
	if (rc) {
		PMD_DRV_LOG(ERR, "Initialize cmdq failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_cmdq_fail;
	}

	/* set hardware state active */
	rc = hinic_activate_hwdev_state(nic_dev->hwdev);
	if (rc) {
		PMD_DRV_LOG(ERR, "Initialize resources state failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_resources_state_fail;
	}

	/* init_capability */
	rc = hinic_init_capability(nic_dev);
	if (rc) {
		PMD_DRV_LOG(ERR, "Initialize capability failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_cap_fail;
	}

	/* init root cla and function table */
	rc = hinic_init_nicio(nic_dev);
	if (rc) {
		PMD_DRV_LOG(ERR, "Initialize nic_io failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_nicio_fail;
	}

	/* init_software_txrxq */
	rc = hinic_init_sw_rxtxqs(nic_dev);
	if (rc) {
		PMD_DRV_LOG(ERR, "Initialize sw_rxtxqs failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_sw_rxtxqs_fail;
	}

	rc = hinic_copy_mempool_init(nic_dev);
	if (rc) {
		PMD_DRV_LOG(ERR, "Create copy mempool failed, dev_name: %s",
			 eth_dev->data->name);
		goto init_mpool_fail;
	}

	/* set hardware feature to default status */
	rc = hinic_set_default_hw_feature(nic_dev);
	if (rc) {
		PMD_DRV_LOG(ERR, "Initialize hardware default features failed, dev_name: %s",
			    eth_dev->data->name);
		goto set_default_hw_feature_fail;
	}

	return 0;

set_default_hw_feature_fail:
	hinic_copy_mempool_uninit(nic_dev);

init_mpool_fail:
	hinic_deinit_sw_rxtxqs(nic_dev);

init_sw_rxtxqs_fail:
	hinic_deinit_nicio(nic_dev);

init_nicio_fail:
init_cap_fail:
	hinic_deactivate_hwdev_state(nic_dev->hwdev);

init_resources_state_fail:
	hinic_comm_cmdqs_free(nic_dev->hwdev);

init_cmdq_fail:
l2nic_reset_fail:
workmode_check_fail:
	hinic_comm_pf_to_mgmt_free(nic_dev);

init_pf_to_mgmt_fail:
	hinic_comm_aeqs_free(nic_dev);

init_aeqs_fail:
	free_cfg_mgmt(nic_dev->hwdev);

init_cfgmgnt_fail:
	hinic_hwif_res_free(nic_dev);

init_hwif_fail:
	hinic_osdep_deinit(nic_dev);

init_osdep_fail:
	rte_free(nic_dev->hwdev);
	nic_dev->hwdev = NULL;

	return rc;
}

void hinic_nic_dev_destroy(struct rte_eth_dev *rte_dev)
{
	struct hinic_nic_dev *nic_dev =
			HINIC_ETH_DEV_TO_PRIVATE_NIC_DEV(rte_dev);

	(void)hinic_set_link_status_follow(nic_dev->hwdev,
					   HINIC_LINK_FOLLOW_DEFAULT);
	hinic_copy_mempool_uninit(nic_dev);
	hinic_deinit_sw_rxtxqs(nic_dev);
	hinic_deinit_nicio(nic_dev);
	hinic_deactivate_hwdev_state(nic_dev->hwdev);
	hinic_comm_cmdqs_free(nic_dev->hwdev);
	hinic_comm_pf_to_mgmt_free(nic_dev);
	hinic_comm_aeqs_free(nic_dev);
	free_cfg_mgmt(nic_dev->hwdev);
	hinic_hwif_res_free(nic_dev);
	hinic_osdep_deinit(nic_dev);

	rte_free(nic_dev->hwdev);
	nic_dev->hwdev = NULL;
}
