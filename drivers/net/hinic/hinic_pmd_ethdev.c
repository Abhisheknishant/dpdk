/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#include <stdio.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_ethdev_pci.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_mempool.h>
#include <rte_dev.h>
#include <rte_errno.h>
#include <rte_kvargs.h>

/** Driver-specific log messages type. */
int hinic_logtype;

RTE_INIT(hinic_init_log)
{
	hinic_logtype = rte_log_register("pmd.net.hinic");
	if (hinic_logtype >= 0)
		rte_log_set_level(hinic_logtype, RTE_LOG_INFO);
}
