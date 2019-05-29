/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */


#include "hinic_logs.h"

int hinic_logtype;

RTE_INIT(hinic_init_log)
{
	hinic_logtype = rte_log_register("pmd.net.hinic");
	if (hinic_logtype >= 0)
		rte_log_set_level(hinic_logtype, RTE_LOG_INFO);
}

