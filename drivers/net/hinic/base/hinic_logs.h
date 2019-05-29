/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#ifndef _HINIC_LOGS_H_
#define _HINIC_LOGS_H_

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */
#include <rte_log.h>

/* Reported driver name. */
#define HINIC_DRIVER_NAME "net_hinic"

extern int hinic_logtype;

#define PMD_DRV_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, hinic_logtype, \
		HINIC_DRIVER_NAME ": " fmt "\n", ##args)


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* _HINIC_LOGS_H_ */
