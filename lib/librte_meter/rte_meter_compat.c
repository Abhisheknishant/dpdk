/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <rte_function_versioning.h>

#include "rte_meter.h"
#include "rte_meter_compat.h"

int
rte_meter_trtcm_rfc4115_profile_config_s(
	struct rte_meter_trtcm_rfc4115_profile *p,
	struct rte_meter_trtcm_rfc4115_params *params)
{
	return rte_meter_trtcm_rfc4115_profile_config_(p, params);
}
BIND_DEFAULT_SYMBOL(rte_meter_trtcm_rfc4115_profile_config, _s, 21);
MAP_STATIC_SYMBOL(int rte_meter_trtcm_rfc4115_profile_config(struct rte_meter_trtcm_rfc4115_profile *p,
		struct rte_meter_trtcm_rfc4115_params *params), rte_meter_trtcm_rfc4115_profile_config_s);

int
rte_meter_trtcm_rfc4115_profile_config_e(
	struct rte_meter_trtcm_rfc4115_profile *p,
	struct rte_meter_trtcm_rfc4115_params *params)
{
	return rte_meter_trtcm_rfc4115_profile_config_(p, params);
}
VERSION_SYMBOL_EXPERIMENTAL(rte_meter_trtcm_rfc4115_profile_config, _e);


int
rte_meter_trtcm_rfc4115_config_s(struct rte_meter_trtcm_rfc4115 *m,
	struct rte_meter_trtcm_rfc4115_profile *p)
{
	return rte_meter_trtcm_rfc4115_config_(m, p);
}
BIND_DEFAULT_SYMBOL(rte_meter_trtcm_rfc4115_config, _s, 21);
MAP_STATIC_SYMBOL(int rte_meter_trtcm_rfc4115_config(struct rte_meter_trtcm_rfc4115 *m,
		 struct rte_meter_trtcm_rfc4115_profile *p), rte_meter_trtcm_rfc4115_config_s);

int
rte_meter_trtcm_rfc4115_config_e(struct rte_meter_trtcm_rfc4115 *m,
	struct rte_meter_trtcm_rfc4115_profile *p)
{
	return rte_meter_trtcm_rfc4115_config_(m, p);
}
VERSION_SYMBOL_EXPERIMENTAL(rte_meter_trtcm_rfc4115_config, _e);
