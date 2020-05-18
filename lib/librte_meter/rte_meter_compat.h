/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

int
rte_meter_trtcm_rfc4115_profile_config_(
	struct rte_meter_trtcm_rfc4115_profile *p,
	struct rte_meter_trtcm_rfc4115_params *params);
int
rte_meter_trtcm_rfc4115_profile_config_s(
	struct rte_meter_trtcm_rfc4115_profile *p,
	struct rte_meter_trtcm_rfc4115_params *params);
int
rte_meter_trtcm_rfc4115_profile_config_e(
	struct rte_meter_trtcm_rfc4115_profile *p,
	struct rte_meter_trtcm_rfc4115_params *params);
int
rte_meter_trtcm_rfc4115_config_s(struct rte_meter_trtcm_rfc4115 *m,
	struct rte_meter_trtcm_rfc4115_profile *p);
int
rte_meter_trtcm_rfc4115_config_e(struct rte_meter_trtcm_rfc4115 *m,
	struct rte_meter_trtcm_rfc4115_profile *p);
int
rte_meter_trtcm_rfc4115_config_(
	struct rte_meter_trtcm_rfc4115 *m,
	struct rte_meter_trtcm_rfc4115_profile *p);
