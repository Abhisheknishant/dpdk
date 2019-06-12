#include <sys/queue.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev_driver.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_eth_ctrl.h>
#include <rte_tailq.h>
#include <rte_flow_driver.h>

#include "ice_logs.h"
#include "base/ice_type.h"
#include "ice_switch_filter.h"

static int
ice_parse_switch_filter(
			const struct rte_flow_item pattern[],
			const struct rte_flow_action actions[],
			struct rte_flow_error *error,
			struct ice_adv_rule_info *rule_info,
			struct ice_adv_lkup_elem **lkup_list,
			uint16_t *lkups_num)
{
	const struct rte_flow_item *item = pattern;
	enum rte_flow_item_type item_type;
	const struct rte_flow_item_eth *eth_spec, *eth_mask;
	const struct rte_flow_item_ipv4 *ipv4_spec, *ipv4_mask;
	const struct rte_flow_item_ipv6 *ipv6_spec, *ipv6_mask;
	const struct rte_flow_item_tcp *tcp_spec, *tcp_mask;
	const struct rte_flow_item_udp *udp_spec, *udp_mask;
	const struct rte_flow_item_sctp *sctp_spec, *sctp_mask;
	const struct rte_flow_item_nvgre  *nvgre_spec, *nvgre_mask;
	const struct rte_flow_item_vxlan  *vxlan_spec, *vxlan_mask;
	struct ice_adv_lkup_elem *list;
	uint16_t i, j, t = 0;
	uint16_t item_num = 0;
	enum ice_sw_tunnel_type tun_type = ICE_NON_TUN;

	for (; item->type != RTE_FLOW_ITEM_TYPE_END; item++) {
		if (item->type == RTE_FLOW_ITEM_TYPE_ETH ||
			item->type == RTE_FLOW_ITEM_TYPE_IPV4 ||
			item->type == RTE_FLOW_ITEM_TYPE_IPV6 ||
			item->type == RTE_FLOW_ITEM_TYPE_UDP ||
			item->type == RTE_FLOW_ITEM_TYPE_TCP ||
			item->type == RTE_FLOW_ITEM_TYPE_SCTP ||
			item->type == RTE_FLOW_ITEM_TYPE_VXLAN ||
			item->type == RTE_FLOW_ITEM_TYPE_NVGRE)
			item_num++;
	}

	list = rte_zmalloc(NULL, item_num * sizeof(*list), 0);
	if (!list) {
		rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_ITEM, actions,
				   "no memory malloc");
		goto out;
	}
	*lkup_list = list;

	for (item = pattern, i = 0; item->type !=
			RTE_FLOW_ITEM_TYPE_END; item++, i++) {
		item_type = item->type;

		switch (item_type) {
		case RTE_FLOW_ITEM_TYPE_ETH:
			eth_spec = item->spec;
			eth_mask = item->mask;
			if (eth_spec && eth_mask) {
				list[t].type = (tun_type == ICE_NON_TUN) ?
					ICE_MAC_OFOS : ICE_MAC_IL;
				for (j = 0; j < RTE_ETHER_ADDR_LEN; j++) {
					if (eth_mask->src.addr_bytes[j] ==
								UINT8_MAX) {
						list[t].h_u.eth_hdr.
							src_addr[j] =
						eth_spec->src.addr_bytes[j];
						list[t].m_u.eth_hdr.
							src_addr[j] =
						eth_mask->src.addr_bytes[j];
					}
					if (eth_mask->dst.addr_bytes[j] ==
								UINT8_MAX) {
						list[t].h_u.eth_hdr.
							dst_addr[j] =
						eth_spec->dst.addr_bytes[j];
						list[t].m_u.eth_hdr.
							dst_addr[j] =
						eth_mask->dst.addr_bytes[j];
					}
				}
				if (eth_mask->type == UINT16_MAX) {
					list[t].h_u.eth_hdr.ethtype_id =
					rte_be_to_cpu_16(eth_spec->type);
					list[t].m_u.eth_hdr.ethtype_id =
						UINT16_MAX;
				}
				t++;
			} else if (!eth_spec && !eth_mask) {
				list[t].type = (tun_type == ICE_NON_TUN) ?
					ICE_MAC_OFOS : ICE_MAC_IL;
			}
			break;

		case RTE_FLOW_ITEM_TYPE_IPV4:
			ipv4_spec = item->spec;
			ipv4_mask = item->mask;
			if (ipv4_spec && ipv4_mask) {
				list[t].type = (tun_type == ICE_NON_TUN) ?
					ICE_IPV4_OFOS : ICE_IPV4_IL;
				if (ipv4_mask->hdr.src_addr == UINT32_MAX) {
					list[t].h_u.ipv4_hdr.src_addr =
						ipv4_spec->hdr.src_addr;
					list[t].m_u.ipv4_hdr.src_addr =
						UINT32_MAX;
				}
				if (ipv4_mask->hdr.dst_addr == UINT32_MAX) {
					list[t].h_u.ipv4_hdr.dst_addr =
						ipv4_spec->hdr.dst_addr;
					list[t].m_u.ipv4_hdr.dst_addr =
						UINT32_MAX;
				}
				if (ipv4_mask->hdr.time_to_live == UINT8_MAX) {
					list[t].h_u.ipv4_hdr.time_to_live =
						ipv4_spec->hdr.time_to_live;
					list[t].m_u.ipv4_hdr.time_to_live =
						UINT8_MAX;
				}
				if (ipv4_mask->hdr.next_proto_id == UINT8_MAX) {
					list[t].h_u.ipv4_hdr.protocol =
						ipv4_spec->hdr.next_proto_id;
					list[t].m_u.ipv4_hdr.protocol =
						UINT8_MAX;
				}
				if (ipv4_mask->hdr.type_of_service ==
						UINT8_MAX) {
					list[t].h_u.ipv4_hdr.tos =
						ipv4_spec->hdr.type_of_service;
					list[t].m_u.ipv4_hdr.tos = UINT8_MAX;
				}
				t++;
			} else if (!ipv4_spec && !ipv4_mask) {
				list[t].type = (tun_type == ICE_NON_TUN) ?
					ICE_IPV4_OFOS : ICE_IPV4_IL;
			}
			break;

		case RTE_FLOW_ITEM_TYPE_IPV6:
			ipv6_spec = item->spec;
			ipv6_mask = item->mask;
			if (ipv6_spec && ipv6_mask) {
				list[t].type = (tun_type == ICE_NON_TUN) ?
					ICE_IPV6_OFOS : ICE_IPV6_IL;
				for (j = 0; j < ICE_IPV6_ADDR_LENGTH; j++) {
					if (ipv6_mask->hdr.src_addr[j] ==
								UINT8_MAX) {
						list[t].h_u.ice_ipv6_ofos_hdr.
							src_addr[j] =
						ipv6_spec->hdr.src_addr[j];
						list[t].m_u.ice_ipv6_ofos_hdr.
							src_addr[j] =
						ipv6_mask->hdr.src_addr[j];
					}
					if (ipv6_mask->hdr.dst_addr[j] ==
								UINT8_MAX) {
						list[t].h_u.ice_ipv6_ofos_hdr.
							dst_addr[j] =
						ipv6_spec->hdr.dst_addr[j];
						list[t].m_u.ice_ipv6_ofos_hdr.
							dst_addr[j] =
						ipv6_mask->hdr.dst_addr[j];
					}
				}
				if (ipv6_mask->hdr.proto == UINT8_MAX) {
					list[t].h_u.ice_ipv6_ofos_hdr.next_hdr =
						ipv6_spec->hdr.proto;
					list[t].m_u.ice_ipv6_ofos_hdr.next_hdr =
						UINT8_MAX;
				}
				if (ipv6_mask->hdr.hop_limits == UINT8_MAX) {
					list[t].h_u.ice_ipv6_ofos_hdr.
					hop_limit = ipv6_spec->hdr.hop_limits;
					list[t].m_u.ice_ipv6_ofos_hdr.
						hop_limit  = UINT8_MAX;
				}
				t++;
			} else if (!ipv6_spec && !ipv6_mask) {
				list[t].type = (tun_type == ICE_NON_TUN) ?
					ICE_IPV4_OFOS : ICE_IPV4_IL;
			}
			break;

		case RTE_FLOW_ITEM_TYPE_UDP:
			udp_spec = item->spec;
			udp_mask = item->mask;
			if (udp_spec && udp_mask) {
				list[t].type = ICE_UDP_ILOS;
				if (udp_mask->hdr.src_port == UINT16_MAX) {
					list[t].h_u.l4_hdr.src_port =
						udp_spec->hdr.src_port;
					list[t].m_u.l4_hdr.src_port =
						udp_mask->hdr.src_port;
				}
				if (udp_mask->hdr.dst_port == UINT16_MAX) {
					list[t].h_u.l4_hdr.dst_port =
						udp_spec->hdr.dst_port;
					list[t].m_u.l4_hdr.dst_port =
						udp_mask->hdr.dst_port;
				}
				t++;
			} else if (!udp_spec && !udp_mask) {
				list[t].type = ICE_UDP_ILOS;
			}
			break;

		case RTE_FLOW_ITEM_TYPE_TCP:
			tcp_spec = item->spec;
			tcp_mask = item->mask;
			if (tcp_spec && tcp_mask) {
				list[t].type = ICE_TCP_IL;
				if (tcp_mask->hdr.src_port == UINT16_MAX) {
					list[t].h_u.l4_hdr.src_port =
						tcp_spec->hdr.src_port;
					list[t].m_u.l4_hdr.src_port =
						tcp_mask->hdr.src_port;
				}
				if (tcp_mask->hdr.dst_port == UINT16_MAX) {
					list[t].h_u.l4_hdr.dst_port =
						tcp_spec->hdr.dst_port;
					list[t].m_u.l4_hdr.dst_port =
						tcp_mask->hdr.dst_port;
				}
				t++;
			} else if (!tcp_spec && !tcp_mask) {
				list[t].type = ICE_TCP_IL;
			}
			break;

		case RTE_FLOW_ITEM_TYPE_SCTP:
			sctp_spec = item->spec;
			sctp_mask = item->mask;
			if (sctp_spec && sctp_mask) {
				list[t].type = ICE_SCTP_IL;
				if (sctp_mask->hdr.src_port == UINT16_MAX) {
					list[t].h_u.sctp_hdr.src_port =
						sctp_spec->hdr.src_port;
					list[t].m_u.sctp_hdr.src_port =
						sctp_mask->hdr.src_port;
				}
				if (sctp_mask->hdr.dst_port == UINT16_MAX) {
					list[t].h_u.sctp_hdr.dst_port =
						sctp_spec->hdr.dst_port;
					list[t].m_u.sctp_hdr.dst_port =
						sctp_mask->hdr.dst_port;
				}
				t++;
			} else if (!sctp_spec && !sctp_mask) {
				list[t].type = ICE_SCTP_IL;
			}
			break;

		case RTE_FLOW_ITEM_TYPE_VXLAN:
			vxlan_spec = item->spec;
			vxlan_mask = item->mask;
			tun_type = ICE_SW_TUN_VXLAN;
			if (vxlan_spec && vxlan_mask) {
				list[t].type = ICE_VXLAN;
				if (vxlan_mask->vni[0] == UINT8_MAX &&
					vxlan_mask->vni[1] == UINT8_MAX &&
					vxlan_mask->vni[2] == UINT8_MAX) {
					list[t].h_u.tnl_hdr.vni =
						(vxlan_spec->vni[1] << 8) |
						vxlan_spec->vni[0];
					list[t].m_u.tnl_hdr.vni =
						UINT16_MAX;
				}
				t++;
			} else if (!vxlan_spec && !vxlan_mask) {
				list[t].type = ICE_VXLAN;
			}
			break;

		case RTE_FLOW_ITEM_TYPE_NVGRE:
			nvgre_spec = item->spec;
			nvgre_mask = item->mask;
			tun_type = ICE_SW_TUN_NVGRE;
			if (nvgre_spec && nvgre_mask) {
				list[t].type = ICE_NVGRE;
				if (nvgre_mask->tni[0] == UINT8_MAX &&
					nvgre_mask->tni[1] == UINT8_MAX &&
					nvgre_mask->tni[2] == UINT8_MAX) {
					list[t].h_u.nvgre_hdr.tni =
						(nvgre_spec->tni[1] << 8) |
						nvgre_spec->tni[0];
					list[t].m_u.nvgre_hdr.tni =
						UINT16_MAX;
				}
				t++;
			} else if (!nvgre_spec && !nvgre_mask) {
				list[t].type = ICE_NVGRE;
			}
			break;

		case RTE_FLOW_ITEM_TYPE_VOID:
		case RTE_FLOW_ITEM_TYPE_END:
			break;

		default:
			rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_ITEM, actions,
				   "Invalid pattern item.");
			goto out;
		}
	}

	rule_info->tun_type = tun_type;
	*lkups_num = t;

	return 0;
out:
	return -rte_errno;
}

/* By now ice switch filter action code implement only
* supports QUEUE or DROP.
*/
static int
ice_parse_switch_action(struct ice_pf *pf,
				 const struct rte_flow_action *actions,
				 struct rte_flow_error *error,
				 struct ice_adv_rule_info *rule_info)
{
	struct ice_hw *hw = ICE_PF_TO_HW(pf);
	struct ice_vsi *vsi = pf->main_vsi;
	const struct rte_flow_action *act;
	const struct rte_flow_action_queue *act_q;
	uint16_t base_queue, index = 0;
	uint32_t reg;

	/* Check if the first non-void action is QUEUE or DROP. */
	NEXT_ITEM_OF_ACTION(act, actions, index);
	if (act->type != RTE_FLOW_ACTION_TYPE_QUEUE &&
	    act->type != RTE_FLOW_ACTION_TYPE_DROP) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
				   act, "Not supported action.");
		return -rte_errno;
	}
	reg = ICE_READ_REG(hw, PFLAN_RX_QALLOC);
	if (reg & PFLAN_RX_QALLOC_VALID_M) {
		base_queue = reg & PFLAN_RX_QALLOC_FIRSTQ_M;
	} else {
		rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_ACTION,
			act, "Invalid queue register");
		return -rte_errno;
	}
	if (act->type == RTE_FLOW_ACTION_TYPE_QUEUE) {
		act_q = act->conf;
		rule_info->sw_act.fltr_act = ICE_FWD_TO_Q;
		rule_info->sw_act.fwd_id.q_id = base_queue + act_q->index;
		if (act_q->index >= pf->dev_data->nb_rx_queues) {
			rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION,
				act, "Invalid queue ID for"
				" switch filter.");
			return -rte_errno;
		}
	} else {
		rule_info->sw_act.fltr_act = ICE_DROP_PACKET;
	}

	rule_info->sw_act.vsi_handle = vsi->idx;
	rule_info->rx = 1;
	rule_info->sw_act.src = vsi->idx;

	/* Check if the next non-void item is END */
	index++;
	NEXT_ITEM_OF_ACTION(act, actions, index);
	if (act->type != RTE_FLOW_ACTION_TYPE_END) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
				   act, "Not supported action.");
		return -rte_errno;
	}

	return 0;
}

static int
ice_switch_rule_set(struct ice_pf *pf,
			struct ice_adv_lkup_elem *list,
			uint16_t lkups_cnt,
			struct ice_adv_rule_info *rule_info,
			struct rte_flow *flow)
{
	struct ice_hw *hw = ICE_PF_TO_HW(pf);
	int ret;
	struct ice_rule_query_data rule_added = {0};
	struct ice_rule_query_data *filter_ptr;

	if (lkups_cnt > ICE_MAX_CHAIN_WORDS) {
		PMD_DRV_LOG(ERR, "item number too large for rule");
		return -ENOTSUP;
	}
	if (!list) {
		PMD_DRV_LOG(ERR, "lookup list should not be NULL");
		return -ENOTSUP;
	}

	ret = ice_add_adv_rule(hw, list, lkups_cnt, rule_info, &rule_added);

	if (!ret) {
		filter_ptr = rte_zmalloc("ice_switch_filter",
			sizeof(struct ice_rule_query_data), 0);
		if (!filter_ptr) {
			PMD_DRV_LOG(ERR, "failed to allocate memory");
			return -EINVAL;
		}
		flow->rule = filter_ptr;
		rte_memcpy(filter_ptr,
			&rule_added,
			sizeof(struct ice_rule_query_data));
	}

	return ret;
}

int
ice_create_switch_filter(struct ice_pf *pf,
			const struct rte_flow_item pattern[],
			const struct rte_flow_action actions[],
			struct rte_flow *flow,
			struct rte_flow_error *error)
{
	int ret = 0;
	struct ice_adv_rule_info rule_info = {0};
	struct ice_adv_lkup_elem *list = NULL;
	uint16_t lkups_num = 0;

	ret = ice_parse_switch_filter(pattern, actions, error,
			&rule_info, &list, &lkups_num);
	if (ret)
		goto out;

	ret = ice_parse_switch_action(pf, actions, error, &rule_info);
	if (ret)
		goto out;

	ret = ice_switch_rule_set(pf, list, lkups_num, &rule_info, flow);
	if (ret)
		goto out;

	rte_free(list);
	return 0;

out:
	rte_free(list);

	return -rte_errno;
}

int
ice_destroy_switch_filter(struct ice_pf *pf,
			struct rte_flow *flow)
{
	struct ice_hw *hw = ICE_PF_TO_HW(pf);
	int ret;
	struct ice_rule_query_data *filter_ptr;
	struct ice_rule_query_data rule_added;

	filter_ptr = (struct ice_rule_query_data *)
			flow->rule;
	rte_memcpy(&rule_added, filter_ptr,
		sizeof(struct ice_rule_query_data));

	if (!filter_ptr) {
		PMD_DRV_LOG(ERR, "no such flow"
			    " create by switch filter");
		return -EINVAL;
	}

	ret = ice_rem_adv_rule_by_id(hw, &rule_added);

	rte_free(filter_ptr);

	return ret;
}

void
ice_free_switch_filter_rule(void *rule)
{
	struct ice_rule_query_data *filter_ptr;

	filter_ptr = (struct ice_rule_query_data *)rule;

	rte_free(filter_ptr);
}
