#ifndef _ICE_SWITCH_FILTER_H_
#define _ICE_SWITCH_FILTER_H_

#include "base/ice_switch.h"
#include "base/ice_type.h"
#include "ice_ethdev.h"

#define NEXT_ITEM_OF_ACTION(act, actions, index)                        \
	do {                                                            \
		act = actions + index;                                  \
		while (act->type == RTE_FLOW_ACTION_TYPE_VOID) {        \
			index++;                                        \
			act = actions + index;                          \
		}                                                       \
	} while (0)

int
ice_create_switch_filter(struct ice_pf *pf,
			const struct rte_flow_item pattern[],
			const struct rte_flow_action actions[],
			struct rte_flow *flow,
			struct rte_flow_error *error);
int
ice_destroy_switch_filter(struct ice_pf *pf,
			struct rte_flow *flow);
void
ice_free_switch_filter_rule(void *rule);
#endif /* _ICE_SWITCH_FILTER_H_ */
