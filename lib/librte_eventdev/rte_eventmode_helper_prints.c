/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2019 Marvell International Ltd.
 */

#include <stdio.h>
#include <string.h>

#include <rte_eventmode_helper.h>
#include "rte_eventmode_helper_internal.h"

static void
rte_eventmode_display_operating_mode(struct eventmode_conf *em_conf)
{
	char sched_types[][32] = {
		"RTE_SCHED_TYPE_ORDERED",
		"RTE_SCHED_TYPE_ATOMIC",
		"RTE_SCHED_TYPE_PARALLEL",
	};
	RTE_EM_HLPR_LOG_INFO("Operating mode:");

	RTE_EM_HLPR_LOG_INFO("\tScheduling type: \t%s",
		sched_types[em_conf->ext_params.sched_type]);

	RTE_EM_HLPR_LOG_INFO("");
}

static void
rte_eventmode_display_event_dev_conf(struct eventmode_conf *em_conf)
{
	int i;
	char print_buf[256] = { 0 };
	char queue_mode[][32] = {
		"",
		"ATQ (ALL TYPE QUEUE)",
		"SINGLE LINK",
	};

	RTE_EM_HLPR_LOG_INFO("Event Device Configuration:");

	for (i = 0; i < em_conf->nb_eventdev; i++) {
		sprintf(print_buf,
			"\tDev ID: %-2d \tQueues: %-2d \tPorts: %-2d",
			em_conf->eventdev_config[i].eventdev_id,
			em_conf->eventdev_config[i].nb_eventqueue,
			em_conf->eventdev_config[i].nb_eventport);
		sprintf(print_buf + strlen(print_buf),
			"\tQueue mode: %s",
			queue_mode[em_conf->eventdev_config[i].ev_queue_mode]);
		RTE_EM_HLPR_LOG_INFO("%s", print_buf);
	}
	RTE_EM_HLPR_LOG_INFO("");
}

static void
rte_eventmode_display_rx_adapter_conf(struct eventmode_conf *em_conf)
{
	int i, j;
	int nb_rx_adapter = em_conf->nb_rx_adapter;
	struct rx_adapter_conf *adapter;
	struct adapter_connection_info *conn;
	char print_buf[256] = { 0 };

	RTE_EM_HLPR_LOG_INFO("Rx adapters configured: %d", nb_rx_adapter);

	for (i = 0; i < nb_rx_adapter; i++) {
		adapter = &(em_conf->rx_adapter[i]);
		sprintf(print_buf,
			"\tRx adaper ID: %-2d\tConnections: %-2d\tEvent dev ID: %-2d",
			adapter->adapter_id,
			adapter->nb_connections,
			adapter->eventdev_id);
		if (adapter->rx_core_id == (uint32_t)-1)
			sprintf(print_buf + strlen(print_buf),
				"\tRx core: %-2s", "[INTERNAL PORT]");
		else if (adapter->rx_core_id == RTE_MAX_LCORE)
			sprintf(print_buf + strlen(print_buf),
				"\tRx core: %-2s", "[NONE]");
		else
			sprintf(print_buf + strlen(print_buf),
				"\tRx core: %-2d", adapter->rx_core_id);

		RTE_EM_HLPR_LOG_INFO("%s", print_buf);

		for (j = 0; j < adapter->nb_connections; j++) {
			conn = &(adapter->conn[j]);

			sprintf(print_buf,
				"\t\tEthdev ID: %-2d", conn->ethdev_id);

			if (conn->ethdev_rx_qid == -1)
				sprintf(print_buf + strlen(print_buf),
					"\tEth rx queue: %-2s", "ALL");
			else
				sprintf(print_buf + strlen(print_buf),
					"\tEth rx queue: %-2d",
					conn->ethdev_rx_qid);

			sprintf(print_buf + strlen(print_buf),
				"\tEvent queue: %-2d", conn->eventq_id);
			RTE_EM_HLPR_LOG_INFO("%s", print_buf);
		}
	}
	RTE_EM_HLPR_LOG_INFO("");
}

static void
rte_eventmode_display_tx_adapter_conf(struct eventmode_conf *em_conf)
{
	RTE_SET_USED(em_conf);
}

static void
rte_eventmode_display_link_conf(struct eventmode_conf *em_conf)
{
	int i;
	struct rte_eventmode_helper_event_link_info *link;
	char print_buf[256] = { 0 };

	RTE_EM_HLPR_LOG_INFO("Links configured: %d", em_conf->nb_link);

	for (i = 0; i < em_conf->nb_link; i++) {
		link = &(em_conf->link[i]);

		sprintf(print_buf,
			"\tEvent dev ID: %-2d\tEvent port: %-2d",
			link->eventdev_id,
			link->event_portid);

		if (em_conf->ext_params.all_ev_queue_to_ev_port)
			sprintf(print_buf + strlen(print_buf),
				"Event queue: %-2s\t", "ALL");
		else
			sprintf(print_buf + strlen(print_buf),
				"Event queue: %-2d\t", link->eventq_id);

		sprintf(print_buf + strlen(print_buf),
			"Lcore: %-2d", link->lcore_id);
		RTE_EM_HLPR_LOG_INFO("%s", print_buf);
	}
	RTE_EM_HLPR_LOG_INFO("");
}

void __rte_experimental
rte_eventmode_helper_display_conf(struct rte_eventmode_helper_conf *mode_conf)
{
	struct eventmode_conf *em_conf;

	if (mode_conf == NULL) {
		RTE_EM_HLPR_LOG_ERR("Invalid conf");
		return;
	}

	if (mode_conf->mode != RTE_EVENTMODE_HELPER_PKT_TRANSFER_MODE_EVENT)
		return;

	if (mode_conf->mode_params == NULL) {
		RTE_EM_HLPR_LOG_ERR("Invalid mode params");
		return;
	}

	/* Get eventmode conf */
	em_conf = (struct eventmode_conf *)(mode_conf->mode_params);

	/* Display user exposed operating modes */
	rte_eventmode_display_operating_mode(em_conf);

	/* Display event device conf */
	rte_eventmode_display_event_dev_conf(em_conf);

	/* Display Rx adapter conf */
	rte_eventmode_display_rx_adapter_conf(em_conf);

	/* Display Tx adapter conf */
	rte_eventmode_display_tx_adapter_conf(em_conf);

	/* Display event-lcore link */
	rte_eventmode_display_link_conf(em_conf);
}

