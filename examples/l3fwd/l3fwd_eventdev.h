/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#ifndef __L3FWD_EVENTDEV_H__
#define __L3FWD_EVENTDEV_H__

#include <rte_common.h>
#include <rte_spinlock.h>

/*
 * This expression is used to calculate the number of mbufs needed
 * depending on user input, taking  into account memory for rx and
 * tx hardware rings, cache per lcore and mtable per port per lcore.
 * RTE_MAX is used to ensure that NB_MBUF never goes below a minimum
 * value of 8192
 */
#define NUM_MBUF(nports) RTE_MAX(		\
	(nports*nb_rx_queue*nb_rxd +		\
	nports*nb_lcores*MAX_PKT_BURST +	\
	nports*n_tx_queue*nb_txd +		\
	nb_lcores*256),				\
	(unsigned int)8192)

#define EVENT_DEV_PARAM_PRESENT	0x8000	/* Random value*/

/* Packet transfer mode of the application */
#define PACKET_TRANSFER_MODE_POLL  1
#define PACKET_TRANSFER_MODE_EVENTDEV  2

#define CMD_LINE_OPT_MODE "mode"
#define CMD_LINE_OPT_EVENTQ_SYNC "eventq-sync"

typedef int (*tx_eventdev_t)(struct rte_mbuf *m[], uint16_t n, uint16_t port);

struct eventdev_queues {
	uint8_t *event_q_id;
	uint8_t	nb_queues;
};

struct eventdev_ports {
	uint8_t *event_p_id;
	uint8_t	nb_ports;
	rte_spinlock_t lock;
};

struct eventdev_rx_adptr {
	uint8_t	nb_rx_adptr;
	uint8_t *rx_adptr;
};

struct eventdev_tx_adptr {
	uint8_t	nb_tx_adptr;
	uint8_t *tx_adptr;
};

struct eventdev_resources {
	tx_eventdev_t	send_burst_eventdev;
	struct eventdev_rx_adptr rx_adptr;
	struct eventdev_tx_adptr tx_adptr;
	struct eventdev_queues evq;
	struct eventdev_ports evp;
	uint8_t event_d_id;
};

extern struct rte_event_dev_config event_d_conf;
extern struct eventdev_resources eventdev_rsrc;
extern int pkt_transfer_mode;
extern int eventq_sync_mode;
extern char *evd_argv[3];
extern int evd_argc;

/* Event device and required resource setup function */
int eventdev_resource_setup(int argc, char **argv);

/* Returns next available event port */
int get_free_event_port(void);

/* Event processing function with exact match algorithm */
int em_main_loop_eventdev(__attribute__((unused)) void *dummy);

/* Event processing function with longest prefix match algorithm */
int lpm_main_loop_eventdev(__attribute__((unused)) void *dummy);

#endif /* __L3FWD_EVENTDEV_H__ */
