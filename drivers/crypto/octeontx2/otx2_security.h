/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2020 Marvell International Ltd.
 */

#ifndef __OTX2_SECURITY_H__
#define __OTX2_SECURITY_H__

#include <rte_atomic.h>
#include <rte_ethdev.h>
#include <rte_spinlock.h>

#include "otx2_ipsec_fp.h"

#define OTX2_MAX_CPT_QP_PER_PORT 64
#define OTX2_MAX_INLINE_PORTS 64

struct otx2_cpt_qp;

struct otx2_sec_eth_cfg {
	struct {
		struct otx2_cpt_qp *qp;
		rte_atomic16_t ref_cnt;
	} tx_cpt[OTX2_MAX_CPT_QP_PER_PORT];

	uint16_t tx_cpt_idx;
	rte_spinlock_t tx_cpt_lock;
};

/*
 * Security session for inline IPsec protocol offload. This is private data of
 * inline capable PMD.
 */
struct otx2_sec_session_ipsec_ip {
	RTE_STD_C11
	union {
		/*
		 * Inbound SA would accessed by crypto block. And so the memory
		 * is allocated differently and shared with the h/w. Only
		 * holding a pointer to this memory in the session private
		 * space.
		 */
		void *in_sa;
		/* Outbound SA */
		struct otx2_ipsec_fp_out_sa out_sa;
	};

	/* Address of CPT LMTLINE */
	void *cpt_lmtline;
	/* CPT LF enqueue register address */
	rte_iova_t cpt_nq_reg;

	/* CPT QP used by SA */
	struct otx2_cpt_qp *qp;
};

struct otx2_sec_session_ipsec {
	struct otx2_sec_session_ipsec_ip ip;
};

struct otx2_sec_session {
	struct otx2_sec_session_ipsec ipsec;
	void *userdata;
	/**< Userdata registered by the application */
} __rte_cache_aligned;

int otx2_sec_eth_ctx_create(struct rte_eth_dev *eth_dev);

void otx2_sec_eth_ctx_destroy(struct rte_eth_dev *eth_dev);

int otx2_sec_eth_init(struct rte_eth_dev *eth_dev);

void otx2_sec_eth_fini(struct rte_eth_dev *eth_dev);

int otx2_sec_tx_cpt_qp_add(uint16_t port_id, struct otx2_cpt_qp *qp);

int otx2_sec_tx_cpt_qp_remove(struct otx2_cpt_qp *qp);
#endif /* __OTX2_SECURITY_H__ */
