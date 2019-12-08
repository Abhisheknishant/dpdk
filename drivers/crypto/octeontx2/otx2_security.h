/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2019 Marvell International Ltd.
 */

#ifndef __OTX2_SECURITY_H__
#define __OTX2_SECURITY_H__

#include <rte_atomic.h>
#include <rte_ethdev.h>
#include <rte_spinlock.h>

#include "otx2_ipsec_fp.h"

#define OTX2_MAX_CPT_QP_PER_PORT 64
#define OTX2_MAX_INLINE_PORTS 64

#define OTX2_CPT_RES_ALIGN		16
#define OTX2_NIX_SEND_DESC_ALIGN	16
#define OTX2_CPT_INST_SIZE		64

#define OTX2_CPT_EGRP_INLINE_IPSEC	1

#define OTX2_CPT_OP_INLINE_IPSEC_OUTB	(0x40 | 0x25)
#define OTX2_CPT_OP_INLINE_IPSEC_INB	(0x40 | 0x26)

struct otx2_cpt_qp;

struct otx2_sec_eth_cfg {
	struct {
		struct otx2_cpt_qp *qp;
		rte_atomic16_t ref_cnt;
	} tx_cpt[OTX2_MAX_CPT_QP_PER_PORT];

	uint16_t tx_cpt_idx;
	rte_spinlock_t tx_cpt_lock;
};

#define OTX2_SEC_CPT_COMP_GOOD	0x1
#define OTX2_SEC_UC_COMP_GOOD	0x0
#define OTX2_SEC_COMP_GOOD	(OTX2_SEC_UC_COMP_GOOD << 8 | \
				 OTX2_SEC_CPT_COMP_GOOD)

/* CPT Result */
struct otx2_cpt_res {
	union {
		struct {
			uint64_t compcode:8;
			uint64_t uc_compcode:8;
			uint64_t doneint:1;
			uint64_t reserved_17_63:47;
			uint64_t reserved_64_127;
		};
		uint16_t u16[8];
	};
};

struct otx2_cpt_inst_s {
	union {
		struct {
			/* W0 */
			uint64_t nixtxl : 3;
			uint64_t doneint : 1;
			uint64_t nixtx_addr : 60;
			/* W1 */
			uint64_t res_addr : 64;
			/* W2 */
			uint64_t tag : 32;
			uint64_t tt : 2;
			uint64_t grp : 10;
			uint64_t rsvd_175_172 : 4;
			uint64_t rvu_pf_func : 16;
			/* W3 */
			uint64_t qord : 1;
			uint64_t rsvd_194_193 : 2;
			uint64_t wqe_ptr : 61;
			/* W4 */
			uint64_t dlen : 16;
			uint64_t param2 : 16;
			uint64_t param1 : 16;
			uint64_t opcode : 16;
			/* W5 */
			uint64_t dptr : 64;
			/* W6 */
			uint64_t rptr : 64;
			/* W7 */
			uint64_t cptr : 61;
			uint64_t egrp : 3;
		};
		uint64_t u64[8];
	};
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

	/* Pre calculated lengths and data for a session */
	uint8_t partial_len;
	uint8_t roundup_len;
	uint8_t roundup_byte;
	uint16_t ip_id;
	union {
		uint64_t esn;
		struct {
			uint32_t seq;
			uint32_t esn_hi;
		};
	};

	uint64_t inst_w7;

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

int otx2_sec_eth_update_tag_type(struct rte_eth_dev *eth_dev);

int otx2_sec_eth_init(struct rte_eth_dev *eth_dev);

void otx2_sec_eth_fini(struct rte_eth_dev *eth_dev);

int otx2_sec_tx_cpt_qp_add(uint16_t port_id, struct otx2_cpt_qp *qp);

int otx2_sec_tx_cpt_qp_remove(struct otx2_cpt_qp *qp);
#endif /* __OTX2_SECURITY_H__ */
