/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2019 Marvell International Ltd.
 */

#ifndef _OTX2_CRYPTODEV_HW_ACCESS_H_
#define _OTX2_CRYPTODEV_HW_ACCESS_H_

#include <rte_cryptodev.h>

#include "otx2_dev.h"

/* Register offsets */

/* LMT LF registers */
#define OTX2_LMT_LF_LMTLINE(a)		(0x0ull | (uint64_t)(a) << 3)

/* CPT LF registers */
#define OTX2_CPT_LF_CTL			0x10ull
#define OTX2_CPT_LF_INPROG		0x40ull
#define OTX2_CPT_LF_MISC_INT		0xb0ull
#define OTX2_CPT_LF_MISC_INT_ENA_W1S	0xd0ull
#define OTX2_CPT_LF_MISC_INT_ENA_W1C	0xe0ull
#define OTX2_CPT_LF_Q_BASE		0xf0ull
#define OTX2_CPT_LF_Q_SIZE		0x100ull
#define OTX2_CPT_LF_NQ(a)		(0x400ull | (uint64_t)(a) << 3)

#define OTX2_CPT_AF_LF_CTL(a)		(0x27000ull | (uint64_t)(a) << 3)

#define OTX2_CPT_LF_BAR2(vf, q_id) \
		((vf)->otx2_dev.bar2 + \
		 ((RVU_BLOCK_ADDR_CPT0 << 20) | ((q_id) << 12)))

union otx2_cpt_lf_ctl {
	uint64_t u;
	struct {
#if (RTE_BYTE_ORDER == RTE_BIG_ENDIAN) /* Word 0 - Big Endian */
		uint64_t reserved_8_63               : 56;
		uint64_t fc_hyst_bits                : 4;
		uint64_t reserved_3_3                : 1;
		uint64_t fc_up_crossing              : 1;
		uint64_t fc_ena                      : 1;
		uint64_t ena                         : 1;
#else /* Word 0 - Little Endian */
		uint64_t ena                         : 1;
		uint64_t fc_ena                      : 1;
		uint64_t fc_up_crossing              : 1;
		uint64_t reserved_3_3                : 1;
		uint64_t fc_hyst_bits                : 4;
		uint64_t reserved_8_63               : 56;
#endif
	} s;
};

union otx2_cpt_lf_inprog {
	uint64_t u;
	struct {
#if (RTE_BYTE_ORDER == RTE_BIG_ENDIAN) /* Word 0 - Big Endian */
		uint64_t reserved_48_63              : 16;
		uint64_t gwb_cnt                     : 8;
		uint64_t grb_cnt                     : 8;
		uint64_t grb_partial                 : 1;
		uint64_t reserved_18_30              : 13;
		uint64_t grp_drp                     : 1;
		uint64_t eena                        : 1;
		uint64_t reserved_9_15               : 7;
		uint64_t inflight                    : 9;
#else /* Word 0 - Little Endian */
		uint64_t inflight                    : 9;
		uint64_t reserved_9_15               : 7;
		uint64_t eena                        : 1;
		uint64_t grp_drp                     : 1;
		uint64_t reserved_18_30              : 13;
		uint64_t grb_partial                 : 1;
		uint64_t grb_cnt                     : 8;
		uint64_t gwb_cnt                     : 8;
		uint64_t reserved_48_63              : 16;
#endif
	} s;
};

union otx2_cpt_lf_q_base {
	uint64_t u;
	struct {
#if (RTE_BYTE_ORDER == RTE_BIG_ENDIAN) /* Word 0 - Big Endian */
		uint64_t reserved_53_63              : 11;
		uint64_t addr                        : 46;
		uint64_t reserved_2_6                : 5;
		uint64_t stopped                     : 1;
		uint64_t fault                       : 1;
#else /* Word 0 - Little Endian */
		uint64_t fault                       : 1;
		uint64_t stopped                     : 1;
		uint64_t reserved_2_6                : 5;
		uint64_t addr                        : 46;
		uint64_t reserved_53_63              : 11;
#endif
	} s;
};

union otx2_cpt_lf_q_size {
	uint64_t u;
	struct {
#if (RTE_BYTE_ORDER == RTE_BIG_ENDIAN) /* Word 0 - Big Endian */
		uint64_t reserved_15_63              : 49;
		uint64_t size_div40                  : 15;
#else /* Word 0 - Little Endian */
		uint64_t size_div40                  : 15;
		uint64_t reserved_15_63              : 49;
#endif
	} s;
};

union otx2_cpt_af_lf_ctl {
	uint64_t u;
	struct {
#if (RTE_BYTE_ORDER == RTE_BIG_ENDIAN) /* Word 0 - Big Endian */
		uint64_t reserved_56_63              : 8;
		uint64_t grp                         : 8;
		uint64_t reserved_17_47              : 31;
		uint64_t nixtx_en                    : 1;
		uint64_t reserved_11_15              : 5;
		uint64_t cont_err                    : 1;
		uint64_t pf_func_inst                : 1;
		uint64_t reserved_1_8                : 8;
		uint64_t pri                         : 1;
#else /* Word 0 - Little Endian */
		uint64_t pri                         : 1;
		uint64_t reserved_1_8                : 8;
		uint64_t pf_func_inst                : 1;
		uint64_t cont_err                    : 1;
		uint64_t reserved_11_15              : 5;
		uint64_t nixtx_en                    : 1;
		uint64_t reserved_17_47              : 31;
		uint64_t grp                         : 8;
		uint64_t reserved_56_63              : 8;
#endif
	} s;
};

void otx2_cpt_err_intr_unregister(const struct rte_cryptodev *dev);

int otx2_cpt_err_intr_register(const struct rte_cryptodev *dev);

#endif /* _OTX2_CRYPTODEV_HW_ACCESS_H_ */
