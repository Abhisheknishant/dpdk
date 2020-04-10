/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation.
 */

#ifndef _AESNI_MB_MFN_RAWDEV_H_
#define _AESNI_MB_MFN_RAWDEV_H_

#include <intel-ipsec-mb.h>

#include <rte_multi_fn.h>
#include <rte_multi_fn_driver.h>

/* AESNI-MB Multi-Function Rawdev PMD logtype */
int aesni_mb_mfn_logtype;

/* Name of the device driver */
#define AESNI_MB_MFN_PMD_RAWDEV_NAME RTE_MULTI_FN_DEV_NAME(aesni_mb)
/* String reported as the device driver name by rte_rawdev_info_get() */
#define AESNI_MB_MFN_PMD_RAWDEV_NAME_STR RTE_STR(AESNI_MB_MFN_PMD_RAWDEV_NAME)
/* Name used to adjust the log level for this driver */
#define AESNI_MB_MFN_PMD_LOG_NAME "rawdev.aesni_mb_mfn"

#define AESNI_MB_MFN_LOG(level, fmt, args...)  \
	rte_log(RTE_LOG_ ## level, aesni_mb_mfn_logtype,  \
		"%s() line %u: " fmt "\n", \
		__func__, __LINE__, ##args)
#define AESNI_MB_MFN_DEBUG(fmt, args...) \
	AESNI_MB_MFN_LOG(DEBUG, fmt, ## args)
#define AESNI_MB_MFN_INFO(fmt, args...) \
	AESNI_MB_MFN_LOG(INFO, fmt, ## args)
#define AESNI_MB_MFN_ERR(fmt, args...) \
	AESNI_MB_MFN_LOG(ERR, fmt, ## args)
#define AESNI_MB_MFN_WARN(fmt, args...) \
	AESNI_MB_MFN_LOG(WARNING, fmt, ## args)

/* Maximum length for output */
#define OUTPUT_LENGTH_MAX 8

/* AESNI-MB Multi-Function supported operations */
enum aesni_mb_mfn_op {
	AESNI_MB_MFN_OP_DOCSIS_CRC_CRYPTO,   /* DOCSIS encrypt */
	AESNI_MB_MFN_OP_DOCSIS_CRYPTO_CRC,   /* DOCSIS decrypt */
	AESNI_MB_MFN_OP_GPON_CRC_CRYPTO_BIP, /* GPON encrypt */
	AESNI_MB_MFN_OP_GPON_BIP_CRYPTO_CRC, /* GPON decrypt */
	AESNI_MB_MFN_OP_NOT_SUPPORTED
};

/* AESNI-MB Multi-Function device statistics */
struct aesni_mb_mfn_stats {
	uint64_t enqueued_count;
	uint64_t dequeued_count;
	uint64_t enqueue_err_count;
	uint64_t dequeue_err_count;
};

/* AESNI-MB Multi-Function queue pair */
struct aesni_mb_mfn_qp {
	uint16_t id;
	char name[RTE_RAWDEV_NAME_MAX_LEN];
	MB_MGR *mb_mgr;
	struct rte_ring *ingress_queue;
	struct aesni_mb_mfn_stats stats;
	uint8_t output_idx;
	uint8_t temp_outputs[MAX_JOBS][OUTPUT_LENGTH_MAX];
} __rte_cache_aligned;

/* AESNI-MB Multi-Function vector modes */
enum aesni_mb_mfn_vector_mode {
	AESNI_MB_MFN_NOT_SUPPORTED = 0,
	AESNI_MB_MFN_SSE,
	AESNI_MB_MFN_AVX,
	AESNI_MB_MFN_AVX2,
	AESNI_MB_MFN_AVX512
};

/* AESNI-MB Multi-Function device data */
struct aesni_mb_mfn_rawdev {
	const struct rte_multi_fn_ops *mf_ops; /* MUST be first */
	MB_MGR *mb_mgr;
	struct aesni_mb_mfn_qp **queue_pairs;
	enum aesni_mb_mfn_vector_mode vector_mode;
	uint16_t max_nb_queue_pairs;
	uint16_t nb_queue_pairs;
};

/* AESNI-MB Multi-Function private session structure */
struct aesni_mb_mfn_session {
	enum aesni_mb_mfn_op op;
	JOB_CHAIN_ORDER chain_order;
	struct {
		uint16_t length;
		uint16_t offset;
	} iv;
	struct {
		JOB_CIPHER_DIRECTION direction;
		JOB_CIPHER_MODE mode;

		uint64_t key_length_in_bytes;

		union {
			struct {
				uint32_t encode[60] __rte_aligned(16);
				uint32_t decode[60] __rte_aligned(16);
			} expanded_aes_keys;
		};
	} cipher;
	struct {
		JOB_HASH_ALG algo;
		enum rte_multi_fn_err_detect_operation operation;
		uint16_t gen_output_len;

	} err_detect;
} __rte_cache_aligned;

int
aesni_mb_mfn_test(uint16_t dev_id);

#endif /* _AESNI_MB_MFN_RAWDEV_H_ */
