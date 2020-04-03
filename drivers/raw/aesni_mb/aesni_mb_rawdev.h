/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation.
 */

#ifndef _AESNI_MB_RAWDEV_H_
#define _AESNI_MB_RAWDEV_H_

#include <intel-ipsec-mb.h>
#include <rte_rawdev.h>
#include <rte_multi_fn.h>
#include <rte_multi_fn_driver.h>

/* AESNI-MB Rawdev PMD logtype */
int aesni_mb_rawdev_pmd_logtype;

#define AESNI_MB_RAWDEV_LOG(level, fmt, args...)  \
	rte_log(RTE_LOG_ ## level, aesni_mb_rawdev_pmd_logtype,  \
		"%s() line %u: " fmt "\n", \
		__func__, __LINE__, ##args)
#define AESNI_MB_RAWDEV_DEBUG(fmt, args...) \
	AESNI_MB_RAWDEV_LOG(DEBUG, fmt, ## args)
#define AESNI_MB_RAWDEV_INFO(fmt, args...) \
	AESNI_MB_RAWDEV_LOG(INFO, fmt, ## args)
#define AESNI_MB_RAWDEV_ERR(fmt, args...) \
	AESNI_MB_RAWDEV_LOG(ERR, fmt, ## args)
#define AESNI_MB_RAWDEV_WARN(fmt, args...) \
	AESNI_MB_RAWDEV_LOG(WARNING, fmt, ## args)


/* Maximum length for output */
#define OUTPUT_LENGTH_MAX 8

/* AESNI-MB supported operations */
enum aesni_mb_rawdev_op {
	AESNI_MB_RAWDEV_OP_DOCSIS_CRC_CRYPTO,  /* DOCSIS encrypt direction */
	AESNI_MB_RAWDEV_OP_DOCSIS_CRYPTO_CRC,  /* DOCSIS decrypt direction */
	AESNI_MB_RAWDEV_OP_PON_CRC_CRYPTO_BIP, /* PON encrypt direction */
	AESNI_MB_RAWDEV_OP_PON_BIP_CRYPTO_CRC, /* PON decrypt direction */
	AESNI_MB_RAWDEV_OP_NOT_SUPPORTED
};

/* AESNI-MB device statistics */
struct aesni_mb_rawdev_stats {
	uint64_t enqueued_count;
	uint64_t dequeued_count;
	uint64_t enqueue_err_count;
	uint64_t dequeue_err_count;
};

/* AESNI-MB queue pair */
struct aesni_mb_rawdev_qp {
	uint16_t id;
	char name[RTE_RAWDEV_NAME_MAX_LEN];
	MB_MGR *mb_mgr;
	struct rte_ring *ingress_queue;
	struct aesni_mb_rawdev_stats stats;
	uint8_t output_idx;
	uint8_t temp_outputs[MAX_JOBS][OUTPUT_LENGTH_MAX];
} __rte_cache_aligned;

/* AESNI-MB vector modes */
enum aesni_mb_rawdev_vector_mode {
	AESNI_MB_RAWDEV_NOT_SUPPORTED = 0,
	AESNI_MB_RAWDEV_SSE,
	AESNI_MB_RAWDEV_AVX,
	AESNI_MB_RAWDEV_AVX2,
	AESNI_MB_RAWDEV_AVX512
};

/* AESNI-MB device data */
struct aesni_mb_rawdev {
	const struct rte_multi_fn_ops *mf_ops; /* MUST be first */
	MB_MGR *mb_mgr;
	struct aesni_mb_rawdev_qp **queue_pairs;
	enum aesni_mb_rawdev_vector_mode vector_mode;
	uint16_t max_nb_queue_pairs;
	uint16_t nb_queue_pairs;
};

/* AESNI-MB private session structure */
struct aesni_mb_rawdev_session {
	enum aesni_mb_rawdev_op op;
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
aesni_mb_rawdev_test(uint16_t dev_id);

#endif /* _AESNI_MB_RAWDEV_H_ */
