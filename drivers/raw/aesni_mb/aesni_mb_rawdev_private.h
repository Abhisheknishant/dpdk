/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _AESNI_MB_RAWDEV_PRIVATE_H_
#define _AESNI_MB_RAWDEV_PRIVATE_H_

#include <intel-ipsec-mb.h>
#include <rte_rawdev.h>
#include <rte_multi_fn.h>

enum aesni_mb_rawdev_vector_mode {
	AESNI_MB_RAWDEV_NOT_SUPPORTED = 0,
	AESNI_MB_RAWDEV_SSE,
	AESNI_MB_RAWDEV_AVX,
	AESNI_MB_RAWDEV_AVX2,
	AESNI_MB_RAWDEV_AVX512
};

#define AESNI_MB_RAWDEV_PMD_SOCKET_ID_ARG			("socket_id")

/* AESNI_MB PMD LOGTYPE DRIVER */
int aesni_mb_rawdev_logtype_driver;

#define AESNI_MB_RAWDEV_LOG(level, fmt, ...)  \
	rte_log(RTE_LOG_ ## level, aesni_mb_rawdev_logtype_driver,  \
			"%s() line %u: " fmt "\n", __func__, __LINE__,  \
					## __VA_ARGS__)

/* Maximum length for digest */
#define DIGEST_LENGTH_MAX 4

/* AESNI-MB operation order */
enum aesni_mb_rawdev_op {
	AESNI_MB_RAWDEV_OP_ERR_DETECT_CIPHER,
	AESNI_MB_RAWDEV_OP_CIPHER_ERR_DETECT,
	AESNI_MB_RAWDEV_OP_NOT_SUPPORTED
};

static const unsigned auth_digest_byte_lengths[] = {
		[IMB_AUTH_DOCSIS_CRC32]  = 4,
       /**< Vector mode dependent pointer table of the multi-buffer APIs */
};

/**
 * Get the full digest size in bytes for a specified authentication algorithm
 * (if available in the Multi-buffer library)
 *
 * @Note: this function will not return a valid value for a non-valid
 * authentication algorithm
 */
static inline unsigned
get_digest_byte_length(JOB_HASH_ALG algo)
{
	return auth_digest_byte_lengths[algo];
}

/* AESNI-MB device statistics */
struct aesni_mb_rawdev_stats {
	uint64_t enqueued_count;
	uint64_t dequeued_count;
	uint64_t enqueue_err_count;
	uint64_t dequeue_err_count;
};

/* Private data structure for each virtual AESNI-MB device */
struct aesni_mb_rawdev_private {
	enum aesni_mb_rawdev_vector_mode vector_mode;
	unsigned max_nb_queue_pairs;
	MB_MGR *mb_mgr;
	unsigned int socket_id;
};

/* AESNI-MB queue pair */
struct aesni_mb_rawdev_qp {
	uint16_t id;
	char name[RTE_RAWDEV_NAME_MAX_LEN];
	MB_MGR *mb_mgr;
	struct rte_ring *ingress_queue;
	struct aesni_mb_rawdev_stats stats;
	uint8_t output_idx;
	uint8_t temp_digests[MAX_JOBS][DIGEST_LENGTH_MAX];
} __rte_cache_aligned;

/* AESNI-MB device data */
struct aesni_mb_rawdev_dev {
	struct aesni_mb_rawdev_private priv;
	uint16_t num_queue_pair;
	struct aesni_mb_rawdev_qp **queue_pairs;
	uint64_t feature_flags;
};

/* AESNI-MB private session structure */
struct aesni_mb_rawdev_session {
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

#endif /* _AESNI_MB_RAWDEV_PRIVATE_H_ */
