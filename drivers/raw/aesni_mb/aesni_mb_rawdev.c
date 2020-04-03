/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation.
 */

#include <stdbool.h>

#include <intel-ipsec-mb.h>

#include <rte_common.h>
#include <rte_hexdump.h>
#include <rte_cryptodev.h>
#include <rte_dev.h>
#include <rte_eal.h>
#include <rte_bus_vdev.h>
#include <rte_malloc.h>
#include <rte_cpuflags.h>
#include <rte_rawdev.h>
#include <rte_rawdev_pmd.h>
#include <rte_string_fns.h>
#include <rte_multi_fn.h>
#include <rte_ether.h>

#include "aesni_mb_rawdev.h"

#define MAX_QUEUES        (64)
#define RING_NAME_MAX_LEN (64)

#define PON_BIP_LEN             (4)
#define PON_AUTH_TAG_CRC_OFFSET (4)

static const uint16_t err_detect_output_byte_lengths[] = {
	[IMB_AUTH_DOCSIS_CRC32] = RTE_ETHER_CRC_LEN,
	[IMB_AUTH_PON_CRC_BIP] = (PON_BIP_LEN + RTE_ETHER_CRC_LEN),
};

static const char * const xstat_names[] = {
		"successful_enqueues", "successful_dequeues",
		"failed_enqueues", "failed_dequeues",
};

static const char *driver_name = "rawdev_aesni_mb";

static int
qp_unique_name_set(struct rte_rawdev *rawdev, struct aesni_mb_rawdev_qp *qp)
{
	unsigned int n = snprintf(qp->name,
				  sizeof(qp->name),
				  "aesni_mb_rawdev_pmd_%u_qp_%u",
				  rawdev->dev_id,
				  qp->id);

	if (n >= sizeof(qp->name))
		return -1;

	return 0;
}

static struct rte_ring *
qp_processed_ops_ring_create(struct aesni_mb_rawdev_qp *qp,
			     unsigned int ring_size,
			     int socket_id)
{
	struct rte_ring *r;
	char ring_name[RING_NAME_MAX_LEN];

	unsigned int n = strlcpy(ring_name, qp->name, sizeof(ring_name));

	if (n >= sizeof(ring_name))
		return NULL;

	r = rte_ring_lookup(ring_name);
	if (r) {
		if (rte_ring_get_size(r) >= ring_size) {
			AESNI_MB_RAWDEV_DEBUG(
				"Reusing existing ring %s for processed ops",
				ring_name);
			return r;
		}

		AESNI_MB_RAWDEV_ERR(
			"Unable to reuse existing ring %s for processed ops",
			ring_name);
		return NULL;
	}

	return rte_ring_create(ring_name,
			       ring_size,
			       socket_id,
			       RING_F_SP_ENQ | RING_F_SC_DEQ);
}

static uint16_t
err_detect_output_byte_length_get(JOB_HASH_ALG algo)
{
	return err_detect_output_byte_lengths[algo];
}

static bool
docsis_crc_crypto_encrypt_check(struct rte_multi_fn_xform *xform)
{
	struct rte_crypto_sym_xform *crypto_sym;
	struct rte_multi_fn_err_detect_xform *err_detect;
	struct rte_multi_fn_xform *next;

	if (xform->type == RTE_MULTI_FN_XFORM_TYPE_ERR_DETECT) {

		err_detect = &xform->err_detect;
		next = xform->next;

		if (err_detect->algo ==
				RTE_MULTI_FN_ERR_DETECT_CRC32_ETH &&
		    err_detect->op ==
				RTE_MULTI_FN_ERR_DETECT_OP_GENERATE &&
		    next != NULL &&
		    next->type == RTE_MULTI_FN_XFORM_TYPE_CRYPTO_SYM) {

			crypto_sym = &next->crypto_sym;
			next = next->next;

			if (crypto_sym->type ==
					RTE_CRYPTO_SYM_XFORM_CIPHER &&
			    crypto_sym->cipher.op ==
					RTE_CRYPTO_CIPHER_OP_ENCRYPT &&
			    crypto_sym->cipher.algo ==
					RTE_CRYPTO_CIPHER_AES_DOCSISBPI &&
			    crypto_sym->cipher.key.length ==
					IMB_KEY_AES_128_BYTES &&
			    crypto_sym->cipher.iv.length ==
					AES_BLOCK_SIZE &&
			    next == NULL)
				return true;
		}
	}

	return false;
}

static bool
docsis_crypto_decrypt_crc_check(struct rte_multi_fn_xform *xform)
{
	struct rte_crypto_sym_xform *crypto_sym;
	struct rte_multi_fn_err_detect_xform *err_detect;
	struct rte_multi_fn_xform *next;

	if (xform->type == RTE_MULTI_FN_XFORM_TYPE_CRYPTO_SYM) {

		crypto_sym = &xform->crypto_sym;
		next = xform->next;

		if (crypto_sym->type ==
				RTE_CRYPTO_SYM_XFORM_CIPHER &&
		    crypto_sym->cipher.op ==
				RTE_CRYPTO_CIPHER_OP_DECRYPT &&
		    crypto_sym->cipher.algo ==
				RTE_CRYPTO_CIPHER_AES_DOCSISBPI &&
		    crypto_sym->cipher.key.length ==
				IMB_KEY_AES_128_BYTES &&
		    crypto_sym->cipher.iv.length ==
				AES_BLOCK_SIZE &&
		    next != NULL &&
		    next->type == RTE_MULTI_FN_XFORM_TYPE_ERR_DETECT) {

			err_detect = &next->err_detect;
			next = next->next;

			if (err_detect->algo ==
					RTE_MULTI_FN_ERR_DETECT_CRC32_ETH &&
			    err_detect->op ==
					RTE_MULTI_FN_ERR_DETECT_OP_VERIFY &&
			    next == NULL)
				return true;
		}
	}

	return false;
}

static bool
pon_crc_crypto_encrypt_bip_check(struct rte_multi_fn_xform *xform)
{
	struct rte_crypto_sym_xform *crypto_sym;
	struct rte_multi_fn_err_detect_xform *err_detect;
	struct rte_multi_fn_xform *next;

	if (xform->type == RTE_MULTI_FN_XFORM_TYPE_ERR_DETECT) {

		err_detect = &xform->err_detect;
		next = xform->next;

		if (err_detect->algo ==
				RTE_MULTI_FN_ERR_DETECT_CRC32_ETH &&
		    err_detect->op ==
				RTE_MULTI_FN_ERR_DETECT_OP_GENERATE &&
		    next != NULL &&
		    next->type == RTE_MULTI_FN_XFORM_TYPE_CRYPTO_SYM) {

			crypto_sym = &next->crypto_sym;
			next = next->next;

			if (crypto_sym->type ==
					RTE_CRYPTO_SYM_XFORM_CIPHER &&
			    crypto_sym->cipher.op ==
					RTE_CRYPTO_CIPHER_OP_ENCRYPT &&
			    crypto_sym->cipher.algo ==
					RTE_CRYPTO_CIPHER_AES_CTR &&
			    crypto_sym->cipher.key.length ==
					IMB_KEY_AES_128_BYTES &&
			    crypto_sym->cipher.iv.length ==
					AES_BLOCK_SIZE &&
			    next != NULL &&
			    next->type ==
				RTE_MULTI_FN_XFORM_TYPE_ERR_DETECT) {

				err_detect = &next->err_detect;
				next = next->next;

				if (err_detect->algo ==
					RTE_MULTI_FN_ERR_DETECT_BIP32 &&
				    err_detect->op ==
					RTE_MULTI_FN_ERR_DETECT_OP_GENERATE &&
				    next == NULL)
					return true;
			}
		}
	}

	return false;
}

static bool
pon_bip_crypto_decrypt_crc_check(struct rte_multi_fn_xform *xform)
{
	struct rte_crypto_sym_xform *crypto_sym;
	struct rte_multi_fn_err_detect_xform *err_detect;
	struct rte_multi_fn_xform *next;

	if (xform->type == RTE_MULTI_FN_XFORM_TYPE_ERR_DETECT) {

		err_detect = &xform->err_detect;
		next = xform->next;

		if (err_detect->algo ==
				RTE_MULTI_FN_ERR_DETECT_BIP32 &&
		    err_detect->op ==
				RTE_MULTI_FN_ERR_DETECT_OP_GENERATE &&
		    next != NULL &&
		    next->type == RTE_MULTI_FN_XFORM_TYPE_CRYPTO_SYM) {

			crypto_sym = &next->crypto_sym;
			next = next->next;

			if (crypto_sym->type ==
					RTE_CRYPTO_SYM_XFORM_CIPHER &&
			    crypto_sym->cipher.op ==
					RTE_CRYPTO_CIPHER_OP_DECRYPT &&
			    crypto_sym->cipher.algo ==
					RTE_CRYPTO_CIPHER_AES_CTR &&
			    crypto_sym->cipher.key.length ==
					IMB_KEY_AES_128_BYTES &&
			    crypto_sym->cipher.iv.length ==
					AES_BLOCK_SIZE &&
			    next != NULL &&
			    next->type ==
				RTE_MULTI_FN_XFORM_TYPE_ERR_DETECT) {

				err_detect = &next->err_detect;
				next = next->next;

				if (err_detect->algo ==
					RTE_MULTI_FN_ERR_DETECT_CRC32_ETH &&
				    err_detect->op ==
					RTE_MULTI_FN_ERR_DETECT_OP_VERIFY &&
				    next == NULL)
					return true;
			}
		}
	}

	return false;
}

static enum aesni_mb_rawdev_op
session_support_check(struct rte_multi_fn_xform *xform)
{
	enum aesni_mb_rawdev_op op = AESNI_MB_RAWDEV_OP_NOT_SUPPORTED;

	if (docsis_crc_crypto_encrypt_check(xform))
		op = AESNI_MB_RAWDEV_OP_DOCSIS_CRC_CRYPTO;
	else if (docsis_crypto_decrypt_crc_check(xform))
		op = AESNI_MB_RAWDEV_OP_DOCSIS_CRYPTO_CRC;
	else if (pon_crc_crypto_encrypt_bip_check(xform))
		op = AESNI_MB_RAWDEV_OP_PON_CRC_CRYPTO_BIP;
	else if (pon_bip_crypto_decrypt_crc_check(xform))
		op = AESNI_MB_RAWDEV_OP_PON_BIP_CRYPTO_CRC;

	return op;
}

static int
session_err_detect_parameters_set(struct aesni_mb_rawdev_session *sess)
{
	switch (sess->op) {
	case AESNI_MB_RAWDEV_OP_DOCSIS_CRC_CRYPTO:
		sess->err_detect.operation =
					RTE_MULTI_FN_ERR_DETECT_OP_GENERATE;
		sess->err_detect.algo = IMB_AUTH_DOCSIS_CRC32;
		break;
	case AESNI_MB_RAWDEV_OP_DOCSIS_CRYPTO_CRC:
		sess->err_detect.operation = RTE_MULTI_FN_ERR_DETECT_OP_VERIFY;
		sess->err_detect.algo = IMB_AUTH_DOCSIS_CRC32;
		break;
	case AESNI_MB_RAWDEV_OP_PON_CRC_CRYPTO_BIP:
		sess->err_detect.operation =
					RTE_MULTI_FN_ERR_DETECT_OP_GENERATE;
		sess->err_detect.algo = IMB_AUTH_PON_CRC_BIP;
		break;
	case AESNI_MB_RAWDEV_OP_PON_BIP_CRYPTO_CRC:
		sess->err_detect.operation = RTE_MULTI_FN_ERR_DETECT_OP_VERIFY;
		sess->err_detect.algo = IMB_AUTH_PON_CRC_BIP;
		break;
	default:
		AESNI_MB_RAWDEV_ERR(
				"Unsupported operation for error detection");
		return -ENOTSUP;
	}

	sess->err_detect.gen_output_len =
		err_detect_output_byte_length_get(sess->err_detect.algo);

	return 0;
}

static int
session_cipher_parameters_set(const MB_MGR *mb_mgr,
			      struct aesni_mb_rawdev_session *sess,
			      const struct rte_crypto_sym_xform *xform)
{

	if (xform == NULL) {
		sess->cipher.mode = IMB_CIPHER_NULL;
		return -EINVAL;
	}

	if (xform->type != RTE_CRYPTO_SYM_XFORM_CIPHER) {
		AESNI_MB_RAWDEV_ERR("Crypto xform not of type cipher");
		return -EINVAL;
	}

	/* Select cipher direction */
	switch (sess->op) {
	case AESNI_MB_RAWDEV_OP_DOCSIS_CRC_CRYPTO:
		sess->cipher.direction = IMB_DIR_ENCRYPT;
		sess->cipher.mode = IMB_CIPHER_DOCSIS_SEC_BPI;
		break;
	case AESNI_MB_RAWDEV_OP_DOCSIS_CRYPTO_CRC:
		sess->cipher.direction = IMB_DIR_DECRYPT;
		sess->cipher.mode = IMB_CIPHER_DOCSIS_SEC_BPI;
		break;
	case AESNI_MB_RAWDEV_OP_PON_CRC_CRYPTO_BIP:
		sess->cipher.direction = IMB_DIR_ENCRYPT;
		sess->cipher.mode = IMB_CIPHER_PON_AES_CNTR;
		break;
	case AESNI_MB_RAWDEV_OP_PON_BIP_CRYPTO_CRC:
		sess->cipher.direction = IMB_DIR_DECRYPT;
		sess->cipher.mode = IMB_CIPHER_PON_AES_CNTR;
		break;
	default:
		AESNI_MB_RAWDEV_ERR("Unsupported operation for cipher");
		return -ENOTSUP;
	}

	/* Set IV parameters */
	sess->iv.offset = xform->cipher.iv.offset;
	sess->iv.length = xform->cipher.iv.length;

	/* Check key length and choose key expansion function for AES */
	switch (xform->cipher.key.length) {
	case IMB_KEY_AES_128_BYTES:
		sess->cipher.key_length_in_bytes = IMB_KEY_AES_128_BYTES;
		IMB_AES_KEYEXP_128(mb_mgr,
				   xform->cipher.key.data,
				   sess->cipher.expanded_aes_keys.encode,
				   sess->cipher.expanded_aes_keys.decode);
		break;
	case IMB_KEY_AES_256_BYTES:
		sess->cipher.key_length_in_bytes = IMB_KEY_AES_256_BYTES;
		IMB_AES_KEYEXP_256(mb_mgr,
				   xform->cipher.key.data,
				   sess->cipher.expanded_aes_keys.encode,
				   sess->cipher.expanded_aes_keys.decode);
		break;
	default:
		AESNI_MB_RAWDEV_ERR("Invalid cipher key length");
		return -EINVAL;
	}

	return 0;
}

static inline struct aesni_mb_rawdev_session *
session_get(struct rte_multi_fn_op *op)
{
	struct aesni_mb_rawdev_session *sess = NULL;

	if (likely(op->sess != NULL))
		sess = op->sess->sess_private_data;
	else
		op->overall_status = RTE_MULTI_FN_STATUS_INVALID_SESSION;

	return sess;
}

static inline int
op_chain_parse(struct aesni_mb_rawdev_session *sess,
	       struct rte_multi_fn_op *op_chain,
	       struct rte_multi_fn_op **cipher_op,
	       struct rte_multi_fn_op **crc_op,
	       struct rte_multi_fn_op **bip_op)
{
	*cipher_op = NULL;
	*crc_op = NULL;
	*bip_op = NULL;

	switch (sess->op) {
	case AESNI_MB_RAWDEV_OP_DOCSIS_CRC_CRYPTO:
	case AESNI_MB_RAWDEV_OP_DOCSIS_CRYPTO_CRC:
		if (unlikely(op_chain == NULL || op_chain->next == NULL)) {
			return -EINVAL;
		} else if (sess->op == AESNI_MB_RAWDEV_OP_DOCSIS_CRC_CRYPTO) {
			*crc_op = op_chain;
			*cipher_op = op_chain->next;
		} else {
			*cipher_op = op_chain;
			*crc_op = op_chain->next;
		}
		break;
	case AESNI_MB_RAWDEV_OP_PON_CRC_CRYPTO_BIP:
	case AESNI_MB_RAWDEV_OP_PON_BIP_CRYPTO_CRC:
		if (unlikely(op_chain == NULL ||
			     op_chain->next == NULL ||
			     op_chain->next->next == NULL)) {
			return -EINVAL;
		} else if (sess->op == AESNI_MB_RAWDEV_OP_PON_CRC_CRYPTO_BIP) {
			*crc_op = op_chain;
			*cipher_op = op_chain->next;
			*bip_op = op_chain->next->next;
		} else {
			*bip_op = op_chain;
			*cipher_op = op_chain->next;
			*crc_op = op_chain->next->next;
		}
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static inline void
op_statuses_set(struct rte_multi_fn_op *first_op,
		struct rte_multi_fn_op *cipher_op,
		struct rte_multi_fn_op *crc_op,
		struct rte_multi_fn_op *bip_op,
		enum rte_multi_fn_op_status overall_status,
		uint8_t crypto_status,
		uint8_t err_detect_status)
{
	first_op->overall_status = overall_status;

	if (cipher_op != NULL)
		cipher_op->op_status = crypto_status;
	if (crc_op != NULL)
		crc_op->op_status = err_detect_status;
	if (bip_op != NULL)
		bip_op->op_status = err_detect_status;
}

#ifdef RTE_LIBRTE_PMD_AESNI_MB_RAWDEV_DEBUG
#define DOCSIS_CIPHER_CRC_OFFSET_DIFF (RTE_ETHER_HDR_LEN - RTE_ETHER_TYPE_LEN)
#define DOCSIS_CIPHER_CRC_LENGTH_DIFF (RTE_ETHER_HDR_LEN - \
					RTE_ETHER_TYPE_LEN - \
					RTE_ETHER_CRC_LEN)

static inline int
docsis_crypto_crc_check(struct rte_multi_fn_op *first_op,
			struct rte_multi_fn_op *cipher_op,
			struct rte_multi_fn_op *crc_op)
{
	struct rte_multi_fn_op *err_op = NULL;
	uint8_t err_op_status;
	const uint32_t offset_diff = DOCSIS_CIPHER_CRC_OFFSET_DIFF;

	if (cipher_op->crypto_sym.cipher.data.length &&
	    crc_op->err_detect.data.length) {
		/* Cipher offset must be at least 12 greater than CRC offset */
		if (cipher_op->crypto_sym.cipher.data.offset <
		    ((uint32_t)crc_op->err_detect.data.offset + offset_diff)) {
			err_op = crc_op;
			err_op_status = RTE_MULTI_FN_ERR_DETECT_OP_STATUS_ERROR;
		/*
		 * Cipher length must be at least 8 less than CRC length, taking
		 * known differences of what is ciphered and what is crc'ed into
		 * account
		 */
		} else if ((cipher_op->crypto_sym.cipher.data.length +
				DOCSIS_CIPHER_CRC_LENGTH_DIFF) >
			    crc_op->err_detect.data.length) {
			err_op = crc_op;
			err_op_status = RTE_MULTI_FN_ERR_DETECT_OP_STATUS_ERROR;
		}
	}

	if (err_op != NULL) {
		err_op->op_status = err_op_status;
		first_op->overall_status = RTE_MULTI_FN_OP_STATUS_FAILURE;
		return -EINVAL;
	}

	return 0;
}

#define PON_FRAME_HDR_SIZE      (8U)
#define PON_FRAME_MULTIPLE_SIZE (4)
#define PON_PLI_SHIFT_BITS      (2)

static inline int
pon_crypto_crc_bip_check(struct rte_multi_fn_op *first_op,
			 struct rte_multi_fn_op *crc_op,
			 struct rte_multi_fn_op *bip_op,
			 struct rte_mbuf *m_src)
{
	struct rte_multi_fn_op *err_op = NULL;
	uint8_t err_op_status;

	/*
	 * BIP length must be multiple of 4 and be at least a full PON header
	 * in size
	 */
	if (bip_op->err_detect.data.length % PON_FRAME_MULTIPLE_SIZE != 0 ||
	    bip_op->err_detect.data.length < PON_FRAME_HDR_SIZE) {
		err_op = bip_op;
		err_op_status = RTE_MULTI_FN_ERR_DETECT_OP_STATUS_ERROR;
	}

	/*
	 * Check the PLI field in the PON frame header matches the
	 * CRC length
	 */
	uint16_t *pli_key_idx = rte_pktmbuf_mtod(m_src, uint16_t *);
	uint16_t pli = rte_bswap16(*pli_key_idx) >> PON_PLI_SHIFT_BITS;
	if (crc_op->err_detect.data.length != 0 &&
	    crc_op->err_detect.data.length != (pli - RTE_ETHER_CRC_LEN)) {
		err_op = crc_op;
		err_op_status = RTE_MULTI_FN_ERR_DETECT_OP_STATUS_ERROR;
	}

	if (err_op != NULL) {
		err_op->op_status = err_op_status;
		first_op->overall_status = RTE_MULTI_FN_OP_STATUS_FAILURE;
		return -EINVAL;
	}

	return 0;
}
#endif /* RTE_LIBRTE_PMD_AESNI_MB_RAWDEV_DEBUG */

static inline int
mb_job_params_set(JOB_AES_HMAC *job,
		  struct aesni_mb_rawdev_qp *qp,
		  struct rte_multi_fn_op *op,
		  uint8_t *output_idx)
{
	struct rte_mbuf *m_src, *m_dst;
	struct rte_multi_fn_op *cipher_op;
	struct rte_multi_fn_op *crc_op;
	struct rte_multi_fn_op *bip_op;
	uint32_t cipher_offset;
	struct aesni_mb_rawdev_session *session;

	session = session_get(op);
	if (unlikely(session == NULL)) {
		op->overall_status = RTE_MULTI_FN_STATUS_INVALID_SESSION;
		return -EINVAL;
	}

	if (unlikely(op_chain_parse(session,
				    op,
				    &cipher_op,
				    &crc_op,
				    &bip_op) < 0)) {
		op_statuses_set(
			op,
			cipher_op,
			crc_op,
			bip_op,
			RTE_MULTI_FN_OP_STATUS_FAILURE,
			RTE_CRYPTO_OP_STATUS_NOT_PROCESSED,
			RTE_MULTI_FN_ERR_DETECT_OP_STATUS_NOT_PROCESSED);
		return -EINVAL;
	}

	op_statuses_set(op,
			cipher_op,
			crc_op,
			bip_op,
			RTE_MULTI_FN_OP_STATUS_NOT_PROCESSED,
			RTE_CRYPTO_OP_STATUS_NOT_PROCESSED,
			RTE_MULTI_FN_ERR_DETECT_OP_STATUS_NOT_PROCESSED);

	m_src = op->m_src;

	if (op->m_dst == NULL || op->m_dst == op->m_src) {
		/* in-place operation */
		m_dst = m_src;
	} else {
		/* out-of-place operation not supported */
		op->overall_status = RTE_MULTI_FN_OP_STATUS_FAILURE;
		return -EINVAL;
	}

#ifdef RTE_LIBRTE_PMD_AESNI_MB_RAWDEV_DEBUG
	switch (session->op) {
	case AESNI_MB_RAWDEV_OP_DOCSIS_CRC_CRYPTO:
	case AESNI_MB_RAWDEV_OP_DOCSIS_CRYPTO_CRC:
		if (docsis_crypto_crc_check(op, cipher_op, crc_op) < 0)
			return -EINVAL;
		break;
	case AESNI_MB_RAWDEV_OP_PON_CRC_CRYPTO_BIP:
	case AESNI_MB_RAWDEV_OP_PON_BIP_CRYPTO_CRC:
	/*
	 * session->op is known to be ok at this point so ok to include
	 * default case here
	 */
	default:
		if (pon_crypto_crc_bip_check(op, crc_op, bip_op, m_src) < 0)
			return -EINVAL;
		break;
	}
#endif

	/* Set order */
	job->chain_order = session->chain_order;

	/* Set cipher parameters */
	job->cipher_direction = session->cipher.direction;
	job->cipher_mode = session->cipher.mode;

	job->key_len_in_bytes = session->cipher.key_length_in_bytes;
	job->enc_keys = session->cipher.expanded_aes_keys.encode;
	job->dec_keys = session->cipher.expanded_aes_keys.decode;

	/*
	 * Set error detection parameters
	 * In intel-ipsec-mb, error detection is treated as a hash algorithm
	 */
	job->hash_alg = session->err_detect.algo;

	job->auth_tag_output = qp->temp_outputs[*output_idx];
	*output_idx = (*output_idx + 1) % MAX_JOBS;

	job->auth_tag_output_len_in_bytes = session->err_detect.gen_output_len;

	/* Set data parameters */
	cipher_offset = cipher_op->crypto_sym.cipher.data.offset;

	job->src = rte_pktmbuf_mtod(m_src, uint8_t *);
	job->dst = rte_pktmbuf_mtod_offset(m_dst, uint8_t *, cipher_offset);

	job->cipher_start_src_offset_in_bytes =	cipher_offset;
	job->msg_len_to_cipher_in_bytes =
				cipher_op->crypto_sym.cipher.data.length;

	switch (session->op) {
	case AESNI_MB_RAWDEV_OP_DOCSIS_CRC_CRYPTO:
	case AESNI_MB_RAWDEV_OP_DOCSIS_CRYPTO_CRC:
		job->hash_start_src_offset_in_bytes =
						crc_op->err_detect.data.offset;
		job->msg_len_to_hash_in_bytes = crc_op->err_detect.data.length;

		break;
	case AESNI_MB_RAWDEV_OP_PON_CRC_CRYPTO_BIP:
	case AESNI_MB_RAWDEV_OP_PON_BIP_CRYPTO_CRC:
	/*
	 * session->op is known to be ok at this point so ok to include
	 * default case here
	 */
	default:
		job->hash_start_src_offset_in_bytes =
						bip_op->err_detect.data.offset;
		job->msg_len_to_hash_in_bytes = bip_op->err_detect.data.length;

#ifdef RTE_LIBRTE_PMD_AESNI_MB_RAWDEV_DEBUG
#endif
		break;
	}

	/* Set IV parameters */
	job->iv_len_in_bytes = session->iv.length;
	job->iv = (uint8_t *)cipher_op + session->iv.offset;

	job->user_data = op;

	return 0;
}

static inline void
bip_copy(JOB_AES_HMAC *job, struct rte_multi_fn_op *bip_op)
{
	if (bip_op->err_detect.data.length == 0)
		return;

	/* Copy BIP to output location */
	memcpy(bip_op->err_detect.output.data,
	       job->auth_tag_output,
	       PON_BIP_LEN);
}

static inline void
crc_verify(JOB_AES_HMAC *job,
	   struct rte_multi_fn_op *crc_op,
	   uint8_t auth_tag_crc_offset)
{
	if (crc_op->err_detect.data.length == 0)
		return;

	/* Verify CRC */
	if (memcmp(job->auth_tag_output + auth_tag_crc_offset,
		   crc_op->err_detect.output.data,
		   RTE_ETHER_CRC_LEN) != 0)
		crc_op->op_status =
			RTE_MULTI_FN_ERR_DETECT_OP_STATUS_VERIFY_FAILED;
}

static inline struct rte_multi_fn_op *
mb_job_post_process(JOB_AES_HMAC *job)
{
	struct rte_multi_fn_op *op = (struct rte_multi_fn_op *)job->user_data;
	struct aesni_mb_rawdev_session *sess = op->sess->sess_private_data;
	struct rte_multi_fn_op *cipher_op;
	struct rte_multi_fn_op *crc_op;
	struct rte_multi_fn_op *bip_op;

	if (unlikely(op_chain_parse(sess,
				    op,
				    &cipher_op,
				    &crc_op,
				    &bip_op) < 0)) {
		op_statuses_set(
			op,
			cipher_op,
			crc_op,
			bip_op,
			RTE_MULTI_FN_OP_STATUS_FAILURE,
			RTE_CRYPTO_OP_STATUS_ERROR,
			RTE_MULTI_FN_ERR_DETECT_OP_STATUS_ERROR);

	} else if (op->overall_status ==
				RTE_MULTI_FN_OP_STATUS_NOT_PROCESSED) {
		switch (job->status) {
		case STS_COMPLETED:
			if (unlikely(job->hash_alg == IMB_AUTH_NULL))
				break;

			op_statuses_set(
				op,
				cipher_op,
				crc_op,
				bip_op,
				RTE_MULTI_FN_OP_STATUS_SUCCESS,
				RTE_CRYPTO_OP_STATUS_SUCCESS,
				RTE_MULTI_FN_ERR_DETECT_OP_STATUS_SUCCESS);

			if (job->hash_alg == IMB_AUTH_PON_CRC_BIP)
				bip_copy(job, bip_op);

			if (sess->err_detect.operation ==
					RTE_MULTI_FN_ERR_DETECT_OP_VERIFY)
				crc_verify(
					job,
					crc_op,
					job->hash_alg == IMB_AUTH_PON_CRC_BIP ?
						PON_AUTH_TAG_CRC_OFFSET : 0);

			if (crc_op->op_status !=
				RTE_MULTI_FN_ERR_DETECT_OP_STATUS_SUCCESS)
				op->overall_status =
					RTE_MULTI_FN_OP_STATUS_FAILURE;
			break;
		default:
			op_statuses_set(
				op,
				cipher_op,
				crc_op,
				bip_op,
				RTE_MULTI_FN_OP_STATUS_FAILURE,
				RTE_CRYPTO_OP_STATUS_ERROR,
				RTE_MULTI_FN_ERR_DETECT_OP_STATUS_ERROR);
			break;
		}
	}

	return op;
}

static unsigned
completed_jobs_handle(struct aesni_mb_rawdev_qp *qp,
		      JOB_AES_HMAC *job,
		      struct rte_multi_fn_op **ops,
		      uint16_t nb_ops)
{
	struct rte_multi_fn_op *op = NULL;
	unsigned int processed_jobs = 0;

	while (job != NULL) {
		op = mb_job_post_process(job);

		if (op) {
			ops[processed_jobs++] = op;
			qp->stats.dequeued_count++;
		} else {
			qp->stats.dequeue_err_count++;
			break;
		}
		if (processed_jobs == nb_ops)
			break;

		job = IMB_GET_COMPLETED_JOB(qp->mb_mgr);
	}

	return processed_jobs;
}

static inline uint16_t
mb_mgr_flush(struct aesni_mb_rawdev_qp *qp,
	     struct rte_multi_fn_op **ops,
	     uint16_t nb_ops)
{
	int processed_ops = 0;

	/* Flush the remaining jobs */
	JOB_AES_HMAC *job = IMB_FLUSH_JOB(qp->mb_mgr);

	if (job)
		processed_ops += completed_jobs_handle(qp,
						       job,
						       &ops[processed_ops],
						       nb_ops - processed_ops);

	return processed_ops;
}

static inline JOB_AES_HMAC *
mb_job_params_null_set(JOB_AES_HMAC *job, struct rte_multi_fn_op *op)
{
	job->chain_order = IMB_ORDER_HASH_CIPHER;
	job->cipher_mode = IMB_CIPHER_NULL;
	job->hash_alg = IMB_AUTH_NULL;
	job->cipher_direction = IMB_DIR_DECRYPT;

	/* Set user data to be crypto operation data struct */
	job->user_data = op;

	return job;
}

static int
aesni_mb_rawdev_pmd_config(const struct rte_rawdev *rawdev,
			   rte_rawdev_obj_t config)
{
	struct aesni_mb_rawdev *aesni_mb_dev = rawdev->dev_private;
	struct rte_multi_fn_dev_config *conf = config;

	aesni_mb_dev->nb_queue_pairs = conf->nb_queues;

	aesni_mb_dev->queue_pairs =
			rte_zmalloc_socket(
				"aesni_mb_rawdev_qps",
				aesni_mb_dev->nb_queue_pairs *
					sizeof(struct aesni_mb_rawdev_qp *),
				RTE_CACHE_LINE_SIZE,
				rawdev->socket_id);

	if (aesni_mb_dev->queue_pairs == NULL) {
		AESNI_MB_RAWDEV_ERR("Unable to allocate queue pairs");
		return -ENOMEM;
	}

	return 0;
}

static void
aesni_mb_rawdev_pmd_info_get(struct rte_rawdev *rawdev,
			     rte_rawdev_obj_t dev_info)
{
	struct aesni_mb_rawdev *aesni_mb_dev = rawdev->dev_private;
	struct rte_multi_fn_dev_info *info = dev_info;

	if (info != NULL)
		info->max_nb_queues = aesni_mb_dev->max_nb_queue_pairs;
}

static int
aesni_mb_rawdev_pmd_start(__rte_unused struct rte_rawdev *rawdev)
{
	return 0;
}

static void
aesni_mb_rawdev_pmd_stop(__rte_unused struct rte_rawdev *rawdev)
{
}

static int
aesni_mb_rawdev_pmd_close(struct rte_rawdev *rawdev)
{
	struct aesni_mb_rawdev *aesni_mb_dev = rawdev->dev_private;

	if (aesni_mb_dev->queue_pairs != NULL)
		rte_free(aesni_mb_dev->queue_pairs);

	return 0;
}

static int
aesni_mb_rawdev_pmd_qp_release(struct rte_rawdev *rawdev, uint16_t qp_id)
{
	struct aesni_mb_rawdev *aesni_mb_dev = rawdev->dev_private;
	struct aesni_mb_rawdev_qp *qp = aesni_mb_dev->queue_pairs[qp_id];
	struct rte_ring *r = NULL;

	if (qp != NULL) {
		r = rte_ring_lookup(qp->name);
		if (r)
			rte_ring_free(r);
		if (qp->mb_mgr)
			free_mb_mgr(qp->mb_mgr);
		rte_free(qp);
		aesni_mb_dev->queue_pairs[qp_id] = NULL;
	}

	return 0;
}

static int
aesni_mb_rawdev_pmd_qp_setup(struct rte_rawdev *rawdev,
			     uint16_t qp_id,
			     rte_rawdev_obj_t qp_c)
{
	struct aesni_mb_rawdev *aesni_mb_dev = rawdev->dev_private;
	struct aesni_mb_rawdev_qp *qp = NULL;
	const struct rte_multi_fn_qp_config *qp_conf =
			(const struct rte_multi_fn_qp_config *)qp_c;
	int ret = -1;

	if (qp_id >= aesni_mb_dev->max_nb_queue_pairs) {
		AESNI_MB_RAWDEV_ERR("Invalid queue pair id=%d", qp_id);
		return -EINVAL;
	}

	/* Free memory prior to re-allocation if needed */
	if (aesni_mb_dev->queue_pairs[qp_id] != NULL)
		aesni_mb_rawdev_pmd_qp_release(rawdev, qp_id);

	/* Allocate the queue pair data structure */
	qp = rte_zmalloc_socket("aesni_mb_rawdev_qp",
				sizeof(struct aesni_mb_rawdev_qp),
				RTE_CACHE_LINE_SIZE,
				rawdev->socket_id);
	if (qp == NULL)
		return -ENOMEM;

	qp->id = qp_id;
	aesni_mb_dev->queue_pairs[qp_id] = qp;

	if (qp_unique_name_set(rawdev, qp))
		goto qp_setup_cleanup;

	qp->mb_mgr = alloc_mb_mgr(0);
	if (qp->mb_mgr == NULL) {
		ret = -ENOMEM;
		goto qp_setup_cleanup;
	}

	switch (aesni_mb_dev->vector_mode) {
	case AESNI_MB_RAWDEV_SSE:
		init_mb_mgr_sse(qp->mb_mgr);
		break;
	case AESNI_MB_RAWDEV_AVX:
		init_mb_mgr_avx(qp->mb_mgr);
		break;
	case AESNI_MB_RAWDEV_AVX2:
		init_mb_mgr_avx2(qp->mb_mgr);
		break;
	case AESNI_MB_RAWDEV_AVX512:
		init_mb_mgr_avx512(qp->mb_mgr);
		break;
	default:
		AESNI_MB_RAWDEV_ERR("Unsupported vector mode %u",
				    aesni_mb_dev->vector_mode);
		goto qp_setup_cleanup;
	}

	qp->ingress_queue = qp_processed_ops_ring_create(
						qp,
						qp_conf->nb_descriptors,
						rawdev->socket_id);
	if (qp->ingress_queue == NULL) {
		ret = -1;
		goto qp_setup_cleanup;
	}

	memset(&qp->stats, 0, sizeof(qp->stats));

	return 0;

qp_setup_cleanup:
	if (qp) {
		if (qp->mb_mgr)
			free_mb_mgr(qp->mb_mgr);
		rte_free(qp);
	}

	return ret;
}

static uint16_t
aesni_mb_rawdev_pmd_qp_count(struct rte_rawdev *rawdev)
{
	struct aesni_mb_rawdev *aesni_mb_dev = rawdev->dev_private;

	return aesni_mb_dev->nb_queue_pairs;
}

static int
aesni_mb_rawdev_pmd_enq(struct rte_rawdev *rawdev,
			struct rte_rawdev_buf **ops,
			unsigned int nb_ops,
			rte_rawdev_obj_t q_id)
{
	struct aesni_mb_rawdev *aesni_mb_dev = rawdev->dev_private;
	struct aesni_mb_rawdev_qp *qp;
	unsigned int nb_enqueued;

	qp = aesni_mb_dev->queue_pairs[*(uint16_t *)q_id];

	nb_enqueued = rte_ring_enqueue_burst(qp->ingress_queue,
					     (void **)ops,
					     nb_ops,
					     NULL);

	qp->stats.enqueued_count += nb_enqueued;

	return nb_enqueued;
}

static int
aesni_mb_rawdev_pmd_deq(struct rte_rawdev *rawdev,
			struct rte_rawdev_buf **ops,
			unsigned int nb_ops,
			rte_rawdev_obj_t q_id)
{
	struct aesni_mb_rawdev *aesni_mb_dev = rawdev->dev_private;
	struct aesni_mb_rawdev_qp *qp;
	struct rte_multi_fn_op *op;
	JOB_AES_HMAC *job;
	uint8_t output_idx;
	unsigned int processed_jobs = 0;
	int ret;

	qp = aesni_mb_dev->queue_pairs[*(uint16_t *)q_id];

	if (unlikely(nb_ops == 0))
		return 0;

	output_idx = qp->output_idx;

	do {
		/* Get next free mb job struct from mb manager */
		job = IMB_GET_NEXT_JOB(qp->mb_mgr);
		if (unlikely(job == NULL)) {
			/* if no free mb job structs we need to flush mb_mgr */
			processed_jobs += mb_mgr_flush(
						qp,
						(struct rte_multi_fn_op **)
							&ops[processed_jobs],
						nb_ops - processed_jobs);

			if (nb_ops == processed_jobs)
				break;

			job = IMB_GET_NEXT_JOB(qp->mb_mgr);
		}

		/*
		 * Get next operation to process from ingress queue.
		 * There is no need to return the job to the MB_MGR if there
		 * are no more operations to process, since the MB_MGR can use
		 * that pointer again in next get_next calls.
		 */
		ret = rte_ring_dequeue(qp->ingress_queue, (void **)&op);
		if (ret < 0)
			break;

		ret = mb_job_params_set(job, qp, op, &output_idx);
		if (unlikely(ret != 0)) {
			qp->stats.dequeue_err_count++;
			mb_job_params_null_set(job, op);
		}

		/* Submit job to multi-buffer for processing */
#ifdef RTE_LIBRTE_PMD_AESNI_MB_RAWDEV_DEBUG
		job = IMB_SUBMIT_JOB(qp->mb_mgr);
#else
		job = IMB_SUBMIT_JOB_NOCHECK(qp->mb_mgr);
#endif
		/*
		 * If submit returns a processed job then handle it,
		 * before submitting subsequent jobs
		 */
		if (job)
			processed_jobs += completed_jobs_handle(
						qp,
						job,
						(struct rte_multi_fn_op **)
							&ops[processed_jobs],
						nb_ops - processed_jobs);

	} while (processed_jobs < nb_ops);

	qp->output_idx = output_idx;

	if (processed_jobs < 1)
		processed_jobs += mb_mgr_flush(qp,
					       (struct rte_multi_fn_op **)
							&ops[processed_jobs],
					       nb_ops - processed_jobs);

	return processed_jobs;
}

static int
aesni_mb_rawdev_pmd_xstats_get(const struct rte_rawdev *rawdev,
			       const unsigned int ids[],
			       uint64_t values[],
			       unsigned int n)
{
	struct aesni_mb_rawdev *aesni_mb_dev = rawdev->dev_private;
	struct aesni_mb_rawdev_qp *qp;
	struct aesni_mb_rawdev_stats stats = {0};
	int qp_id;
	unsigned int i;

	for (qp_id = 0; qp_id < aesni_mb_dev->nb_queue_pairs; qp_id++) {
		qp = aesni_mb_dev->queue_pairs[qp_id];

		stats.enqueued_count += qp->stats.enqueued_count;
		stats.dequeued_count += qp->stats.dequeued_count;

		stats.enqueue_err_count += qp->stats.enqueue_err_count;
		stats.dequeue_err_count += qp->stats.dequeue_err_count;
	}

	for (i = 0; i < n; i++) {
		switch (ids[i]) {
		case 0:
			values[i] = stats.enqueued_count;
			break;
		case 1:
			values[i] = stats.dequeued_count;
			break;
		case 2:
			values[i] = stats.enqueue_err_count;
			break;
		case 3:
			values[i] = stats.dequeue_err_count;
			break;
		default:
			values[i] = 0;
			break;
		}
	}

	return n;
}

static int
aesni_mb_rawdev_pmd_xstats_get_names(
				__rte_unused const struct rte_rawdev *rawdev,
				struct rte_rawdev_xstats_name *names,
				unsigned int size)
{
	unsigned int i;

	if (size < RTE_DIM(xstat_names))
		return RTE_DIM(xstat_names);

	for (i = 0; i < RTE_DIM(xstat_names); i++)
		strlcpy(names[i].name, xstat_names[i], sizeof(names[i]));

	return RTE_DIM(xstat_names);
}

static int
aesni_mb_rawdev_pmd_xstats_reset(struct rte_rawdev *rawdev,
				 const uint32_t *ids,
				 uint32_t nb_ids)
{
	struct aesni_mb_rawdev *aesni_mb_dev = rawdev->dev_private;
	struct aesni_mb_rawdev_qp *qp;
	unsigned int i;
	int qp_id;

	if (!ids) {
		for (qp_id = 0; qp_id < aesni_mb_dev->nb_queue_pairs; qp_id++) {
			qp = aesni_mb_dev->queue_pairs[qp_id];
			qp->stats.enqueued_count = 0;
			qp->stats.dequeued_count = 0;
			qp->stats.enqueue_err_count = 0;
			qp->stats.dequeue_err_count = 0;
		}

		return 0;
	}

	for (i = 0; i < nb_ids; i++) {
		switch (ids[i]) {
		case 0:
			for (qp_id = 0;
			     qp_id < aesni_mb_dev->nb_queue_pairs;
			     qp_id++) {
				qp = aesni_mb_dev->queue_pairs[qp_id];
				qp->stats.enqueued_count = 0;
			}
			break;
		case 1:
			for (qp_id = 0;
			     qp_id < aesni_mb_dev->nb_queue_pairs;
			     qp_id++) {
				qp = aesni_mb_dev->queue_pairs[qp_id];
				qp->stats.dequeued_count = 0;
			}
			break;
		case 2:
			for (qp_id = 0;
			     qp_id < aesni_mb_dev->nb_queue_pairs;
			     qp_id++) {
				qp = aesni_mb_dev->queue_pairs[qp_id];
				qp->stats.enqueue_err_count = 0;
			}
			break;
		case 3:
			for (qp_id = 0;
			     qp_id < aesni_mb_dev->nb_queue_pairs;
			     qp_id++) {
				qp = aesni_mb_dev->queue_pairs[qp_id];
				qp->stats.dequeue_err_count = 0;
			}
			break;
		default:
			AESNI_MB_RAWDEV_ERR("Invalid xstat id - cannot reset");
			break;
		}
	}

	return 0;
}

static int
aesni_mb_rawdev_pmd_selftest(uint16_t dev_id)
{
	return aesni_mb_rawdev_test(dev_id);
}

static struct rte_multi_fn_session *
aesni_mb_rawdev_pmd_session_create(struct rte_rawdev *rawdev,
				   struct rte_multi_fn_xform *xform,
				   int socket_id)
{
	struct aesni_mb_rawdev *aesni_mb_dev = rawdev->dev_private;
	struct aesni_mb_rawdev_session *aesni_sess = NULL;
	struct rte_multi_fn_session *session;
	struct rte_crypto_sym_xform *cipher_xform;
	enum aesni_mb_rawdev_op op;
	int ret;

	op = session_support_check(xform);

	/* Allocate multi-function session */
	session = rte_zmalloc_socket("multi_fn_session",
				     sizeof(struct rte_multi_fn_session),
				     RTE_CACHE_LINE_MIN_SIZE,
				     socket_id);

	if (session == NULL) {
		AESNI_MB_RAWDEV_ERR("Multi-function session allocation failed");
		return NULL;
	}

	/* Allocate AESNI-MB_rawdev session */
	aesni_sess = rte_zmalloc_socket("aesni_mb_rawdev_session",
					sizeof(struct aesni_mb_rawdev_session),
					RTE_CACHE_LINE_MIN_SIZE,
					socket_id);

	if (aesni_sess == NULL) {
		AESNI_MB_RAWDEV_ERR(
				"AESNI-MB rawdev session allocation failed");
		return NULL;
	}

	session->sess_private_data = aesni_sess;
	aesni_sess->op = op;

	switch (op) {
	case AESNI_MB_RAWDEV_OP_DOCSIS_CRC_CRYPTO:
	case AESNI_MB_RAWDEV_OP_PON_CRC_CRYPTO_BIP:
		aesni_sess->chain_order = IMB_ORDER_HASH_CIPHER;
		cipher_xform = &xform->next->crypto_sym;
		break;
	case AESNI_MB_RAWDEV_OP_DOCSIS_CRYPTO_CRC:
		aesni_sess->chain_order = IMB_ORDER_CIPHER_HASH;
		cipher_xform = &xform->crypto_sym;
		break;
	case AESNI_MB_RAWDEV_OP_PON_BIP_CRYPTO_CRC:
		aesni_sess->chain_order = IMB_ORDER_CIPHER_HASH;
		cipher_xform = &xform->next->crypto_sym;
		break;
	default:
		AESNI_MB_RAWDEV_ERR("Unsupported multi-function xform chain");
		return NULL;
	}

	ret = session_err_detect_parameters_set(aesni_sess);

	if (ret != 0) {
		AESNI_MB_RAWDEV_ERR(
				"Invalid/unsupported error detect parameters");
		return NULL;
	}

	ret = session_cipher_parameters_set(aesni_mb_dev->mb_mgr,
					    aesni_sess,
					    cipher_xform);

	if (ret != 0) {
		AESNI_MB_RAWDEV_ERR("Invalid/unsupported cipher parameters");
		return NULL;
	}

	return session;
}

static int
aesni_mb_rawdev_pmd_session_destroy(__rte_unused struct rte_rawdev *rawdev,
				    struct rte_multi_fn_session *sess)
{

	if (sess) {
		if (sess->sess_private_data)
			rte_free(sess->sess_private_data);
		rte_free(sess);
	}

	return 0;
}

static const struct rte_rawdev_ops aesni_mb_rawdev_ops = {
	.dev_configure = aesni_mb_rawdev_pmd_config,
	.dev_info_get = aesni_mb_rawdev_pmd_info_get,
	.dev_start = aesni_mb_rawdev_pmd_start,
	.dev_stop = aesni_mb_rawdev_pmd_stop,
	.dev_close = aesni_mb_rawdev_pmd_close,
	.queue_setup = aesni_mb_rawdev_pmd_qp_setup,
	.queue_release = aesni_mb_rawdev_pmd_qp_release,
	.queue_count = aesni_mb_rawdev_pmd_qp_count,
	.enqueue_bufs = aesni_mb_rawdev_pmd_enq,
	.dequeue_bufs = aesni_mb_rawdev_pmd_deq,
	.xstats_get = aesni_mb_rawdev_pmd_xstats_get,
	.xstats_get_names = aesni_mb_rawdev_pmd_xstats_get_names,
	.xstats_reset = aesni_mb_rawdev_pmd_xstats_reset,
	.dev_selftest = aesni_mb_rawdev_pmd_selftest,
};

static const struct rte_multi_fn_ops mf_ops = {
	.session_create = aesni_mb_rawdev_pmd_session_create,
	.session_destroy = aesni_mb_rawdev_pmd_session_destroy,
};

static int
aesni_mb_rawdev_create(const char *name,
		       struct rte_vdev_device *vdev,
		       unsigned int socket_id)
{
	struct rte_rawdev *rawdev;
	struct aesni_mb_rawdev *aesni_mb_dev;
	enum aesni_mb_rawdev_vector_mode vector_mode;
	MB_MGR *mb_mgr;

	/* Allocate device structure */
	rawdev = rte_rawdev_pmd_allocate(name,
					 sizeof(struct aesni_mb_rawdev),
					 socket_id);
	if (!rawdev) {
		AESNI_MB_RAWDEV_ERR("Unable to allocate raw device");
		return -EINVAL;
	}

	rawdev->dev_ops = &aesni_mb_rawdev_ops;
	rawdev->device = &vdev->device;
	rawdev->driver_name = driver_name;

	/* Check CPU for supported vector instruction set */
	if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512F))
		vector_mode = AESNI_MB_RAWDEV_AVX512;
	else if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX2))
		vector_mode = AESNI_MB_RAWDEV_AVX2;
	else if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX))
		vector_mode = AESNI_MB_RAWDEV_AVX;
	else
		vector_mode = AESNI_MB_RAWDEV_SSE;

	/* Check CPU for support for AES instruction set */
	if (!rte_cpu_get_flag_enabled(RTE_CPUFLAG_AES))
		AESNI_MB_RAWDEV_WARN("AES instructions not supported by CPU");

	mb_mgr = alloc_mb_mgr(0);

	if (mb_mgr == NULL)
		return -ENOMEM;

	switch (vector_mode) {
	case AESNI_MB_RAWDEV_SSE:
		init_mb_mgr_sse(mb_mgr);
		break;
	case AESNI_MB_RAWDEV_AVX:
		init_mb_mgr_avx(mb_mgr);
		break;
	case AESNI_MB_RAWDEV_AVX2:
		init_mb_mgr_avx2(mb_mgr);
		break;
	case AESNI_MB_RAWDEV_AVX512:
		init_mb_mgr_avx512(mb_mgr);
		break;
	default:
		AESNI_MB_RAWDEV_ERR("Unsupported vector mode %u",
				    vector_mode);
		free_mb_mgr(mb_mgr);
		mb_mgr = NULL;
		break;
	}

	if (mb_mgr == NULL) {
		rte_rawdev_pmd_release(rawdev);
		return -1;
	}

	/* Set the device's private data */
	aesni_mb_dev = rawdev->dev_private;
	aesni_mb_dev->mf_ops = &mf_ops;
	aesni_mb_dev->vector_mode = vector_mode;
	aesni_mb_dev->max_nb_queue_pairs = MAX_QUEUES;
	aesni_mb_dev->mb_mgr = mb_mgr;

	AESNI_MB_RAWDEV_INFO("IPSec Multi-buffer library version used: %s",
			     imb_get_version_str());

	return 0;
}

static int
aesni_mb_rawdev_destroy(const char *name)
{
	struct rte_rawdev *rawdev;
	struct aesni_mb_rawdev *aesni_mb_dev;
	int ret;

	rawdev = rte_rawdev_pmd_get_named_dev(name);
	if (rawdev == NULL) {
		AESNI_MB_RAWDEV_ERR("Invalid device name (%s)", name);
		return -EINVAL;
	}

	aesni_mb_dev = rawdev->dev_private;
	free_mb_mgr(aesni_mb_dev->mb_mgr);

	ret = rte_rawdev_pmd_release(rawdev);
	if (ret)
		AESNI_MB_RAWDEV_DEBUG("Device cleanup failed");

	return 0;
}

static int
aesni_mb_rawdev_probe(struct rte_vdev_device *vdev)
{
	const char *name;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	AESNI_MB_RAWDEV_INFO("Init %s on NUMA node %d", name, rte_socket_id());

	return aesni_mb_rawdev_create(name, vdev, rte_socket_id());
}

static int
aesni_mb_rawdev_remove(struct rte_vdev_device *vdev)
{
	const char *name;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -1;

	AESNI_MB_RAWDEV_INFO("Closing %s on NUMA node %d",
			     name,
			     rte_socket_id());

	return aesni_mb_rawdev_destroy(name);
}

static struct rte_vdev_driver rawdev_aesni_mb_pmd_drv = {
	.probe = aesni_mb_rawdev_probe,
	.remove = aesni_mb_rawdev_remove
};

RTE_PMD_REGISTER_VDEV(rawdev_aesni_mb, rawdev_aesni_mb_pmd_drv);

RTE_INIT(aesni_mb_raw_init_log)
{
	aesni_mb_rawdev_pmd_logtype = rte_log_register("rawdev.aesni_mb");
	if (aesni_mb_rawdev_pmd_logtype >= 0)
		rte_log_set_level(aesni_mb_rawdev_pmd_logtype, RTE_LOG_INFO);
}
