/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

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

#include "aesni_mb_rawdev_private.h"

#define AESNI_MB_RAWDEV_PMD_SOCKET_ID_ARG ("socket_id")

static const char * const rawdev_pmd_valid_params[] = {
		AESNI_MB_RAWDEV_PMD_SOCKET_ID_ARG
};

static const unsigned err_detect_output_byte_lengths[] = {
		[IMB_AUTH_DOCSIS_CRC32]  = 4,
};

static inline unsigned
get_output_byte_length(JOB_HASH_ALG algo)
{
	return err_detect_output_byte_lengths[algo];
}

int
pmd_parse_uint_arg(const char *key __rte_unused,
		const char *value, void *extra_args);

int
parse_input_args(unsigned int *socket_id,
		const char *args);

static int
aesni_mb_rawdev_pmd_config(const struct rte_rawdev *dev,
		rte_rawdev_obj_t config)
{
	struct rte_multi_fn_device_info *dev_priv;
	struct rte_multi_fn_dev_config *conf;
	struct aesni_mb_rawdev_dev *d;

	dev_priv = config;
	conf = dev_priv->config;
	d = dev->dev_private;
	d->num_queue_pair = conf->nb_queues;

	d->queue_pairs = rte_zmalloc_socket("aesni_rawdev_qps",
			d->num_queue_pair * sizeof(struct aesni_mb_rawdev_qp),
			RTE_CACHE_LINE_SIZE, dev->socket_id);

	if (!d->queue_pairs) {
		AESNI_MB_RAWDEV_LOG(ERR, "Unable to allocate queue pairs");
		return -ENOMEM;
	}

	return 0;
}

static int
aesni_mb_rawdev_pmd_start(__rte_unused struct rte_rawdev *dev)
{
	return 0;
}

static void
aesni_mb_rawdev_pmd_stop(__rte_unused struct rte_rawdev *dev)
{
}

static int
aesni_mb_rawdev_pmd_close(__rte_unused struct rte_rawdev *dev)
{
	return 0;
}

static int
set_session_err_detect_parameters(struct aesni_mb_rawdev_session *sess,
		struct rte_multi_fn_err_detect_xform *xform)
{

	if (xform == NULL) {
		AESNI_MB_RAWDEV_LOG(ERR, "Invalid error detection xform");
		return -EINVAL;
	}

	/* Select error detect generate/verify */
	if (xform->op == RTE_MULTI_FN_ERR_DETECT_OP_VERIFY)
		sess->err_detect.operation =
				RTE_MULTI_FN_ERR_DETECT_OP_VERIFY;
	else if (xform->op == RTE_MULTI_FN_ERR_DETECT_OP_GENERATE)
		sess->err_detect.operation =
				RTE_MULTI_FN_ERR_DETECT_OP_GENERATE;
	else {
		AESNI_MB_RAWDEV_LOG(ERR, "Unsupported err_detect operation");
		return -ENOTSUP;
	}

	if (xform->algo == RTE_MULTI_FN_ERR_DETECT_CRC32_ETH) {
		sess->err_detect.algo = IMB_AUTH_DOCSIS_CRC32;
	} else {
		AESNI_MB_RAWDEV_LOG(ERR,
			"Unsupported error detect algorithm selection");
		return -ENOTSUP;
	}

	sess->err_detect.gen_output_len =
			get_output_byte_length(sess->err_detect.algo);

	return 0;
}

static int
set_session_cipher_parameters(const MB_MGR *mb_mgr,
		struct aesni_mb_rawdev_session *sess,
		const struct rte_crypto_sym_xform *xform)
{

	if (xform == NULL) {
		sess->cipher.mode = IMB_CIPHER_NULL;
		return -EINVAL;
	}

	if (xform->type != RTE_CRYPTO_SYM_XFORM_CIPHER) {
		AESNI_MB_RAWDEV_LOG(ERR, "Crypto xform not of type cipher");
		return -EINVAL;
	}

	/* Select cipher direction */
	switch (xform->cipher.op) {
	case RTE_CRYPTO_CIPHER_OP_ENCRYPT:
		sess->cipher.direction = IMB_DIR_ENCRYPT;
		break;
	case RTE_CRYPTO_CIPHER_OP_DECRYPT:
		sess->cipher.direction = IMB_DIR_DECRYPT;
		break;
	default:
		AESNI_MB_RAWDEV_LOG(ERR, "Invalid cipher operation parameter");
		return -EINVAL;
	}

	if (xform->cipher.algo == RTE_CRYPTO_CIPHER_AES_DOCSISBPI) {
		sess->cipher.mode = IMB_CIPHER_DOCSIS_SEC_BPI;
	} else {
		AESNI_MB_RAWDEV_LOG(ERR, "Unsupported cipher mode parameter");
		return -ENOTSUP;
	}

	/* Set IV parameters */
	sess->iv.offset = xform->cipher.iv.offset;
	sess->iv.length = xform->cipher.iv.length;

	/* Check key length and choose key expansion function for AES */
	switch (xform->cipher.key.length) {
	case IMB_KEY_AES_128_BYTES:
		sess->cipher.key_length_in_bytes = IMB_KEY_AES_128_BYTES;
		IMB_AES_KEYEXP_128(mb_mgr, xform->cipher.key.data,
				sess->cipher.expanded_aes_keys.encode,
				sess->cipher.expanded_aes_keys.decode);
		break;
	case IMB_KEY_AES_256_BYTES:
		sess->cipher.key_length_in_bytes = IMB_KEY_AES_256_BYTES;
		IMB_AES_KEYEXP_256(mb_mgr, xform->cipher.key.data,
				sess->cipher.expanded_aes_keys.encode,
				sess->cipher.expanded_aes_keys.decode);
		break;
	default:
		AESNI_MB_RAWDEV_LOG(ERR, "Invalid cipher key length");
		return -EINVAL;
	}

	return 0;
}

static int
aesni_mb_rawdev_pmd_enq(struct rte_rawdev *dev, struct rte_rawdev_buf **ops,
		unsigned int nb_ops, rte_rawdev_obj_t q_id)
{
	unsigned int nb_enqueued;
	struct aesni_mb_rawdev_dev *hw = dev->dev_private;
	struct aesni_mb_rawdev_qp *qp;

	qp = hw->queue_pairs[*(uint16_t *)q_id];

	nb_enqueued = rte_ring_enqueue_burst(qp->ingress_queue,
			(void **)ops, nb_ops, NULL);

	qp->stats.enqueued_count += nb_enqueued;

	return nb_enqueued;
}

static inline struct aesni_mb_rawdev_session *
get_session(struct rte_multi_fn_op *op)
{
	struct aesni_mb_rawdev_session *sess = NULL;

	if (likely(op->sess != NULL))
		sess = op->sess->sess_private_data;
	else
		op->op_status = RTE_MULTI_FN_STATUS_INVALID_SESSION;

	return sess;
}

static inline uint64_t
err_start_offset(struct rte_multi_fn_op *op,
		struct aesni_mb_rawdev_session *session, uint32_t oop)
{
	struct rte_mbuf *m_src, *m_dst;
	uint8_t *p_src, *p_dst;
	uintptr_t u_src, u_dst;
	uint32_t cipher_end, err_detect_end;
	struct rte_crypto_sym_op *s_op;
	struct rte_multi_fn_err_detect_op *e_op;

	s_op = &op->next->crypto_sym;
	e_op = &op->err_detect;
	m_src = op->m_src;
	m_dst = op->m_dst;

	/* Only cipher then error detect needs special calculation. */
	if (!oop || session->chain_order != IMB_ORDER_CIPHER_HASH)
		return op->next->err_detect.data.offset;

	p_src = rte_pktmbuf_mtod(m_src, uint8_t *);
	p_dst = rte_pktmbuf_mtod(m_dst, uint8_t *);
	u_src = (uintptr_t)p_src;
	u_dst = (uintptr_t)p_dst + e_op->data.offset;

	/**
	 * Copy the content between cipher offset and err detect offset
	 * for generating correct output.
	 */
	if (s_op->cipher.data.offset > e_op->data.offset)
		memcpy(p_dst + e_op->data.offset,
				p_src + e_op->data.offset,
				s_op->cipher.data.offset -
				e_op->data.offset);

	/**
	 * Copy the content between (cipher offset + length) and
	 * (error detect offset + length) for generating correct output
	 */
	cipher_end = s_op->cipher.data.offset + s_op->cipher.data.length;
	err_detect_end = e_op->data.offset + e_op->data.length;
	if (cipher_end < err_detect_end)
		memcpy(p_dst + cipher_end, p_src + cipher_end,
				err_detect_end - cipher_end);

	/**
	 * Since intel-ipsec-mb only supports positive values,
	 * we need to deduct the correct offset between src and dst.
	 */

	return u_src < u_dst ? (u_dst - u_src) :
			(UINT64_MAX - u_src + u_dst + 1);
}

static inline int
set_mb_job_params(JOB_AES_HMAC *job, struct aesni_mb_rawdev_qp *qp,
		struct rte_multi_fn_op *op, uint8_t *output_idx)
{
	struct rte_mbuf *m_src, *m_dst;
	struct rte_crypto_sym_op *s_op;
	struct rte_multi_fn_err_detect_op *e_op;
	uint32_t m_offset, oop;
	struct aesni_mb_rawdev_session *session;

	session = get_session(op);
	if (session == NULL) {
		op->op_status = RTE_MULTI_FN_STATUS_INVALID_SESSION;
		return -1;
	}

	if (op->next == NULL) {
		op->op_status = RTE_MULTI_FN_OP_STATUS_FAILURE;
		return -1;
	}

	m_src = op->m_src;

	/* Set crypto operation */
	job->chain_order = session->chain_order;
	if (session->chain_order == IMB_ORDER_CIPHER_HASH) {
		s_op = &op->crypto_sym;
		e_op = &op->next->err_detect;
	} else {
		s_op = &op->next->crypto_sym;
		e_op = &op->err_detect;
	}

	/* Set cipher parameters */
	job->cipher_direction = session->cipher.direction;
	job->cipher_mode = session->cipher.mode;

	job->aes_key_len_in_bytes = session->cipher.key_length_in_bytes;

	/* Set authentication parameters */
	job->hash_alg = session->err_detect.algo;

	job->aes_enc_key_expanded = session->cipher.expanded_aes_keys.encode;
	job->aes_dec_key_expanded = session->cipher.expanded_aes_keys.decode;

	if (!op->m_dst) {
		/* in-place operation */
		m_dst = m_src;
		oop = 0;
	} else if (op->m_dst == op->m_src) {
		/* in-place operation */
		m_dst = m_src;
		oop = 0;
	} else {
		/* out-of-place operation */
		m_dst = op->m_dst;
		oop = 1;
	}

	m_offset = s_op->cipher.data.offset;

	/* Set output location */
	if (session->err_detect.operation ==
			RTE_MULTI_FN_ERR_DETECT_OP_VERIFY) {
		job->auth_tag_output = qp->temp_digests[*output_idx];
		*output_idx = (*output_idx + 1) % MAX_JOBS;
	} else {
		job->auth_tag_output = e_op->output.data;
	}

	/* Set output length */
	job->auth_tag_output_len_in_bytes = session->err_detect.gen_output_len;

	/* Set IV parameters */
	job->iv_len_in_bytes = session->iv.length;

	/* Data Parameters */
	job->src = rte_pktmbuf_mtod(m_src, uint8_t *);
	job->dst = rte_pktmbuf_mtod_offset(m_dst, uint8_t *, m_offset);

	job->cipher_start_src_offset_in_bytes =	s_op->cipher.data.offset;
	job->msg_len_to_cipher_in_bytes = s_op->cipher.data.length;

	job->hash_start_src_offset_in_bytes = err_start_offset(op,
			session, oop);
	job->msg_len_to_hash_in_bytes = e_op->data.length;

	job->iv = (uint8_t *)op + session->iv.offset;

	job->user_data = op;

	return 0;
}

static inline void
verify_crc(JOB_AES_HMAC *job, uint8_t *status)
{
	uint16_t crc_offset = job->hash_start_src_offset_in_bytes +
				job->msg_len_to_hash_in_bytes -
				job->cipher_start_src_offset_in_bytes;
	uint8_t *embedded_crc = job->dst + crc_offset;

	if (!job->msg_len_to_hash_in_bytes)
		return;

	/* Verify CRC (at the end of the message) */
	if (memcmp(job->auth_tag_output, embedded_crc, 4) != 0)
		*status = RTE_CRYPTO_OP_STATUS_AUTH_FAILED;
}

static inline struct rte_multi_fn_op *
post_process_mb_job(JOB_AES_HMAC *job)
{
	struct rte_multi_fn_op *op = (struct rte_multi_fn_op *)
					job->user_data;
	struct aesni_mb_rawdev_session *sess = op->sess->sess_private_data;

	AESNI_MB_RAWDEV_LOG(INFO, "struct rte_multi_fn_session %p",
			op->sess);
	AESNI_MB_RAWDEV_LOG(INFO, "struct aesni_mb_rawdev_session %p", sess);

	if (likely(op->op_status ==
			RTE_MULTI_FN_OP_STATUS_NOT_PROCESSED)) {
		switch (job->status) {
		case STS_COMPLETED:
			op->op_status = RTE_MULTI_FN_OP_STATUS_SUCCESS;

			if (job->hash_alg == IMB_AUTH_NULL)
				break;

			if (sess->err_detect.operation ==
					RTE_MULTI_FN_ERR_DETECT_OP_VERIFY)
				verify_crc(job, &op->op_status);
			break;
		default:
			op->op_status = RTE_MULTI_FN_OP_STATUS_FAILURE;
		}
	}

	return op;
}

static unsigned
handle_completed_jobs(struct aesni_mb_rawdev_qp *qp, JOB_AES_HMAC *job,
		struct rte_multi_fn_op **ops, uint16_t nb_ops)
{
	struct rte_multi_fn_op *op = NULL;
	unsigned processed_jobs = 0;

	while (job != NULL) {
		op = post_process_mb_job(job);

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
flush_mb_mgr(struct aesni_mb_rawdev_qp *qp, struct rte_multi_fn_op **ops,
		uint16_t nb_ops)
{
	int processed_ops = 0;

	/* Flush the remaining jobs */
	JOB_AES_HMAC *job = IMB_FLUSH_JOB(qp->mb_mgr);

	AESNI_MB_RAWDEV_LOG(INFO, "qp->mb_mgr %p", qp->mb_mgr);

	if (job)
		processed_ops += handle_completed_jobs(qp, job,
				&ops[processed_ops], nb_ops - processed_ops);

	return processed_ops;
}

static inline JOB_AES_HMAC *
set_job_null_op(JOB_AES_HMAC *job, struct rte_multi_fn_op *op)
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
aesni_mb_rawdev_pmd_deq(struct rte_rawdev *dev, struct rte_rawdev_buf **ops,
		unsigned int nb_ops, rte_rawdev_obj_t q_id)
{
	struct aesni_mb_rawdev_qp *qp;
	struct rte_multi_fn_op *op;
	JOB_AES_HMAC *job;
	struct aesni_mb_rawdev_dev *hw = dev->dev_private;

	qp = hw->queue_pairs[*(uint16_t *)q_id];
	int retval;
	unsigned int processed_jobs = 0;

	if (unlikely(nb_ops == 0))
		return 0;

	AESNI_MB_RAWDEV_LOG(INFO, "qp->mb_mgr %p", qp->mb_mgr);

	uint8_t output_idx = qp->output_idx;
	do {
		/* Get next free mb job struct from mb manager */
		job = IMB_GET_NEXT_JOB(qp->mb_mgr);
		if (unlikely(job == NULL)) {
			/* if no free mb job structs we need to flush mb_mgr */
			processed_jobs += flush_mb_mgr(qp,
					(struct rte_multi_fn_op **)
					&ops[processed_jobs],
					nb_ops - processed_jobs);

			if (nb_ops == processed_jobs)
				break;

			job = IMB_GET_NEXT_JOB(qp->mb_mgr);
		}

		/*
		 * Get next operation to process from ingress queue.
		 * There is no need to return the job to the MB_MGR
		 * if there are no more operations to process, since the MB_MGR
		 * can use that pointer again in next get_next calls.
		 */
		retval = rte_ring_dequeue(qp->ingress_queue, (void **)&op);
		if (retval < 0)
			break;

		retval = set_mb_job_params(job, qp, op, &output_idx);
		if (unlikely(retval != 0)) {
			qp->stats.dequeue_err_count++;
			set_job_null_op(job, op);
		}

		/* Submit job to multi-buffer for processing */
#ifdef RTE_LIBRTE_PMD_AESNI_MB_DEBUG
		job = IMB_SUBMIT_JOB(qp->mb_mgr);
#else
		job = IMB_SUBMIT_JOB_NOCHECK(qp->mb_mgr);
#endif
		/*
		 * If submit returns a processed job then handle it,
		 * before submitting subsequent jobs
		 */
		if (job)
			processed_jobs += handle_completed_jobs(qp, job,
					(struct rte_multi_fn_op **)
					&ops[processed_jobs],
					nb_ops - processed_jobs);

	} while (processed_jobs < nb_ops);

	qp->output_idx = output_idx;

	if (processed_jobs < 1)
		processed_jobs += flush_mb_mgr(qp,
				(struct rte_multi_fn_op **)
				&ops[processed_jobs],
				nb_ops - processed_jobs);

	return processed_jobs;
}

static int
aesni_mb_rawdev_pmd_qp_release(struct rte_rawdev *dev, uint16_t qp_id)
{
	struct aesni_mb_rawdev_dev *hw = dev->dev_private;
	struct aesni_mb_rawdev_qp *qp = hw->queue_pairs[qp_id];
	struct rte_ring *r = NULL;

	if (qp != NULL) {
		r = rte_ring_lookup(qp->name);
		if (r)
			rte_ring_free(r);
		if (qp->mb_mgr)
			free_mb_mgr(qp->mb_mgr);
		rte_free(qp);
		hw->queue_pairs[qp_id] = NULL;
	}
	return 0;
}

static int
qp_set_unique_name(struct rte_rawdev *dev,
		struct aesni_mb_rawdev_qp *qp)
{
	unsigned n = snprintf(qp->name, sizeof(qp->name),
			"aesni_mb_pmd_%u_qp_%u",
			dev->dev_id, qp->id);

	if (n >= sizeof(qp->name))
		return -1;

	return 0;
}

static struct rte_ring *
qp_create_processed_ops_ring(struct aesni_mb_rawdev_qp *qp,
		unsigned int ring_size, int socket_id)
{
	struct rte_ring *r;
	char ring_name[RTE_CRYPTODEV_NAME_MAX_LEN];

	unsigned int n = strlcpy(ring_name, qp->name, sizeof(ring_name));

	if (n >= sizeof(ring_name))
		return NULL;

	r = rte_ring_lookup(ring_name);
	if (r) {
		if (rte_ring_get_size(r) >= ring_size) {
			AESNI_MB_RAWDEV_LOG(INFO, "Reusing existing ring %s for processed ops",
			ring_name);
			return r;
		}

		AESNI_MB_RAWDEV_LOG(ERR, "Unable to reuse existing ring %s for processed ops",
			ring_name);
		return NULL;
	}

	return rte_ring_create(ring_name, ring_size, socket_id,
			RING_F_SP_ENQ | RING_F_SC_DEQ);
}

static int
aesni_mb_rawdev_pmd_qp_setup(struct rte_rawdev *dev, uint16_t qp_id,
		rte_rawdev_obj_t qp_c)
{

	struct aesni_mb_rawdev_qp *qp = NULL;
	struct aesni_mb_rawdev_dev *hw = dev->dev_private;
	struct aesni_mb_rawdev_private *internals = &hw->priv;
	const struct rte_multi_fn_qp_config *qp_conf =
			(const struct rte_multi_fn_qp_config *)qp_c;
	int ret = -1;

	/* Free memory prior to re-allocation if needed. */
	if (hw->queue_pairs[qp_id] != NULL)
		aesni_mb_rawdev_pmd_qp_release(dev, qp_id);

	/* Allocate the queue pair data structure. */
	qp = rte_zmalloc_socket("AES-NI PMD Queue Pair", sizeof(*qp),
					RTE_CACHE_LINE_SIZE,
					internals->socket_id);
	if (qp == NULL)
		return -ENOMEM;

	qp->id = qp_id;
	hw->queue_pairs[qp_id] = qp;

	if (qp_set_unique_name(dev, qp))
		goto qp_setup_cleanup;

	qp->mb_mgr = alloc_mb_mgr(0);
	AESNI_MB_RAWDEV_LOG(INFO, "mb_mgr %p", qp->mb_mgr);
	if (qp->mb_mgr == NULL) {
		ret = -ENOMEM;
		goto qp_setup_cleanup;
	}

	switch (internals->vector_mode) {
	case AESNI_MB_RAWDEV_SSE:
		hw->feature_flags |= RTE_CRYPTODEV_FF_CPU_SSE;
		init_mb_mgr_sse(qp->mb_mgr);
		break;
	case AESNI_MB_RAWDEV_AVX:
		hw->feature_flags |= RTE_CRYPTODEV_FF_CPU_AVX;
		init_mb_mgr_avx(qp->mb_mgr);
		break;
	case AESNI_MB_RAWDEV_AVX2:
		hw->feature_flags |= RTE_CRYPTODEV_FF_CPU_AVX2;
		init_mb_mgr_avx2(qp->mb_mgr);
		break;
	case AESNI_MB_RAWDEV_AVX512:
		hw->feature_flags |= RTE_CRYPTODEV_FF_CPU_AVX512;
		init_mb_mgr_avx512(qp->mb_mgr);
		break;
	default:
		AESNI_MB_RAWDEV_LOG(ERR, "Unsupported vector mode %u\n",
				internals->vector_mode);
		goto qp_setup_cleanup;
	}

	qp->ingress_queue = qp_create_processed_ops_ring(qp,
			qp_conf->nb_descriptors, rte_socket_id());
	if (qp->ingress_queue == NULL) {
		ret = -1;
		goto qp_setup_cleanup;
	}

	memset(&qp->stats, 0, sizeof(qp->stats));

	char mp_name[RTE_MEMPOOL_NAMESIZE];

	snprintf(mp_name, RTE_MEMPOOL_NAMESIZE,
				"digest_mp_%u_%u", dev->dev_id, qp_id);
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
aesni_mb_rawdev_pmd_qp_count(struct rte_rawdev *dev)
{
	struct aesni_mb_rawdev_dev *hw = dev->dev_private;
	return hw->num_queue_pair;
}

static enum aesni_mb_rawdev_op
session_support(struct rte_multi_fn_xform *xform)
{
	struct rte_crypto_sym_xform *crypto_sym;
	struct rte_multi_fn_err_detect_xform *err_detect;
	struct rte_multi_fn_xform *next;
	enum aesni_mb_rawdev_op op = AESNI_MB_RAWDEV_OP_NOT_SUPPORTED;

	next = xform->next;
	/* err detect generate -> cipher encrypt */
	if (xform->type == RTE_MULTI_FN_XFORM_TYPE_ERR_DETECT) {

		err_detect = &xform->err_detect;
		if ((err_detect->algo ==
				RTE_MULTI_FN_ERR_DETECT_CRC32_ETH) &&
		    (err_detect->op ==
				RTE_MULTI_FN_ERR_DETECT_OP_GENERATE) &&
		     next != NULL &&
		     next->type == RTE_MULTI_FN_XFORM_TYPE_CRYPTO_SYM) {

			crypto_sym = &next->crypto_sym;
			if (crypto_sym->type ==
				RTE_CRYPTO_SYM_XFORM_CIPHER &&
			    crypto_sym->cipher.op ==
				RTE_CRYPTO_CIPHER_OP_ENCRYPT &&
			    crypto_sym->cipher.algo ==
				RTE_CRYPTO_CIPHER_AES_DOCSISBPI &&
			    crypto_sym->cipher.key.length ==
				IMB_KEY_AES_128_BYTES &&
			    crypto_sym->cipher.iv.length ==
				AES_BLOCK_SIZE) {
				op = AESNI_MB_RAWDEV_OP_ERR_DETECT_CIPHER;
			}
		}
	/* cipher decrypt -> err detect verify */
	} else if (xform->type == RTE_MULTI_FN_XFORM_TYPE_CRYPTO_SYM) {
		crypto_sym = &xform->crypto_sym;
		if (crypto_sym->type == RTE_CRYPTO_SYM_XFORM_CIPHER &&
		    crypto_sym->cipher.op == RTE_CRYPTO_CIPHER_OP_DECRYPT &&
		    crypto_sym->cipher.algo ==
				    RTE_CRYPTO_CIPHER_AES_DOCSISBPI &&
		    crypto_sym->cipher.key.length == IMB_KEY_AES_128_BYTES &&
		    crypto_sym->cipher.iv.length == AES_BLOCK_SIZE &&
		    next != NULL &&
		    next->type == RTE_MULTI_FN_XFORM_TYPE_ERR_DETECT) {

			err_detect = &next->err_detect;
			if ((err_detect->algo ==
				RTE_MULTI_FN_ERR_DETECT_CRC32_ETH) &&
			    (err_detect->op ==
				RTE_MULTI_FN_ERR_DETECT_OP_VERIFY)) {
				op = AESNI_MB_RAWDEV_OP_CIPHER_ERR_DETECT;
			}
		}

	}

	return op;
}

static struct rte_multi_fn_session *
aesni_mb_pmd_session_create(struct rte_rawdev *dev,
		struct rte_multi_fn_xform *xform,
		int socket_id)
{
	int ret;
	enum aesni_mb_rawdev_op op;
	struct rte_multi_fn_err_detect_xform *err_detect_xform;
	struct rte_crypto_sym_xform *cipher_xform;
	struct rte_multi_fn_session *session;
	struct aesni_mb_rawdev_session *aesni_sess = NULL;
	struct aesni_mb_rawdev_dev *d = dev->dev_private;
	struct aesni_mb_rawdev_private *internals = &d->priv;

	op = session_support(xform);

	/* Alloc rte_multi_fn_session */
	session = rte_zmalloc_socket("rte_multi_fn_session",
				sizeof(struct rte_multi_fn_session),
				RTE_CACHE_LINE_MIN_SIZE,
				socket_id);

	if (!session) {
		AESNI_MB_RAWDEV_LOG(ERR, "rte_multi_fn_session alloc failed");
		return NULL;
	}

	/* Alloc aesni_mb_rawdev_session */
	aesni_sess = rte_zmalloc_socket("aesni_mb_rawdev_session",
				sizeof(struct aesni_mb_rawdev_session),
				RTE_CACHE_LINE_MIN_SIZE,
				socket_id);

	if (!aesni_sess) {
		AESNI_MB_RAWDEV_LOG(ERR, "aesni_mb_rawdev_session alloc failed");
		return NULL;
	}

	session->sess_private_data = aesni_sess;

	switch (op) {
	case AESNI_MB_RAWDEV_OP_ERR_DETECT_CIPHER:
		aesni_sess->chain_order = IMB_ORDER_HASH_CIPHER;
		err_detect_xform = &xform->err_detect;
		cipher_xform = &xform->next->crypto_sym;
		break;
	case AESNI_MB_RAWDEV_OP_CIPHER_ERR_DETECT:
		aesni_sess->chain_order = IMB_ORDER_CIPHER_HASH;
		cipher_xform = &xform->crypto_sym;
		err_detect_xform = &xform->next->err_detect;
		break;
	default:
		AESNI_MB_RAWDEV_LOG(ERR, "Unsupported multi-function xform chain");
		return NULL;
	}

	/* Default IV length = 0 */
	aesni_sess->iv.length = 0;

	ret = set_session_err_detect_parameters(aesni_sess,
			err_detect_xform);

	if (ret != 0) {
		AESNI_MB_RAWDEV_LOG(ERR, "Invalid/unsupported error detect parameters");
		return NULL;
	}

	ret = set_session_cipher_parameters(internals->mb_mgr,
			aesni_sess,
			cipher_xform);

	if (ret != 0) {
		AESNI_MB_RAWDEV_LOG(ERR, "Invalid/unsupported cipher parameters");
		return NULL;
	}

	return session;
}

static int
aesni_mb_rawdev_pmd_session_destroy(struct rte_rawdev *dev __rte_unused,
				 struct rte_multi_fn_session *sess)
{

	if (sess) {
		if (sess->sess_private_data)
			rte_free(sess->sess_private_data);
		rte_free(sess);
	}

	return 0;
}

#define MAX_QUEUES 64

static void
aesni_mb_rawdev_pmd_info_get(struct rte_rawdev *dev __rte_unused,
				  rte_rawdev_obj_t dev_info)
{
	struct rte_multi_fn_dev_config *config = NULL;
	struct rte_multi_fn_device_info *dev_priv = dev_info;
	dev_priv->create = aesni_mb_pmd_session_create;
	dev_priv->destroy = aesni_mb_rawdev_pmd_session_destroy;
	config = dev_priv->config;
	config->nb_queues = MAX_QUEUES;
}

int
pmd_parse_uint_arg(const char *key __rte_unused,
		const char *value, void *extra_args)
{
	int i;
	char *end;
	errno = 0;

	i = strtol(value, &end, 10);
	if (*end != 0 || errno != 0 || i < 0)
		return -EINVAL;

	*((uint32_t *)extra_args) = i;
	return 0;
}

int
parse_input_args(unsigned int *socket_id,
		const char *args)
{
	struct rte_kvargs *kvlist = NULL;
	int ret = 0;

	if (socket_id == NULL)
		return -EINVAL;

	if (args) {
		kvlist = rte_kvargs_parse(args,	rawdev_pmd_valid_params);
		if (kvlist == NULL)
			return -EINVAL;

		ret = rte_kvargs_process(kvlist,
				AESNI_MB_RAWDEV_PMD_SOCKET_ID_ARG,
				&pmd_parse_uint_arg,
				socket_id);
		if (ret < 0)
			goto free_kvlist;

	}

free_kvlist:
	rte_kvargs_free(kvlist);
	return ret;
}

#define RTE_RAWDEV_PMD_DEFAULT_MAX_NB_QUEUE_PAIRS 8

static const char * const xstat_names[] = {
		"successful_enqueues", "successful_dequeues",
		"failed_enqueues", "failed_dequeues",
};

static int
aesni_mb_rawdev_xstats_get(const struct rte_rawdev *dev,
		const unsigned int ids[],
		uint64_t values[], unsigned int n)
{
	unsigned int i;
	struct aesni_mb_rawdev_dev *hw = dev->dev_private;
	struct aesni_mb_rawdev_qp *qp;
	struct aesni_mb_rawdev_stats stats = {0};
	int qp_id;

	for (qp_id = 0; qp_id < hw->num_queue_pair; qp_id++) {
		qp = hw->queue_pairs[qp_id];

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
aesni_mb_rawdev_xstats_get_names(const struct rte_rawdev *dev,
		struct rte_rawdev_xstats_name *names,
		unsigned int size)
{
	unsigned int i;

	RTE_SET_USED(dev);
	if (size < RTE_DIM(xstat_names))
		return RTE_DIM(xstat_names);

	for (i = 0; i < RTE_DIM(xstat_names); i++)
		strlcpy(names[i].name, xstat_names[i], sizeof(names[i]));

	return RTE_DIM(xstat_names);
}

static int
aesni_mb_rawdev_xstats_reset(struct rte_rawdev *dev, const uint32_t *ids,
		uint32_t nb_ids)
{
	struct aesni_mb_rawdev_dev *hw = dev->dev_private;
	struct aesni_mb_rawdev_qp *qp;
	unsigned int i;
	int qp_id;

	if (!ids) {

		for (qp_id = 0; qp_id < hw->num_queue_pair; qp_id++) {
			qp = hw->queue_pairs[qp_id];
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
			for (qp_id = 0; qp_id < hw->num_queue_pair; qp_id++) {
				qp = hw->queue_pairs[qp_id];
				qp->stats.enqueued_count = 0;
			}
			break;
		case 1:
			for (qp_id = 0; qp_id < hw->num_queue_pair; qp_id++) {
				qp = hw->queue_pairs[qp_id];
				qp->stats.dequeued_count = 0;
			}
			break;
		case 2:
			for (qp_id = 0; qp_id < hw->num_queue_pair; qp_id++) {
				qp = hw->queue_pairs[qp_id];
				qp->stats.enqueue_err_count = 0;
			}
			break;
		case 3:
			for (qp_id = 0; qp_id < hw->num_queue_pair; qp_id++) {
				qp = hw->queue_pairs[qp_id];
				qp->stats.dequeue_err_count = 0;
			}
			break;
		default:
			AESNI_MB_RAWDEV_LOG(ERR,
					"Invalid xstat id - cannot reset val");
			break;
		}
	}

	return 0;
}

static int
rawdev_aesni_mb_create(struct rte_rawdev *dev,
		struct rte_multi_fn_dev_config *init_params)
{

	static const struct rte_rawdev_ops aesni_mb_raw_ops = {
		.enqueue_bufs = aesni_mb_rawdev_pmd_enq,
		.dequeue_bufs = aesni_mb_rawdev_pmd_deq,
		.dev_configure = aesni_mb_rawdev_pmd_config,
		.dev_info_get = aesni_mb_rawdev_pmd_info_get,
		.dev_start = aesni_mb_rawdev_pmd_start,
		.dev_stop = aesni_mb_rawdev_pmd_stop,
		.dev_close = aesni_mb_rawdev_pmd_close,
		.queue_setup = aesni_mb_rawdev_pmd_qp_setup,
		.queue_release = aesni_mb_rawdev_pmd_qp_release,
		.queue_count = aesni_mb_rawdev_pmd_qp_count,
		.xstats_get = aesni_mb_rawdev_xstats_get,
		.xstats_get_names = aesni_mb_rawdev_xstats_get_names,
		.xstats_reset = aesni_mb_rawdev_xstats_reset,
	};

	struct aesni_mb_rawdev_dev *hw;
	struct aesni_mb_rawdev_private *internals;
	enum aesni_mb_rawdev_vector_mode vector_mode;
	MB_MGR *mb_mgr;

	hw = dev->dev_private;

	/* Check CPU for supported vector instruction set */
	if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512F))
		vector_mode = AESNI_MB_RAWDEV_AVX512;
	else if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX2))
		vector_mode = AESNI_MB_RAWDEV_AVX2;
	else if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX))
		vector_mode = AESNI_MB_RAWDEV_AVX;
	else
		vector_mode = AESNI_MB_RAWDEV_SSE;

	dev->dev_ops = &aesni_mb_raw_ops;

	hw->feature_flags = RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO |
			RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING |
			RTE_CRYPTODEV_FF_OOP_LB_IN_LB_OUT;

	/* Check CPU for support for AES instruction set */
	if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_AES))
		hw->feature_flags |= RTE_CRYPTODEV_FF_CPU_AESNI;
	else
		AESNI_MB_RAWDEV_LOG(WARNING, "AES instructions not supported by CPU");

	mb_mgr = alloc_mb_mgr(0);
	AESNI_MB_RAWDEV_LOG(INFO, "create() mb_mgr %p", mb_mgr);

	if (mb_mgr == NULL)
		return -ENOMEM;

	switch (vector_mode) {
	case AESNI_MB_RAWDEV_SSE:
		hw->feature_flags |= RTE_CRYPTODEV_FF_CPU_SSE;
		init_mb_mgr_sse(mb_mgr);
		break;
	case AESNI_MB_RAWDEV_AVX:
		hw->feature_flags |= RTE_CRYPTODEV_FF_CPU_AVX;
		init_mb_mgr_avx(mb_mgr);
		break;
	case AESNI_MB_RAWDEV_AVX2:
		hw->feature_flags |= RTE_CRYPTODEV_FF_CPU_AVX2;
		init_mb_mgr_avx2(mb_mgr);
		break;
	case AESNI_MB_RAWDEV_AVX512:
		hw->feature_flags |= RTE_CRYPTODEV_FF_CPU_AVX512;
		init_mb_mgr_avx512(mb_mgr);
		break;
	default:
		AESNI_MB_RAWDEV_LOG(ERR, "Unsupported vector mode %u\n",
			vector_mode);
		goto error_exit;
	}

	/* Set vector instructions mode supported */
	internals = &hw->priv;

	internals->vector_mode = vector_mode;
	internals->max_nb_queue_pairs = init_params->nb_queues;
	internals->mb_mgr = mb_mgr;
	internals->socket_id = init_params->socket_id;

	AESNI_MB_RAWDEV_LOG(INFO, "IPSec Multi-buffer library version used: %s\n",
			imb_get_version_str());

	return 0;

error_exit:
	if (mb_mgr)
		free_mb_mgr(mb_mgr);

	rte_rawdev_pmd_release(dev);

	return -1;
}

static int
aesni_mb_rawdev_probe(struct rte_vdev_device *vdev)
{
	const char *vdev_name;
	const char *args;
	struct rte_rawdev *rawdev;
	struct rte_multi_fn_dev_config init_params = {
			.nb_queues = 64,
			.socket_id = SOCKET_ID_ANY};

	vdev_name = rte_vdev_device_name(vdev);
	if (vdev_name == NULL)
		return -EINVAL;

	args = rte_vdev_device_args(vdev);

	/* Parse args */
	parse_input_args(&init_params.socket_id, args);

	AESNI_MB_RAWDEV_LOG(INFO, "device name %s", vdev_name);

	/* Allocate device structure */
	rawdev = rte_rawdev_pmd_allocate(vdev_name,
			sizeof(struct aesni_mb_rawdev_dev),
			rte_socket_id());

	if (!rawdev) {
		AESNI_MB_RAWDEV_LOG(ERR, "Unable to allocate raw device");
		return -EINVAL;
	}

	rawdev->driver_name = RTE_STR(rawdev_aesni_mb);

	AESNI_MB_RAWDEV_LOG(INFO, "Driver name %s", rawdev->driver_name);

	return rawdev_aesni_mb_create(rawdev, &init_params);
}

static int
aesni_mb_rawdev_remove(struct rte_vdev_device *vdev)
{
	struct rte_rawdev *dev;
	struct aesni_mb_rawdev_dev *hw;
	struct aesni_mb_rawdev_private *internals;
	const char *name;

	name = rte_vdev_device_name(vdev);
	if (name == NULL) {
		AESNI_MB_RAWDEV_LOG(INFO, "Driver name %s", name);
		return -EINVAL;
	}

	dev = rte_rawdev_pmd_get_named_dev(name);
	if (dev == NULL)
		return -ENODEV;

	hw = dev->dev_private;
	internals = &hw->priv;

	free_mb_mgr(internals->mb_mgr);

	return rte_rawdev_pmd_release(dev);
}

static struct rte_vdev_driver rawdev_aesni_mb_pmd_drv = {
	.probe = aesni_mb_rawdev_probe,
	.remove = aesni_mb_rawdev_remove
};

RTE_PMD_REGISTER_VDEV(rawdev_aesni_mb, rawdev_aesni_mb_pmd_drv);

RTE_INIT(aesni_mb_raw_init_log)
{
	aesni_mb_rawdev_logtype_driver = rte_log_register("pmd.raw.aesni_mb");
}
