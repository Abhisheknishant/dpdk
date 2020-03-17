/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015-2018 Intel Corporation
 */

#include <rte_bus_pci.h>
#include <rte_common.h>
#include <rte_dev.h>
#include <rte_malloc.h>
#include <rte_pci.h>
#include <rte_cryptodev_pmd.h>
#include <rte_rawdev_pmd.h>

#include "qat_sym_capabilities.h"
#include "qat_device.h"

//#include "qat_logs.h"
#include "qat.h"
#include "qat.h"
//#include "qat_raw_session.h"
//#include "qat_raw_pmd.h"

static const struct rte_cryptodev_capabilities qat_gen1_sym_capabilities[] = {
	QAT_BASE_GEN1_SYM_CAPABILITIES,
	RTE_CRYPTODEV_END_OF_CAPABILITIES_LIST()
};

static const struct rte_cryptodev_capabilities qat_gen2_sym_capabilities[] = {
	QAT_BASE_GEN1_SYM_CAPABILITIES,
	QAT_EXTRA_GEN2_SYM_CAPABILITIES,
	RTE_CRYPTODEV_END_OF_CAPABILITIES_LIST()
};

static int qat_raw_qp_release(struct rte_rawdev *dev,
	uint16_t queue_pair_id);

static int qat_raw_dev_config(__rte_unused struct rte_rawdev *dev,
		__rte_unused struct rte_cryptodev_config *config)
{
	return 0;
}

static int qat_raw_dev_start(__rte_unused struct rte_rawdev *dev)
{
	return 0;
}

static void qat_raw_dev_stop(__rte_unused struct rte_rawdev *dev)
{
	return;
}

static int qat_raw_dev_close(struct rte_rawdev *dev)
{
	int i, ret;
	struct qat_private *priv = dev->dev_private;

	for (i = 0; i < priv->data->nb_queue_pairs; i++) {
		ret = qat_raw_qp_release(dev, i);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static void qat_raw_dev_info_get(struct rte_rawdev *dev,
			struct rte_cryptodev_info *info)
{
	struct qat_private *priv = dev->dev_private;
	struct qat_raw_dev_private *internals = priv->data->dev_private;
	const struct qat_qp_hw_data *sym_hw_qps =
		qat_gen_config[internals->qat_dev->qat_dev_gen]
			      .qp_hw_data[QAT_SERVICE_SYMMETRIC];

	if (info != NULL) {
		info->max_nb_queue_pairs =
			qat_qps_per_service(sym_hw_qps, QAT_SERVICE_SYMMETRIC);
		info->feature_flags = priv->feature_flags;
		info->capabilities = internals->qat_dev_capabilities;
		/* No limit of number of sessions */
		info->sym.max_nb_sessions = 0;
	}
}

static void qat_raw_stats_get(struct rte_rawdev *dev,
		struct rte_cryptodev_stats *stats)
{
	struct qat_common_stats qat_stats = {0};
	struct qat_private *priv = NULL;
	struct qat_raw_dev_private *qat_priv;

	if (stats == NULL || dev == NULL) {
		QAT_LOG(ERR, "invalid ptr: stats %p, dev %p", stats, dev);
		return;
	}
	priv = dev->dev_private;
	qat_priv = &priv->raw_priv;

	qat_stats_get(qat_priv->qat_dev, &qat_stats, QAT_SERVICE_SYMMETRIC);
	stats->enqueued_count = qat_stats.enqueued_count;
	stats->dequeued_count = qat_stats.dequeued_count;
	stats->enqueue_err_count = qat_stats.enqueue_err_count;
	stats->dequeue_err_count = qat_stats.dequeue_err_count;
}

static void qat_raw_stats_reset(struct rte_rawdev *dev)
{
	struct qat_raw_dev_private *qat_priv;
	struct qat_private *priv = NULL;

	if (dev == NULL) {
		QAT_LOG(ERR, "invalid cryptodev ptr %p", dev);
		return;
	}
	priv = dev->dev_private;
	qat_priv = &priv->raw_priv;

	qat_stats_reset(qat_priv->qat_dev, QAT_SERVICE_SYMMETRIC);

}

static int qat_raw_qp_release(struct rte_rawdev *dev, uint16_t queue_pair_id)
{
	struct qat_private *priv = dev->dev_private;
	struct qat_raw_dev_private *qat_private = &priv->raw_priv;

	QAT_LOG(DEBUG, "Release sym qp %u on device %d",
				queue_pair_id, priv->data->dev_id);

	qat_private->qat_dev->qps_in_use[QAT_SERVICE_SYMMETRIC][queue_pair_id]
						= NULL;

	return qat_qp_release((struct qat_qp **)
			&(priv->data->queue_pairs[queue_pair_id]));
}

int
qat_raw_build_request(void *in_op, uint8_t *out_msg,
		void *op_cookie, enum qat_device_gen qat_dev_gen)
{
	int ret = 0;
	struct qat_sym_session *ctx;
	struct icp_qat_fw_la_cipher_req_params *cipher_param;
	struct icp_qat_fw_la_auth_req_params *auth_param;
	register struct icp_qat_fw_la_bulk_req *qat_req;
	uint8_t do_auth = 0, do_cipher = 0, do_aead = 0;
	uint32_t cipher_len = 0, cipher_ofs = 0;
	uint32_t auth_len = 0, auth_ofs = 0;
	uint32_t min_ofs = 0;
	uint64_t src_buf_start = 0, dst_buf_start = 0;
	uint64_t auth_data_end = 0;
	uint8_t do_sgl = 0;
	uint8_t in_place = 1;
	int alignment_adjustment = 0;
	struct rte_crypto_op *op = (struct rte_crypto_op *)in_op;
	struct qat_sym_op_cookie *cookie =
				(struct qat_sym_op_cookie *)op_cookie;

	if (unlikely(op->type != RTE_CRYPTO_OP_TYPE_SYMMETRIC)) {
		QAT_DP_LOG(ERR, "QAT PMD only supports symmetric crypto "
				"operation requests, op (%p) is not a "
				"symmetric operation.", op);
		return -EINVAL;
	}

	if (unlikely(op->sess_type == RTE_CRYPTO_OP_SESSIONLESS)) {
		QAT_DP_LOG(ERR, "QAT PMD only supports session oriented"
				" requests, op (%p) is sessionless.", op);
		return -EINVAL;
	}

	ctx = (struct qat_sym_session *)get_sym_session_private_data(
			op->sym->session, cryptodev_qat_driver_id);

	if (unlikely(ctx == NULL)) {
		QAT_DP_LOG(ERR, "Session was not created for this device");
		return -EINVAL;
	}

	if (unlikely(ctx->min_qat_dev_gen > qat_dev_gen)) {
		QAT_DP_LOG(ERR, "Session alg not supported on this device gen");
		op->status = RTE_CRYPTO_OP_STATUS_INVALID_SESSION;
		return -EINVAL;
	}

	qat_req = (struct icp_qat_fw_la_bulk_req *)out_msg;
	rte_mov128((uint8_t *)qat_req, (const uint8_t *)&(ctx->fw_req));
	qat_req->comn_mid.opaque_data = (uint64_t)(uintptr_t)op;
	cipher_param = (void *)&qat_req->serv_specif_rqpars;
	auth_param = (void *)((uint8_t *)cipher_param +
			ICP_QAT_FW_HASH_REQUEST_PARAMETERS_OFFSET);

	if (ctx->qat_cmd == ICP_QAT_FW_LA_CMD_HASH_CIPHER ||
			ctx->qat_cmd == ICP_QAT_FW_LA_CMD_CIPHER_HASH) {
		/* AES-GCM or AES-CCM */
		if (ctx->qat_hash_alg == ICP_QAT_HW_AUTH_ALGO_GALOIS_128 ||
			ctx->qat_hash_alg == ICP_QAT_HW_AUTH_ALGO_GALOIS_64 ||
			(ctx->qat_cipher_alg == ICP_QAT_HW_CIPHER_ALGO_AES128
			&& ctx->qat_mode == ICP_QAT_HW_CIPHER_CTR_MODE
			&& ctx->qat_hash_alg ==
					ICP_QAT_HW_AUTH_ALGO_AES_CBC_MAC)) {
			do_aead = 1;
		} else {
			do_auth = 1;
			do_cipher = 1;
		}
	} else if (ctx->qat_cmd == ICP_QAT_FW_LA_CMD_AUTH) {
		do_auth = 1;
		do_cipher = 0;
	} else if (ctx->qat_cmd == ICP_QAT_FW_LA_CMD_CIPHER) {
		do_auth = 0;
		do_cipher = 1;
	}

	if (do_cipher) {

		if (ctx->qat_cipher_alg ==
					 ICP_QAT_HW_CIPHER_ALGO_SNOW_3G_UEA2 ||
			ctx->qat_cipher_alg == ICP_QAT_HW_CIPHER_ALGO_KASUMI ||
			ctx->qat_cipher_alg ==
				ICP_QAT_HW_CIPHER_ALGO_ZUC_3G_128_EEA3) {

			if (unlikely(
			    (op->sym->cipher.data.length % BYTE_LENGTH != 0) ||
			    (op->sym->cipher.data.offset % BYTE_LENGTH != 0))) {
				QAT_DP_LOG(ERR,
		  "SNOW3G/KASUMI/ZUC in QAT PMD only supports byte aligned values");
				op->status = RTE_CRYPTO_OP_STATUS_INVALID_ARGS;
				return -EINVAL;
			}
			cipher_len = op->sym->cipher.data.length >> 3;
			cipher_ofs = op->sym->cipher.data.offset >> 3;

		} else if (ctx->bpi_ctx) {
			/* DOCSIS - only send complete blocks to device
			 * Process any partial block using CFB mode.
			 * Even if 0 complete blocks, still send this to device
			 * to get into rx queue for post-process and dequeuing
			 */
			cipher_len = qat_bpicipher_preprocess(ctx, op);
			cipher_ofs = op->sym->cipher.data.offset;
		} else {
			cipher_len = op->sym->cipher.data.length;
			cipher_ofs = op->sym->cipher.data.offset;
		}

		set_cipher_iv(ctx->cipher_iv.length, ctx->cipher_iv.offset,
				cipher_param, op, qat_req);
		min_ofs = cipher_ofs;
	}

	if (do_auth) {

		if (ctx->qat_hash_alg == ICP_QAT_HW_AUTH_ALGO_SNOW_3G_UIA2 ||
			ctx->qat_hash_alg == ICP_QAT_HW_AUTH_ALGO_KASUMI_F9 ||
			ctx->qat_hash_alg ==
				ICP_QAT_HW_AUTH_ALGO_ZUC_3G_128_EIA3) {
			if (unlikely(
			    (op->sym->auth.data.offset % BYTE_LENGTH != 0) ||
			    (op->sym->auth.data.length % BYTE_LENGTH != 0))) {
				QAT_DP_LOG(ERR,
		"For SNOW3G/KASUMI/ZUC, QAT PMD only supports byte aligned values");
				op->status = RTE_CRYPTO_OP_STATUS_INVALID_ARGS;
				return -EINVAL;
			}
			auth_ofs = op->sym->auth.data.offset >> 3;
			auth_len = op->sym->auth.data.length >> 3;

			auth_param->u1.aad_adr =
					rte_crypto_op_ctophys_offset(op,
							ctx->auth_iv.offset);

		} else if (ctx->qat_hash_alg ==
					ICP_QAT_HW_AUTH_ALGO_GALOIS_128 ||
				ctx->qat_hash_alg ==
					ICP_QAT_HW_AUTH_ALGO_GALOIS_64) {
			/* AES-GMAC */
			set_cipher_iv(ctx->auth_iv.length,
				ctx->auth_iv.offset,
				cipher_param, op, qat_req);
			auth_ofs = op->sym->auth.data.offset;
			auth_len = op->sym->auth.data.length;

			auth_param->u1.aad_adr = 0;
			auth_param->u2.aad_sz = 0;

			/*
			 * If len(iv)==12B fw computes J0
			 */
			if (ctx->auth_iv.length == 12) {
				ICP_QAT_FW_LA_GCM_IV_LEN_FLAG_SET(
					qat_req->comn_hdr.serv_specif_flags,
					ICP_QAT_FW_LA_GCM_IV_LEN_12_OCTETS);

			}
		} else {
			auth_ofs = op->sym->auth.data.offset;
			auth_len = op->sym->auth.data.length;

		}
		min_ofs = auth_ofs;

		auth_param->auth_res_addr =
			op->sym->auth.digest.phys_addr;

	}

	if (do_aead) {
		/*
		 * This address may used for setting AAD physical pointer
		 * into IV offset from op
		 */
		rte_iova_t aad_phys_addr_aead = op->sym->aead.aad.phys_addr;
		if (ctx->qat_hash_alg ==
				ICP_QAT_HW_AUTH_ALGO_GALOIS_128 ||
				ctx->qat_hash_alg ==
					ICP_QAT_HW_AUTH_ALGO_GALOIS_64) {
			/*
			 * If len(iv)==12B fw computes J0
			 */
			if (ctx->cipher_iv.length == 12) {
				ICP_QAT_FW_LA_GCM_IV_LEN_FLAG_SET(
					qat_req->comn_hdr.serv_specif_flags,
					ICP_QAT_FW_LA_GCM_IV_LEN_12_OCTETS);
			}
			set_cipher_iv(ctx->cipher_iv.length,
					ctx->cipher_iv.offset,
					cipher_param, op, qat_req);

		} else if (ctx->qat_hash_alg ==
				ICP_QAT_HW_AUTH_ALGO_AES_CBC_MAC) {

			/* In case of AES-CCM this may point to user selected
			 * memory or iv offset in cypto_op
			 */
			uint8_t *aad_data = op->sym->aead.aad.data;
			/* This is true AAD length, it not includes 18 bytes of
			 * preceding data
			 */
			uint8_t aad_ccm_real_len = 0;
			uint8_t aad_len_field_sz = 0;
			uint32_t msg_len_be =
					rte_bswap32(op->sym->aead.data.length);

			if (ctx->aad_len > ICP_QAT_HW_CCM_AAD_DATA_OFFSET) {
				aad_len_field_sz = ICP_QAT_HW_CCM_AAD_LEN_INFO;
				aad_ccm_real_len = ctx->aad_len -
					ICP_QAT_HW_CCM_AAD_B0_LEN -
					ICP_QAT_HW_CCM_AAD_LEN_INFO;
			} else {
				/*
				 * aad_len not greater than 18, so no actual aad
				 *  data, then use IV after op for B0 block
				 */
				aad_data = rte_crypto_op_ctod_offset(op,
						uint8_t *,
						ctx->cipher_iv.offset);
				aad_phys_addr_aead =
						rte_crypto_op_ctophys_offset(op,
							ctx->cipher_iv.offset);
			}

			uint8_t q = ICP_QAT_HW_CCM_NQ_CONST -
							ctx->cipher_iv.length;

			aad_data[0] = ICP_QAT_HW_CCM_BUILD_B0_FLAGS(
							aad_len_field_sz,
							ctx->digest_length, q);

			if (q > ICP_QAT_HW_CCM_MSG_LEN_MAX_FIELD_SIZE) {
				memcpy(aad_data	+ ctx->cipher_iv.length +
				    ICP_QAT_HW_CCM_NONCE_OFFSET +
				    (q - ICP_QAT_HW_CCM_MSG_LEN_MAX_FIELD_SIZE),
				    (uint8_t *)&msg_len_be,
				    ICP_QAT_HW_CCM_MSG_LEN_MAX_FIELD_SIZE);
			} else {
				memcpy(aad_data	+ ctx->cipher_iv.length +
				    ICP_QAT_HW_CCM_NONCE_OFFSET,
				    (uint8_t *)&msg_len_be
				    + (ICP_QAT_HW_CCM_MSG_LEN_MAX_FIELD_SIZE
				    - q), q);
			}

			if (aad_len_field_sz > 0) {
				*(uint16_t *)&aad_data[ICP_QAT_HW_CCM_AAD_B0_LEN]
						= rte_bswap16(aad_ccm_real_len);

				if ((aad_ccm_real_len + aad_len_field_sz)
						% ICP_QAT_HW_CCM_AAD_B0_LEN) {
					uint8_t pad_len = 0;
					uint8_t pad_idx = 0;

					pad_len = ICP_QAT_HW_CCM_AAD_B0_LEN -
					((aad_ccm_real_len + aad_len_field_sz) %
						ICP_QAT_HW_CCM_AAD_B0_LEN);
					pad_idx = ICP_QAT_HW_CCM_AAD_B0_LEN +
					    aad_ccm_real_len + aad_len_field_sz;
					memset(&aad_data[pad_idx],
							0, pad_len);
				}

			}

			set_cipher_iv_ccm(ctx->cipher_iv.length,
					ctx->cipher_iv.offset,
					cipher_param, op, q,
					aad_len_field_sz);

		}

		cipher_len = op->sym->aead.data.length;
		cipher_ofs = op->sym->aead.data.offset;
		auth_len = op->sym->aead.data.length;
		auth_ofs = op->sym->aead.data.offset;

		auth_param->u1.aad_adr = aad_phys_addr_aead;
		auth_param->auth_res_addr = op->sym->aead.digest.phys_addr;
		min_ofs = op->sym->aead.data.offset;
	}

	if (op->sym->m_src->next || (op->sym->m_dst && op->sym->m_dst->next))
		do_sgl = 1;

	/* adjust for chain case */
	if (do_cipher && do_auth)
		min_ofs = cipher_ofs < auth_ofs ? cipher_ofs : auth_ofs;

	if (unlikely(min_ofs >= rte_pktmbuf_data_len(op->sym->m_src) && do_sgl))
		min_ofs = 0;

	if (unlikely(op->sym->m_dst != NULL)) {
		/* Out-of-place operation (OOP)
		 * Don't align DMA start. DMA the minimum data-set
		 * so as not to overwrite data in dest buffer
		 */
		in_place = 0;
		src_buf_start =
			rte_pktmbuf_iova_offset(op->sym->m_src, min_ofs);
		dst_buf_start =
			rte_pktmbuf_iova_offset(op->sym->m_dst, min_ofs);

	} else {
		/* In-place operation
		 * Start DMA at nearest aligned address below min_ofs
		 */
		src_buf_start =
			rte_pktmbuf_iova_offset(op->sym->m_src, min_ofs)
						& QAT_64_BTYE_ALIGN_MASK;

		if (unlikely((rte_pktmbuf_iova(op->sym->m_src) -
					rte_pktmbuf_headroom(op->sym->m_src))
							> src_buf_start)) {
			/* alignment has pushed addr ahead of start of mbuf
			 * so revert and take the performance hit
			 */
			src_buf_start =
				rte_pktmbuf_iova_offset(op->sym->m_src,
								min_ofs);
		}
		dst_buf_start = src_buf_start;

		/* remember any adjustment for later, note, can be +/- */
		alignment_adjustment = src_buf_start -
			rte_pktmbuf_iova_offset(op->sym->m_src, min_ofs);
	}

	if (do_cipher || do_aead) {
		cipher_param->cipher_offset =
				(uint32_t)rte_pktmbuf_iova_offset(
				op->sym->m_src, cipher_ofs) - src_buf_start;
		cipher_param->cipher_length = cipher_len;
	} else {
		cipher_param->cipher_offset = 0;
		cipher_param->cipher_length = 0;
	}

	if (do_auth || do_aead) {
		auth_param->auth_off = (uint32_t)rte_pktmbuf_iova_offset(
				op->sym->m_src, auth_ofs) - src_buf_start;
		auth_param->auth_len = auth_len;
	} else {
		auth_param->auth_off = 0;
		auth_param->auth_len = 0;
	}

	qat_req->comn_mid.dst_length =
		qat_req->comn_mid.src_length =
		(cipher_param->cipher_offset + cipher_param->cipher_length)
		> (auth_param->auth_off + auth_param->auth_len) ?
		(cipher_param->cipher_offset + cipher_param->cipher_length)
		: (auth_param->auth_off + auth_param->auth_len);

	if (do_auth && do_cipher) {
		/* Handle digest-encrypted cases, i.e.
		 * auth-gen-then-cipher-encrypt and
		 * cipher-decrypt-then-auth-verify
		 */
		 /* First find the end of the data */
		if (do_sgl) {
			uint32_t remaining_off = auth_param->auth_off +
				auth_param->auth_len + alignment_adjustment;
			struct rte_mbuf *sgl_buf =
				(in_place ?
					op->sym->m_src : op->sym->m_dst);

			while (remaining_off >= rte_pktmbuf_data_len(sgl_buf)
					&& sgl_buf->next != NULL) {
				remaining_off -= rte_pktmbuf_data_len(sgl_buf);
				sgl_buf = sgl_buf->next;
			}

			auth_data_end = (uint64_t)rte_pktmbuf_iova_offset(
				sgl_buf, remaining_off);
		} else {
			auth_data_end = (in_place ?
				src_buf_start : dst_buf_start) +
				auth_param->auth_off + auth_param->auth_len;
		}
		/* Then check if digest-encrypted conditions are met */
		if ((auth_param->auth_off + auth_param->auth_len <
					cipher_param->cipher_offset +
					cipher_param->cipher_length) &&
				(op->sym->auth.digest.phys_addr ==
					auth_data_end)) {
			/* Handle partial digest encryption */
			if (cipher_param->cipher_offset +
					cipher_param->cipher_length <
					auth_param->auth_off +
					auth_param->auth_len +
					ctx->digest_length)
				qat_req->comn_mid.dst_length =
					qat_req->comn_mid.src_length =
					auth_param->auth_off +
					auth_param->auth_len +
					ctx->digest_length;
			struct icp_qat_fw_comn_req_hdr *header =
				&qat_req->comn_hdr;
			ICP_QAT_FW_LA_DIGEST_IN_BUFFER_SET(
				header->serv_specif_flags,
				ICP_QAT_FW_LA_DIGEST_IN_BUFFER);
		}
	}

	if (do_sgl) {

		ICP_QAT_FW_COMN_PTR_TYPE_SET(qat_req->comn_hdr.comn_req_flags,
				QAT_COMN_PTR_TYPE_SGL);
		ret = qat_sgl_fill_array(op->sym->m_src,
		   (int64_t)(src_buf_start - rte_pktmbuf_iova(op->sym->m_src)),
		   &cookie->qat_sgl_src,
		   qat_req->comn_mid.src_length,
		   QAT_SYM_SGL_MAX_NUMBER);

		if (unlikely(ret)) {
			QAT_DP_LOG(ERR, "QAT PMD Cannot fill sgl array");
			return ret;
		}

		if (likely(op->sym->m_dst == NULL))
			qat_req->comn_mid.dest_data_addr =
				qat_req->comn_mid.src_data_addr =
				cookie->qat_sgl_src_phys_addr;
		else {
			ret = qat_sgl_fill_array(op->sym->m_dst,
				(int64_t)(dst_buf_start -
					  rte_pktmbuf_iova(op->sym->m_dst)),
				 &cookie->qat_sgl_dst,
				 qat_req->comn_mid.dst_length,
				 QAT_SYM_SGL_MAX_NUMBER);

			if (unlikely(ret)) {
				QAT_DP_LOG(ERR, "QAT PMD can't fill sgl array");
				return ret;
			}

			qat_req->comn_mid.src_data_addr =
				cookie->qat_sgl_src_phys_addr;
			qat_req->comn_mid.dest_data_addr =
					cookie->qat_sgl_dst_phys_addr;
		}
		qat_req->comn_mid.src_length = 0;
		qat_req->comn_mid.dst_length = 0;
	} else {
		qat_req->comn_mid.src_data_addr = src_buf_start;
		qat_req->comn_mid.dest_data_addr = dst_buf_start;
	}

	/* Handle Single-Pass GCM */
	if (ctx->is_single_pass) {
		cipher_param->spc_aad_addr = op->sym->aead.aad.phys_addr;
		cipher_param->spc_auth_res_addr =
				op->sym->aead.digest.phys_addr;
	}

#if RTE_LOG_DP_LEVEL >= RTE_LOG_DEBUG
	QAT_DP_HEXDUMP_LOG(DEBUG, "qat_req:", qat_req,
			sizeof(struct icp_qat_fw_la_bulk_req));
	QAT_DP_HEXDUMP_LOG(DEBUG, "src_data:",
			rte_pktmbuf_mtod(op->sym->m_src, uint8_t*),
			rte_pktmbuf_data_len(op->sym->m_src));
	if (do_cipher) {
		uint8_t *cipher_iv_ptr = rte_crypto_op_ctod_offset(op,
						uint8_t *,
						ctx->cipher_iv.offset);
		QAT_DP_HEXDUMP_LOG(DEBUG, "cipher iv:", cipher_iv_ptr,
				ctx->cipher_iv.length);
	}

	if (do_auth) {
		if (ctx->auth_iv.length) {
			uint8_t *auth_iv_ptr = rte_crypto_op_ctod_offset(op,
							uint8_t *,
							ctx->auth_iv.offset);
			QAT_DP_HEXDUMP_LOG(DEBUG, "auth iv:", auth_iv_ptr,
						ctx->auth_iv.length);
		}
		QAT_DP_HEXDUMP_LOG(DEBUG, "digest:", op->sym->auth.digest.data,
				ctx->digest_length);
	}

	if (do_aead) {
		QAT_DP_HEXDUMP_LOG(DEBUG, "digest:", op->sym->aead.digest.data,
				ctx->digest_length);
		QAT_DP_HEXDUMP_LOG(DEBUG, "aad:", op->sym->aead.aad.data,
				ctx->aad_len);
	}
#endif
	return 0;
}

static int qat_raw_qp_setup(struct rte_rawdev *dev, uint16_t qp_id,
	const struct rte_cryptodev_qp_conf *qp_conf,
	int socket_id)
{
	struct qat_qp *qp;
	int ret = 0;
	uint32_t i;
	struct qat_qp_config qat_qp_conf;
	struct qat_private *priv = dev->dev_private;

	struct qat_qp **qp_addr =
			(struct qat_qp **)&(priv->data->queue_pairs[qp_id]);
	struct qat_raw_dev_private *qat_private = priv->data->dev_private;
	const struct qat_qp_hw_data *sym_hw_qps =
			qat_gen_config[qat_private->qat_dev->qat_dev_gen]
				      .qp_hw_data[QAT_SERVICE_SYMMETRIC];
	const struct qat_qp_hw_data *qp_hw_data = sym_hw_qps + qp_id;

	/* If qp is already in use free ring memory and qp metadata. */
	if (*qp_addr != NULL) {
		ret = qat_raw_qp_release(dev, qp_id);
		if (ret < 0)
			return ret;
	}
	if (qp_id >= qat_qps_per_service(sym_hw_qps, QAT_SERVICE_SYMMETRIC)) {
		QAT_LOG(ERR, "qp_id %u invalid for this device", qp_id);
		return -EINVAL;
	}

	qat_qp_conf.hw = qp_hw_data;
	qat_qp_conf.build_request = qat_raw_build_request;
	qat_qp_conf.cookie_size = sizeof(struct qat_raw_op_cookie);
	qat_qp_conf.nb_descriptors = qp_conf->nb_descriptors;
	qat_qp_conf.socket_id = socket_id;
	qat_qp_conf.service_str = "sym";

	ret = qat_qp_setup(qat_private->qat_dev, qp_addr, qp_id, &qat_qp_conf);
	if (ret != 0)
		return ret;

	/* store a link to the qp in the qat_pci_device */
	qat_private->qat_dev->qps_in_use[QAT_SERVICE_SYMMETRIC][qp_id]
							= *qp_addr;

	qp = (struct qat_qp *)*qp_addr;
	qp->min_enq_burst_threshold = qat_private->min_enq_burst_threshold;

	for (i = 0; i < qp->nb_descriptors; i++) {

		struct qat_sym_op_cookie *cookie =
				qp->op_cookies[i];

		cookie->qat_sgl_src_phys_addr =
				rte_mempool_virt2iova(cookie) +
				offsetof(struct qat_sym_op_cookie,
				qat_sgl_src);

		cookie->qat_sgl_dst_phys_addr =
				rte_mempool_virt2iova(cookie) +
				offsetof(struct qat_sym_op_cookie,
				qat_sgl_dst);
	}

	return ret;
}

static struct rte_rawdev_ops rawdev_qat_ops = {

		/* Device related operations */
		.dev_configure		= qat_raw_dev_config,
		.dev_start		= qat_raw_dev_start,
		.dev_stop		= qat_raw_dev_stop,
		.dev_close		= qat_raw_dev_close,
		.dev_infos_get		= qat_raw_dev_info_get,

		.stats_get		= qat_raw_stats_get,
		.stats_reset		= qat_raw_stats_reset,
		.queue_pair_setup	= qat_raw_qp_setup,
		.queue_pair_release	= qat_raw_qp_release,
		.queue_pair_count	= NULL,

		/* Crypto related operations */
		.sym_session_get_size	= qat_raw_session_get_private_size,
		.sym_session_configure	= qat_raw_session_configure,
		.sym_session_clear	= qat_raw_session_clear
};

static uint16_t
qat_raw_pmd_enqueue_op_burst(void *qp, struct rte_crypto_op **ops,
		uint16_t nb_ops)
{
	return qat_enqueue_op_burst(qp, (void **)ops, nb_ops);
}

static uint16_t
qat_raw_pmd_dequeue_op_burst(void *qp, struct rte_crypto_op **ops,
		uint16_t nb_ops)
{
	return qat_dequeue_op_burst(qp, (void **)ops, nb_ops);
}

/* An rte_driver is needed in the registration of both the device and the driver
 * with cryptodev.
 * The actual qat pci's rte_driver can't be used as its name represents
 * the whole pci device with all services. Think of this as a holder for a name
 * for the crypto part of the pci device.
 */
static const char qat_raw_drv_name[] = RTE_STR(CRYPTODEV_NAME_QAT_SYM_PMD);
static const struct rte_driver rawdev_qat_raw_driver = {
	.name = qat_raw_drv_name,
	.alias = qat_raw_drv_name
};

int
qat_raw_dev_create(struct qat_pci_device *qat_pci_dev,
		struct qat_dev_cmd_param *qat_dev_cmd_param __rte_unused)
{
	int i = 0;
	struct qat_raw_pmd_init_params init_params = {
			.name = "",
			.socket_id = qat_pci_dev->pci_dev->device.numa_node,
			.private_data_size = sizeof(struct qat_raw_dev_private)
	};
	char name[RTE_RAWDEV_NAME_MAX_LEN];
	struct rte_rawdev *rawdev;
	struct qat_raw_dev_private *internals;
	struct qat_private *qat_priv = NULL;

	snprintf(name, RTE_RAWDEV_NAME_MAX_LEN, "%s_%s",
			qat_pci_dev->name, "raw");
	QAT_LOG(DEBUG, "Creating RAWDEV device %s", name);

	/* Populate subset device to use in cryptodev device creation */
	qat_pci_dev->sym_rte_dev.driver = &rawdev_qat_raw_driver;
	qat_pci_dev->sym_rte_dev.numa_node =
				qat_pci_dev->pci_dev->device.numa_node;
	qat_pci_dev->sym_rte_dev.devargs = NULL;


	rawdev = rte_rawdev_pmd_allocate(name, sizeof(struct qat_private),
			rte_socket_id());

//	dev = rte_cryptodev_pmd_create(name,
//			&(qat_pci_dev->sym_rte_dev), &init_params);

	rawdev = rte_rawdev_pmd_allocate(name, &(qat_pci_dev->sym_rte_dev),
			init_params->socket_id);

	if (rawdev == NULL)
		return -ENODEV;

	qat_pci_dev->sym_rte_dev.name = rawdev->name;
	rawdev->dev_ops = &crypto_qat_ops;

//	cryptodev->enqueue_burst = qat_raw_pmd_enqueue_op_burst;
//	cryptodev->dequeue_burst = qat_raw_pmd_dequeue_op_burst;

	qat_priv = rawdev->dev_private;
	qat_priv->feature_flags = RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO |
			RTE_CRYPTODEV_FF_HW_ACCELERATED |
			RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING |
			RTE_CRYPTODEV_FF_IN_PLACE_SGL |
			RTE_CRYPTODEV_FF_OOP_SGL_IN_SGL_OUT |
			RTE_CRYPTODEV_FF_OOP_SGL_IN_LB_OUT |
			RTE_CRYPTODEV_FF_OOP_LB_IN_SGL_OUT |
			RTE_CRYPTODEV_FF_OOP_LB_IN_LB_OUT |
			RTE_CRYPTODEV_FF_DIGEST_ENCRYPTED;

	internals = qat_priv->raw_priv;
	internals->qat_dev = qat_pci_dev;
	qat_pci_dev->sym_dev = internals;

	internals->sym_dev_id = cryptodev->data->dev_id;
	switch (qat_pci_dev->qat_dev_gen) {
	case QAT_GEN1:
		internals->qat_dev_capabilities = qat_gen1_sym_capabilities;
		break;
	case QAT_GEN2:
	case QAT_GEN3:
		internals->qat_dev_capabilities = qat_gen2_sym_capabilities;
		break;
	default:
		internals->qat_dev_capabilities = qat_gen2_sym_capabilities;
		QAT_LOG(DEBUG,
			"QAT gen %d capabilities unknown, default to GEN2",
					qat_pci_dev->qat_dev_gen);
		break;
	}

	while (1) {
		if (qat_dev_cmd_param[i].name == NULL)
			break;
		if (!strcmp(qat_dev_cmd_param[i].name, SYM_ENQ_THRESHOLD_NAME))
			internals->min_enq_burst_threshold =
					qat_dev_cmd_param[i].val;
		i++;
	}

	QAT_LOG(DEBUG, "Created QAT SYM device %s as cryptodev instance %d",
			cryptodev->data->name, internals->sym_dev_id);
	return 0;
}

int
qat_raw_dev_destroy(struct qat_pci_device *qat_pci_dev)
{
	struct rte_cryptodev *cryptodev;

	if (qat_pci_dev == NULL)
		return -ENODEV;
	if (qat_pci_dev->sym_dev == NULL)
		return 0;

	/* free crypto device */
	cryptodev = rte_cryptodev_pmd_get_dev(qat_pci_dev->sym_dev->sym_dev_id);
	rte_cryptodev_pmd_destroy(cryptodev);
	qat_pci_dev->sym_rte_dev.name = NULL;
	qat_pci_dev->sym_dev = NULL;

	return 0;

	rte_rawdev_pmd_allocate()
}

static struct cryptodev_driver qat_crypto_drv;
