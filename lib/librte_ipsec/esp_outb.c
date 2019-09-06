/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#include <rte_ipsec.h>
#include <rte_esp.h>
#include <rte_ip.h>
#include <rte_errno.h>
#include <rte_cryptodev.h>

#include "sa.h"
#include "ipsec_sqn.h"
#include "crypto.h"
#include "iph.h"
#include "misc.h"
#include "pad.h"


/*
 * helper function to fill crypto_sym op for cipher+auth algorithms.
 * used by outb_cop_prepare(), see below.
 */
static inline void
sop_ciph_auth_prepare(struct rte_crypto_sym_op *sop,
	const struct rte_ipsec_sa *sa, const union sym_op_data *icv,
	uint32_t pofs, uint32_t plen)
{
	sop->cipher.data.offset = sa->ctp.cipher.offset + pofs;
	sop->cipher.data.length = sa->ctp.cipher.length + plen;
	sop->auth.data.offset = sa->ctp.auth.offset + pofs;
	sop->auth.data.length = sa->ctp.auth.length + plen;
	sop->auth.digest.data = icv->va;
	sop->auth.digest.phys_addr = icv->pa;
}

/*
 * helper function to fill crypto_sym op for cipher+auth algorithms.
 * used by outb_cop_prepare(), see below.
 */
static inline void
sop_aead_prepare(struct rte_crypto_sym_op *sop,
	const struct rte_ipsec_sa *sa, const union sym_op_data *icv,
	uint32_t pofs, uint32_t plen)
{
	sop->aead.data.offset = sa->ctp.cipher.offset + pofs;
	sop->aead.data.length = sa->ctp.cipher.length + plen;
	sop->aead.digest.data = icv->va;
	sop->aead.digest.phys_addr = icv->pa;
	sop->aead.aad.data = icv->va + sa->icv_len;
	sop->aead.aad.phys_addr = icv->pa + sa->icv_len;
}

/*
 * setup crypto op and crypto sym op for ESP outbound packet.
 */
static inline void
outb_cop_prepare(struct rte_crypto_op *cop,
	const struct rte_ipsec_sa *sa, const uint64_t ivp[IPSEC_MAX_IV_QWORD],
	const union sym_op_data *icv, uint32_t hlen, uint32_t plen)
{
	struct rte_crypto_sym_op *sop;
	struct aead_gcm_iv *gcm;
	struct aesctr_cnt_blk *ctr;
	uint32_t algo;

	algo = sa->algo_type;

	/* fill sym op fields */
	sop = cop->sym;

	switch (algo) {
	case ALGO_TYPE_AES_CBC:
		/* Cipher-Auth (AES-CBC *) case */
	case ALGO_TYPE_3DES_CBC:
		/* Cipher-Auth (3DES-CBC *) case */
	case ALGO_TYPE_NULL:
		/* NULL case */
		sop_ciph_auth_prepare(sop, sa, icv, hlen, plen);
		break;
	case ALGO_TYPE_AES_GCM:
		/* AEAD (AES_GCM) case */
		sop_aead_prepare(sop, sa, icv, hlen, plen);

		/* fill AAD IV (located inside crypto op) */
		gcm = rte_crypto_op_ctod_offset(cop, struct aead_gcm_iv *,
			sa->iv_ofs);
		aead_gcm_iv_fill(gcm, ivp[0], sa->salt);
		break;
	case ALGO_TYPE_AES_CTR:
		/* Cipher-Auth (AES-CTR *) case */
		sop_ciph_auth_prepare(sop, sa, icv, hlen, plen);

		/* fill CTR block (located inside crypto op) */
		ctr = rte_crypto_op_ctod_offset(cop, struct aesctr_cnt_blk *,
			sa->iv_ofs);
		aes_ctr_cnt_blk_fill(ctr, ivp[0], sa->salt);
		break;
	}
}

/*
 * setup/update packet data and metadata for ESP outbound tunnel case.
 */
static inline int32_t
outb_tun_pkt_prepare(struct rte_ipsec_sa *sa, rte_be64_t sqc,
	const uint64_t ivp[IPSEC_MAX_IV_QWORD], struct rte_mbuf *mb,
	union sym_op_data *icv, uint8_t sqh_len)
{
	uint32_t clen, hlen, l2len, pdlen, pdofs, plen, tlen;
	struct rte_mbuf *ml;
	struct rte_esp_hdr *esph;
	struct esp_tail *espt;
	char *ph, *pt;
	uint64_t *iv;

	/* calculate extra header space required */
	hlen = sa->hdr_len + sa->iv_len + sizeof(*esph);

	/* size of ipsec protected data */
	l2len = mb->l2_len;
	plen = mb->pkt_len - l2len;

	/* number of bytes to encrypt */
	clen = plen + sizeof(*espt);
	clen = RTE_ALIGN_CEIL(clen, sa->pad_align);

	/* pad length + esp tail */
	pdlen = clen - plen;
	tlen = pdlen + sa->icv_len + sqh_len;

	/* do append and prepend */
	ml = rte_pktmbuf_lastseg(mb);
	if (tlen + sa->aad_len > rte_pktmbuf_tailroom(ml))
		return -ENOSPC;

	/* prepend header */
	ph = rte_pktmbuf_prepend(mb, hlen - l2len);
	if (ph == NULL)
		return -ENOSPC;

	/* append tail */
	pdofs = ml->data_len;
	ml->data_len += tlen;
	mb->pkt_len += tlen;
	pt = rte_pktmbuf_mtod_offset(ml, typeof(pt), pdofs);

	/* update pkt l2/l3 len */
	mb->tx_offload = (mb->tx_offload & sa->tx_offload.msk) |
		sa->tx_offload.val;

	/* copy tunnel pkt header */
	rte_memcpy(ph, sa->hdr, sa->hdr_len);

	/* update original and new ip header fields */
	update_tun_outb_l3hdr(sa, ph + sa->hdr_l3_off, ph + hlen,
			mb->pkt_len - sqh_len, sa->hdr_l3_off, sqn_low16(sqc));

	/* update spi, seqn and iv */
	esph = (struct rte_esp_hdr *)(ph + sa->hdr_len);
	iv = (uint64_t *)(esph + 1);
	copy_iv(iv, ivp, sa->iv_len);

	esph->spi = sa->spi;
	esph->seq = sqn_low32(sqc);

	/* offset for ICV */
	pdofs += pdlen + sa->sqh_len;

	/* pad length */
	pdlen -= sizeof(*espt);

	/* copy padding data */
	rte_memcpy(pt, esp_pad_bytes, pdlen);

	/* update esp trailer */
	espt = (struct esp_tail *)(pt + pdlen);
	espt->pad_len = pdlen;
	espt->next_proto = sa->proto;

	icv->va = rte_pktmbuf_mtod_offset(ml, void *, pdofs);
	icv->pa = rte_pktmbuf_iova_offset(ml, pdofs);

	return clen;
}

/*
 * for pure cryptodev (lookaside none) depending on SA settings,
 * we might have to write some extra data to the packet.
 */
static inline void
outb_pkt_xprepare(const struct rte_ipsec_sa *sa, rte_be64_t sqc,
	const union sym_op_data *icv)
{
	uint32_t *psqh;
	struct aead_gcm_aad *aad;

	/* insert SQN.hi between ESP trailer and ICV */
	if (sa->sqh_len != 0) {
		psqh = (uint32_t *)(icv->va - sa->sqh_len);
		psqh[0] = sqn_hi32(sqc);
	}

	/*
	 * fill IV and AAD fields, if any (aad fields are placed after icv),
	 * right now we support only one AEAD algorithm: AES-GCM .
	 */
	if (sa->aad_len != 0) {
		aad = (struct aead_gcm_aad *)(icv->va + sa->icv_len);
		aead_gcm_aad_fill(aad, sa->spi, sqc, IS_ESN(sa));
	}
}

/*
 * setup/update packets and crypto ops for ESP outbound tunnel case.
 */
uint16_t
esp_outb_tun_prepare(const struct rte_ipsec_session *ss, struct rte_mbuf *mb[],
	struct rte_crypto_op *cop[], uint16_t num)
{
	int32_t rc;
	uint32_t i, k, n;
	uint64_t sqn;
	rte_be64_t sqc;
	struct rte_ipsec_sa *sa;
	struct rte_cryptodev_sym_session *cs;
	union sym_op_data icv;
	uint64_t iv[IPSEC_MAX_IV_QWORD];
	uint32_t dr[num];

	sa = ss->sa;
	cs = ss->crypto.ses;

	n = num;
	sqn = esn_outb_update_sqn(sa, &n);
	if (n != num)
		rte_errno = EOVERFLOW;

	k = 0;
	for (i = 0; i != n; i++) {

		sqc = rte_cpu_to_be_64(sqn + i);
		gen_iv(iv, sqc);

		/* try to update the packet itself */
		rc = outb_tun_pkt_prepare(sa, sqc, iv, mb[i], &icv,
					  sa->sqh_len);
		/* success, setup crypto op */
		if (rc >= 0) {
			outb_pkt_xprepare(sa, sqc, &icv);
			lksd_none_cop_prepare(cop[k], cs, mb[i]);
			outb_cop_prepare(cop[k], sa, iv, &icv, 0, rc);
			k++;
		/* failure, put packet into the death-row */
		} else {
			dr[i - k] = i;
			rte_errno = -rc;
		}
	}

	 /* copy not prepared mbufs beyond good ones */
	if (k != n && k != 0)
		move_bad_mbufs(mb, dr, n, n - k);

	return k;
}

/*
 * setup/update packet data and metadata for ESP outbound transport case.
 */
static inline int32_t
outb_trs_pkt_prepare(struct rte_ipsec_sa *sa, rte_be64_t sqc,
	const uint64_t ivp[IPSEC_MAX_IV_QWORD], struct rte_mbuf *mb,
	uint32_t l2len, uint32_t l3len, union sym_op_data *icv,
	uint8_t sqh_len)
{
	uint8_t np;
	uint32_t clen, hlen, pdlen, pdofs, plen, tlen, uhlen;
	struct rte_mbuf *ml;
	struct rte_esp_hdr *esph;
	struct esp_tail *espt;
	char *ph, *pt;
	uint64_t *iv;

	uhlen = l2len + l3len;
	plen = mb->pkt_len - uhlen;

	/* calculate extra header space required */
	hlen = sa->iv_len + sizeof(*esph);

	/* number of bytes to encrypt */
	clen = plen + sizeof(*espt);
	clen = RTE_ALIGN_CEIL(clen, sa->pad_align);

	/* pad length + esp tail */
	pdlen = clen - plen;
	tlen = pdlen + sa->icv_len + sqh_len;

	/* do append and insert */
	ml = rte_pktmbuf_lastseg(mb);
	if (tlen + sa->aad_len > rte_pktmbuf_tailroom(ml))
		return -ENOSPC;

	/* prepend space for ESP header */
	ph = rte_pktmbuf_prepend(mb, hlen);
	if (ph == NULL)
		return -ENOSPC;

	/* append tail */
	pdofs = ml->data_len;
	ml->data_len += tlen;
	mb->pkt_len += tlen;
	pt = rte_pktmbuf_mtod_offset(ml, typeof(pt), pdofs);

	/* shift L2/L3 headers */
	insert_esph(ph, ph + hlen, uhlen);

	/* update ip  header fields */
	np = update_trs_l3hdr(sa, ph + l2len, mb->pkt_len - sqh_len, l2len,
			l3len, IPPROTO_ESP);

	/* update spi, seqn and iv */
	esph = (struct rte_esp_hdr *)(ph + uhlen);
	iv = (uint64_t *)(esph + 1);
	copy_iv(iv, ivp, sa->iv_len);

	esph->spi = sa->spi;
	esph->seq = sqn_low32(sqc);

	/* offset for ICV */
	pdofs += pdlen + sa->sqh_len;

	/* pad length */
	pdlen -= sizeof(*espt);

	/* copy padding data */
	rte_memcpy(pt, esp_pad_bytes, pdlen);

	/* update esp trailer */
	espt = (struct esp_tail *)(pt + pdlen);
	espt->pad_len = pdlen;
	espt->next_proto = np;

	icv->va = rte_pktmbuf_mtod_offset(ml, void *, pdofs);
	icv->pa = rte_pktmbuf_iova_offset(ml, pdofs);

	return clen;
}

/*
 * setup/update packets and crypto ops for ESP outbound transport case.
 */
uint16_t
esp_outb_trs_prepare(const struct rte_ipsec_session *ss, struct rte_mbuf *mb[],
	struct rte_crypto_op *cop[], uint16_t num)
{
	int32_t rc;
	uint32_t i, k, n, l2, l3;
	uint64_t sqn;
	rte_be64_t sqc;
	struct rte_ipsec_sa *sa;
	struct rte_cryptodev_sym_session *cs;
	union sym_op_data icv;
	uint64_t iv[IPSEC_MAX_IV_QWORD];
	uint32_t dr[num];

	sa = ss->sa;
	cs = ss->crypto.ses;

	n = num;
	sqn = esn_outb_update_sqn(sa, &n);
	if (n != num)
		rte_errno = EOVERFLOW;

	k = 0;
	for (i = 0; i != n; i++) {

		l2 = mb[i]->l2_len;
		l3 = mb[i]->l3_len;

		sqc = rte_cpu_to_be_64(sqn + i);
		gen_iv(iv, sqc);

		/* try to update the packet itself */
		rc = outb_trs_pkt_prepare(sa, sqc, iv, mb[i], l2, l3, &icv,
					  sa->sqh_len);
		/* success, setup crypto op */
		if (rc >= 0) {
			outb_pkt_xprepare(sa, sqc, &icv);
			lksd_none_cop_prepare(cop[k], cs, mb[i]);
			outb_cop_prepare(cop[k], sa, iv, &icv, l2 + l3, rc);
			k++;
		/* failure, put packet into the death-row */
		} else {
			dr[i - k] = i;
			rte_errno = -rc;
		}
	}

	/* copy not prepared mbufs beyond good ones */
	if (k != n && k != 0)
		move_bad_mbufs(mb, dr, n, n - k);

	return k;
}


static inline int
outb_sync_crypto_proc_prepare(struct rte_mbuf *m, const struct rte_ipsec_sa *sa,
		const uint64_t ivp[IPSEC_MAX_IV_QWORD],
		const union sym_op_data *icv, uint32_t hlen, uint32_t plen,
		struct rte_security_vec *buf, struct iovec *cur_vec, void *iv,
		void **aad, void **digest)
{
	struct rte_mbuf *ms;
	struct aead_gcm_iv *gcm;
	struct aesctr_cnt_blk *ctr;
	struct iovec *vec = cur_vec;
	uint32_t left, off = 0, n_seg = 0;
	uint32_t algo;

	algo = sa->algo_type;

	switch (algo) {
	case ALGO_TYPE_AES_GCM:
		gcm = iv;
		aead_gcm_iv_fill(gcm, ivp[0], sa->salt);
		*aad = (void *)(icv->va + sa->icv_len);
		off = sa->ctp.cipher.offset + hlen;
		break;
	case ALGO_TYPE_AES_CBC:
	case ALGO_TYPE_3DES_CBC:
		off = sa->ctp.auth.offset + hlen;
		break;
	case ALGO_TYPE_AES_CTR:
		ctr = iv;
		aes_ctr_cnt_blk_fill(ctr, ivp[0], sa->salt);
		break;
	case ALGO_TYPE_NULL:
		break;
	}

	*digest = (void *)icv->va;

	left = sa->ctp.cipher.length + plen;

	ms = mbuf_get_seg_ofs(m, &off);
	if (!ms)
		return -1;

	while (n_seg < RTE_LIBRTE_IP_FRAG_MAX_FRAG && left && ms) {
		uint32_t len = RTE_MIN(left, ms->data_len - off);

		vec->iov_base = rte_pktmbuf_mtod_offset(ms, void *, off);
		vec->iov_len = len;

		left -= len;
		vec++;
		n_seg++;
		ms = ms->next;
		off = 0;
	}

	if (left)
		return -1;

	buf->vec = cur_vec;
	buf->num = n_seg;

	return n_seg;
}

/**
 * Local post process function prototype that same as process function prototype
 * as rte_ipsec_sa_pkt_func's process().
 */
typedef uint16_t (*sync_crypto_post_process)(const struct rte_ipsec_session *ss,
				struct rte_mbuf *mb[],
				uint16_t num);
static uint16_t
esp_outb_tun_sync_crypto_process(const struct rte_ipsec_session *ss,
		struct rte_mbuf *mb[], uint16_t num,
		sync_crypto_post_process post_process)
{
	uint64_t sqn;
	rte_be64_t sqc;
	struct rte_ipsec_sa *sa;
	struct rte_security_ctx *ctx;
	struct rte_security_session *rss;
	union sym_op_data icv;
	struct rte_security_vec buf[num];
	struct iovec vec[RTE_LIBRTE_IP_FRAG_MAX_FRAG * num];
	uint32_t vec_idx = 0;
	void *aad[num];
	void *digest[num];
	void *iv[num];
	uint8_t ivs[num][IPSEC_MAX_IV_SIZE];
	uint64_t ivp[IPSEC_MAX_IV_QWORD];
	int status[num];
	uint32_t dr[num];
	uint32_t i, n, k;
	int32_t rc;

	sa = ss->sa;
	ctx = ss->security.ctx;
	rss = ss->security.ses;

	k = 0;
	n = num;
	sqn = esn_outb_update_sqn(sa, &n);
	if (n != num)
		rte_errno = EOVERFLOW;

	for (i = 0; i != n; i++) {
		sqc = rte_cpu_to_be_64(sqn + i);
		gen_iv(ivp, sqc);

		/* try to update the packet itself */
		rc = outb_tun_pkt_prepare(sa, sqc, ivp, mb[i], &icv,
				sa->sqh_len);

		/* success, setup crypto op */
		if (rc >= 0) {
			outb_pkt_xprepare(sa, sqc, &icv);

			iv[k] = (void *)ivs[k];
			rc = outb_sync_crypto_proc_prepare(mb[i], sa, ivp, &icv,
					0, rc, &buf[k], &vec[vec_idx], iv[k],
					&aad[k], &digest[k]);
			if (rc < 0) {
				dr[i - k] = i;
				rte_errno = -rc;
				continue;
			}

			vec_idx += rc;
			k++;
		/* failure, put packet into the death-row */
		} else {
			dr[i - k] = i;
			rte_errno = -rc;
		}
	}

	 /* copy not prepared mbufs beyond good ones */
	if (k != n && k != 0)
		move_bad_mbufs(mb, dr, n, n - k);

	if (unlikely(k == 0)) {
		rte_errno = EBADMSG;
		return 0;
	}

	/* process the packets */
	n = 0;
	rte_security_process_cpu_crypto_bulk(ctx, rss, buf, iv, aad, digest,
			status, k);
	/* move failed process packets to dr */
	for (i = 0; i < n; i++) {
		if (status[i])
			dr[n++] = i;
	}

	if (n)
		move_bad_mbufs(mb, dr, k, n);

	return post_process(ss, mb, k - n);
}

static uint16_t
esp_outb_trs_sync_crypto_process(const struct rte_ipsec_session *ss,
		struct rte_mbuf *mb[], uint16_t num,
		sync_crypto_post_process post_process)

{
	uint64_t sqn;
	rte_be64_t sqc;
	struct rte_ipsec_sa *sa;
	struct rte_security_ctx *ctx;
	struct rte_security_session *rss;
	union sym_op_data icv;
	struct rte_security_vec buf[num];
	struct iovec vec[RTE_LIBRTE_IP_FRAG_MAX_FRAG * num];
	uint32_t vec_idx = 0;
	void *aad[num];
	void *digest[num];
	uint8_t ivs[num][IPSEC_MAX_IV_SIZE];
	void *iv[num];
	int status[num];
	uint64_t ivp[IPSEC_MAX_IV_QWORD];
	uint32_t dr[num];
	uint32_t i, n, k;
	uint32_t l2, l3;
	int32_t rc;

	sa = ss->sa;
	ctx = ss->security.ctx;
	rss = ss->security.ses;

	k = 0;
	n = num;
	sqn = esn_outb_update_sqn(sa, &n);
	if (n != num)
		rte_errno = EOVERFLOW;

	for (i = 0; i != n; i++) {
		l2 = mb[i]->l2_len;
		l3 = mb[i]->l3_len;

		sqc = rte_cpu_to_be_64(sqn + i);
		gen_iv(ivp, sqc);

		/* try to update the packet itself */
		rc = outb_trs_pkt_prepare(sa, sqc, ivp, mb[i], l2, l3, &icv,
				sa->sqh_len);

		/* success, setup crypto op */
		if (rc >= 0) {
			outb_pkt_xprepare(sa, sqc, &icv);

			iv[k] = (void *)ivs[k];

			rc = outb_sync_crypto_proc_prepare(mb[i], sa, ivp, &icv,
					l2 + l3, rc, &buf[k], &vec[vec_idx],
					iv[k], &aad[k], &digest[k]);
			if (rc < 0) {
				dr[i - k] = i;
				rte_errno = -rc;
				continue;
			}

			vec_idx += rc;
			k++;
		/* failure, put packet into the death-row */
		} else {
			dr[i - k] = i;
			rte_errno = -rc;
		}
	}

	 /* copy not prepared mbufs beyond good ones */
	if (k != n && k != 0)
		move_bad_mbufs(mb, dr, n, n - k);

	/* process the packets */
	n = 0;
	rte_security_process_cpu_crypto_bulk(ctx, rss, buf, iv, aad, digest,
			status, k);
	/* move failed process packets to dr */
	for (i = 0; i < k; i++) {
		if (status[i])
			dr[n++] = i;
	}

	if (n)
		move_bad_mbufs(mb, dr, k, n);

	return post_process(ss, mb, k - n);
}

uint16_t
esp_outb_tun_sync_crpyto_sqh_process(const struct rte_ipsec_session *ss,
		struct rte_mbuf *mb[], uint16_t num)
{
	return esp_outb_tun_sync_crypto_process(ss, mb, num,
			esp_outb_sqh_process);
}

uint16_t
esp_outb_tun_sync_crpyto_flag_process(const struct rte_ipsec_session *ss,
		struct rte_mbuf *mb[], uint16_t num)
{
	return esp_outb_tun_sync_crypto_process(ss, mb, num,
			esp_outb_pkt_flag_process);
}

uint16_t
esp_outb_trs_sync_crpyto_sqh_process(const struct rte_ipsec_session *ss,
		struct rte_mbuf *mb[], uint16_t num)
{
	return esp_outb_trs_sync_crypto_process(ss, mb, num,
			esp_outb_sqh_process);
}

uint16_t
esp_outb_trs_sync_crpyto_flag_process(const struct rte_ipsec_session *ss,
		struct rte_mbuf *mb[], uint16_t num)
{
	return esp_outb_trs_sync_crypto_process(ss, mb, num,
			esp_outb_pkt_flag_process);
}

/*
 * process outbound packets for SA with ESN support,
 * for algorithms that require SQN.hibits to be implictly included
 * into digest computation.
 * In that case we have to move ICV bytes back to their proper place.
 */
uint16_t
esp_outb_sqh_process(const struct rte_ipsec_session *ss,
	struct rte_mbuf *mb[], uint16_t num)
{
	uint32_t i, k, icv_len, *icv;
	struct rte_mbuf *ml;
	struct rte_ipsec_sa *sa;
	uint32_t dr[num];

	sa = ss->sa;

	k = 0;
	icv_len = sa->icv_len;

	for (i = 0; i != num; i++) {
		if ((mb[i]->ol_flags & PKT_RX_SEC_OFFLOAD_FAILED) == 0) {
			ml = rte_pktmbuf_lastseg(mb[i]);
			/* remove high-order 32 bits of esn from packet len */
			mb[i]->pkt_len -= sa->sqh_len;
			ml->data_len -= sa->sqh_len;
			icv = rte_pktmbuf_mtod_offset(ml, void *,
				ml->data_len - icv_len);
			remove_sqh(icv, icv_len);
			k++;
		} else
			dr[i - k] = i;
	}

	/* handle unprocessed mbufs */
	if (k != num) {
		rte_errno = EBADMSG;
		if (k != 0)
			move_bad_mbufs(mb, dr, num, num - k);
	}

	return k;
}

/*
 * prepare packets for inline ipsec processing:
 * set ol_flags and attach metadata.
 */
static inline void
inline_outb_mbuf_prepare(const struct rte_ipsec_session *ss,
	struct rte_mbuf *mb[], uint16_t num)
{
	uint32_t i, ol_flags;

	ol_flags = ss->security.ol_flags & RTE_SECURITY_TX_OLOAD_NEED_MDATA;
	for (i = 0; i != num; i++) {

		mb[i]->ol_flags |= PKT_TX_SEC_OFFLOAD;
		if (ol_flags != 0)
			rte_security_set_pkt_metadata(ss->security.ctx,
				ss->security.ses, mb[i], NULL);
	}
}

/*
 * process group of ESP outbound tunnel packets destined for
 * INLINE_CRYPTO type of device.
 */
uint16_t
inline_outb_tun_pkt_process(const struct rte_ipsec_session *ss,
	struct rte_mbuf *mb[], uint16_t num)
{
	int32_t rc;
	uint32_t i, k, n;
	uint64_t sqn;
	rte_be64_t sqc;
	struct rte_ipsec_sa *sa;
	union sym_op_data icv;
	uint64_t iv[IPSEC_MAX_IV_QWORD];
	uint32_t dr[num];

	sa = ss->sa;

	n = num;
	sqn = esn_outb_update_sqn(sa, &n);
	if (n != num)
		rte_errno = EOVERFLOW;

	k = 0;
	for (i = 0; i != n; i++) {

		sqc = rte_cpu_to_be_64(sqn + i);
		gen_iv(iv, sqc);

		/* try to update the packet itself */
		rc = outb_tun_pkt_prepare(sa, sqc, iv, mb[i], &icv, 0);

		k += (rc >= 0);

		/* failure, put packet into the death-row */
		if (rc < 0) {
			dr[i - k] = i;
			rte_errno = -rc;
		}
	}

	/* copy not processed mbufs beyond good ones */
	if (k != n && k != 0)
		move_bad_mbufs(mb, dr, n, n - k);

	inline_outb_mbuf_prepare(ss, mb, k);
	return k;
}

/*
 * process group of ESP outbound transport packets destined for
 * INLINE_CRYPTO type of device.
 */
uint16_t
inline_outb_trs_pkt_process(const struct rte_ipsec_session *ss,
	struct rte_mbuf *mb[], uint16_t num)
{
	int32_t rc;
	uint32_t i, k, n, l2, l3;
	uint64_t sqn;
	rte_be64_t sqc;
	struct rte_ipsec_sa *sa;
	union sym_op_data icv;
	uint64_t iv[IPSEC_MAX_IV_QWORD];
	uint32_t dr[num];

	sa = ss->sa;

	n = num;
	sqn = esn_outb_update_sqn(sa, &n);
	if (n != num)
		rte_errno = EOVERFLOW;

	k = 0;
	for (i = 0; i != n; i++) {

		l2 = mb[i]->l2_len;
		l3 = mb[i]->l3_len;

		sqc = rte_cpu_to_be_64(sqn + i);
		gen_iv(iv, sqc);

		/* try to update the packet itself */
		rc = outb_trs_pkt_prepare(sa, sqc, iv, mb[i],
				l2, l3, &icv, 0);

		k += (rc >= 0);

		/* failure, put packet into the death-row */
		if (rc < 0) {
			dr[i - k] = i;
			rte_errno = -rc;
		}
	}

	/* copy not processed mbufs beyond good ones */
	if (k != n && k != 0)
		move_bad_mbufs(mb, dr, n, n - k);

	inline_outb_mbuf_prepare(ss, mb, k);
	return k;
}

/*
 * outbound for RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL:
 * actual processing is done by HW/PMD, just set flags and metadata.
 */
uint16_t
inline_proto_outb_pkt_process(const struct rte_ipsec_session *ss,
	struct rte_mbuf *mb[], uint16_t num)
{
	inline_outb_mbuf_prepare(ss, mb, num);
	return num;
}
