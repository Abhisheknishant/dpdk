/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2020 Intel Corporation
 */

#ifndef _MISC_H_
#define _MISC_H_

/**
 * @file misc.h
 * Contains miscellaneous functions/structures/macros used internally
 * by ipsec library.
 */

/*
 * Move bad (unprocessed) mbufs beyond the good (processed) ones.
 * bad_idx[] contains the indexes of bad mbufs inside the mb[].
 */
static inline void
move_bad_mbufs(struct rte_mbuf *mb[], const uint32_t bad_idx[], uint32_t nb_mb,
	uint32_t nb_bad)
{
	uint32_t i, j, k;
	struct rte_mbuf *drb[nb_bad];

	j = 0;
	k = 0;

	/* copy bad ones into a temp place */
	for (i = 0; i != nb_mb; i++) {
		if (j != nb_bad && i == bad_idx[j])
			drb[j++] = mb[i];
		else
			mb[k++] = mb[i];
	}

	/* copy bad ones after the good ones */
	for (i = 0; i != nb_bad; i++)
		mb[k + i] = drb[i];
}

/*
 * Find packet's segment for the specified offset.
 * ofs - at input should contain required offset, at output would contain
 * offset value within the segment.
 */
static inline struct rte_mbuf *
mbuf_get_seg_ofs(struct rte_mbuf *mb, uint32_t *ofs)
{
	uint32_t k, n, plen;
	struct rte_mbuf *ms;

	plen = mb->pkt_len;
	n = *ofs;

	if (n == plen) {
		ms = rte_pktmbuf_lastseg(mb);
		n = n + rte_pktmbuf_data_len(ms) - plen;
	} else {
		ms = mb;
		for (k = rte_pktmbuf_data_len(ms); n >= k;
				k = rte_pktmbuf_data_len(ms)) {
			ms = ms->next;
			n -= k;
		}
	}

	*ofs = n;
	return ms;
}

/*
 * Trim multi-segment packet at the specified offset, and free
 * all unused segments.
 * mb - input packet
 * ms - segment where to cut
 * ofs - offset within the *ms*
 * len - length to cut (from given offset to the end of the packet)
 * Can be used in conjunction with mbuf_get_seg_ofs():
 * ofs = new_len;
 * ms = mbuf_get_seg_ofs(mb, &ofs);
 * mbuf_cut_seg_ofs(mb, ms, ofs, mb->pkt_len - new_len);
 */
static inline void
mbuf_cut_seg_ofs(struct rte_mbuf *mb, struct rte_mbuf *ms, uint32_t ofs,
	uint32_t len)
{
	uint32_t n, slen;
	struct rte_mbuf *mn;

	slen = ms->data_len;
	ms->data_len = ofs;

	/* tail spawns through multiple segments */
	if (slen < ofs + len) {
		mn = ms->next;
		ms->next = NULL;
		for (n = 0; mn != NULL; n++) {
			ms = mn->next;
			rte_pktmbuf_free_seg(mn);
			mn = ms;
		}
		mb->nb_segs -= n;
	}

	mb->pkt_len -= len;
}

static inline int
mbuf_to_cryptovec(const struct rte_mbuf *mb, uint32_t ofs, uint32_t data_len,
	struct rte_crypto_vec vec[], uint32_t num)
{
	uint32_t i;
	struct rte_mbuf *nseg;
	uint32_t left;
	uint32_t seglen;

	/* assuming that requested data starts in the first segment */
	RTE_ASSERT(mb->data_len > ofs);

	if (mb->nb_segs > num)
		return -mb->nb_segs;

	vec[0].base = rte_pktmbuf_mtod_offset(mb, void *, ofs);

	/* whole data lies in the first segment */
	seglen = mb->data_len - ofs;
	if (data_len <= seglen) {
		vec[0].len = data_len;
		return 1;
	}

	/* data spread across segments */
	vec[0].len = seglen;
	left = data_len - seglen;
	for (i = 1, nseg = mb->next; nseg != NULL; nseg = nseg->next, i++) {
		vec[i].base = rte_pktmbuf_mtod(nseg, void *);

		seglen = nseg->data_len;
		if (left <= seglen) {
			/* whole requested data is completed */
			vec[i].len = left;
			left = 0;
			break;
		}

		/* use whole segment */
		vec[i].len = seglen;
		left -= seglen;
	}

	RTE_ASSERT(left == 0);
	return i + 1;
}

/*
 * process packets using sync crypto engine
 */
static inline void
cpu_crypto_bulk(const struct rte_ipsec_session *ss,
	union rte_crypto_sym_ofs ofs, struct rte_mbuf *mb[],
	void *iv[], void *aad[], void *dgst[], uint32_t l4ofs[],
	uint32_t clen[], uint32_t num)
{
	uint32_t i, j, n;
	int32_t vcnt, vofs;
	int32_t st[num];
	struct rte_crypto_sgl vecpkt[num];
	struct rte_crypto_vec vec[UINT8_MAX];
	struct rte_crypto_sym_vec symvec;

	const uint32_t vnum = RTE_DIM(vec);

	j = 0, n = 0;
	vofs = 0;
	for (i = 0; i != num; i++) {

		vcnt = mbuf_to_cryptovec(mb[i], l4ofs[i], clen[i], &vec[vofs],
			vnum - vofs);

		/* not enough space in vec[] to hold all segments */
		if (vcnt < 0) {
			/* fill the request structure */
			symvec.sgl = &vecpkt[j];
			symvec.iv = &iv[j];
			symvec.aad = &aad[j];
			symvec.digest = &dgst[j];
			symvec.status = &st[j];
			symvec.num = i - j;

			/* flush vec array and try again */
			n += rte_cryptodev_sym_cpu_crypto_process(
				ss->crypto.dev_id, ss->crypto.ses, ofs,
				&symvec);
			vofs = 0;
			vcnt = mbuf_to_cryptovec(mb[i], l4ofs[i], clen[i], vec,
				vnum);
			RTE_ASSERT(vcnt > 0);
			j = i;
		}

		vecpkt[i].vec = &vec[vofs];
		vecpkt[i].num = vcnt;
		vofs += vcnt;
	}

	/* fill the request structure */
	symvec.sgl = &vecpkt[j];
	symvec.iv = &iv[j];
	symvec.aad = &aad[j];
	symvec.digest = &dgst[j];
	symvec.status = &st[j];
	symvec.num = i - j;

	n += rte_cryptodev_sym_cpu_crypto_process(ss->crypto.dev_id,
		ss->crypto.ses, ofs, &symvec);

	j = num - n;
	for (i = 0; j != 0 && i != num; i++) {
		if (st[i] != 0) {
			mb[i]->ol_flags |= PKT_RX_SEC_OFFLOAD_FAILED;
			j--;
		}
	}
}

#endif /* _MISC_H_ */
