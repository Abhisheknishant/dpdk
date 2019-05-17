/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#ifndef _IPH_H_
#define _IPH_H_

/**
 * @file iph.h
 * Contains functions/structures/macros to manipulate IPv4/IPv6 headers
 * used internally by ipsec library.
 */

#define IPV6_DSCP_MASK	(DSCP_MASK << IPV6_HDR_TC_SHIFT)
#define IPV6_ECN_MASK	(ECN_MASK << IPV6_HDR_TC_SHIFT)
#define IPV6_TOS_MASK	(IPV6_ECN_MASK | IPV6_DSCP_MASK)
#define IPV6_ECN_CE	IPV6_ECN_MASK

/*
 * Move preceding (L3) headers down to remove ESP header and IV.
 */
static inline void
remove_esph(char *np, char *op, uint32_t hlen)
{
	uint32_t i;

	for (i = hlen; i-- != 0; np[i] = op[i])
		;
}

/*
 * Move preceding (L3) headers up to free space for ESP header and IV.
 */
static inline void
insert_esph(char *np, char *op, uint32_t hlen)
{
	uint32_t i;

	for (i = 0; i != hlen; i++)
		np[i] = op[i];
}

static inline uint8_t
get_ipv6_tos(rte_be32_t vtc_flow)
{
	uint32_t v;

	v = rte_be_to_cpu_32(vtc_flow);
	return v >> IPV6_HDR_TC_SHIFT;
}

static inline rte_be32_t
set_ipv6_tos(rte_be32_t vtc_flow, uint32_t tos)
{
	uint32_t v;

	v = rte_cpu_to_be_32(tos << IPV6_HDR_TC_SHIFT);
	vtc_flow &= ~rte_cpu_to_be_32(IPV6_TOS_MASK);

	return (v | vtc_flow);
}

/* update original ip header fields for transport case */
static inline int
update_trs_l3hdr(const struct rte_ipsec_sa *sa, void *p, uint32_t plen,
		uint32_t l2len, uint32_t l3len, uint8_t proto)
{
	struct ipv4_hdr *v4h;
	struct ipv6_hdr *v6h;
	int32_t rc;

	if ((sa->type & RTE_IPSEC_SATP_IPV_MASK) == RTE_IPSEC_SATP_IPV4) {
		v4h = p;
		rc = v4h->next_proto_id;
		v4h->next_proto_id = proto;
		v4h->total_length = rte_cpu_to_be_16(plen - l2len);
	} else if (l3len == sizeof(*v6h)) {
		v6h = p;
		rc = v6h->proto;
		v6h->proto = proto;
		v6h->payload_len = rte_cpu_to_be_16(plen - l2len -
				sizeof(*v6h));
	/* need to add support for IPv6 with options */
	} else
		rc = -ENOTSUP;

	return rc;
}

/* update original and new ip header fields for tunnel case */
static inline void
update_outb_tun_l3hdr(const struct rte_ipsec_sa *sa, void *outh,
		const void *inh, uint32_t plen, uint32_t l2len, rte_be16_t pid)
{
	struct ipv4_hdr *v4h;
	struct ipv6_hdr *v6h;
	uint32_t itp, otp;
	const struct ipv4_hdr *v4in_h;
	const struct ipv6_hdr *v6in_h;

	if (sa->type & RTE_IPSEC_SATP_MODE_TUNLV4) {
		v4h = outh;
		v4h->packet_id = pid;
		v4h->total_length = rte_cpu_to_be_16(plen - l2len);

		if (sa->proto == IPPROTO_IPIP) {
			/* ipv4 inner header */
			v4in_h = inh;

			otp = v4h->type_of_service & ~sa->tos_mask;
			itp = v4in_h->type_of_service & sa->tos_mask;
			v4h->type_of_service = (otp | itp);
		} else {
			/* ipv6 inner header */
			v6in_h = inh;

			otp = v4h->type_of_service & ~sa->tos_mask;
			itp = get_ipv6_tos(v6in_h->vtc_flow) & sa->tos_mask;
			v4h->type_of_service = (otp | itp);
		}
	} else {
		v6h = outh;
		v6h->payload_len = rte_cpu_to_be_16(plen - l2len -
				sizeof(*v6h));

		if (sa->proto == IPPROTO_IPIP) {
			/* ipv4 inner header */
			v4in_h = inh;

			otp = get_ipv6_tos(v6h->vtc_flow) & ~sa->tos_mask;
			itp = v4in_h->type_of_service & sa->tos_mask;
			v6h->vtc_flow = set_ipv6_tos(v6h->vtc_flow, otp | itp);
		} else {
			/* ipv6 inner header */
			v6in_h = inh;

			otp = get_ipv6_tos(v6h->vtc_flow) & ~sa->tos_mask;
			itp = get_ipv6_tos(v6in_h->vtc_flow) & sa->tos_mask;
			v6h->vtc_flow = set_ipv6_tos(v6h->vtc_flow, otp | itp);
		}
	}
}

static inline void
update_inb_tun_l3_hdr(const struct rte_ipsec_sa *sa, void *ip_inner,
		const void *ip_outter)
{
	struct ipv4_hdr *inner_v4h;
	const struct ipv4_hdr *outter_v4h;
	struct ipv6_hdr *inner_v6h;
	const struct ipv6_hdr *outter_v6h;
	uint8_t ecn_v4out, ecn_v4in;
	uint32_t ecn_v6out, ecn_v6in;

	inner_v4h = ip_inner;
	outter_v4h = ip_outter;

	inner_v6h = ip_inner;
	outter_v6h = ip_outter;

	/* <update ecn bits in inner IP header> */
	if (sa->type & RTE_IPSEC_SATP_MODE_TUNLV4) {

		ecn_v4out = outter_v4h->type_of_service & ECN_MASK;

		if ((sa->type & RTE_IPSEC_SATP_IPV_MASK) == RTE_IPSEC_SATP_IPV4) {
			ecn_v4in = inner_v4h->type_of_service & ECN_MASK;
			if (ecn_v4out == ECN_CE && ecn_v4in != 0)
				inner_v4h->type_of_service |= ECN_CE;
		} else {
			ecn_v6in = inner_v6h->vtc_flow &
					rte_cpu_to_be_32(IPV6_ECN_MASK);
			if (ecn_v4out == ECN_CE && ecn_v6in != 0)
				inner_v6h->vtc_flow |=
						rte_cpu_to_be_32(IPV6_ECN_CE);
		}
	} else {
		ecn_v6out = outter_v6h->vtc_flow &
				rte_cpu_to_be_32(IPV6_ECN_MASK);

		if ((sa->type & RTE_IPSEC_SATP_IPV_MASK) == RTE_IPSEC_SATP_IPV6) {
			ecn_v6in = inner_v6h->vtc_flow &
					rte_cpu_to_be_32(IPV6_ECN_MASK);
			if (ecn_v6out == IPV6_ECN_CE && ecn_v6in != 0)
				inner_v6h->vtc_flow |=
						rte_cpu_to_be_32(IPV6_ECN_CE);
		} else {
			ecn_v4in = inner_v4h->type_of_service & ECN_MASK;
			if (ecn_v6out == ECN_CE && ecn_v4in != 0)
				inner_v4h->type_of_service |= ECN_CE;
		}
	}
}

#endif /* _IPH_H_ */
