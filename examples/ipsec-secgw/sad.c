/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#include <rte_errno.h>

#include "ipsec.h"
#include "sad.h"

int
ipsec_sad_add(struct ipsec_sad *sad, struct ipsec_sa *sa)
{
	int ret;
	union rte_ipsec_sad_key key = { {0} };

	/* spi field is common for ipv4 and ipv6 key types */
	key.v4.spi = rte_cpu_to_be_32(sa->spi);
	switch (WITHOUT_TRANSPORT_VERSION(sa->flags)) {
	case IP4_TUNNEL:
		key.v4.dip = rte_cpu_to_be_32(sa->dst.ip.ip4);
		key.v4.sip = rte_cpu_to_be_32(sa->src.ip.ip4);
		ret = rte_ipsec_sad_add(sad->sad_v4, &key,
				RTE_IPSEC_SAD_SPI_DIP_SIP, sa);
		if (ret != 0)
			return ret;
		break;
	case IP6_TUNNEL:
		memcpy(key.v6.dip, sa->dst.ip.ip6.ip6,
				sizeof(key.v6.dip));
		memcpy(key.v6.sip, sa->src.ip.ip6.ip6,
				sizeof(key.v6.sip));
		ret = rte_ipsec_sad_add(sad->sad_v6, &key,
				RTE_IPSEC_SAD_SPI_DIP_SIP, sa);
		if (ret != 0)
			return ret;
		break;
	case TRANSPORT:
		if (sp4_spi_present(sa->spi, 1, NULL, NULL) >= 0) {
			ret = rte_ipsec_sad_add(sad->sad_v4, &key,
				RTE_IPSEC_SAD_SPI_ONLY, sa);
			if (ret != 0)
				return ret;
		}

		if (sp6_spi_present(sa->spi, 1, NULL, NULL) >= 0) {
			ret = rte_ipsec_sad_add(sad->sad_v6, &key,
				RTE_IPSEC_SAD_SPI_ONLY, sa);
			if (ret != 0)
				return ret;
		}
	}

	return 0;
}

int
ipsec_sad_create(const char *name, struct ipsec_sad *sad,
	int socket_id, struct ipsec_sa_cnt *sa_cnt)
{
	int ret;
	struct rte_ipsec_sad_conf sad_conf;
	char sad_name[RTE_IPSEC_SAD_NAMESIZE];

	ret = snprintf(sad_name, RTE_IPSEC_SAD_NAMESIZE, "%s_v4", name);
	if (ret < 0 || ret >= RTE_IPSEC_SAD_NAMESIZE)
		return -ENAMETOOLONG;

	sad_conf.socket_id = socket_id;
	sad_conf.flags = 0;
	/* Make SAD have extra 25% of required number of entries */
	sad_conf.max_sa[RTE_IPSEC_SAD_SPI_ONLY] = sa_cnt->nb_trn * 5 / 4;
	sad_conf.max_sa[RTE_IPSEC_SAD_SPI_DIP] = 0;
	sad_conf.max_sa[RTE_IPSEC_SAD_SPI_DIP_SIP] = sa_cnt->nb_v4_tun * 5 / 4;

	if ((sa_cnt->nb_trn != 0) || (sa_cnt->nb_v4_tun != 0)) {
		sad->sad_v4 = rte_ipsec_sad_create(sad_name, &sad_conf);
		if (sad->sad_v4 == NULL)
			return -rte_errno;
	}

	ret = snprintf(sad_name, RTE_IPSEC_SAD_NAMESIZE, "%s_v6", name);
	if (ret < 0 || ret >= RTE_IPSEC_SAD_NAMESIZE)
		return -ENAMETOOLONG;
	sad_conf.flags = RTE_IPSEC_SAD_FLAG_IPV6;
	sad_conf.max_sa[RTE_IPSEC_SAD_SPI_DIP_SIP] = sa_cnt->nb_v6_tun * 5 / 4;

	if ((sa_cnt->nb_trn != 0) || (sa_cnt->nb_v6_tun != 0)) {
		sad->sad_v6 = rte_ipsec_sad_create(name, &sad_conf);
		if (sad->sad_v6 == NULL)
			return -rte_errno;
	}

	return 0;
}
