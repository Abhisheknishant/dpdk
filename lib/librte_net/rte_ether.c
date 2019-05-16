/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <rte_ether.h>

void
eth_random_addr(uint8_t *addr)
{
	uint64_t rand = rte_rand();
	uint8_t *p = (uint8_t *)&rand;

	rte_memcpy(addr, p, ETHER_ADDR_LEN);
	addr[0] &= (uint8_t)~ETHER_GROUP_ADDR;	/* clear multicast bit */
	addr[0] |= ETHER_LOCAL_ADMIN_ADDR;	/* set local assignment bit */
}

void
ether_format_addr(char *buf, uint16_t size,
		  const struct ether_addr *eth_addr)
{
	snprintf(buf, size, "%02X:%02X:%02X:%02X:%02X:%02X",
		 eth_addr->addr_bytes[0],
		 eth_addr->addr_bytes[1],
		 eth_addr->addr_bytes[2],
		 eth_addr->addr_bytes[3],
		 eth_addr->addr_bytes[4],
		 eth_addr->addr_bytes[5]);
}
