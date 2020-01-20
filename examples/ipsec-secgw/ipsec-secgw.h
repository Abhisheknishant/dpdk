/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2020 Marvell International Ltd.
 */
#ifndef _IPSEC_SECGW_H_
#define _IPSEC_SECGW_H_

#define NB_SOCKETS 4

#define UNPROTECTED_PORT(portid) (unprotected_port_mask & (1 << portid))

/* Port mask to identify the unprotected ports */
uint32_t unprotected_port_mask;

/* Index of SA in single mode */
uint32_t single_sa_idx;

#endif /* _IPSEC_SECGW_H_ */
