/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2011 Matteo Landi, Luigi Rizzo. All rights reserved.
 */

/*
 * $FreeBSD: head/sys/net/netmap_user.h 231198 2012-02-08 11:43:29Z luigi $
 * $Id: netmap_user.h 10879 2012-04-12 22:48:59Z luigi $
 *
 * This header contains the macros used to manipulate netmap structures
 * and packets in userspace. See netmap(4) for more information.
 *
 * The address of the struct netmap_if, say nifp, is computed from the
 * value returned from ioctl(.., NIOCREG, ...) and the mmap region:
 *	ioctl(fd, NIOCREG, &req);
 *	mem = mmap(0, ... );
 *	nifp = NETMAP_IF(mem, req.nr_nifp);
 *		(so simple, we could just do it manually)
 *
 * From there:
 *	struct netmap_ring *NETMAP_TXRING(nifp, index)
 *	struct netmap_ring *NETMAP_RXRING(nifp, index)
 *		we can access ring->nr_cur, ring->nr_avail, ring->nr_flags
 *
 *	ring->slot[i] gives us the i-th slot (we can access
 *		directly plen, flags, bufindex)
 *
 *	char *buf = NETMAP_BUF(ring, index) returns a pointer to
 *		the i-th buffer
 *
 * Since rings are circular, we have macros to compute the next index
 *	i = NETMAP_RING_NEXT(ring, i);
 */

#ifndef _NET_NETMAP_USER_H_
#define _NET_NETMAP_USER_H_

#define NETMAP_IF(b, o)	(struct netmap_if *)((char *)(b) + (o))

#define NETMAP_TXRING(nifp, index)			\
	((struct netmap_ring *)((char *)(nifp) +	\
		(nifp)->ring_ofs[index] ) )

#define NETMAP_RXRING(nifp, index)			\
	((struct netmap_ring *)((char *)(nifp) +	\
	    (nifp)->ring_ofs[index + (nifp)->ni_tx_rings + 1] ) )

#define NETMAP_BUF(ring, index)				\
	((char *)(ring) + (ring)->buf_ofs + ((index)*(ring)->nr_buf_size))

#define NETMAP_BUF_IDX(ring, buf)			\
	( ((char *)(buf) - ((char *)(ring) + (ring)->buf_ofs) ) / \
		(ring)->nr_buf_size )

#define	NETMAP_RING_NEXT(r, i)				\
	((i)+1 == (r)->num_slots ? 0 : (i) + 1 )

#define	NETMAP_RING_FIRST_RESERVED(r)			\
	( (r)->cur < (r)->reserved ?			\
	  (r)->cur + (r)->num_slots - (r)->reserved :	\
	  (r)->cur - (r)->reserved )

/*
 * Return 1 if the given tx ring is empty.
 */
#define NETMAP_TX_RING_EMPTY(r)	((r)->avail >= (r)->num_slots - 1)

#endif /* _NET_NETMAP_USER_H_ */
