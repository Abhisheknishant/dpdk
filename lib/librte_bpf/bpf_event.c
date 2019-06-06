/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/queue.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_eventdev.h>

#include <rte_bpf_eventdev.h>
#include "bpf_impl.h"

/*
 * information about installed BPF enq/deq callback
 */

struct bpf_event_cbi {
	/* used by both data & control path */
	uint32_t use;    /*usage counter */
	struct rte_eventdev_callback *cb;  /* callback handle */
	struct rte_bpf *bpf;
	struct rte_bpf_jit jit;
	/* used by control path only */
	LIST_ENTRY(bpf_event_cbi) link;
	uint16_t deviceid;
} __rte_cache_aligned;

/*
 * Odd number means that callback is used by datapath.
 * Even number means that callback is not used by datapath.
 */
#define BPF_EVENT_CBI_INUSE  1

/*
 * List to manage RX/TX installed callbacks.
 */
LIST_HEAD(bpf_event_cbi_list, bpf_event_cbi);

enum {
	BPF_EVENT_ENQ,
	BPF_EVENT_DEQ,
	BPF_EVENT_NUM,
};

/*
 * information about all installed BPF rx/tx callbacks
 */
struct bpf_event_cbh {
	rte_spinlock_t lock;
	struct bpf_event_cbi_list list;
	uint32_t type;
};

static struct bpf_event_cbh event_enq_cbh = {
	.lock = RTE_SPINLOCK_INITIALIZER,
	.list = LIST_HEAD_INITIALIZER(list),
	.type = BPF_EVENT_ENQ,
};

static struct bpf_event_cbh event_deq_cbh = {
	.lock = RTE_SPINLOCK_INITIALIZER,
	.list = LIST_HEAD_INITIALIZER(list),
	.type = BPF_EVENT_DEQ,
};
/*
 * Marks given callback as used by datapath.
 */

/*
 * Marks given callback list as not used by datapath.
 */

/*
 * Waits till datapath finished using given callback.
 */

/*
 * BPF packet processing routinies.
 */

static void
bpf_event_cbi_wait(const struct bpf_event_cbi *cbi)
{
	uint32_t nuse, puse;

	/* make sure all previous loads and stores are completed */
	rte_smp_mb();

	puse = cbi->use;

	/* in use, busy wait till current RX/TX iteration is finished */
	if ((puse & BPF_EVENT_CBI_INUSE) != 0) {
		do {
			rte_pause();
			rte_compiler_barrier();
			nuse = cbi->use;
		} while (nuse == puse);
	}
}

static inline uint32_t
apply_event_filter(struct rte_event *ev,
		const uint64_t rc[], uint32_t num)
{
	uint32_t i, j, k;
	struct rte_event *dr[num];

	for (i = 0, j = 0, k = 0; i != num; i++) {
		/* filter matches */
		if (rc[i] != 0)
			ev[j++] = ev[i];
		/* no match */
		else
			dr[k++] = &ev[i];
	}

	for (i = 0; i != k; i++)
		ev[j + i] = *dr[i];

	return j;
}

static inline uint32_t
event_filter_jit(const struct rte_bpf_jit *jit, struct rte_event *ev,
		uint16_t num)
{
	uint32_t i, n;
	uint64_t rc[num];

	n = 0;
	for (i = 0; i != num; i++) {
		rc[i] = jit->func((void *) &ev[i]);
		n += (rc[i] == 0);
	}

	if (n != 0)
		num = apply_event_filter(ev, rc, num);

	return num;
}

static __rte_always_inline void
bpf_event_cbi_inuse(struct bpf_event_cbi *cbi)
{
	cbi->use++;
	/* make sure no store/load reordering could happen */
	rte_smp_mb();
}

static __rte_always_inline void
bpf_event_cbi_unuse(struct bpf_event_cbi *cbi)
{
	/* make sure all previous loads are completed */
	rte_smp_rmb();
	cbi->use++;
}

static uint16_t
bpf_event_enq_jit(__rte_unused uint16_t deviceid,
		__rte_unused uint16_t port,
		struct rte_event *ev, uint16_t nb_events, void *user_param)
{
	struct bpf_event_cbi *cbi;
	uint16_t rc;

	cbi = user_param;
	bpf_event_cbi_inuse(cbi);
	rc = (cbi->cb != NULL) ?
			event_filter_jit(&cbi->jit, ev, nb_events) :
			nb_events;
	bpf_event_cbi_unuse(cbi);

	return rc;
}

static uint16_t
bpf_event_deq_jit(__rte_unused uint16_t deviceid,
		__rte_unused uint16_t port,
		struct rte_event *ev, uint16_t nb_events, void *user_param)
{
	struct bpf_event_cbi *cbi;
	uint16_t rc;

	cbi = user_param;
	bpf_event_cbi_inuse(cbi);
	rc = (cbi->cb != NULL) ?
			event_filter_jit(&cbi->jit, ev, nb_events) :
			nb_events;
	bpf_event_cbi_unuse(cbi);

	return rc;
}

static void
bpf_event_cbi_cleanup(struct bpf_event_cbi *bc)
{
	bc->bpf = NULL;
	memset(&bc->jit, 0, sizeof(bc->jit));
}

static struct bpf_event_cbi *
bpf_event_cbh_find(struct bpf_event_cbh *cbh, uint16_t deviceid)
{
	struct bpf_event_cbi *cbi;

	LIST_FOREACH(cbi, &cbh->list, link) {
		if (cbi->deviceid == deviceid)
			break;
	}
	return cbi;
}

static struct bpf_event_cbi *
bpf_event_cbh_add(struct bpf_event_cbh *cbh, uint16_t deviceid)
{
	struct bpf_event_cbi *cbi;

	/* return an existing one */
	cbi = bpf_event_cbh_find(cbh, deviceid);
	if (cbi != NULL)
		return cbi;

	cbi = rte_zmalloc(NULL, sizeof(*cbi), RTE_CACHE_LINE_SIZE);
	if (cbi != NULL) {
		cbi->deviceid = deviceid;
		LIST_INSERT_HEAD(&cbh->list, cbi, link);
	}
	return cbi;
}

static void
bpf_event_cbi_unload(struct bpf_event_cbi *bc)
{
	/* mark this cbi as empty */
	bc->cb = NULL;
	rte_smp_mb();

	/* make sure datapath doesn't use bpf anymore, then destroy bpf */
	bpf_event_cbi_wait(bc);
	rte_bpf_destroy(bc->bpf);
	bpf_event_cbi_cleanup(bc);
}
static void
bpf_event_unload(struct bpf_event_cbh *cbh, uint16_t deviceid)
{
	struct bpf_event_cbi *bc;
	struct rte_eventdev_callback *cb;

	bc = bpf_event_cbh_find(cbh, deviceid);
	if (bc == NULL || bc->cb == NULL)
		return;

	cb = bc->cb;

	if (cbh->type == BPF_EVENT_ENQ)
		rte_eventdev_preenq_callback_unregister(deviceid, 0,
			cb->cb_fn, cb->cb_arg);
	else
		rte_eventdev_pstdeq_callback_unregister(deviceid, 0,
			cb->cb_fn, cb->cb_arg);

	bpf_event_cbi_unload(bc);
}

__rte_experimental void
rte_bpf_event_enq_unload(uint8_t device, __rte_unused uint8_t port)
{
	struct bpf_event_cbh *cbh;

	cbh = &event_enq_cbh;
	rte_spinlock_lock(&cbh->lock);
	bpf_event_unload(cbh, device);
	rte_spinlock_unlock(&cbh->lock);
}

__rte_experimental void
rte_bpf_event_deq_unload(uint8_t device, __rte_unused uint8_t port)
{
	struct bpf_event_cbh *cbh;

	cbh = &event_deq_cbh;
	rte_spinlock_lock(&cbh->lock);
	bpf_event_unload(cbh, device);
	rte_spinlock_unlock(&cbh->lock);
}


static rte_eventdev_cb_fn
select_event_enq_callback(enum rte_bpf_arg_type type, uint32_t flags)
{
	if (flags & RTE_BPF_EVENT_F_JIT) {
		if (type == RTE_BPF_ARG_PTR)
			return (rte_eventdev_cb_fn) bpf_event_enq_jit;
	}

	return NULL;
}

static rte_eventdev_cb_fn
select_event_deq_callback(enum rte_bpf_arg_type type, uint32_t flags)
{
	if (flags & RTE_BPF_EVENT_F_JIT) {
		if (type == RTE_BPF_ARG_PTR)
			return (rte_eventdev_cb_fn) bpf_event_deq_jit;
	}

	return NULL;
}


static int
bpf_event_elf_load(struct bpf_event_cbh *cbh, uint16_t deviceid, uint16_t port,
	const struct rte_bpf_prm *prm, const char *fname, const char *sname,
	uint32_t flags)
{
	int32_t rc;
	struct bpf_event_cbi *bc;
	struct rte_bpf *bpf;
	rte_eventdev_cb_fn fenq;
	rte_eventdev_cb_fn fdeq;
	struct rte_bpf_jit jit;

	fenq = NULL;
	fdeq = NULL;

	if (prm == NULL || rte_event_dev_socket_id(deviceid) == -EINVAL)
		return -EINVAL;

	if (cbh->type == BPF_EVENT_ENQ)
		fenq = select_event_enq_callback(prm->prog_arg.type, flags);
	else if (cbh->type == BPF_EVENT_DEQ)
		fdeq = select_event_deq_callback(prm->prog_arg.type, flags);
	else
		return -EINVAL;

	if (fenq == NULL && fdeq == NULL) {
		RTE_BPF_LOG(ERR, "%s(%u): no callback selected;\n",
			__func__, deviceid);
		return -EINVAL;
	}

	bpf = rte_bpf_elf_load(prm, fname, sname);
	if (bpf == NULL)
		return -rte_errno;

	rte_bpf_get_jit(bpf, &jit);

	if ((flags & RTE_BPF_EVENT_F_JIT) != 0 && jit.func == NULL) {
		RTE_BPF_LOG(ERR, "%s(%u): no JIT generated;\n",
			__func__, deviceid);
		rte_bpf_destroy(bpf);
		return -ENOTSUP;
	}

	/* setup/update global callback info */
	bc = bpf_event_cbh_add(cbh, deviceid);
	if (bc == NULL)
		return -ENOMEM;

	/* remove old one, if any */
	if (bc->cb != NULL)
		bpf_event_unload(cbh, deviceid);

	bc->bpf = bpf;
	bc->jit = jit;

	if (cbh->type == BPF_EVENT_ENQ)
		bc->cb = rte_event_add_preenq(deviceid, port, fenq, bc);
	else if (cbh->type == BPF_EVENT_DEQ)
		bc->cb = rte_event_add_pstdeq(deviceid, port, fdeq, bc);

	if (bc->cb == NULL) {
		rc = -rte_errno;
		rte_bpf_destroy(bpf);
		bpf_event_cbi_cleanup(bc);
	} else
		rc = 0;

	return rc;
}

__rte_experimental int
rte_bpf_event_enq_elf_load(uint8_t deviceid, uint8_t port,
	const struct rte_bpf_prm *prm, const char *fname, const char *sname,
	uint32_t flags)
{
	int32_t rc;
	struct bpf_event_cbh *cbh;

	cbh = &event_enq_cbh;
	rte_spinlock_lock(&cbh->lock);
	rc = bpf_event_elf_load(cbh, deviceid, port, prm, fname, sname, flags);
	rte_spinlock_unlock(&cbh->lock);

	return rc;
}

__rte_experimental int
rte_bpf_event_deq_elf_load(uint8_t deviceid, uint8_t port,
	const struct rte_bpf_prm *prm, const char *fname, const char *sname,
	uint32_t flags)
{
	int32_t rc;
	struct bpf_event_cbh *cbh;

	cbh = &event_deq_cbh;
	rte_spinlock_lock(&cbh->lock);
	rc = bpf_event_elf_load(cbh, deviceid, port, prm, fname, sname, flags);
	rte_spinlock_unlock(&cbh->lock);

	return rc;
}
