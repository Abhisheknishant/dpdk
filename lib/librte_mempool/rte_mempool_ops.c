/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016 Intel Corporation.
 * Copyright(c) 2016 6WIND S.A.
 */

#include <stdio.h>
#include <string.h>

#include <rte_string_fns.h>
#include <rte_mempool.h>
#include <rte_errno.h>
#include <rte_dev.h>

/* indirect jump table to support external memory pools. */
struct rte_mempool_ops_table rte_mempool_ops_table = {
	.sl =  RTE_SPINLOCK_INITIALIZER,
};

static int
rte_mempool_register_shared_ops(const char *name)
{
	static bool mempool_shared_ops_inited = false;
	struct rte_mempool_shared_ops *shared_ops;
	const struct rte_memzone *mz;
	uint32_t ops_index = 0;

	if (rte_eal_process_type() == RTE_PROC_PRIMARY &&
	    !mempool_shared_ops_inited) {

		mz = rte_memzone_reserve("mempool_ops_shared",
					 sizeof(*shared_ops), 0, 0);
		if (mz == NULL)
			return -ENOMEM;

		shared_ops = mz->addr;
		shared_ops->num_mempool_ops = 0;
		rte_spinlock_init(&shared_ops->mempool);

		mempool_shared_ops_inited = true;
	} else {
		mz = rte_memzone_lookup("mempool_ops_shared");
		if (mz == NULL)
			return -ENOMEM;

		shared_ops = mz->addr;
	}

	rte_spinlock_lock(&shared_ops->mempool);

	if (shared_ops->num_mempool_ops >= RTE_MEMPOOL_MAX_OPS_IDX) {
		rte_spinlock_unlock(&shared_ops->mempool);
		RTE_LOG(ERR, MEMPOOL,
			"Maximum number of mempool ops structs exceeded\n");
		return -ENOSPC;
	}

	while (shared_ops->mempool_ops[ops_index].name[0]) {
		if (!strcmp(name, shared_ops->mempool_ops[ops_index].name)) {
			rte_spinlock_unlock(&shared_ops->mempool);
			return ops_index;
		}

		ops_index++;
	}

	strlcpy(shared_ops->mempool_ops[ops_index].name, name,
		sizeof(shared_ops->mempool_ops[0].name));

	shared_ops->num_mempool_ops++;

	rte_spinlock_unlock(&shared_ops->mempool);
	return ops_index;
}

/* add a new ops struct in rte_mempool_ops_table, return its index. */
int
rte_mempool_register_ops(const struct rte_mempool_ops *h)
{
	struct rte_mempool_ops *ops;
	int16_t ops_index;

	if (h->alloc == NULL || h->enqueue == NULL ||
	    h->dequeue == NULL || h->get_count == NULL) {
		RTE_LOG(ERR, MEMPOOL,
			"Missing callback while registering mempool ops\n");
		rte_errno = EINVAL;
		return -EINVAL;
	}

	if (strlen(h->name) >= sizeof(ops->name) - 1) {
		RTE_LOG(ERR, MEMPOOL,
			"The registering  mempool_ops <%s>: name too long\n",
			h->name);
		rte_errno = EEXIST;
		return -EEXIST;
	}

	ops_index = rte_mempool_register_shared_ops(h->name);
	if (ops_index < 0) {
		rte_errno = -ops_index;
		return ops_index;
	}

	rte_spinlock_lock(&rte_mempool_ops_table.sl);

	ops = &rte_mempool_ops_table.ops[ops_index];
	strlcpy(ops->name, h->name, sizeof(ops->name));
	ops->alloc = h->alloc;
	ops->free = h->free;
	ops->enqueue = h->enqueue;
	ops->dequeue = h->dequeue;
	ops->get_count = h->get_count;
	ops->calc_mem_size = h->calc_mem_size;
	ops->populate = h->populate;
	ops->get_info = h->get_info;
	ops->dequeue_contig_blocks = h->dequeue_contig_blocks;

	rte_spinlock_unlock(&rte_mempool_ops_table.sl);

	return ops_index;
}

/* wrapper to allocate an external mempool's private (pool) data. */
int
rte_mempool_ops_alloc(struct rte_mempool *mp)
{
	struct rte_mempool_ops *ops;

	ops = rte_mempool_get_ops(mp->ops_index);
	return ops->alloc(mp);
}

/* wrapper to free an external pool ops. */
void
rte_mempool_ops_free(struct rte_mempool *mp)
{
	struct rte_mempool_ops *ops;

	ops = rte_mempool_get_ops(mp->ops_index);
	if (ops->free == NULL)
		return;
	ops->free(mp);
}

/* wrapper to get available objects in an external mempool. */
unsigned int
rte_mempool_ops_get_count(const struct rte_mempool *mp)
{
	struct rte_mempool_ops *ops;

	ops = rte_mempool_get_ops(mp->ops_index);
	return ops->get_count(mp);
}

/* wrapper to calculate the memory size required to store given number
 * of objects
 */
ssize_t
rte_mempool_ops_calc_mem_size(const struct rte_mempool *mp,
				uint32_t obj_num, uint32_t pg_shift,
				size_t *min_chunk_size, size_t *align)
{
	struct rte_mempool_ops *ops;

	ops = rte_mempool_get_ops(mp->ops_index);

	if (ops->calc_mem_size == NULL)
		return rte_mempool_op_calc_mem_size_default(mp, obj_num,
				pg_shift, min_chunk_size, align);

	return ops->calc_mem_size(mp, obj_num, pg_shift, min_chunk_size, align);
}

/* wrapper to populate memory pool objects using provided memory chunk */
int
rte_mempool_ops_populate(struct rte_mempool *mp, unsigned int max_objs,
				void *vaddr, rte_iova_t iova, size_t len,
				rte_mempool_populate_obj_cb_t *obj_cb,
				void *obj_cb_arg)
{
	struct rte_mempool_ops *ops;

	ops = rte_mempool_get_ops(mp->ops_index);

	if (ops->populate == NULL)
		return rte_mempool_op_populate_default(mp, max_objs, vaddr,
						       iova, len, obj_cb,
						       obj_cb_arg);

	return ops->populate(mp, max_objs, vaddr, iova, len, obj_cb,
			     obj_cb_arg);
}

/* wrapper to get additional mempool info */
int
rte_mempool_ops_get_info(const struct rte_mempool *mp,
			 struct rte_mempool_info *info)
{
	struct rte_mempool_ops *ops;

	ops = rte_mempool_get_ops(mp->ops_index);

	RTE_FUNC_PTR_OR_ERR_RET(ops->get_info, -ENOTSUP);
	return ops->get_info(mp, info);
}


/* sets mempool ops previously registered by rte_mempool_register_ops. */
int
rte_mempool_set_ops_byname(struct rte_mempool *mp, const char *name,
	void *pool_config)
{
	struct rte_mempool_ops *ops = NULL;
	unsigned i;

	/* too late, the mempool is already populated. */
	if (mp->flags & MEMPOOL_F_POOL_CREATED)
		return -EEXIST;

	for (i = 0; i < RTE_MEMPOOL_MAX_OPS_IDX; i++) {
		if (!strcmp(name, rte_mempool_ops_table.ops[i].name)) {
			ops = &rte_mempool_ops_table.ops[i];
			break;
		}
	}

	if (ops == NULL)
		return -EINVAL;

	mp->ops_index = i;
	mp->pool_config = pool_config;
	return 0;
}
