/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016 Intel Corporation.
 * Copyright(c) 2016 6WIND S.A.
 * Copyright(c) 2018 Solarflare Communications Inc.
 */

#include <rte_mempool.h>

ssize_t
rte_mempool_op_calc_mem_size_default(const struct rte_mempool *mp,
				     uint32_t obj_num, uint32_t pg_shift,
				     size_t *min_chunk_size, size_t *align)
{
	size_t total_elt_sz;
	size_t obj_per_page, pg_num, pg_sz;
	size_t mem_size;

	total_elt_sz = mp->header_size + mp->elt_size + mp->trailer_size;
	if (total_elt_sz == 0) {
		mem_size = 0;
	} else if (pg_shift == 0) {
		mem_size = total_elt_sz * obj_num;
	} else {
		pg_sz = (size_t)1 << pg_shift;
		obj_per_page = pg_sz / total_elt_sz;
		if (obj_per_page == 0) {
			/*
			 * Note that if object size is bigger than page size,
			 * then it is assumed that pages are grouped in subsets
			 * of physically continuous pages big enough to store
			 * at least one object.
			 */
			mem_size =
				RTE_ALIGN_CEIL(total_elt_sz, pg_sz) * obj_num;
		} else {
			pg_num = (obj_num + obj_per_page - 1) / obj_per_page;
			mem_size = pg_num << pg_shift;
		}
	}

	*min_chunk_size = RTE_MAX((size_t)1 << pg_shift, total_elt_sz);

	*align = RTE_MAX((size_t)RTE_CACHE_LINE_SIZE, (size_t)1 << pg_shift);

	return mem_size;
}

/* Returns -1 if object falls on a page boundary, else returns 0 */
static inline int
mempool_check_obj_bounds(void *obj, uint64_t hugepage_sz, size_t elt_sz)
{
	uintptr_t page_end, elt_addr = (uintptr_t)obj;
	uint32_t pg_shift = rte_bsf32(hugepage_sz);
	uint64_t page_mask;

	page_mask =  ~((1ull << pg_shift) - 1);
	page_end = (elt_addr & page_mask) + hugepage_sz;

	if (elt_addr + elt_sz > page_end)
		return -1;

	return 0;
}

int
rte_mempool_op_populate_default(struct rte_mempool *mp, unsigned int max_objs,
		void *vaddr, rte_iova_t iova, size_t len,
		rte_mempool_populate_obj_cb_t *obj_cb, void *obj_cb_arg)
{
	struct rte_memzone *mz = obj_cb_arg;
	size_t total_elt_sz, off;
	unsigned int i;
	void *obj;

	total_elt_sz = mp->header_size + mp->elt_size + mp->trailer_size;

	for (off = 0, i = 0; off + total_elt_sz <= len && i < max_objs; i++) {

		/* Skip page boundary check if element is bigger than page */
		if (mz->hugepage_sz >= total_elt_sz) {
			if (mempool_check_obj_bounds((char *)vaddr + off,
						    mz->hugepage_sz,
						    total_elt_sz) < 0) {
				i--; /* Decrement count & skip this obj */
				off += total_elt_sz;
				continue;
			}
		}

		off += mp->header_size;
		obj = (char *)vaddr + off;
		obj_cb(mp, obj_cb_arg, obj,
		       (iova == RTE_BAD_IOVA) ? RTE_BAD_IOVA : (iova + off));
		rte_mempool_ops_enqueue_bulk(mp, &obj, 1);
		off += mp->elt_size + mp->trailer_size;
	}

	return i;
}
