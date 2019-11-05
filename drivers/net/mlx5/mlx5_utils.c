/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019 Mellanox Technologies, Ltd
 */

#include <rte_malloc.h>

#include "mlx5_utils.h"

struct mlx5_hlist *
mlx5_hlist_create(char *name, uint64_t size, mlx5_hlist_destroy_callback_fn cb)
{
	struct mlx5_hlist *h;
	uint64_t act_size;
	uint64_t alloc_size;

	if (!size)
		return NULL;
	/* If the low 32B is power of 2, then the 64B integer is too. */
	if (!rte_is_power_of_2((uint32_t)size)) {
		act_size = rte_align64pow2(size);
		DRV_LOG(WARNING, "Size 0x%" PRIX64 " is not power of 2, will "
			"be aligned to 0x%" PRIX64 ".\n", size, act_size);
	} else {
		act_size = size;
	}
	alloc_size = sizeof(struct mlx5_hlist) +
		     sizeof(struct mlx5_hlist_head) * act_size;
	/* Using zmalloc, then no need to initialize the heads. */
	h = rte_zmalloc(name, alloc_size, RTE_CACHE_LINE_SIZE);
	if (!h) {
		DRV_LOG(ERR, "No memory for hash list %s creation\n",
			name ? name : "None");
		return NULL;
	}
	if (name)
		snprintf(h->name, MLX5_HLIST_NAMESIZE, "%s", name);
	if (!cb)
		DRV_LOG(WARNING, "No callback function is specified, will use "
			"rte_free when destroying hlist %p %s\n",
			(void *)h, h->name);
	else
		h->cb = cb;
	h->table_sz = act_size;
	h->mask = act_size - 1;
	DRV_LOG(DEBUG, "Hash list with %s size 0x%" PRIX64 ", callback "
		"0x%" PRIX64 "is created.\n",
		h->name, act_size, (uint64_t)(uintptr_t)cb);
	return h;
}

struct mlx5_hlist_entry *
mlx5_hlist_lookup(struct mlx5_hlist *h, uint64_t key)
{
	uint64_t idx;
	struct mlx5_hlist_head *first;
	struct mlx5_hlist_entry *node;

	assert(h);
	idx = key & h->mask;
	first = &h->heads[idx];
	LIST_FOREACH(node, first, next) {
		if (node->key == key)
			return node;
	}
	return NULL;
}

int
mlx5_hlist_insert(struct mlx5_hlist *h, struct mlx5_hlist_entry *entry)
{
	uint64_t idx;
	struct mlx5_hlist_head *first;
	struct mlx5_hlist_entry *node;

	assert(h && entry);
	idx = entry->key & h->mask;
	first = &h->heads[idx];
	/* No need to reuse the lookup function. */
	LIST_FOREACH(node, first, next) {
		if (node->key == entry->key)
			return -EEXIST;
	}
	LIST_INSERT_HEAD(first, entry, next);
	return 0;
}

void
mlx5_hlist_remove(struct mlx5_hlist *h __rte_unused,
		  struct mlx5_hlist_entry *entry)
{
	assert(entry && entry->next.le_prev);
	LIST_REMOVE(entry, next);
	/* Set to NULL to get rid of removing action for more than once. */
	entry->next.le_prev = NULL;
}

void
mlx5_hlist_destroy(struct mlx5_hlist *h)
{
	uint64_t idx;
	struct mlx5_hlist_entry *entry;
	mlx5_hlist_destroy_callback_fn cb;

	assert(h);
	cb = h->cb;
	for (idx = 0; idx < h->table_sz; ++idx) {
		/* no LIST_FOREACH_SAFE, using while instead */
		while (!LIST_EMPTY(&h->heads[idx])) {
			entry = LIST_FIRST(&h->heads[idx]);
			LIST_REMOVE(entry, next);
			/*
			 * The owner of whole element which contains data entry
			 * is the user, so it's the user's duty to do the clean
			 * up and the free work because someone may not put the
			 * hlist entry at the beginning(suggested to locate at
			 * the beginning). Or else the default free function
			 * will be used.
			 */
			if (cb)
				h->cb(entry);
			else
				rte_free(entry);
		}
	}
	rte_free(h);
}
