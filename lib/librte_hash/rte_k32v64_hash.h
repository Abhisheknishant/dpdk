/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _RTE_K32V64_HASH_H_
#define _RTE_K32V64_HASH_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_compat.h>
#include <rte_atomic.h>
#include <rte_mempool.h>

#define RTE_K32V64_HASH_NAMESIZE		32
#define RTE_K32V64_KEYS_PER_BUCKET		4
#define RTE_K32V64_WRITE_IN_PROGRESS		1

struct rte_k32v64_hash_params {
	const char *name;
	uint32_t entries;
	int socket_id;
};

struct rte_k32v64_ext_ent {
	SLIST_ENTRY(rte_k32v64_ext_ent) next;
	uint32_t	key;
	uint64_t	val;
};

struct rte_k32v64_hash_bucket {
	uint32_t	key[RTE_K32V64_KEYS_PER_BUCKET];
	uint64_t	val[RTE_K32V64_KEYS_PER_BUCKET];
	uint8_t		key_mask;
	rte_atomic32_t	cnt;
	SLIST_HEAD(rte_k32v64_list_head, rte_k32v64_ext_ent) head;
} __rte_cache_aligned;

struct rte_k32v64_hash_table;

typedef int (*rte_k32v64_hash_bulk_lookup_t)
(struct rte_k32v64_hash_table *table, uint32_t *keys, uint32_t *hashes,
	uint64_t *values, unsigned int n);

struct rte_k32v64_hash_table {
	char name[RTE_K32V64_HASH_NAMESIZE];	/**< Name of the hash. */
	uint32_t	nb_ent;		/**< Number of entities in the table*/
	uint32_t	nb_ext_ent;	/**< Number of extended entities */
	uint32_t	max_ent;	/**< Maximum number of entities */
	uint32_t	bucket_msk;
	struct rte_mempool	*ext_ent_pool;
	rte_k32v64_hash_bulk_lookup_t	lookup;
	__extension__ struct rte_k32v64_hash_bucket	t[0];
};

typedef int (*rte_k32v64_cmp_fn_t)
(struct rte_k32v64_hash_bucket *bucket, uint32_t key, uint64_t *val);

static inline int
__k32v64_cmp_keys(struct rte_k32v64_hash_bucket *bucket, uint32_t key,
	uint64_t *val)
{
	int i;

	for (i = 0; i < RTE_K32V64_KEYS_PER_BUCKET; i++) {
		if ((key == bucket->key[i]) &&
				(bucket->key_mask & (1 << i))) {
			*val = bucket->val[i];
			return 1;
		}
	}

	return 0;
}

static inline int
__k32v64_hash_lookup(struct rte_k32v64_hash_table *table, uint32_t key,
	uint32_t hash, uint64_t *value, rte_k32v64_cmp_fn_t cmp_f)
{
	uint64_t	val = 0;
	struct rte_k32v64_ext_ent *ent;
	int32_t	cnt;
	int found = 0;
	uint32_t bucket = hash & table->bucket_msk;

	do {
		do
			cnt = rte_atomic32_read(&table->t[bucket].cnt);
		while (unlikely(cnt & RTE_K32V64_WRITE_IN_PROGRESS));

		found = cmp_f(&table->t[bucket], key, &val);
		if (unlikely((found == 0) &&
				(!SLIST_EMPTY(&table->t[bucket].head)))) {
			SLIST_FOREACH(ent, &table->t[bucket].head, next) {
				if (ent->key == key) {
					val = ent->val;
					found = 1;
					break;
				}
			}
		}

	} while (unlikely(cnt != rte_atomic32_read(&table->t[bucket].cnt)));

	if (found == 1) {
		*value = val;
		return 0;
	} else
		return -ENOENT;
}

static inline int
rte_k32v64_hash_lookup(struct rte_k32v64_hash_table *table, uint32_t key,
	uint32_t hash, uint64_t *value)
{
	return __k32v64_hash_lookup(table, key, hash, value, __k32v64_cmp_keys);
}

static inline int
rte_k32v64_hash_bulk_lookup(struct rte_k32v64_hash_table *table,
	uint32_t *keys, uint32_t *hashes, uint64_t *values, unsigned int n)
{
	return table->lookup(table, keys, hashes, values, n);
}

/**
 * Add a key to an existing hash table with hash value.
 * This operation is not multi-thread safe
 * and should only be called from one thread.
 *
 * @param ht
 *   Hash table to add the key to.
 * @param key
 *   Key to add to the hash table.
 * @param value
 *   Value to associate with key.
 * @param hash
 *   Hash value associated with key.
 * @return
 *   0 if ok, or negative value on error.
 */
__rte_experimental
int
rte_k32v64_hash_add(struct rte_k32v64_hash_table *table, uint32_t key,
	uint32_t hash, uint64_t value);

/**
 * Remove a key with a given hash value from an existing hash table.
 * This operation is not multi-thread
 * safe and should only be called from one thread.
 *
 * @param ht
 *   Hash table to remove the key from.
 * @param key
 *   Key to remove from the hash table.
 * @param hash
 *   hash value associated with key.
 * @return
 *   0 if ok, or negative value on error.
 */
__rte_experimental
int
rte_k32v64_hash_delete(struct rte_k32v64_hash_table *table, uint32_t key,
	uint32_t hash);


/**
 * Performs a lookup for an existing hash table, and returns a pointer to
 * the table if found.
 *
 * @param name
 *   Name of the hash table to find
 *
 * @return
 *   pointer to hash table structure or NULL on error with rte_errno
 *   set appropriately.
 */
__rte_experimental
struct rte_k32v64_hash_table *
rte_k32v64_hash_find_existing(const char *name);

/**
 * Create a new hash table for use with four byte keys.
 *
 * @param params
 *   Parameters used in creation of hash table.
 *
 * @return
 *   Pointer to hash table structure that is used in future hash table
 *   operations, or NULL on error with rte_errno set appropriately.
 */
__rte_experimental
struct rte_k32v64_hash_table *
rte_k32v64_hash_create(const struct rte_k32v64_hash_params *params);

/**
 * Free all memory used by a hash table.
 *
 * @param table
 *   Hash table to deallocate.
 */
__rte_experimental
void
rte_k32v64_hash_free(struct rte_k32v64_hash_table *table);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_K32V64_HASH_H_ */
