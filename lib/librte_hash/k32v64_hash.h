/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <rte_kv_hash.h>

#define K32V64_KEYS_PER_BUCKET		4
#define K32V64_WRITE_IN_PROGRESS	1
#define VALID_KEY_MSK           ((1 << K32V64_KEYS_PER_BUCKET) - 1)

struct k32v64_ext_ent {
	SLIST_ENTRY(k32v64_ext_ent) next;
	uint32_t	key;
	uint64_t	val;
};

struct k32v64_hash_bucket {
	uint32_t	key[K32V64_KEYS_PER_BUCKET];
	uint64_t	val[K32V64_KEYS_PER_BUCKET];
	uint8_t		key_mask;
	uint32_t	cnt;
	SLIST_HEAD(k32v64_list_head, k32v64_ext_ent) head;
} __rte_cache_aligned;

struct k32v64_hash_table {
	struct rte_kv_hash_table pub;	/**< Public part */
	uint32_t	nb_ent;		/**< Number of entities in the table*/
	uint32_t	nb_ext_ent;	/**< Number of extended entities */
	uint32_t	max_ent;	/**< Maximum number of entities */
	uint32_t	bucket_msk;
	struct rte_mempool	*ext_ent_pool;
	__extension__ struct k32v64_hash_bucket	t[0];
};

typedef int (*k32v64_cmp_fn_t)
(struct k32v64_hash_bucket *bucket, uint32_t key, uint64_t *val);

static inline int
__kv_cmp_keys(struct k32v64_hash_bucket *bucket, uint32_t key,
	uint64_t *val)
{
	int i;

	for (i = 0; i < K32V64_KEYS_PER_BUCKET; i++) {
		if ((key == bucket->key[i]) &&
				(bucket->key_mask & (1 << i))) {
			*val = bucket->val[i];
			return 1;
		}
	}

	return 0;
}

static inline int
__k32v64_hash_lookup(struct k32v64_hash_table *table, uint32_t key,
	uint32_t hash, uint64_t *value, k32v64_cmp_fn_t cmp_f)
{
	uint64_t	val = 0;
	struct k32v64_ext_ent *ent;
	uint32_t	cnt;
	int found = 0;
	uint32_t bucket = hash & table->bucket_msk;

	do {

		do {
			cnt = __atomic_load_n(&table->t[bucket].cnt,
				__ATOMIC_ACQUIRE);
		} while (unlikely(cnt & K32V64_WRITE_IN_PROGRESS));

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
		__atomic_thread_fence(__ATOMIC_RELEASE);
	} while (unlikely(cnt != __atomic_load_n(&table->t[bucket].cnt,
			 __ATOMIC_RELAXED)));

	if (found == 1) {
		*value = val;
		return 0;
	} else
		return -ENOENT;
}

struct rte_kv_hash_table *
k32v64_hash_create(const struct rte_kv_hash_params *params);

void
k32v64_hash_free(struct rte_kv_hash_table *ht);
