/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <string.h>

#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_memory.h>

#include "k32v64_hash.h"

static inline int
k32v64_hash_lookup(struct k32v64_hash_table *table, uint32_t key,
	uint32_t hash, uint64_t *value)
{
	return __k32v64_hash_lookup(table, key, hash, value, __kv_cmp_keys);
}

static int
k32v64_hash_bulk_lookup(struct rte_kv_hash_table *ht, void *keys_p,
	uint32_t *hashes, void *values_p, unsigned int n)
{
	struct k32v64_hash_table *table = (struct k32v64_hash_table *)ht;
	uint32_t *keys = keys_p;
	uint64_t *values = values_p;
	int ret, cnt = 0;
	unsigned int i;

	if (unlikely((table == NULL) || (keys == NULL) || (hashes == NULL) ||
			(values == NULL)))
		return -EINVAL;

	for (i = 0; i < n; i++) {
		ret = k32v64_hash_lookup(table, keys[i], hashes[i],
			&values[i]);
		if (ret == 0)
			cnt++;
	}
	return cnt;
}

#ifdef CC_AVX512VL_SUPPORT
int
k32v64_hash_bulk_lookup_avx512vl(struct rte_kv_hash_table *ht,
	void *keys_p, uint32_t *hashes, void *values_p, unsigned int n);
#endif

static rte_kv_hash_bulk_lookup_t
get_lookup_bulk_fn(void)
{
#ifdef CC_AVX512VL_SUPPORT
	if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512VL))
		return k32v64_hash_bulk_lookup_avx512vl;
#endif
	return k32v64_hash_bulk_lookup;
}

static int
k32v64_hash_add(struct k32v64_hash_table *table, uint32_t key,
	uint32_t hash, uint64_t value, uint64_t *old_value, int *found)
{
	uint32_t bucket;
	int i, idx, ret;
	uint8_t msk;
	struct k32v64_ext_ent *tmp, *ent, *prev = NULL;

	if (table == NULL)
		return -EINVAL;

	bucket = hash & table->bucket_msk;
	/* Search key in table. Update value if exists */
	for (i = 0; i < K32V64_KEYS_PER_BUCKET; i++) {
		if ((key == table->t[bucket].key[i]) &&
				(table->t[bucket].key_mask & (1 << i))) {
			*old_value = table->t[bucket].val[i];
			*found = 1;
			__atomic_fetch_add(&table->t[bucket].cnt, 1,
				__ATOMIC_ACQUIRE);
			table->t[bucket].val[i] = value;
			__atomic_fetch_add(&table->t[bucket].cnt, 1,
				__ATOMIC_RELEASE);
			return 0;
		}
	}

	if (!SLIST_EMPTY(&table->t[bucket].head)) {
		SLIST_FOREACH(ent, &table->t[bucket].head, next) {
			if (ent->key == key) {
				*old_value = ent->val;
				*found = 1;
				__atomic_fetch_add(&table->t[bucket].cnt, 1,
					__ATOMIC_ACQUIRE);
				ent->val = value;
				__atomic_fetch_add(&table->t[bucket].cnt, 1,
					__ATOMIC_RELEASE);
				return 0;
			}
		}
	}

	msk = ~table->t[bucket].key_mask & VALID_KEY_MSK;
	if (msk) {
		idx = __builtin_ctz(msk);
		table->t[bucket].key[idx] = key;
		table->t[bucket].val[idx] = value;
		__atomic_or_fetch(&table->t[bucket].key_mask, 1 << idx,
			__ATOMIC_RELEASE);
		table->nb_ent++;
		*found = 0;
		return 0;
	}

	ret = rte_mempool_get(table->ext_ent_pool, (void **)&ent);
	if (ret < 0)
		return ret;

	SLIST_NEXT(ent, next) = NULL;
	ent->key = key;
	ent->val = value;
	rte_smp_wmb();
	SLIST_FOREACH(tmp, &table->t[bucket].head, next)
		prev = tmp;

	if (prev == NULL)
		SLIST_INSERT_HEAD(&table->t[bucket].head, ent, next);
	else
		SLIST_INSERT_AFTER(prev, ent, next);

	table->nb_ent++;
	table->nb_ext_ent++;
	*found = 0;
	return 0;
}

static int
k32v64_hash_delete(struct k32v64_hash_table *table, uint32_t key,
	uint32_t hash, uint64_t *old_value)
{
	uint32_t bucket;
	int i;
	struct k32v64_ext_ent *ent;

	if (table == NULL)
		return -EINVAL;

	bucket = hash & table->bucket_msk;

	for (i = 0; i < K32V64_KEYS_PER_BUCKET; i++) {
		if ((key == table->t[bucket].key[i]) &&
				(table->t[bucket].key_mask & (1 << i))) {
			*old_value = table->t[bucket].val[i];
			ent = SLIST_FIRST(&table->t[bucket].head);
			if (ent) {
				__atomic_fetch_add(&table->t[bucket].cnt, 1,
					__ATOMIC_ACQUIRE);
				table->t[bucket].key[i] = ent->key;
				table->t[bucket].val[i] = ent->val;
				SLIST_REMOVE_HEAD(&table->t[bucket].head, next);
				__atomic_fetch_add(&table->t[bucket].cnt, 1,
					__ATOMIC_RELEASE);
				table->nb_ext_ent--;
			} else
				__atomic_and_fetch(&table->t[bucket].key_mask,
					~(1 << i), __ATOMIC_RELEASE);
			if (ent)
				rte_mempool_put(table->ext_ent_pool, ent);
			table->nb_ent--;
			return 0;
		}
	}

	SLIST_FOREACH(ent, &table->t[bucket].head, next)
		if (ent->key == key)
			break;

	if (ent == NULL)
		return -ENOENT;

	*old_value = ent->val;

	__atomic_fetch_add(&table->t[bucket].cnt, 1, __ATOMIC_ACQUIRE);
	SLIST_REMOVE(&table->t[bucket].head, ent, k32v64_ext_ent, next);
	__atomic_fetch_add(&table->t[bucket].cnt, 1, __ATOMIC_RELEASE);
	rte_mempool_put(table->ext_ent_pool, ent);

	table->nb_ext_ent--;
	table->nb_ent--;

	return 0;
}

static int
k32v64_modify(struct rte_kv_hash_table *table, void *key_p, uint32_t hash,
	enum rte_kv_modify_op op, void *value_p, int *found)
{
	struct k32v64_hash_table *ht = (struct k32v64_hash_table *)table;
	uint32_t *key = key_p;
	uint64_t value;

	if ((ht == NULL) || (key == NULL) || (value_p == NULL) ||
			(found == NULL) || (op >= RTE_KV_MODIFY_OP_MAX)) {
		return -EINVAL;
	}

	value = *(uint64_t *)value_p;
	switch (op) {
	case RTE_KV_MODIFY_ADD:
		return k32v64_hash_add(ht, *key, hash, value, value_p, found);
	case RTE_KV_MODIFY_DEL:
		return k32v64_hash_delete(ht, *key, hash, value_p);
	default:
		break;
	}

	return -EINVAL;
}

struct rte_kv_hash_table *
k32v64_hash_create(const struct rte_kv_hash_params *params)
{
	char hash_name[RTE_KV_HASH_NAMESIZE];
	struct k32v64_hash_table *ht = NULL;
	uint32_t mem_size, nb_buckets, max_ent;
	int ret;
	struct rte_mempool *mp;

	if ((params == NULL) || (params->name == NULL) ||
			(params->entries == 0)) {
		rte_errno = EINVAL;
		return NULL;
	}

	ret = snprintf(hash_name, sizeof(hash_name), "KV_%s", params->name);
	if (ret < 0 || ret >= RTE_KV_HASH_NAMESIZE) {
		rte_errno = ENAMETOOLONG;
		return NULL;
	}

	max_ent = rte_align32pow2(params->entries);
	nb_buckets = max_ent / K32V64_KEYS_PER_BUCKET;
	mem_size = sizeof(struct k32v64_hash_table) +
		sizeof(struct k32v64_hash_bucket) * nb_buckets;

	mp = rte_mempool_create(hash_name, max_ent,
		sizeof(struct k32v64_ext_ent), 0, 0, NULL, NULL, NULL, NULL,
		params->socket_id, 0);

	if (mp == NULL)
		return NULL;

	ht = rte_zmalloc_socket(hash_name, mem_size,
		RTE_CACHE_LINE_SIZE, params->socket_id);
	if (ht == NULL) {
		rte_mempool_free(mp);
		return NULL;
	}

	memcpy(ht->pub.name, hash_name, sizeof(ht->pub.name));
	ht->max_ent = max_ent;
	ht->bucket_msk = nb_buckets - 1;
	ht->ext_ent_pool = mp;
	ht->pub.lookup = get_lookup_bulk_fn();
	ht->pub.modify = k32v64_modify;

	return (struct rte_kv_hash_table *)ht;
}

void
k32v64_hash_free(struct rte_kv_hash_table *ht)
{
	if (ht == NULL)
		return;

	rte_mempool_free(((struct k32v64_hash_table *)ht)->ext_ent_pool);
	rte_free(ht);
}
