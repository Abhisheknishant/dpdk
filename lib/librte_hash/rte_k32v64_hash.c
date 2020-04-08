/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <string.h>

#include <rte_eal_memconfig.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_tailq.h>

#include <rte_k32v64_hash.h>

TAILQ_HEAD(rte_k32v64_hash_list, rte_tailq_entry);

static struct rte_tailq_elem rte_k32v64_hash_tailq = {
	.name = "RTE_K32V64_HASH",
};

EAL_REGISTER_TAILQ(rte_k32v64_hash_tailq);

#define VALID_KEY_MSK           ((1 << RTE_K32V64_KEYS_PER_BUCKET) - 1)

int
rte_k32v64_hash_add(struct rte_k32v64_hash_table *table, uint32_t key,
	uint32_t hash, uint64_t value)
{
	uint32_t bucket;
	int i, idx, ret;
	uint8_t msk;
	struct rte_k32v64_ext_ent *tmp, *ent, *prev = NULL;

	if (table == NULL)
		return -EINVAL;

	bucket = hash & table->bucket_msk;
	/* Search key in table. Update value if exists */
	for (i = 0; i < RTE_K32V64_KEYS_PER_BUCKET; i++) {
		if ((key == table->t[bucket].key[i]) &&
				(table->t[bucket].key_mask & (1 << i))) {
			table->t[bucket].val[i] = value;
			return 0;
		}
	}

	if (!SLIST_EMPTY(&table->t[bucket].head)) {
		SLIST_FOREACH(ent, &table->t[bucket].head, next) {
			if (ent->key == key) {
				ent->val = value;
				return 0;
			}
		}
	}

	msk = ~table->t[bucket].key_mask & VALID_KEY_MSK;
	if (msk) {
		idx = __builtin_ctz(msk);
		table->t[bucket].key[idx] = key;
		table->t[bucket].val[idx] = value;
		rte_smp_wmb();
		table->t[bucket].key_mask |= 1 << idx;
		table->nb_ent++;
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
	return 0;
}

int
rte_k32v64_hash_delete(struct rte_k32v64_hash_table *table, uint32_t key,
	uint32_t hash)
{
	uint32_t bucket;
	int i;
	struct rte_k32v64_ext_ent *ent;

	if (table == NULL)
		return -EINVAL;

	bucket = hash & table->bucket_msk;

	for (i = 0; i < RTE_K32V64_KEYS_PER_BUCKET; i++) {
		if ((key == table->t[bucket].key[i]) &&
				(table->t[bucket].key_mask & (1 << i))) {
			ent = SLIST_FIRST(&table->t[bucket].head);
			if (ent) {
				rte_atomic32_inc(&table->t[bucket].cnt);
				table->t[bucket].key[i] = ent->key;
				table->t[bucket].val[i] = ent->val;
				SLIST_REMOVE_HEAD(&table->t[bucket].head, next);
				rte_atomic32_inc(&table->t[bucket].cnt);
				table->nb_ext_ent--;
			} else
				table->t[bucket].key_mask &= ~(1 << i);
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

	rte_atomic32_inc(&table->t[bucket].cnt);
	SLIST_REMOVE(&table->t[bucket].head, ent, rte_k32v64_ext_ent, next);
	rte_atomic32_inc(&table->t[bucket].cnt);
	rte_mempool_put(table->ext_ent_pool, ent);

	table->nb_ext_ent--;
	table->nb_ent--;

	return 0;
}

struct rte_k32v64_hash_table *
rte_k32v64_hash_find_existing(const char *name)
{
	struct rte_k32v64_hash_table *h = NULL;
	struct rte_tailq_entry *te;
	struct rte_k32v64_hash_list *k32v64_hash_list;

	k32v64_hash_list = RTE_TAILQ_CAST(rte_k32v64_hash_tailq.head,
			rte_k32v64_hash_list);

	rte_mcfg_tailq_read_lock();
	TAILQ_FOREACH(te, k32v64_hash_list, next) {
		h = (struct rte_k32v64_hash_table *) te->data;
		if (strncmp(name, h->name, RTE_K32V64_HASH_NAMESIZE) == 0)
			break;
	}
	rte_mcfg_tailq_read_unlock();
	if (te == NULL) {
		rte_errno = ENOENT;
		return NULL;
	}
	return h;
}

struct rte_k32v64_hash_table *
rte_k32v64_hash_create(const struct rte_k32v64_hash_params *params)
{
	char hash_name[RTE_K32V64_HASH_NAMESIZE];
	struct rte_k32v64_hash_table *ht = NULL;
	struct rte_tailq_entry *te;
	struct rte_k32v64_hash_list *k32v64_hash_list;
	uint32_t mem_size, nb_buckets, max_ent;
	int ret;
	struct rte_mempool *mp;

	if ((params == NULL) || (params->name == NULL) ||
			(params->entries == 0)) {
		rte_errno = EINVAL;
		return NULL;
	}

	k32v64_hash_list = RTE_TAILQ_CAST(rte_k32v64_hash_tailq.head,
		rte_k32v64_hash_list);

	ret = snprintf(hash_name, sizeof(hash_name), "K32V64_%s", params->name);
	if (ret < 0 || ret >= RTE_K32V64_HASH_NAMESIZE) {
		rte_errno = ENAMETOOLONG;
		return NULL;
	}

	max_ent = rte_align32pow2(params->entries);
	nb_buckets = max_ent / RTE_K32V64_KEYS_PER_BUCKET;
	mem_size = sizeof(struct rte_k32v64_hash_table) +
		sizeof(struct rte_k32v64_hash_bucket) * nb_buckets;

	mp = rte_mempool_create(hash_name, max_ent,
		sizeof(struct rte_k32v64_ext_ent), 0, 0, NULL, NULL, NULL, NULL,
		params->socket_id, 0);

	if (mp == NULL)
		return NULL;

	rte_mcfg_tailq_write_lock();
	TAILQ_FOREACH(te, k32v64_hash_list, next) {
		ht = (struct rte_k32v64_hash_table *) te->data;
		if (strncmp(params->name, ht->name,
				RTE_K32V64_HASH_NAMESIZE) == 0)
			break;
	}
	ht = NULL;
	if (te != NULL) {
		rte_errno = EEXIST;
		rte_mempool_free(mp);
		goto exit;
	}

	te = rte_zmalloc("K32V64_HASH_TAILQ_ENTRY", sizeof(*te), 0);
	if (te == NULL) {
		RTE_LOG(ERR, HASH, "Failed to allocate tailq entry\n");
		rte_mempool_free(mp);
		goto exit;
	}

	ht = rte_zmalloc_socket(hash_name, mem_size,
		RTE_CACHE_LINE_SIZE, params->socket_id);
	if (ht == NULL) {
		RTE_LOG(ERR, HASH, "Failed to allocate fbk hash table\n");
		rte_free(te);
		rte_mempool_free(mp);
		goto exit;
	}

	memcpy(ht->name, hash_name, sizeof(ht->name));
	ht->max_ent = max_ent;
	ht->bucket_msk = nb_buckets - 1;
	ht->ext_ent_pool = mp;

	te->data = (void *)ht;
	TAILQ_INSERT_TAIL(k32v64_hash_list, te, next);

exit:
	rte_mcfg_tailq_write_unlock();

	return ht;
}

void
rte_k32v64_hash_free(struct rte_k32v64_hash_table *ht)
{
	struct rte_tailq_entry *te;
	struct rte_k32v64_hash_list *k32v64_hash_list;

	if (ht == NULL)
		return;

	k32v64_hash_list = RTE_TAILQ_CAST(rte_k32v64_hash_tailq.head,
				rte_k32v64_hash_list);

	rte_mcfg_tailq_write_lock();

	/* find out tailq entry */
	TAILQ_FOREACH(te, k32v64_hash_list, next) {
		if (te->data == (void *) ht)
			break;
	}


	if (te == NULL) {
		rte_mcfg_tailq_write_unlock();
		return;
	}

	TAILQ_REMOVE(k32v64_hash_list, te, next);

	rte_mcfg_tailq_write_unlock();

	rte_mempool_free(ht->ext_ent_pool);
	rte_free(ht);
	rte_free(te);
}

