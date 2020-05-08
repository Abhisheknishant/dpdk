/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <string.h>

#include <rte_eal_memconfig.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_tailq.h>

#include <rte_kv_hash.h>
#include "k32v64_hash.h"

TAILQ_HEAD(rte_kv_hash_list, rte_tailq_entry);

static struct rte_tailq_elem rte_kv_hash_tailq = {
	.name = "RTE_KV_HASH",
};

EAL_REGISTER_TAILQ(rte_kv_hash_tailq);

int
rte_kv_hash_add(struct rte_kv_hash_table *table, void *key,
	uint32_t hash, void *value, int *found)
{
	if (table == NULL)
		return -EINVAL;

	return table->modify(table, key, hash, RTE_KV_MODIFY_ADD,
		value, found);
}

int
rte_kv_hash_delete(struct rte_kv_hash_table *table, void *key,
	uint32_t hash, void *value)
{
	int found;

	if (table == NULL)
		return -EINVAL;

	return table->modify(table, key, hash, RTE_KV_MODIFY_DEL,
		value, &found);
}

struct rte_kv_hash_table *
rte_kv_hash_find_existing(const char *name)
{
	struct rte_kv_hash_table *h = NULL;
	struct rte_tailq_entry *te;
	struct rte_kv_hash_list *kv_hash_list;

	kv_hash_list = RTE_TAILQ_CAST(rte_kv_hash_tailq.head,
			rte_kv_hash_list);

	rte_mcfg_tailq_read_lock();
	TAILQ_FOREACH(te, kv_hash_list, next) {
		h = (struct rte_kv_hash_table *) te->data;
		if (strncmp(name, h->name, RTE_KV_HASH_NAMESIZE) == 0)
			break;
	}
	rte_mcfg_tailq_read_unlock();
	if (te == NULL) {
		rte_errno = ENOENT;
		return NULL;
	}
	return h;
}

struct rte_kv_hash_table *
rte_kv_hash_create(const struct rte_kv_hash_params *params)
{
	char hash_name[RTE_KV_HASH_NAMESIZE];
	struct rte_kv_hash_table *ht, *tmp_ht = NULL;
	struct rte_tailq_entry *te;
	struct rte_kv_hash_list *kv_hash_list;
	int ret;

	if ((params == NULL) || (params->name == NULL) ||
			(params->entries == 0) ||
			(params->type >= RTE_KV_HASH_MAX)) {
		rte_errno = EINVAL;
		return NULL;
	}

	kv_hash_list = RTE_TAILQ_CAST(rte_kv_hash_tailq.head,
		rte_kv_hash_list);

	ret = snprintf(hash_name, sizeof(hash_name), "KV_%s", params->name);
	if (ret < 0 || ret >= RTE_KV_HASH_NAMESIZE) {
		rte_errno = ENAMETOOLONG;
		return NULL;
	}

	switch (params->type) {
	case RTE_KV_HASH_K32V64:
		ht = k32v64_hash_create(params);
		break;
	default:
		rte_errno = EINVAL;
		return NULL;
	}
	if (ht == NULL)
		return ht;

	rte_mcfg_tailq_write_lock();
	TAILQ_FOREACH(te, kv_hash_list, next) {
		tmp_ht = (struct rte_kv_hash_table *) te->data;
		if (strncmp(params->name, tmp_ht->name,
				RTE_KV_HASH_NAMESIZE) == 0)
			break;
	}
	if (te != NULL) {
		rte_errno = EEXIST;
		goto exit;
	}

	te = rte_zmalloc("KV_HASH_TAILQ_ENTRY", sizeof(*te), 0);
	if (te == NULL) {
		RTE_LOG(ERR, HASH, "Failed to allocate tailq entry\n");
		goto exit;
	}

	ht->type = params->type;
	te->data = (void *)ht;
	TAILQ_INSERT_TAIL(kv_hash_list, te, next);

	rte_mcfg_tailq_write_unlock();

	return ht;

exit:
	rte_mcfg_tailq_write_unlock();
	switch (params->type) {
	case RTE_KV_HASH_K32V64:
		k32v64_hash_free(ht);
		break;
	default:
		break;
	}
	return NULL;
}

void
rte_kv_hash_free(struct rte_kv_hash_table *ht)
{
	struct rte_tailq_entry *te;
	struct rte_kv_hash_list *kv_hash_list;

	if (ht == NULL)
		return;

	kv_hash_list = RTE_TAILQ_CAST(rte_kv_hash_tailq.head,
				rte_kv_hash_list);

	rte_mcfg_tailq_write_lock();

	/* find out tailq entry */
	TAILQ_FOREACH(te, kv_hash_list, next) {
		if (te->data == (void *) ht)
			break;
	}


	if (te == NULL) {
		rte_mcfg_tailq_write_unlock();
		return;
	}

	TAILQ_REMOVE(kv_hash_list, te, next);

	rte_mcfg_tailq_write_unlock();

	switch (ht->type) {
	case RTE_KV_HASH_K32V64:
		k32v64_hash_free(ht);
		break;
	default:
		break;
	}
	rte_free(te);
}
