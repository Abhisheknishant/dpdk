/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _RTE_KV_HASH_H_
#define _RTE_KV_HASH_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_compat.h>
#include <rte_atomic.h>
#include <rte_mempool.h>

#define RTE_KV_HASH_NAMESIZE		32

enum rte_kv_hash_type {
	RTE_KV_HASH_K32V64,
	RTE_KV_HASH_MAX
};

enum rte_kv_modify_op {
	RTE_KV_MODIFY_ADD,
	RTE_KV_MODIFY_DEL,
	RTE_KV_MODIFY_OP_MAX
};

struct rte_kv_hash_params {
	const char *name;
	uint32_t entries;
	int socket_id;
	enum rte_kv_hash_type type;
};

struct rte_kv_hash_table;

typedef int (*rte_kv_hash_bulk_lookup_t)
(struct rte_kv_hash_table *table, void *keys, uint32_t *hashes,
	void *values, unsigned int n);

typedef int (*rte_kv_hash_modify_t)
(struct rte_kv_hash_table *table, void *key, uint32_t hash,
	enum rte_kv_modify_op op, void *value, int *found);

struct rte_kv_hash_table {
	char name[RTE_KV_HASH_NAMESIZE];	/**< Name of the hash. */
	rte_kv_hash_bulk_lookup_t	lookup;
	rte_kv_hash_modify_t		modify;
	enum rte_kv_hash_type		type;
};

/**
 * Lookup bulk of keys.
 * This function is multi-thread safe with regarding to other lookup threads.
 *
 * @param table
 *   Hash table to add the key to.
 * @param keys
 *   Pointer to array of keys
 * @param hashes
 *   Pointer to array of hash values associated with keys.
 * @param values
 *   Pointer to array of value corresponded to keys
 *   If the key was not found the corresponding value remains intact.
 * @param n
 *   Number of keys to lookup in batch.
 * @return
 *   -EINVAL if there's an error, otherwise number of successful lookups.
 */
static inline int
rte_kv_hash_bulk_lookup(struct rte_kv_hash_table *table,
	void *keys, uint32_t *hashes, void *values, unsigned int n)
{
	return table->lookup(table, keys, hashes, values, n);
}

/**
 * Add a key to an existing hash table with hash value.
 * This operation is not multi-thread safe regarding to add/delete functions
 * and should only be called from one thread.
 * However it is safe to call it along with lookup.
 *
 * @param table
 *   Hash table to add the key to.
 * @param key
 *   Key to add to the hash table.
 * @param value
 *   Value to associate with key.
 * @param hash
 *   Hash value associated with key.
 * @found
 *   0 if no previously added key was found
 *   1 previously added key was found, old value associated with the key
 *   was written to *value
 * @return
 *   0 if ok, or negative value on error.
 */
__rte_experimental
int
rte_kv_hash_add(struct rte_kv_hash_table *table, void *key,
	uint32_t hash, void *value, int *found);

/**
 * Remove a key with a given hash value from an existing hash table.
 * This operation is not multi-thread safe regarding to add/delete functions
 * and should only be called from one thread.
 * However it is safe to call it along with lookup.
 *
 * @param table
 *   Hash table to remove the key from.
 * @param key
 *   Key to remove from the hash table.
 * @param hash
 *   hash value associated with key.
 * @param value
 *   pointer to memory where the old value will be written to on success
 * @return
 *   0 if ok, or negative value on error.
 */
__rte_experimental
int
rte_kv_hash_delete(struct rte_kv_hash_table *table, void *key,
	uint32_t hash, void *value);

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
struct rte_kv_hash_table *
rte_kv_hash_find_existing(const char *name);

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
struct rte_kv_hash_table *
rte_kv_hash_create(const struct rte_kv_hash_params *params);

/**
 * Free all memory used by a hash table.
 *
 * @param table
 *   Hash table to deallocate.
 */
__rte_experimental
void
rte_kv_hash_free(struct rte_kv_hash_table *table);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_KV_HASH_H_ */
