/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <rte_k32v64_hash.h>

int
k32v64_hash_bulk_lookup_avx512vl(struct rte_k32v64_hash_table *table,
	uint32_t *keys, uint32_t *hashes, uint64_t *values, unsigned int n);

static inline int
k32v64_cmp_keys_avx512vl(struct rte_k32v64_hash_bucket *bucket, uint32_t key,
	uint64_t *val)
{
	__m128i keys, srch_key;
	__mmask8 msk;

	keys = _mm_load_si128((void *)bucket);
	srch_key = _mm_set1_epi32(key);

	msk = _mm_mask_cmpeq_epi32_mask(bucket->key_mask, keys, srch_key);
	if (msk) {
		*val = bucket->val[__builtin_ctz(msk)];
		return 1;
	}

	return 0;
}

static inline int
k32v64_hash_lookup_avx512vl(struct rte_k32v64_hash_table *table, uint32_t key,
	uint32_t hash, uint64_t *value)
{
	return __k32v64_hash_lookup(table, key, hash, value,
		k32v64_cmp_keys_avx512vl);
}

int
k32v64_hash_bulk_lookup_avx512vl(struct rte_k32v64_hash_table *table,
	uint32_t *keys, uint32_t *hashes, uint64_t *values, unsigned int n)
{
	int ret, cnt = 0;
	unsigned int i;

	if (unlikely((table == NULL) || (keys == NULL) || (hashes == NULL) ||
			(values == NULL)))
		return -EINVAL;

	for (i = 0; i < n; i++) {
		ret = k32v64_hash_lookup_avx512vl(table, keys[i], hashes[i],
			&values[i]);
		if (ret == 0)
			cnt++;
	}
	return cnt;
}
