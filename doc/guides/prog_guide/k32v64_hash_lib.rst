..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2020 Intel Corporation.

.. _k32v64_hash_Library:

K32V64 Hash Library
===================

This hash library implementation is intended to be better optimized for 32-bit keys when compared to existing Cuckoo hash-based rte_hash implementation. Current rte_fbk implementation is pretty fast but it has a number of drawbacks such as 2 byte values and limited collision resolving capabilities. rte_hash (which is based on Cuckoo hash algorithm) doesn't have these drawbacks, but it comes at a cost of lower performance compared to rte_fbk.

The following flow illustrates the source of performance penalties of Cuckoo hash:

*  Loading two buckets at once (extra memory consumption)
*  Сomparing signatures first (extra step before key comparison)
*  If signature comparison hits, get a key index, find memory location with a key itself, and get the key (memory pressure and indirection)
*  Using indirect call to memcmp() to compare two uint32_t (function call overhead)

K32V64 hash table doesn't have the drawbacks associated with rte_fbk while offering the same performance as rte_fbk. The bucket contains 4 consecutive keys which can be compared very quickly, and subsequent keys are kept in a linked list.

The main disadvantage compared to rte_hash is performance degradation with high average table utilization due to chain resolving for 5th and subsequent collisions.

To estimate the probability of 5th collision we can use "birthday paradox" approach. We can figure out the number of insertions (can be treated as a load factor) that will likely yield a 50% probability of 5th collision for a given number of buckets.

It could be calculated with an asymptotic formula from [1]:

E(n, k) ~= (k!)^(1/k)*Γ(1 + 1/k)*n^(1-1/k), n -> inf

,where

k - level of collision

n - number of buckets

Г - gamma function

So, for k = 5 (5th collision), and given the fact that number of buckets is a power of 2, we can simplify formula:

E(n) = 2.392 * 2^(m * 4/5) , where number of buckets n = 2^m

.. note::

   You can calculate it by yourself using Wolfram Alpha [2]. For example for 8k buckets:

   solve ((k!)^(1/k)*Γ(1 + 1/k)*n^(1-1/k), n = 8192, k = 5)


API Overview
-----------------

The main configuration parameters for the hash table are:

*  Total number of hash entries in the table
*  Socket id

K32V64 is "hash function-less", so user must specify precalculated hash value for every key. The main methods exported by the Hash Library are:

*   Add entry with key and precomputed hash: The key, precomputed hash and value are provided as input.
*   Delete entry with key and precomputed hash: The key and precomputed hash are provided as input.
*   Lookup entry with key and precomputed hash: The key, precomputed hash and a pointer to expected value are provided as input. If an entry with the specified key is found in the hash table (i.e. lookup hit), then the value associated with the key will be written to the memory specified by the pointer, and the function will return 0; otherwise (i.e. a lookup miss) a negative value is returned, and memory described by the pointer is not modified.

References
----------

[1] M.S. Klamkin and D.J. Newman, Extensions of the Birthday Surprise

[2] https://www.wolframalpha.com/
