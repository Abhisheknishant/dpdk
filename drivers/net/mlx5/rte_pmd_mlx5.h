/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#ifndef RTE_PMD_PRIVATE_MLX5_H_
#define RTE_PMD_PRIVATE_MLX5_H_

/**
 * @file
 * MLX5 public header.
 *
 * This interface provides the ability to support private PMD
 * dynamic flags.
 */

#define RTE_PMD_MLX5_FINE_GRANULARITY_INLINE "mlx5_fine_granularity_inline"

/**
 * Returns the dynamic flags name, that are supported.
 *
 * @param[out] names
 *   Array that is used to return the supported dynamic flags names.
 * @param[in] n
 *   The number of elements in the names array.
 *
 * @return
 *   The number of dynamic flags that were copied.
 */
__rte_experimental
int rte_pmd_mlx5_get_dyn_flag_names(char *names[], uint16_t n);

#endif
