/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Microsoft Corp
 */
#ifndef RTE_OVERFLOW_H_
#define RTE_OVERFLOW_H_
/**
 * @file
 *
 * Math functions with overflow checking.
 * Wrappers for the __builtin_XXX_overflow functions that exist
 * in recent versions of GCC and CLANG but may not exist
 * in older compilers. They are macros to allow use with any
 * size of unsigned number.
 *
 * See:
 *  https://gcc.gnu.org/onlinedocs/gcc/Integer-Overflow-Builtins.html
 *  https://github.com/nemequ/portable-snippets/tree/master/safe-math
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

#if defined(__has_builtin)
#    if __has_builtin(__builtin_add_overflow)
#        define RTE_HAVE_BUILTIN_OVERFLOW
#    endif
#elif defined(RTE_TOOLCHAIN_GCC) && (GCC_VERSION >= 5000)
#    define RTE__HAVE_BUILTIN_OVERFLOW
#endif

/**
 * Safely add two bit unsigned numbers
 * @param a
 *   One operand
 * @param b
 *   Other operand
 * @param res
 *   Pointer to the where result of a + b is stored.
 *   Must not be NULL
 * @return
 *   return true if the result overflows and is therefore truncated.
 */
#ifdef RTE_HAVE_BUILTIN_OVERFLOW
#define rte_add_overflow(a, b, res) __builtin_add_overflow(a, b, res)
#else
#define rte_add_overflow(a, b, res) ({ *res = a + b; *res < a; })
#endif

/**
 * Safely multiply two unsigned numbers
 * @param a
 *   One operand
 * @param b
 *   Other operand
 * @param res
 *   Pointer to the where result of a + b is stored.
 *   Must not be NULL
 * @return
 *   return true if the result overflows and is therefore truncated.
 */
#ifdef RTE_HAVE_BUILTIN_OVERFLOW
#define rte_mul_overflow(a, b, res) __builtin_mul_overflow(a, b, res)
#else
#define rte_mul_overflow(a, b, res) ({ *res = a * b; *res < a; })
#endif

#ifdef __cplusplus
}
#endif

#endif /* RTE_OVERFLOW_H_ */
