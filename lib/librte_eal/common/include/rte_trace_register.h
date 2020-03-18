/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#ifndef _RTE_TRACE_H_
#error do not include this file directly, use <rte_trace.h> instead
#endif

#ifndef _RTE_TRACE_REGISTER_H_
#define _RTE_TRACE_REGISTER_H_

#include <rte_per_lcore.h>
#include <rte_log.h>

RTE_DECLARE_PER_LCORE(volatile int, trace_point_sz);

#define RTE_TRACE_POINT_REGISTER(trace, name, level)\
	__rte_trace_point_register(&__##trace, RTE_STR(name),\
			RTE_LOG_ ## level, (void (*)(void)) trace)

#define __rte_trace_emit_header_generic(t)\
	RTE_PER_LCORE(trace_point_sz) = __RTE_TRACE_EVENT_HEADER_SZ

#define __rte_trace_emit_header_dp(t) __rte_trace_emit_header_generic(t)

#define rte_trace_ctf_u64(in)\
	RTE_BUILD_BUG_ON(sizeof(uint64_t) != sizeof(typeof(in)));\
	__rte_trace_emit_ctf_field(sizeof(uint64_t), RTE_STR(in), "uint64_t")
#define rte_trace_ctf_i64(in)\
	RTE_BUILD_BUG_ON(sizeof(int64_t) != sizeof(typeof(in)));\
	__rte_trace_emit_ctf_field(sizeof(int64_t), RTE_STR(in), "int64_t")
#define rte_trace_ctf_u32(in)\
	RTE_BUILD_BUG_ON(sizeof(uint32_t) != sizeof(typeof(in)));\
	__rte_trace_emit_ctf_field(sizeof(uint32_t), RTE_STR(in), "uint32_t")
#define rte_trace_ctf_i32(in)\
	RTE_BUILD_BUG_ON(sizeof(int32_t) != sizeof(typeof(in)));\
	__rte_trace_emit_ctf_field(sizeof(int32_t), RTE_STR(in), "int32_t")
#define rte_trace_ctf_u16(in)\
	RTE_BUILD_BUG_ON(sizeof(uint16_t) != sizeof(typeof(in)));\
	__rte_trace_emit_ctf_field(sizeof(uint16_t), RTE_STR(in), "uint16_t")
#define rte_trace_ctf_i16(in)\
	RTE_BUILD_BUG_ON(sizeof(int16_t) != sizeof(typeof(in)));\
	__rte_trace_emit_ctf_field(sizeof(int16_t), RTE_STR(in), "int16_t")
#define rte_trace_ctf_u8(in)\
	RTE_BUILD_BUG_ON(sizeof(uint8_t) != sizeof(typeof(in)));\
	__rte_trace_emit_ctf_field(sizeof(uint8_t), RTE_STR(in), "uint8_t")
#define rte_trace_ctf_i8(in)\
	RTE_BUILD_BUG_ON(sizeof(int8_t) != sizeof(typeof(in)));\
	__rte_trace_emit_ctf_field(sizeof(int8_t), RTE_STR(in), "int8_t")
#define rte_trace_ctf_int(in)\
	RTE_BUILD_BUG_ON(sizeof(int) != sizeof(typeof(in)));\
	__rte_trace_emit_ctf_field(sizeof(int), RTE_STR(in), "int32_t")
#define rte_trace_ctf_long(in)\
	RTE_BUILD_BUG_ON(sizeof(long) != sizeof(typeof(in)));\
	__rte_trace_emit_ctf_field(sizeof(long), RTE_STR(in), "long")
#define rte_trace_ctf_float(in)\
	RTE_BUILD_BUG_ON(sizeof(float) != sizeof(typeof(in)));\
	__rte_trace_emit_ctf_field(sizeof(float), RTE_STR(in), "float")
#define rte_trace_ctf_double(in)\
	RTE_BUILD_BUG_ON(sizeof(double) != sizeof(typeof(in)));\
	__rte_trace_emit_ctf_field(sizeof(double), RTE_STR(in), "double")
#define rte_trace_ctf_ptr(in)\
	RTE_BUILD_BUG_ON(sizeof(void *) != sizeof(typeof(in)));\
	__rte_trace_emit_ctf_field(sizeof(void *), RTE_STR(in), "uintptr_t")
#define rte_trace_ctf_string(in)\
	RTE_SET_USED(in);\
	__rte_trace_emit_ctf_field(__RTE_TRACE_EMIT_STRING_LEN_MAX,\
				   RTE_STR(in)"[32]", "string_bounded_t")

#endif /* _RTE_TRACE_REGISTER_H_ */
