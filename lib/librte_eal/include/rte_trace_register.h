/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#ifndef _RTE_TRACE_H_
#error do not include this file directly, use <rte_trace.h> instead
#endif

#ifndef _RTE_TRACE_REGISTER_H_
#define _RTE_TRACE_REGISTER_H_

#include <rte_per_lcore.h>

RTE_DECLARE_PER_LCORE(volatile int, trace_point_sz);

#define RTE_TRACE_POINT_REGISTER(trace, name)\
	__rte_trace_point_register(&__##trace, RTE_STR(name),\
				   (void (*)(void)) trace)

#define __rte_trace_emit_header_generic(t)\
	RTE_PER_LCORE(trace_point_sz) = __RTE_TRACE_EVENT_HEADER_SZ

#define __rte_trace_emit_header_fp(t) __rte_trace_emit_header_generic(t)

#define __rte_trace_emit_datatype(in, type)\
do {\
	RTE_BUILD_BUG_ON(sizeof(type) != sizeof(typeof(in)));\
	__rte_trace_emit_ctf_field(sizeof(type), RTE_STR(in), RTE_STR(type));\
} while (0)

#define rte_trace_ctf_u64(in) __rte_trace_emit_datatype(in, uint64_t)
#define rte_trace_ctf_i64(in) __rte_trace_emit_datatype(in, int64_t)
#define rte_trace_ctf_u32(in) __rte_trace_emit_datatype(in, uint32_t)
#define rte_trace_ctf_i32(in) __rte_trace_emit_datatype(in, int32_t)
#define rte_trace_ctf_u16(in) __rte_trace_emit_datatype(in, uint16_t)
#define rte_trace_ctf_i16(in) __rte_trace_emit_datatype(in, int16_t)
#define rte_trace_ctf_u8(in) __rte_trace_emit_datatype(in, uint8_t)
#define rte_trace_ctf_i8(in) __rte_trace_emit_datatype(in, int8_t)
#define rte_trace_ctf_int(in) __rte_trace_emit_datatype(in, int32_t)
#define rte_trace_ctf_long(in) __rte_trace_emit_datatype(in, long)
#define rte_trace_ctf_float(in) __rte_trace_emit_datatype(in, float)
#define rte_trace_ctf_double(in) __rte_trace_emit_datatype(in, double)
#define rte_trace_ctf_ptr(in) __rte_trace_emit_datatype(in, uintptr_t)

#define rte_trace_ctf_string(in)\
do {\
	RTE_SET_USED(in);\
	__rte_trace_emit_ctf_field(__RTE_TRACE_EMIT_STRING_LEN_MAX,\
				   RTE_STR(in)"[32]", "string_bounded_t");\
} while (0)

#endif /* _RTE_TRACE_REGISTER_H_ */
