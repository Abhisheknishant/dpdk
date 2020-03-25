/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#ifndef _RTE_TRACE_H_
#define _RTE_TRACE_H_

/**
 * @file
 *
 * RTE Trace API
 *
 * This file provides the trace API to RTE applications.
 *
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdio.h>

#include <rte_common.h>
#include <rte_compat.h>

/** The trace object. The trace APIs are based on this opaque object. */
typedef uint64_t rte_trace_t;

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Enumerate trace mode operation.
 */
enum rte_trace_mode {
	/**
	 * In this mode, When no space left in trace buffer, the subsequent
	 * events overwrite the old events in the trace buffer.
	 */
	RTE_TRACE_MODE_OVERWRITE,
	/**
	 * In this mode, When no space left on trace buffer, the subsequent
	 * events shall not be recorded in the trace buffer.
	 */
	RTE_TRACE_MODE_DISCARD,
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Test if global trace is enabled.
 *
 * @return
 *    true if global trace is enabled, false otherwise.
 */
__rte_experimental
bool rte_trace_global_is_enabled(void);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Test if global trace is disabled.
 *
 * @return
 *    true if global trace is disabled, false otherwise.
 */
__rte_experimental
bool rte_trace_global_is_disabled(void);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Test if a given trace is invalid.
 * @param trace
 *    The trace object.
 * @return
 *    true if global trace is invalid, false otherwise.
 */
__rte_experimental
bool rte_trace_is_id_invalid(rte_trace_t *trace);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Set the global trace level.
 *
 * After this call, trace with a level lower or equal than the level
 * passed as argument will be captured in the trace buffer.
 *
 * @param level
 *   Trace level. A value between RTE_LOG_EMERG (1) and RTE_LOG_DEBUG (8).
 */
__rte_experimental
void rte_trace_global_level_set(uint32_t level);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Get the global trace level.
 *
 * @return
 *   The current global trace level.
 */
__rte_experimental
uint32_t rte_trace_global_level_get(void);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Set the global trace mode.
 *
 * After this call, All tracepoints will be switched to new mode.
 *
 * @param mode
 *   Trace mode.
 */
__rte_experimental
void rte_trace_global_mode_set(enum rte_trace_mode mode);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Get the global trace mode.
 *
 * @return
 *   The current global trace mode.
 */
__rte_experimental
enum rte_trace_mode rte_trace_global_mode_get(void);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Enable recording of the given tracepoint in the trace buffer.
 *
 * @param trace
 *   The tracepoint object to enable.
 * @return
 *   - 0: Success.
 *   - (-ERANGE): Trace object is not registered.
 *   - (-EACCES): Trace object level is less than the global trace level.
 */
__rte_experimental
int rte_trace_enable(rte_trace_t *trace);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Disable recording of the given tracepoint in the trace buffer.
 *
 * @param trace
 *   The tracepoint object to disable.
 * @return
 *   - 0: Success.
 *   - (-ERANGE): Trace object is not registered.
 */
__rte_experimental
int rte_trace_disable(rte_trace_t *trace);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Test if given trace is enabled.
 *
 * @param trace
 *    The trace object.
 * @return
 *    true if trace is enabled, false otherwise.
 */
__rte_experimental
bool rte_trace_is_enabled(rte_trace_t *trace);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Test if given trace is disabled.
 *
 * @param trace
 *    The trace object.
 * @return
 *    true if trace is disabled, false otherwise.
 */
__rte_experimental
bool rte_trace_is_disabled(rte_trace_t *trace);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Set the trace level for the given tracepoint.
 *
 * After this call, if passed trace level lower or equal than the global trace
 * level and this trace is enabled then trace will be captured in the
 * trace buffer.
 *
 * @param trace
 *    The trace object.
 * @param level
 *   Trace level. A value between RTE_LOG_EMERG (1) and RTE_LOG_DEBUG (8).
 * @return
 *   - 0: Success.
 *   - (-EINVAL): Trace object is not registered or invalid trace level.
 */
__rte_experimental
int rte_trace_level_set(rte_trace_t *trace, uint32_t level);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Get the trace level for the given tracepoint.
 *
 * @param trace
 *    The trace object.
 * @return
 *   - A value between RTE_LOG_EMERG (1) and RTE_LOG_DEBUG (8).
 *   - 0: Trace object is not registered.
 */
__rte_experimental
uint32_t rte_trace_level_get(rte_trace_t *trace);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Set the trace mode for the given tracepoint.
 *
 * @param trace
 *    The trace object.
 * @param mode
 *   Trace mode.
 * @return
 *   - 0: Success.
 *   - (-EINVAL): Trace object is not registered or invalid trace level.
 */
__rte_experimental
int rte_trace_mode_set(rte_trace_t *trace, enum rte_trace_mode mode);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Get the trace mode for the given tracepoint.
 *
 * @param trace
 *    The trace object.
 * @return
 *   - Zero or positive: Mode encoded as enum rte_trace_mode.
 *   - (-EINVAL): Trace object is not registered.
 */
__rte_experimental
int rte_trace_mode_get(rte_trace_t *trace);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Enable/Disable a set of tracepoints based on shell pattern.
 *
 * @param pattern
 *   The match pattern identifying the tracepoint.
 * @param enable
 *    true to enable tracepoint, false to disable the tracepoint, upon match.
 * @return
 *   - 0: Success and no pattern match.
 *   - 1: Success and found pattern match.
 *   - (-ERANGE): Trace object is not registered.
 */
__rte_experimental
int rte_trace_pattern(const char *pattern, bool enable);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Enable/Disable a set of tracepoints based on regular expression.
 *
 * @param regex
 *   A regular expression identifying the tracepoint.
 * @param enable
 *    true to enable tracepoint, false to disable the tracepoint, upon match.
 * @return
 *   - 0: Success.
 *   - (-ERANGE): Trace object is not registered.
 *   - (-EINVAL): Invalid regular expression rule.
 */
__rte_experimental
int rte_trace_regexp(const char *regex, bool enable);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Save the trace buffer to the trace directory.
 *
 * By default, trace directory will be created at HOME directory and this can be
 * overridden by --trace-dir EAL parameter.
 *
 * @return
 *   - 0: Success.
 *   - <0 : Failure.
 */
__rte_experimental
int rte_trace_save(void);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Search a trace object from its name.
 *
 * @param name
 *   The name of the tracepoint.
 * @return
 *   The tracepoint object or NULL if not found.
 */
__rte_experimental
rte_trace_t *rte_trace_by_name(const char *name);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Dump the trace metadata to a file.
 *
 * @param f
 *   A pointer to a file for output
 * @return
 *   - 0: Success.
 *   - <0 : Failure.
 */
__rte_experimental
int rte_trace_metadata_dump(FILE *f);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 * Dump the trace subsystem status to a file.
 *
 * @param f
 *   A pointer to a file for output
 */
__rte_experimental
void rte_trace_dump(FILE *f);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Test if the trace datapath compile-time option is enabled.
 *
 * @return
 *   true if trace datapath enabled, false otherwise.
 */
static __rte_always_inline bool
rte_trace_is_dp_enabled(void)
{
#ifdef RTE_ENABLE_TRACE_DP
	return RTE_ENABLE_TRACE_DP;
#else
	return false;
#endif
}

/** Macro to define the tracepoint. */
#define RTE_TRACE_POINT_DEFINE(tp)\
rte_trace_t __attribute__((section("__rte_trace_point"))) __##tp

/**
 * Macro to define the tracepoint arguments in RTE_TRACE_POINT macro.

 * @see RTE_TRACE_POINT RTE_TRACE_POINT_DP
 */
#define RTE_TRACE_POINT_ARGS

/** @internal Helper Macro to support RTE_TRACE_POINT and RTE_TRACE_POINT_DP */
#define __RTE_TRACE_POINT(_mode, _tp, _args, ...)\
extern rte_trace_t __##_tp;\
static __rte_always_inline void \
_tp _args \
{\
	__rte_trace_emit_header_##_mode(&__##_tp);\
	__VA_ARGS__\
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Create a tracepoint definition.
 *
 * A tracepoint definition defines, for a given tracepoint:
 * - Its input arguments. They are the C function style parameters to define
 * the arguments of tracepoint function. These input arguments embedded using
 * RTE_TRACE_POINT_ARGS macro.
 * - Its output event fields. They are the sources of event fields that form
 * the payload of any event that the execution of the tracepoint macro emits
 * for this particular tracepoint. The application uses rte_trace_ctf_* macros
 * to emit the output event fields.
 *
 * @param tp
 *   Tracepoint object. Before using the tracepoint, an application needs to
 * define the tracepoint using RTE_TRACE_POINT_DEFINE() macro.
 * @param args
 *   C function style input arguments to define the arguments to tracepoint
 * function.
 * @param ...
 *   Define the payload of trace function. The payload will be formed using
 * rte_trace_ctf_* macros, Use ";" delimiter between two payloads.
 *
 * @see RTE_TRACE_POINT_ARGS, RTE_TRACE_POINT_DEFINE, rte_trace_ctf_*
 */
#define RTE_TRACE_POINT(tp, args, ...)\
	__RTE_TRACE_POINT(generic, tp, args, __VA_ARGS__)

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Create a tracepoint definition for the data path.
 *
 * Similar to RTE_TRACE_POINT(), except that it is removed at compilation time
 * using RTE_ENABLE_TRACE_DP configuration parameter.
 *
 * @param tp
 *   Tracepoint object. Before using the tracepoint, an application needs to
 * define the tracepoint using RTE_TRACE_POINT_DEFINE() macro.
 * @param args
 *   C function style input arguments to define the arguments to tracepoint
 * function.
 * @param ...
 *   Define the payload of trace function. The payload will be formed using
 * rte_trace_ctf_* macros, Use ";" delimiter between two payloads.
 *
 * @see rte_trace_is_dp_enabled, RTE_TRACE_POINT()
 */
#define RTE_TRACE_POINT_DP(tp, args, ...)\
	__RTE_TRACE_POINT(dp, tp, args, __VA_ARGS__)

#ifdef __DOXYGEN__

/**
 * Macro to select rte_trace_ctf_* definition for trace register function.
 *
 * rte_trace_ctf_* emits different definitions for trace function.
 * Application must define RTE_TRACE_POINT_REGISTER_SELECT before including
 * rte_trace.h in the C file where RTE_TRACE_POINT_REGISTER() used.
 *
 * @see RTE_TRACE_POINT_REGISTER()
 */
#define RTE_TRACE_POINT_REGISTER_SELECT

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Register a dynamic tracepoint.
 *
 * @param trace
 *   The tracepoint object created using RTE_TRACE_POINT_DEFINE().
 * @param name
 *   The name of the tracepoint object.
 * @param level
 *   Trace level. A value between RTE_LOG_EMERG (1) and RTE_LOG_DEBUG (8).
 * @return
 *   - 0: Successfully registered the tracepoint.
 *   - <0: Failure to register the tracepoint.
 *
 * @see RTE_TRACE_POINT_REGISTER_SELECT
 */
#define RTE_TRACE_POINT_REGISTER(trace, name, level)

/** Tracepoint function payload for uint64_t datatype */
#define rte_trace_ctf_u64(val)
/** Tracepoint function payload for int64_t datatype */
#define rte_trace_ctf_i64(val)
/** Tracepoint function payload for uint32_t datatype */
#define rte_trace_ctf_u32(val)
/** Tracepoint function payload for int32_t datatype */
#define rte_trace_ctf_i32(val)
/** Tracepoint function payload for uint16_t datatype */
#define rte_trace_ctf_u16(val)
/** Tracepoint function payload for int16_t datatype */
#define rte_trace_ctf_i16(val)
/** Tracepoint function payload for uint8_t datatype */
#define rte_trace_ctf_u8(val)
/** Tracepoint function payload for int8_t datatype */
#define rte_trace_ctf_i8(val)
/** Tracepoint function payload for int datatype */
#define rte_trace_ctf_int(val)
/** Tracepoint function payload for long datatype */
#define rte_trace_ctf_long(val)
/** Tracepoint function payload for float datatype */
#define rte_trace_ctf_float(val)
/** Tracepoint function payload for double datatype */
#define rte_trace_ctf_double(val)
/** Tracepoint function payload for pointer datatype */
#define rte_trace_ctf_ptr(val)
/** Tracepoint function payload for string datatype */
#define rte_trace_ctf_string(val)

#endif /* __DOXYGEN__ */

/** @internal Macro to define maximum emit length of string datatype. */
#define __RTE_TRACE_EMIT_STRING_LEN_MAX 32
/** @internal Macro to define event header size. */
#define __RTE_TRACE_EVENT_HEADER_SZ sizeof(uint64_t)

/**
 * @internal @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Allocate trace memory buffer per thread.
 *
 */
__rte_experimental
void __rte_trace_mem_per_thread_alloc(void);

/**
 * @internal @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Helper function to register a dynamic tracepoint.
 * Use RTE_TRACE_POINT_REGISTER() macro for tracepoint registration.
 *
 * @param trace
 *   The tracepoint object created using RTE_TRACE_POINT_DEFINE().
 * @param name
 *   The name of the tracepoint object.
 * @param level
 *   Trace level. A value between RTE_LOG_EMERG (1) and RTE_LOG_DEBUG (8).
 * @param register_fn
 *   Trace registration function.
 * @return
 *   - 0: Successfully registered the tracepoint.
 *   - <0: Failure to register the tracepoint.
 */
__rte_experimental
int __rte_trace_point_register(rte_trace_t *trace, const char *name,
			     uint32_t level, void (*register_fn)(void));
/**
 * @internal @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Helper function to emit ctf field.
 *
 * @param sz
 *   The tracepoint size.
 * @param field
 *   The name of the trace event.
 * @param type
 *   The datatype of the trace event as string.
 * @return
 *   - 0: Success.
 *   - <0: Failure.
 */
__rte_experimental
void __rte_trace_emit_ctf_field(size_t sz, const char *field, const char *type);

#ifdef RTE_TRACE_POINT_REGISTER_SELECT
#include <rte_trace_register.h>
#else
#include <rte_trace_provider.h>
#endif

#ifdef __cplusplus
}
#endif

#endif /* _RTE_TRACE_H_ */
