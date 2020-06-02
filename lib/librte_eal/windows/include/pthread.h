/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#ifndef _PTHREAD_H_
#define _PTHREAD_H_

#include <stdint.h>
#include <sched.h>

/**
 * This file is required to support the common code in eal_common_proc.c,
 * eal_common_thread.c and common\include\rte_per_lcore.h as Microsoft libc
 * does not contain pthread.h. This may be removed in future releases.
 */
#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>
#include <rte_windows.h>

#define PTHREAD_BARRIER_SERIAL_THREAD TRUE

/* defining pthread_t type on Windows since there is no in Microsoft libc*/
typedef uintptr_t pthread_t;

/* defining pthread_attr_t type on Windows since there is no in Microsoft libc*/
typedef void *pthread_attr_t;

typedef SYNCHRONIZATION_BARRIER pthread_barrier_t;

#define pthread_barrier_init(barrier, attr, count) \
	InitializeSynchronizationBarrier(barrier, count, -1)
#define pthread_barrier_wait(barrier) EnterSynchronizationBarrier(barrier, \
	SYNCHRONIZATION_BARRIER_FLAGS_BLOCK_ONLY)
#define pthread_barrier_destroy(barrier) \
	DeleteSynchronizationBarrier(barrier)
#define pthread_cancel(thread) TerminateThread((HANDLE) thread, 0)

/* pthread function overrides */
#define pthread_self() \
	((pthread_t)GetCurrentThreadId())
#define pthread_setaffinity_np(thread, size, cpuset) \
	eal_set_thread_affinity_mask(thread, cpuset)
#define pthread_getaffinity_np(thread, size, cpuset) \
	eal_get_thread_affinity_mask(thread, cpuset)
#define pthread_create(threadid, threadattr, threadfunc, args) \
	eal_create_thread(threadid, threadfunc, args)

static inline int
eal_set_thread_affinity_mask(pthread_t threadid, rte_cpuset_t *cpuset)
{
	DWORD_PTR ret;
	HANDLE thread_handle;

	thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, threadid);
	if (thread_handle == NULL) {
		RTE_LOG_WIN32_ERR("OpenThread()");
		return -1;
	}

	ret = SetThreadAffinityMask(thread_handle, *cpuset->_bits);
	if (ret == 0) {
		RTE_LOG_WIN32_ERR("SetThreadAffinityMask()");
		CloseHandle(thread_handle);
		return -1;
	}
	CloseHandle(thread_handle);
	return 0;
}

static inline int
eal_get_thread_affinity_mask(pthread_t threadid, rte_cpuset_t *cpuset)
{
	/* Workaround for the lack of a GetThreadAffinityMask()
	 *API in Windows
	 */
	DWORD_PTR dwprevaffinitymask;
	HANDLE thread_handle;
	DWORD_PTR ret;

	thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, threadid);
	if (thread_handle == NULL) {
		RTE_LOG_WIN32_ERR("OpenThread()");
		return -1;
	}

	/* obtain previous mask by setting dummy mask */
	dwprevaffinitymask = SetThreadAffinityMask(thread_handle, 0x1);
	if (dwprevaffinitymask == 0) {
		RTE_LOG_WIN32_ERR("SetThreadAffinityMask()");
		CloseHandle(thread_handle);
		return -1;
	}

	/* set it back! */
	ret = SetThreadAffinityMask(thread_handle, dwprevaffinitymask);
	if (ret == 0) {
		RTE_LOG_WIN32_ERR("SetThreadAffinityMask()");
		CloseHandle(thread_handle);
		return -1;
	}
	memset(cpuset, 0, sizeof(rte_cpuset_t));
	*cpuset->_bits = dwprevaffinitymask;
	CloseHandle(thread_handle);
	return 0;
}

static inline int
eal_create_thread(void *threadid, void *threadfunc, void *args)
{
	HANDLE hThread;
	hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)threadfunc,
		args, 0, (LPDWORD)threadid);
	if (hThread) {
		SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
		SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);
	}
	return ((hThread != NULL) ? 0 : E_FAIL);
}

static inline int
pthread_join(__rte_unused pthread_t thread,
	__rte_unused void **value_ptr)
{
	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* _PTHREAD_H_ */
