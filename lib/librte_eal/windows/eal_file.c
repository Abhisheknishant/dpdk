/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Dmitry Kozlyuk
 */

#include <fcntl.h>
#include <io.h>
#include <share.h>
#include <sys/stat.h>

#include "eal_private.h"
#include "eal_windows.h"

int
eal_file_create(const char *path)
{
	int fd, ret;

	ret = _sopen_s(&fd, path, _O_CREAT | _O_RDWR, _SH_DENYNO, _S_IWRITE);
	if (ret) {
		rte_errno = ret;
		return -1;
	}

	return fd;
}

int
eal_file_open(const char *path, bool writable)
{
	int fd, ret, flags;

	flags = writable ? _O_RDWR : _O_RDONLY;
	ret = _sopen_s(&fd, path, flags, _SH_DENYNO, 0);
	if (ret < 0) {
		rte_errno = errno;
		return -1;
	}

	return fd;
}

int
eal_file_truncate(int fd, ssize_t size)
{
	HANDLE handle;
	DWORD ret;
	LONG low = (LONG)((size_t)size);
	LONG high = (LONG)((size_t)size >> 32);

	handle = (HANDLE)_get_osfhandle(fd);
	if (handle == INVALID_HANDLE_VALUE) {
		rte_errno = EBADF;
		return -1;
	}

	ret = SetFilePointer(handle, low, &high, FILE_BEGIN);
	if (ret == INVALID_SET_FILE_POINTER) {
		RTE_LOG_WIN32_ERR("SetFilePointer()");
		rte_errno = EINVAL;
		return -1;
	}

	return 0;
}

static int
lock_file(HANDLE handle, enum eal_flock_op op, enum eal_flock_mode mode)
{
	DWORD sys_flags = 0;
	OVERLAPPED overlapped;

	if (op == EAL_FLOCK_EXCLUSIVE)
		sys_flags |= LOCKFILE_EXCLUSIVE_LOCK;
	if (mode == EAL_FLOCK_RETURN)
		sys_flags |= LOCKFILE_FAIL_IMMEDIATELY;

	memset(&overlapped, 0, sizeof(overlapped));
	if (!LockFileEx(handle, sys_flags, 0, 0, 0, &overlapped)) {
		if ((sys_flags & LOCKFILE_FAIL_IMMEDIATELY) &&
			(GetLastError() == ERROR_IO_PENDING)) {
			rte_errno = EWOULDBLOCK;
		} else {
			RTE_LOG_WIN32_ERR("LockFileEx()");
			rte_errno = EINVAL;
		}
		return -1;
	}

	return 0;
}

static int
unlock_file(HANDLE handle)
{
	if (!UnlockFileEx(handle, 0, 0, 0, NULL)) {
		RTE_LOG_WIN32_ERR("UnlockFileEx()");
		rte_errno = EINVAL;
		return -1;
	}
	return 0;
}

int
eal_file_lock(int fd, enum eal_flock_op op, enum eal_flock_mode mode)
{
	HANDLE handle = (HANDLE)_get_osfhandle(fd);

	if (handle == INVALID_HANDLE_VALUE) {
		rte_errno = EBADF;
		return -1;
	}

	switch (op) {
	case EAL_FLOCK_EXCLUSIVE:
	case EAL_FLOCK_SHARED:
		return lock_file(handle, op, mode);
	case EAL_FLOCK_UNLOCK:
		return unlock_file(handle);
	default:
		rte_errno = EINVAL;
		return -1;
	}
}
