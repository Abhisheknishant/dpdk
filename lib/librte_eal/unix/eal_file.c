/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Dmitry Kozlyuk
 */

#include <sys/file.h>
#include <sys/mman.h>
#include <unistd.h>

#include <rte_errno.h>

#include "eal_private.h"

int
eal_file_create(const char *path)
{
	int ret;

	ret = open(path, O_CREAT | O_RDWR, 0600);
	if (ret < 0)
		rte_errno = errno;

	return ret;
}

int
eal_file_open(const char *path, bool writable)
{
	int ret, flags;

	flags = writable ? O_RDWR : O_RDONLY;
	ret = open(path, flags);
	if (ret < 0)
		rte_errno = errno;

	return ret;
}

int
eal_file_truncate(int fd, ssize_t size)
{
	int ret;

	ret = ftruncate(fd, size);
	if (ret)
		rte_errno = errno;

	return ret;
}

int
eal_file_lock(int fd, enum eal_flock_op op, enum eal_flock_mode mode)
{
	int sys_flags = 0;
	int ret;

	if (mode == EAL_FLOCK_RETURN)
		sys_flags |= LOCK_NB;

	switch (op) {
	case EAL_FLOCK_EXCLUSIVE:
		sys_flags |= LOCK_EX;
		break;
	case EAL_FLOCK_SHARED:
		sys_flags |= LOCK_SH;
		break;
	case EAL_FLOCK_UNLOCK:
		sys_flags |= LOCK_UN;
		break;
	}

	ret = flock(fd, sys_flags);
	if (ret)
		rte_errno = errno;

	return ret;
}
