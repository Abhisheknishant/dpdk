/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

/**
 * @file
 * Stores functions and path defines for files and directories
 * on the filesystem for Windows, that are used by the Windows EAL.
 */

#ifndef EAL_FILESYSTEM_H
#define EAL_FILESYSTEM_H

#include "eal_internal_cfg.h"

/* sets up platform-specific runtime data dir */
int
eal_create_runtime_dir(void);

/* returns runtime dir */
const char *
eal_get_runtime_dir(void);

/* define the default filename prefix for the %s values below */
#define HUGEFILE_PREFIX_DEFAULT "rte"

/** Path of rte config file */
#define RUNTIME_CONFIG_FMT "%s\\%s.config"

static inline const char *
eal_runtime_config_path(void)
{
	static char buffer[PATH_MAX];  /* static so auto-zeroed */
	char  Directory[PATH_MAX];

	GetTempPathA(sizeof(Directory), Directory);
	snprintf(buffer, sizeof(buffer)-1, RUNTIME_CONFIG_FMT, Directory,
		internal_config.hugefile_prefix);

	return buffer;
}

/* Path of file backed array */
#define FBARRAY_NAME_FMT "%s\\fbarray_%s"

static inline const char *
eal_get_fbarray_path(char *buffer, size_t buflen, const char *name) {
	snprintf(buffer, buflen, FBARRAY_NAME_FMT, eal_get_runtime_dir(), name);
	return buffer;
}

/* Path of primary/secondary communication unix socket file. */
#define MP_SOCKET_FNAME "mp_socket"

static inline const char *
eal_mp_socket_path(void)
{
	static char buffer[PATH_MAX]; /* static so auto-zeroed */

	snprintf(buffer, sizeof(buffer) - 1, "%s/%s", eal_get_runtime_dir(),
		MP_SOCKET_FNAME);
	return buffer;
}

/** Path of hugepage info file */
#define HUGEPAGE_INFO_FMT "%s\\.%s_hugepage_info"

static inline const char *
eal_hugepage_info_path(void)
{
	static char buffer[PATH_MAX];  /* static so auto-zeroed */
	TCHAR  Directory[PATH_MAX];

	GetSystemDirectory(Directory, sizeof(Directory));
	snprintf(buffer, sizeof(buffer)-1, HUGEPAGE_INFO_FMT, Directory,
		internal_config.hugefile_prefix);
	return buffer;
}

/** String format for hugepage map files */
#define HUGEFILE_FMT "%s/%smap_%d"
#define TEMP_HUGEFILE_FMT "%s/%smap_temp_%d"

static inline const char *
eal_get_hugefile_path(char *buffer, size_t buflen, const char *hugedir,
	int f_id)
{
	snprintf(buffer, buflen, HUGEFILE_FMT, hugedir,
		internal_config.hugefile_prefix, f_id);
	buffer[buflen - 1] = '\0';
	return buffer;
}

/** Function to read a single numeric value from a file on the filesystem.
 * Used to read information from files on /sys
 */
int eal_parse_sysfs_value(const char *filename, unsigned long *val);

#endif /* EAL_FILESYSTEM_H */
