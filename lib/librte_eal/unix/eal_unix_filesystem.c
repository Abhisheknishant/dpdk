/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Dmitry Kozlyuk
 */

#include <stdlib.h>

#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <rte_errno.h>

#include <eal_filesystem.h>

const char *
eal_permanent_data_path(void)
{
	static char path[PATH_MAX]; /* static so auto-zeroed */

	const char *home_dir;
	struct passwd *pwd;

	if (path[0] != '\0')
		return path;

	/* First check for shell environment variable */
	home_dir = getenv("HOME");
	if (home_dir == NULL) {
		/* Fallback to password file entry */
		pwd = getpwuid(getuid());
		if (pwd == NULL)
			return NULL;

		home_dir = pwd->pw_dir;
	}

	if (strlen(home_dir) >= sizeof(path))
		return NULL;

	strncpy(path, home_dir, sizeof(path));
	return path;
}

int
eal_dir_create(const char *path)
{
	int ret = mkdir(path, 0700);
	if (ret)
		rte_errno = errno;
	return ret;
}
