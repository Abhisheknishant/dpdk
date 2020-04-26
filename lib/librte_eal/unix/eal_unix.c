/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Dmitry Kozlyuk
 */

#include <stdlib.h>

#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <rte_errno.h>

#include <eal_private.h>

const char *
eal_permanent_data_path(void)
{
	static const char *home_dir; /* static so auto-zeroed */

	struct passwd *pwd;

	if (home_dir != NULL)
		return home_dir;

	/* First check for shell environment variable */
	home_dir = getenv("HOME");
	if (home_dir == NULL) {
		/* Fallback to password file entry */
		pwd = getpwuid(getuid());
		if (pwd == NULL)
			return NULL;

		home_dir = pwd->pw_dir;
	}
	return home_dir;
}

int
eal_dir_create(const char *path)
{
	int ret = mkdir(path, 0700);
	if (ret)
		rte_errno = errno;
	return ret;
}
