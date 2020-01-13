/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#ifndef _DLFCN_H_
#define _DLFCN_H_

/**
 * This file is added to support common code in eal_common_options.c
 * as Microsoft libc does not contain dlfcn.h. This may be removed
 * in future releases.
 */

/* The windows port does not currently support dynamic loading of libraries,
 * so fail these calls
 */
#define dlopen(lib, flag)   (0)
#define RTLD_NOW 0
#define dlerror()           ("Not supported!")

#endif /* _DLFCN_H_ */
