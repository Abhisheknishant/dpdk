/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Dmitry Kozlyuk
 */

#ifndef _RTE_WINDOWS_H_
#define _RTE_WINDOWS_H_

/**
 * @file Windows-specific facilities
 *
 * This file should be included by DPDK libraries and applications
 * that need access to Windows API. It includes platform SDK headers
 * in compatible order and with proper options.
 *
 * Future versions may include macros for Windows-specific error handling.
 */

#define WIN32_LEAN_AND_MEAN /* Disable excessive libraries. */
#define INITGUID            /* Have GUIDs defined. */

#include <windows.h>
#include <basetsd.h>

#endif /* _RTE_WINDOWS_H_ */
