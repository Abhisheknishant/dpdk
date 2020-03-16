/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (C) 2015-2016 Freescale Semiconductor,Inc.
 * Copyright 2018-2019 NXP
 */

#ifndef TEST_RAWDEV_MULTI_FN_TEST_VECTORS_H_
#define TEST_RAWDEV_MULTI_FN_TEST_VECTORS_H_

#include <stdbool.h>

struct docsis_test_data {
	struct {
		uint8_t data[16];
		unsigned int len;
	} key;

	struct {
		uint8_t data[16] __rte_aligned(16);
		unsigned int len;
	} cipher_iv;

	struct {
		uint8_t data[1024];
		unsigned int len;
		unsigned int cipher_offset;
		unsigned int auth_offset;
		bool no_cipher;
		bool no_auth;
	} plaintext;

	struct {
		uint8_t data[1024];
		unsigned int len;
		unsigned int cipher_offset;
		unsigned int auth_offset;
		bool no_cipher;
		bool no_auth;
	} ciphertext;
};

struct docsis_test_data docsis_test_case_1 = {
	.key = {
		.data = {
			0x00, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD,
			0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55
		},
		.len = 16
	},
	.cipher_iv = {
		.data = {
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
		},
		.len = 16
	},
	.plaintext = {
		.data = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02,
			0x03, 0x04, 0x05, 0x06, 0x06, 0x05, 0x04, 0x03,
			0x02, 0x01, 0x08, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
		},
		.len = 24,
		.cipher_offset = 18,
		.auth_offset = 6,
		.no_cipher = false,
		.no_auth = false
	},
	.ciphertext = {
		.data = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02,
			0x03, 0x04, 0x05, 0x06, 0x06, 0x05, 0x04, 0x03,
			0x02, 0x01, 0x7A, 0xF0, 0x61, 0xF8, 0x63, 0x42
		},
		.len = 24,
		.cipher_offset = 18,
		.auth_offset = 6,
		.no_cipher = false,
		.no_auth = false
	}
};

#endif /* TEST_RAWDEV_MULTI_FN_TEST_VECTORS_H_ */
