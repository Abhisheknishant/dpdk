/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2019 Marvell International Ltd.
 */
#include <getopt.h>

#include <rte_eventmode_helper.h>
#include <rte_malloc.h>

#include "rte_eventmode_helper_internal.h"

#define CMD_LINE_OPT_TRANSFER_MODE	"transfer-mode"

static const char short_options[] =
	""
	;

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options
	 */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_TRANSFER_MODE_NUM,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_TRANSFER_MODE, 1, 0, CMD_LINE_OPT_TRANSFER_MODE_NUM},
	{NULL, 0, 0, 0}
};

/* Internal functions */

static int32_t
internal_parse_decimal(const char *str)
{
	char *end = NULL;
	unsigned long num;

	num = strtoul(str, &end, 10);
	if ((str[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	return num;
}

/* Global functions */

void __rte_experimental
rte_eventmode_helper_print_options_list(void)
{
	fprintf(stderr, " --"
		" [--transfer-mode MODE]"
		);
}

void __rte_experimental
rte_eventmode_helper_print_options_description(void)
{
	fprintf(stderr,
		"  --transfer-mode MODE\n"
		"               0: Packet transfer via polling (default)\n"
		"               1: Packet transfer via eventdev\n"
		"\n");
}

static int
em_parse_transfer_mode(struct rte_eventmode_helper_conf *conf,
		const char *optarg)
{
	int32_t parsed_dec;

	parsed_dec = internal_parse_decimal(optarg);
	if (parsed_dec != RTE_EVENTMODE_HELPER_PKT_TRANSFER_MODE_POLL &&
	    parsed_dec != RTE_EVENTMODE_HELPER_PKT_TRANSFER_MODE_EVENT) {
		RTE_EM_HLPR_LOG_ERR("Unsupported packet transfer mode");
		return -1;
	}
	conf->mode = parsed_dec;
	return 0;
}

static void
em_initialize_helper_conf(struct rte_eventmode_helper_conf *conf)
{
	/* Set default conf */

	/* Packet transfer mode: poll */
	conf->mode = RTE_EVENTMODE_HELPER_PKT_TRANSFER_MODE_POLL;
}

struct rte_eventmode_helper_conf *
rte_eventmode_helper_parse_args(int argc, char **argv)
{
	int32_t opt, ret;
	struct rte_eventmode_helper_conf *conf = NULL;

	/* Allocate memory for conf */
	conf = rte_zmalloc("eventmode-helper-conf",
			sizeof(struct rte_eventmode_helper_conf),
			RTE_CACHE_LINE_SIZE);
	if (conf == NULL) {
		RTE_EM_HLPR_LOG_ERR(
			"Failed allocating memory for eventmode helper conf");
			goto err;
	}

	/* Initialize conf with default values */
	em_initialize_helper_conf(conf);

	while ((opt = getopt_long(argc, argv, short_options,
				lgopts, NULL)) != EOF) {
		switch (opt) {

		/* Packet transfer mode */
		case CMD_LINE_OPT_TRANSFER_MODE_NUM:
			ret = em_parse_transfer_mode(conf, optarg);
			if (ret < 0) {
				RTE_EM_HLPR_LOG_ERR(
					"Invalid packet transfer mode");
				goto err;
			}
			break;
		default:
			goto err;
		}
	}
	return conf;

err:
	if (conf != NULL)
		rte_free(conf);

	return NULL;
}
