/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#include <rte_string_fns.h>
#include <rte_ipsec_sad.h>
#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_ip.h>
#include <rte_random.h>
#include <rte_malloc.h>
#include <rte_ipsec_sad.h>

#define	PRINT_USAGE_START	"%s [EAL options] --\n"

#define GET_CB_FIELD(in, fd, base, lim, dlm)	do {		\
	unsigned long val;					\
	char *end_fld;						\
	errno = 0;						\
	val = strtoul((in), &end_fld, (base));			\
	if (errno != 0 || end_fld[0] != (dlm) || val > (lim))	\
		return -EINVAL;					\
	(fd) = (typeof(fd))val;					\
	(in) = end_fld + 1;					\
} while (0)

#define	DEF_RULE_NUM		0x10000
#define	DEF_TUPLES_NUM	0x100000

static struct {
	const char	*prgname;
	const char	*rules_file;
	const char	*tuples_file;
	uint32_t	nb_rules;
	uint32_t	nb_tuples;
	uint32_t	nb_rules_32;
	uint32_t	nb_rules_64;
	uint32_t	nb_rules_96;
	uint32_t	nb_tuples_rnd;
	uint8_t		fract_32;
	uint8_t		fract_64;
	uint8_t		fract_96;
	uint8_t		fract_rnd_tuples;
} config = {
	.rules_file = NULL,
	.tuples_file = NULL,
	.nb_rules = DEF_RULE_NUM,
	.nb_tuples = DEF_TUPLES_NUM,
	.nb_rules_32 = 0,
	.nb_rules_64 = 0,
	.nb_rules_96 = 0,
	.nb_tuples_rnd = 0,
	.fract_32 = 90,
	.fract_64 = 9,
	.fract_96 = 1,
	.fract_rnd_tuples = 0
};

enum {
	CB_RULE_SPI,
	CB_RULE_DIP,
	CB_RULE_SIP,
	CB_RULE_LEN,
	CB_RULE_NUM,
};

static char line[LINE_MAX];
struct rule {
	struct rte_ipsec_sadv4_key tuple;
	int rule_type;
};

static struct rule *rules_tbl;
static struct rule *tuples_tbl;

static int
parse_distrib(const char *in)
{
	int a, b, c;

	GET_CB_FIELD(in, a, 0, UINT8_MAX, '/');
	GET_CB_FIELD(in, b, 0, UINT8_MAX, '/');
	GET_CB_FIELD(in, c, 0, UINT8_MAX, 0);

	if ((a + b + c) != 100)
		return -EINVAL;

	config.fract_32 = a;
	config.fract_64 = b;
	config.fract_96 = c;

	return 0;
}

static void
print_config(void)
{
	fprintf(stdout,
		"Rules total: %u\n"
		"Configured rules distribution SPI/SPI_DIP/SIP_DIP_SIP:"
		"%u/%u/%u\n"
		"SPI only rules: %u\n"
		"SPI_DIP  rules: %u\n"
		"SPI_DIP_SIP rules: %u\n"
		"Lookup tuples: %u\n"
		"Configured fraction of random tuples: %u\n"
		"Random lookup tuples: %u\n",
		config.nb_rules, config.fract_32, config.fract_64,
		config.fract_96, config.nb_rules_32, config.nb_rules_64,
		config.nb_rules_96, config.nb_tuples, config.fract_rnd_tuples,
		config.nb_tuples_rnd);
}

static void
print_usage(void)
{
	fprintf(stdout,
		PRINT_USAGE_START
		"[-f <rules file>]\n"
		"[-t <tuples file for lookup>]\n"
		"[-n <rules number (if -f is not specified)>]\n"
		"[-l <lookup tuples number (if -t is not specified)>]\n"
		"[-d <\"/\" separated rules length distribution"
		"(if -f is not specified)>]\n"
		"[-r <random tuples fraction to lookup"
		"(if -t is not specified)>]\n",
		config.prgname);

}

static int
get_str_num(FILE *f, int num)
{
	int n_lines = 0;

	if (f != NULL) {
		while (fgets(line, sizeof(line), f) != NULL)
			n_lines++;
		rewind(f);
	} else {
		n_lines = num;
	}
	return n_lines;
}

static int
parse_file(FILE *f, struct rule *tbl, int rule_tbl)
{
	int ret, i, j = 0;
	char *s, *sp, *in[CB_RULE_NUM];
	static const char *dlm = " \t\n";
	int string_tok_nb = RTE_DIM(in);

	string_tok_nb -= (rule_tbl == 0) ? 1 : 0;
	while (fgets(line, sizeof(line), f) != NULL) {
		s = line;
		for (i = 0; i != string_tok_nb; i++) {
			in[i] = strtok_r(s, dlm, &sp);
			if (in[i] == NULL)
				return -EINVAL;
			s = NULL;
		}
		GET_CB_FIELD(in[CB_RULE_SPI], tbl[j].tuple.spi, 0,
				UINT32_MAX, 0);

		ret = inet_pton(AF_INET, in[CB_RULE_DIP], &tbl[j].tuple.dip);
		if (ret != 1)
			return -EINVAL;
		ret = inet_pton(AF_INET, in[CB_RULE_SIP], &tbl[j].tuple.sip);
		if (ret != 1)
			return -EINVAL;
		if ((rule_tbl) && (in[CB_RULE_LEN] != NULL)) {
			if (strcmp(in[CB_RULE_LEN], "SPI_DIP_SIP") == 0) {
				tbl[j].rule_type = RTE_IPSEC_SAD_SPI_DIP_SIP;
				config.nb_rules_96++;
			} else if (strcmp(in[CB_RULE_LEN], "SPI_DIP") == 0) {
				tbl[j].rule_type = RTE_IPSEC_SAD_SPI_DIP;
				config.nb_rules_64++;
			} else if (strcmp(in[CB_RULE_LEN], "SPI") == 0) {
				tbl[j].rule_type = RTE_IPSEC_SAD_SPI_ONLY;
				config.nb_rules_32++;
			} else {
				return -EINVAL;
			}
		}
		j++;
	}
	return 0;
}

static void
get_random_rules(struct rule *tbl, uint32_t nb_rules, int rule_tbl)
{
	unsigned i, rnd;
	int rule_type;

	for (i = 0; i < nb_rules; i++) {
		rnd = rte_rand() % 100;
		if (rule_tbl) {
			tbl[i].tuple.spi = rte_rand();
			tbl[i].tuple.dip = rte_rand();
			tbl[i].tuple.sip = rte_rand();
			if (rnd >= (100UL - config.fract_32)) {
				rule_type = RTE_IPSEC_SAD_SPI_ONLY;
				config.nb_rules_32++;
			} else if (rnd >= (100UL - (config.fract_32 +
					config.fract_64))) {
				rule_type = RTE_IPSEC_SAD_SPI_DIP;
				config.nb_rules_64++;
			} else {
				rule_type = RTE_IPSEC_SAD_SPI_DIP_SIP;
				config.nb_rules_96++;
			}
			tbl[i].rule_type = rule_type;
		} else {
			if (rnd >= 100UL - config.fract_rnd_tuples) {
				tbl[i].tuple.spi = rte_rand();
				tbl[i].tuple.dip = rte_rand();
				tbl[i].tuple.sip = rte_rand();
				config.nb_tuples_rnd++;
			} else {
				tbl[i].tuple.spi = rules_tbl[i %
					config.nb_rules].tuple.spi;
				tbl[i].tuple.dip = rules_tbl[i %
					config.nb_rules].tuple.dip;
				tbl[i].tuple.sip = rules_tbl[i %
					config.nb_rules].tuple.sip;
			}
		}
	}
}

static void
tbl_init(struct rule **tbl, uint32_t *n_entries,
	const char *file_name, int rule_tbl)
{
	FILE *f = NULL;
	int ret;
	const char *rules = "rules";
	const char *tuples = "tuples";

	if (file_name != NULL) {
		f = fopen(file_name, "r");
		if (f == NULL)
			rte_exit(-EINVAL, "failed to open file: %s\n",
				file_name);
	}

	printf("init %s table...", (rule_tbl) ? rules : tuples);
	*n_entries = get_str_num(f, *n_entries);
	printf("%d entries\n", *n_entries);
	*tbl = rte_zmalloc(NULL, sizeof(struct rule) * *n_entries,
		RTE_CACHE_LINE_SIZE);
	if (*tbl == NULL)
		rte_exit(-ENOMEM, "failed to allocate tbl\n");

	if (f != NULL) {
		printf("parse file %s\n", file_name);
		ret = parse_file(f, *tbl, rule_tbl);
		if (ret != 0)
			rte_exit(-EINVAL, "failed to parse file %s\n"
				"rules file must be: "
				"<uint32_t: spi> <space> "
				"<ip_addr: dip> <space> "
				"<ip_addr: sip> <space> "
				"<string: SPI|SPI_DIP|SIP_DIP_SIP>\n"
				"tuples file must be: "
				"<uint32_t: spi> <space> "
				"<ip_addr: dip> <space> "
				"<ip_addr: sip>\n",
				file_name);
	} else {
		printf("generate random values in %s table\n",
			(rule_tbl) ? rules : tuples);
		get_random_rules(*tbl, *n_entries, rule_tbl);
	}
	if (f != NULL)
		fclose(f);
}

static void
parse_opts(int argc, char **argv)
{
	int opt, ret;
	char *endptr;

	while ((opt = getopt(argc, argv, "f:t:n:d:l:r:")) != -1) {
		switch (opt) {
		case 'f':
			config.rules_file = optarg;
			break;
		case 't':
			config.tuples_file = optarg;
			break;
		case 'n':
			errno = 0;
			config.nb_rules = strtoul(optarg, &endptr, 10);
			if ((errno != 0) || (config.nb_rules == 0)) {
				print_usage();
				rte_exit(-EINVAL, "Invalid option -n\n");
			}
			break;
		case 'd':
			ret = parse_distrib(optarg);
			if (ret != 0) {
				print_usage();
				rte_exit(-EINVAL, "Invalid option -d\n");
			}
			break;
		case 'l':
			errno = 0;
			config.nb_tuples = strtoul(optarg, &endptr, 10);
			if ((errno != 0) || (config.nb_tuples == 0)) {
				print_usage();
				rte_exit(-EINVAL, "Invalid option -l\n");
			}
			break;
		case 'r':
			errno = 0;
			config.fract_rnd_tuples = strtoul(optarg, &endptr, 10);
			if ((errno != 0) || (config.fract_rnd_tuples == 0) ||
					(config.fract_rnd_tuples >= 100)) {
				print_usage();
				rte_exit(-EINVAL, "Invalid option -r\n");
			}
			break;
		default:
			print_usage();
			rte_exit(-EINVAL, "Invalid options\n");
		}
	}
}

#define BURST_SZ	64
static void
lookup(struct rte_ipsec_sad *sad)
{
	int ret, j;
	unsigned i;
	const union rte_ipsec_sad_key *keys[BURST_SZ];
	void *vals[BURST_SZ];
	uint64_t start, acc = 0;

	for (i = 0; i < config.nb_tuples; i += BURST_SZ) {
		for (j = 0; j < BURST_SZ; j++)
			keys[j] = (union rte_ipsec_sad_key *)
				(&tuples_tbl[i + j].tuple);
		start = rte_rdtsc();
		ret = rte_ipsec_sad_lookup(sad, keys, BURST_SZ, vals);
		acc += rte_rdtsc() - start;
		if (ret < 0)
			rte_exit(-EINVAL, "Lookup failed\n");
	}
	printf("Average lookup cycles %lu\n", acc / config.nb_tuples);
}

int
main(int argc, char **argv)
{
	int ret;
	unsigned i;
	struct rte_ipsec_sad *sad;
	struct rte_ipsec_sad_conf conf;
	uint64_t start;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	argc -= ret;
	argv += ret;

	config.prgname = argv[0];

	parse_opts(argc, argv);
	tbl_init(&rules_tbl, &config.nb_rules, config.rules_file, 1);
	tbl_init(&tuples_tbl, &config.nb_tuples, config.tuples_file, 0);
	if (config.rules_file != NULL) {
		config.fract_32 = (100 * config.nb_rules_32) / config.nb_rules;
		config.fract_64 = (100 * config.nb_rules_64) / config.nb_rules;
		config.fract_96 = (100 * config.nb_rules_96) / config.nb_rules;
	}
	if (config.tuples_file != NULL) {
		config.fract_rnd_tuples = 0;
		config.nb_tuples_rnd = 0;
	}
	conf.socket_id = -1;
	conf.max_sa[RTE_IPSEC_SAD_SPI_ONLY] = config.nb_rules * 2;
	conf.max_sa[RTE_IPSEC_SAD_SPI_DIP] = config.nb_rules * 2;
	conf.max_sa[RTE_IPSEC_SAD_SPI_DIP_SIP] = config.nb_rules * 2;
	conf.flags = RTE_IPSEC_SAD_FLAG_IPV4|RTE_IPSEC_SAD_FLAG_RW_CONCURRENCY;
	sad = rte_ipsec_sad_create("test", &conf);
	if (sad == NULL)
		rte_exit(-rte_errno, "can not allocate SAD table\n");

	print_config();

	start = rte_rdtsc();
	for (i = 0; i < config.nb_rules; i++) {
		ret = rte_ipsec_sad_add(sad,
			(union rte_ipsec_sad_key *)&rules_tbl[i].tuple,
			rules_tbl[i].rule_type, &rules_tbl[i]);
		if (ret != 0)
			rte_exit(ret, "can not add rule to SAD table\n");
	}
	printf("Average ADD cycles: %lu\n",
		(rte_rdtsc() - start) / config.nb_rules);

	lookup(sad);

	return 0;
}
