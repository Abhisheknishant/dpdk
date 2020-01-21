/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2019 Advanced Micro Devices, Inc. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cryptodev.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_interrupts.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#ifdef RTE_LIBRTE_PMD_CRYPTO_SCHEDULER
#include <rte_cryptodev_scheduler.h>
#endif

#define MAX_STR_LEN 32
#define MAX_KEY_SIZE 512
#define MAX_PT_SIZE 65535
#define MAX_IV_SIZE 256
#define MAX_AAD_SIZE 65535
#define MAX_DIGEST_SIZE 16
#define SESSION_POOL_CACHE_SIZE 0
#define IV_OFFSET		(sizeof(struct rte_crypto_op) + \
				sizeof(struct rte_crypto_sym_op))
#define BURST_SIZE           1
#define BUFFER_SIZE          64
#define NUM_MBUFS            1024
#define POOL_CACHE_SIZE      128

#define AES_CBC_IV_LENGTH    16
#define AES_CBC_KEY_LENGTH   16

#define SHA_DIGEST_LENGTH 20
#define SHA224_DIGEST_LENGTH    28
#define SHA256_DIGEST_LENGTH    32
#define SHA384_DIGEST_LENGTH    48
#define SHA512_DIGEST_LENGTH    64


enum cdev_type {
	CDEV_TYPE_ANY,
	CDEV_TYPE_HW,
	CDEV_TYPE_SW
};

struct cdev_iv {
	uint8_t *data;
	uint16_t length;
};
struct cdev_aad_key {
	uint8_t *data;
	uint16_t length;
};
struct cdev_aad_digest {
	uint8_t *data;
	uint16_t length;
};

/** crypto application command line options */
struct ccp_crypto_options {
	enum cdev_type type;
	unsigned int crypto_op_private_data;

	struct rte_crypto_sym_xform cipher_xform;
	struct cdev_iv cipher_iv;
	uint8_t cipher_key[MAX_KEY_SIZE];

	struct rte_crypto_sym_xform auth_xform;
	uint8_t auth_key[MAX_KEY_SIZE];

	struct rte_crypto_sym_xform aead_xform;
	struct cdev_iv aead_iv;
	struct cdev_aad_key aad;
	uint8_t aead_key[MAX_KEY_SIZE];
	struct cdev_aad_digest aad_digest;
	int digest_size;

	char string_type[MAX_STR_LEN];
};
uint8_t *pt;
int pt_length;
struct rte_mempool *session_pool_socket[RTE_MAX_NUMA_NODES] = { 0 };
int buffer_size = BUFFER_SIZE;

/* Display command line arguments usage */
static void
ccp_crypto_usage(const char *prgname)
{
	printf("%s [EAL options] --\n"
	"  --cdev_type HW / SW / ANY\n"
	"  --cipher_op ENCRYPT / DECRYPT\n"
	"  --cipher_algo ALGO\n"
	"  --plain_text  (bytes separated with \":\")\n"
	"  --cipher_key KEY (bytes separated with \":\")\n"
	"  --cipher_iv  (bytes separated with \":\")\n"
	"  --auth_op GENERATE / VERIFY\n"
	"  --auth_algo ALGO\n"
	"  --auth_key KEY (bytes separated with \":\")\n"
	"  --aead_algo ALGO\n"
	"  --aead_op ENCRYPT / DECRYPT\n"
	"  --aead_key KEY (bytes separated with \":\")\n"
	"  --aead_iv IV (bytes separated with \":\")\n"
	"  --aad AAD (bytes separated with \":\")\n"
	"  --digest (16-bytes separated with \":\")\n",
	prgname);
}

/** Parse crypto device type command line argument */
static int
parse_cryptodev_type(enum cdev_type *type, char *optarg)
{
	if (strcmp("HW", optarg) == 0) {
		*type = CDEV_TYPE_HW;
		return 0;
	} else if (strcmp("SW", optarg) == 0) {
		*type = CDEV_TYPE_SW;
		return 0;
	} else if (strcmp("ANY", optarg) == 0) {
		*type = CDEV_TYPE_ANY;
		return 0;
	}
	return -1;
}

/** Parse crypto cipher operation command line argument */
static int
parse_cipher_op(enum rte_crypto_cipher_operation *op, char *optarg)
{
	if (strcmp("ENCRYPT", optarg) == 0) {
		*op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
		return 0;
	} else if (strcmp("DECRYPT", optarg) == 0) {
		*op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
		return 0;
	}
	printf("Cipher operation not supported!\n");
	return -1;
}

/** Parse crypto cipher algo option command line argument */
static int
parse_cipher_algo(enum rte_crypto_cipher_algorithm *algo, char *optarg)
{
	if (rte_cryptodev_get_cipher_algo_enum(algo, optarg) < 0) {
		printf("Cipher algorithm specified not supported!\n");
	return -1;
	}
	return 0;
}
/** Parse bytes from command line argument */
static int
parse_bytes(uint8_t *data, char *input_arg, uint16_t max_size)
{
	int byte_count;
	char *token;

	errno = 0;
	for (byte_count = 0, token = strtok(input_arg, ":");
		(byte_count < max_size) && (token != NULL);
		token = strtok(NULL, ":")) {
		int number = (int)strtol(token, NULL, 16);
		if (errno == EINVAL || errno == ERANGE || number > 0xFF)
			return -1;
		data[byte_count++] = (uint8_t)number;
	}
	return byte_count;
}

/** Parse crypto cipher operation command line argument */
static int
parse_auth_algo(enum rte_crypto_auth_algorithm *algo, char *optarg)
{
	if (rte_cryptodev_get_auth_algo_enum(algo, optarg) < 0) {
		printf("Authentication algorithm specified not supported!\n");
		return -1;
	}
	return 0;
}

static int
parse_auth_op(enum rte_crypto_auth_operation *op, char *optarg)
{
	if (strcmp("VERIFY", optarg) == 0) {
		*op = RTE_CRYPTO_AUTH_OP_VERIFY;
		return 0;
	} else if (strcmp("GENERATE", optarg) == 0) {
		*op = RTE_CRYPTO_AUTH_OP_GENERATE;
		return 0;
	}
	printf("Authentication operation specified not supported!\n");
	return -1;
}

static int
parse_aead_algo(enum rte_crypto_aead_algorithm *algo, char *optarg)
{
	if (rte_cryptodev_get_aead_algo_enum(algo, optarg) < 0) {
		printf("AEAD algorithm specified not supported!\n");
		return -1;
	}
	return 0;
}

static int
parse_aead_op(enum rte_crypto_aead_operation *op, char *optarg)
{
	if (strcmp("ENCRYPT", optarg) == 0) {
		*op = RTE_CRYPTO_AEAD_OP_ENCRYPT;
		return 0;
	} else if (strcmp("DECRYPT", optarg) == 0) {
		*op = RTE_CRYPTO_AEAD_OP_DECRYPT;
		return 0;
	}
	printf("AEAD operation specified not supported!\n");
	return -1;
}

/** Parse long options */
static int
ccp_crypto_parse_args_long_options(struct ccp_crypto_options *options,
		struct option *lgopts, int option_index)
{
	int retval;

	if (strcmp(lgopts[option_index].name, "cdev_type") == 0) {
		retval = parse_cryptodev_type(&options->type, optarg);
		if (retval == 0)
			snprintf(options->string_type, MAX_STR_LEN,
				"%s", optarg);
		return retval;
	} else if (strcmp(lgopts[option_index].name, "plain_text") == 0) {
		pt_length =
			parse_bytes(pt, optarg, MAX_PT_SIZE);
		buffer_size = pt_length;
		if (pt_length > 0)
			return 0;
		else
			return -1;
	} else if (strcmp(lgopts[option_index].name, "cipher_op") == 0)
		return parse_cipher_op(&options->cipher_xform.cipher.op,
			optarg);
	else if (strcmp(lgopts[option_index].name, "cipher_algo") == 0)
		return parse_cipher_algo(&options->cipher_xform.cipher.algo,
			optarg);
	else if (strcmp(lgopts[option_index].name, "cipher_key") == 0) {
		options->cipher_xform.cipher.key.length =
		parse_bytes(options->cipher_key, optarg, MAX_KEY_SIZE);
		if (options->cipher_xform.cipher.key.length > 0)
			return 0;
		else
			return -1;
	} else if (strcmp(lgopts[option_index].name, "cipher_iv") == 0) {
		options->cipher_iv.length =
			parse_bytes(options->cipher_iv.data,
					optarg, MAX_IV_SIZE);
		options->cipher_xform.cipher.iv.length =
			options->cipher_iv.length;
		options->cipher_xform.cipher.iv.offset =  IV_OFFSET;
		if (options->cipher_iv.length > 0)
			return 0;
		else
			return -1;
	}

	/* Authentication options */
	else if (strcmp(lgopts[option_index].name, "auth_op") == 0)
		return parse_auth_op(&options->auth_xform.auth.op,
					optarg);
	else if (strcmp(lgopts[option_index].name, "auth_algo") == 0) {
		return parse_auth_algo(&options->auth_xform.auth.algo,
					optarg);
	} else if (strcmp(lgopts[option_index].name, "auth_key") == 0) {
		options->auth_xform.auth.key.length =
			parse_bytes(options->auth_key, optarg, MAX_KEY_SIZE);
		if (options->auth_xform.auth.key.length > 0)
			return 0;
		else
			return -1;
	}
	/* AEAD options */
	else if (strcmp(lgopts[option_index].name, "aead_algo") == 0) {
		return parse_aead_algo(&options->aead_xform.aead.algo,
					optarg);
	} else if (strcmp(lgopts[option_index].name, "aead_op") == 0)
		return parse_aead_op(&options->aead_xform.aead.op,
					optarg);
	else if (strcmp(lgopts[option_index].name, "aead_key") == 0) {
		options->aead_xform.aead.key.length =
			parse_bytes(options->aead_key, optarg, MAX_KEY_SIZE);
		if (options->aead_xform.aead.key.length > 0)
			return 0;
		else
			return -1;
	} else if (strcmp(lgopts[option_index].name, "aead_iv") == 0) {
		options->aead_iv.length =
			parse_bytes(options->aead_iv.data,
					optarg, MAX_IV_SIZE);
		options->aead_xform.aead.iv.length = options->aead_iv.length;
		options->aead_xform.aead.iv.offset =  IV_OFFSET;
		if (options->aead_xform.aead.iv.length > 0)
			return 0;
		else
			return -1;
	} else if (strcmp(lgopts[option_index].name, "aad") == 0) {
		options->aad.length =
			parse_bytes(options->aad.data, optarg, MAX_AAD_SIZE);
		options->aead_xform.aead.aad_length = options->aad.length;
		if (options->aad.length > 0)
			return 0;
		else
			return -1;
	} else if (strcmp(lgopts[option_index].name, "digest") == 0) {
		options->digest_size =
			parse_bytes(options->aad_digest.data,
					optarg, MAX_DIGEST_SIZE);
		options->aead_xform.aead.digest_length = options->digest_size;
		if (options->digest_size > 0)
			return 0;
		else
			return -1;
	}
	return -1;
}

static void
ccp_crypto_default_options(struct ccp_crypto_options *options)
{
	options->type = CDEV_TYPE_ANY;
	options->crypto_op_private_data = AES_CBC_IV_LENGTH;

	/* Cipher Data */
	options->cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	options->cipher_xform.next = NULL;
	options->cipher_xform.cipher.key.length = 0;
	options->cipher_xform.cipher.algo = RTE_CRYPTO_CIPHER_AES_CBC;
	options->cipher_xform.cipher.op = -1;
	options->cipher_xform.cipher.iv.offset = IV_OFFSET;
	options->cipher_xform.cipher.iv.length = AES_CBC_IV_LENGTH;

	 /* Authentication Data */
	options->auth_xform.type = RTE_CRYPTO_SYM_XFORM_AUTH;
	options->auth_xform.next = NULL;
	options->auth_xform.auth.key.length = 20;
	options->auth_xform.auth.digest_length = 20;
	options->auth_xform.auth.algo = RTE_CRYPTO_AUTH_SHA1_HMAC;
	options->auth_xform.auth.op = -1;

	/* AEAD Data */
	options->aead_xform.type = RTE_CRYPTO_SYM_XFORM_AEAD;
	options->aead_xform.next = NULL;
	options->aead_xform.aead.key.length = 0;
	options->aead_xform.aead.digest_length = 0;
	options->aead_iv.length = 16;
	options->aead_xform.aead.iv.offset =  IV_OFFSET;
	options->aead_xform.aead.algo = RTE_CRYPTO_AEAD_AES_GCM;
	options->aead_xform.aead.op = -1;
	options->aad.length = 0;
	options->digest_size = -1;
}

static int
ccp_crypto_parse_args(struct ccp_crypto_options *options,
	int argc, char **argv)
{
	int opt, retval, option_index;
	char **argvopt = argv, *prgname = argv[0];

	static struct option lgopts[] = {
		{ "cdev_type", required_argument, 0, 0 },
		{ "cipher_op", required_argument, 0, 0 },
		{ "cipher_algo", required_argument, 0, 0 },
		{ "plain_text", required_argument, 0, 0 },
		{ "cipher_key", required_argument, 0, 0 },
		{ "cipher_iv", required_argument, 0, 0 },

		{ "auth_op", required_argument, 0, 0 },
		{ "auth_algo", required_argument, 0, 0 },
		{ "auth_key", required_argument, 0, 0 },

		{ "aead_algo", required_argument, 0, 0 },
		{ "aead_op", required_argument, 0, 0 },
		{ "aead_key", required_argument, 0, 0 },
		{ "aead_iv", required_argument, 0, 0 },
		{ "aad", required_argument, 0, 0 },
		{ "digest", required_argument, 0, 0 },

		{ NULL, 0, 0, 0 }
	};

	ccp_crypto_default_options(options);

	while ((opt = getopt_long(argc, argvopt, "ac:", lgopts,
			&option_index)) != EOF) {
		switch (opt) {
		case 0:
			retval = ccp_crypto_parse_args_long_options(options,
						lgopts, option_index);
			if (retval < 0) {
				ccp_crypto_usage(prgname);
				return -1;
			}
		break;
		default:
			ccp_crypto_usage(prgname);
			return -1;
		}
	}
	if (optind >= 0)
		argv[optind-1] = prgname;

	retval = optind-1;
	optind = 1;

	return retval;
}

static void
reserve_key_memory(struct ccp_crypto_options *options)
{
	pt = rte_malloc("plain_text", MAX_PT_SIZE, 0);
	if (pt == NULL)
		rte_exit(EXIT_FAILURE,
			       "Failed to allocate memory for plain text");

	options->cipher_xform.cipher.key.data = options->cipher_key;

	options->cipher_iv.data = rte_malloc("cipher iv", MAX_IV_SIZE, 0);
	if (options->cipher_iv.data == NULL)
		rte_exit(EXIT_FAILURE,
			       "Failed to allocate memory for cipher IV");

	options->auth_xform.auth.key.data = options->auth_key;

	options->aead_iv.data = rte_malloc("aead_iv", MAX_IV_SIZE, 0);
	if (options->aead_iv.data == NULL)
		rte_exit(EXIT_FAILURE, "Failed to allocate memory for AEAD iv");

	options->aead_xform.aead.key.data = options->aead_key;
	options->aad.data = rte_malloc("aad", MAX_AAD_SIZE, 0);
	if (options->aad.data == NULL)
		rte_exit(EXIT_FAILURE, "Failed to allocate memory for AAD");

	options->aad_digest.data = rte_malloc("digest", MAX_DIGEST_SIZE, 0);
	if (options->aad_digest.data == NULL)
		rte_exit(EXIT_FAILURE, "Failed to allocate memory for Digest");
}

static struct rte_cryptodev_sym_session *
initialize_crypto_session(struct ccp_crypto_options *options,
			struct rte_mempool *sess_mp,
			struct rte_mempool *sess_mp_priv,
			uint8_t cdev_id)
{
	struct rte_crypto_sym_xform *xform;
	struct rte_cryptodev_sym_session *session;
	int retval = rte_cryptodev_socket_id(cdev_id);

	if (retval < 0)
		return NULL;

	if (options->cipher_xform.cipher.op == RTE_CRYPTO_CIPHER_OP_ENCRYPT ||
		options->cipher_xform.cipher.op ==
			RTE_CRYPTO_CIPHER_OP_DECRYPT) {
		xform = &options->cipher_xform;
	} else if (options->auth_xform.auth.op == RTE_CRYPTO_AUTH_OP_GENERATE ||
		options->auth_xform.auth.op == RTE_CRYPTO_AUTH_OP_VERIFY) {
		xform = &options->auth_xform;
	} else if (options->aead_xform.aead.op == RTE_CRYPTO_AEAD_OP_ENCRYPT ||
		options->aead_xform.aead.op == RTE_CRYPTO_AEAD_OP_DECRYPT) {
		xform = &options->aead_xform;
	} else {
		xform = &options->cipher_xform;
	}

	session = rte_cryptodev_sym_session_create(sess_mp);

	if (session == NULL) {
		printf("session NULL\n");
		return NULL;
	}

	if (rte_cryptodev_sym_session_init(cdev_id, session,
			xform, sess_mp_priv) < 0) {
		printf("sym session init fails");
		return NULL;
	}
	return session;
}

int
main(int argc, char **argv)
{
	int ret, save_file = 1;
	uint8_t  cdev_id = 0, cdev_count;
	unsigned int sess_sz;

	struct rte_cryptodev_qp_conf qp_conf;
	struct rte_cryptodev_info dev_info;
	struct rte_cryptodev_sym_session *session;
	struct rte_mempool *mbuf_pool, *crypto_op_pool;
	struct ccp_crypto_options options;

	char mp_name[RTE_MEMPOOL_NAMESIZE], mp_name2[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *sess_mp, *sess_mp_priv;
	int retval = rte_cryptodev_socket_id(cdev_id);
	uint8_t socket_id = (uint8_t) retval;
	uint8_t *input_file = NULL;
	long flen = 0;
	unsigned int crypto_op_private_data = AES_CBC_IV_LENGTH;
	struct rte_crypto_op *crypto_ops[BURST_SIZE];
	struct rte_mbuf *mbufs[BURST_SIZE];
	unsigned int i;
	int buff_size;
	int md_size;
	int log_size;
	int loop = 0;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");
	argc -= ret;
	argv += ret;

	/* reserve memory for Plain_text/Cipher/Auth key/IV and AEAD*/
	reserve_key_memory(&options);

	/* parse application arguments (after the EAL ones) */
	ret = ccp_crypto_parse_args(&options, argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid CCP-CRYPTO arguments\n");

	cdev_count = rte_cryptodev_count();
	printf("cdev_count: %d\n", cdev_count);

	sess_sz = rte_cryptodev_sym_get_private_session_size(cdev_id);

	rte_cryptodev_info_get(cdev_id, &dev_info);
	printf("crypto dev name: %s\n", dev_info.driver_name);

	retval = rte_cryptodev_socket_id(cdev_id);
	socket_id = (uint8_t) retval;

	snprintf(mp_name, RTE_MEMPOOL_NAMESIZE, "sess_mp_%u", socket_id);
	snprintf(mp_name2, RTE_MEMPOOL_NAMESIZE, "sess_mp_priv%u", socket_id);

	sess_mp = rte_cryptodev_sym_session_pool_create(mp_name,
				sess_sz, 0, 0, 0, socket_id);
	if (sess_mp == NULL) {
		printf("Cannot create session pool on socket %d\n", socket_id);
				return -ENOMEM;
	}
	sess_mp_priv = rte_mempool_create(mp_name2, 2, sess_sz,
					SESSION_POOL_CACHE_SIZE,
					0, NULL, NULL, NULL,
					NULL, socket_id, 0);
	if (sess_mp == NULL) {
		printf("Cannot create session pool on socket %d\n", socket_id);
		return -ENOMEM;
	}

	struct rte_cryptodev_config conf = {
			.nb_queue_pairs = 1,
			.socket_id = socket_id,
	};
	retval = rte_cryptodev_configure(cdev_id, &conf);
	qp_conf.nb_descriptors = 2048;
	qp_conf.mp_session = sess_mp;
	qp_conf.mp_session_private = sess_mp_priv;

	retval = rte_cryptodev_queue_pair_setup(cdev_id, 0, &qp_conf,
			socket_id);
	if (retval < 0) {
		printf("Failed to setup queue pair %u on cryptodev %u",
				0, cdev_id);
		return -1;
	}

	retval = rte_cryptodev_start(cdev_id);
	if (retval < 0) {
		printf("Failed to start device %u: error %d\n",
			cdev_id, retval);
		return -1;
	}
	/* Create crypto operation pool. */
	crypto_op_pool = rte_crypto_op_pool_create("crypto_op_pool",
						RTE_CRYPTO_OP_TYPE_SYMMETRIC,
						NUM_MBUFS,
						POOL_CACHE_SIZE,
						crypto_op_private_data,
						socket_id);

	if (options.cipher_xform.cipher.op == RTE_CRYPTO_CIPHER_OP_DECRYPT
		|| options.aead_xform.aead.op == RTE_CRYPTO_AEAD_OP_DECRYPT) {
		FILE *f = fopen("encoded.data", "rb");
		fseek(f, 0L, SEEK_END);
		flen = ftell(f);
		input_file = malloc(flen);
		rewind(f);
		size_t result = fread(input_file, flen, 1, f);
		if (!result) {
			fputs("Reading error", stderr); exit(3);
		}
		fclose(f);
	}

	if (options.auth_xform.auth.op == RTE_CRYPTO_AUTH_OP_VERIFY) {
		FILE *f = fopen("sha.data", "rb");
		fseek(f, 0L, SEEK_END);
		flen = ftell(f);
		input_file = malloc(flen);
		rewind(f);
		size_t result = fread(input_file, flen, 1, f);
		if (!result) {
			fputs("Reading error", stderr); exit(3);
		}
		fclose(f);
	}
	if ((options.auth_xform.auth.op == RTE_CRYPTO_AUTH_OP_VERIFY)
		|| (options.auth_xform.auth.op ==
		       RTE_CRYPTO_AUTH_OP_GENERATE)) {
		switch (options.auth_xform.auth.algo) {
		case RTE_CRYPTO_AUTH_SHA1:
		case RTE_CRYPTO_AUTH_SHA1_HMAC:
			md_size = SHA_DIGEST_LENGTH;
			break;
		case RTE_CRYPTO_AUTH_SHA224:
		case RTE_CRYPTO_AUTH_SHA224_HMAC:
		case RTE_CRYPTO_AUTH_SHA3_224:
		case RTE_CRYPTO_AUTH_SHA3_224_HMAC:
			md_size = SHA224_DIGEST_LENGTH;
			break;
		case RTE_CRYPTO_AUTH_SHA256:
		case RTE_CRYPTO_AUTH_SHA256_HMAC:
		case RTE_CRYPTO_AUTH_SHA3_256:
		case RTE_CRYPTO_AUTH_SHA3_256_HMAC:
			md_size = SHA256_DIGEST_LENGTH;
			break;
		case RTE_CRYPTO_AUTH_SHA384:
		case RTE_CRYPTO_AUTH_SHA384_HMAC:
		case RTE_CRYPTO_AUTH_SHA3_384:
		case RTE_CRYPTO_AUTH_SHA3_384_HMAC:
			md_size = SHA384_DIGEST_LENGTH;
			break;
		case RTE_CRYPTO_AUTH_SHA512:
		case RTE_CRYPTO_AUTH_SHA512_HMAC:
		case RTE_CRYPTO_AUTH_SHA3_512:
		case RTE_CRYPTO_AUTH_SHA3_512_HMAC:
			md_size = SHA512_DIGEST_LENGTH;
			break;
		default:
			md_size = 20;
			printf("Non-supported mode !!!\n");
			break;
		}
		options.auth_xform.auth.digest_length = md_size;
	}

	session = initialize_crypto_session(&options,
				sess_mp, sess_mp_priv, cdev_id);
	if (session == NULL) {
		printf("session NULL\n");
		return 0;
	}

	/* Get a burst of crypto operations. */
	if (rte_crypto_op_bulk_alloc(crypto_op_pool,
					RTE_CRYPTO_OP_TYPE_SYMMETRIC,
					crypto_ops, BURST_SIZE) == 0)
		rte_exit(EXIT_FAILURE,
				"Not enough crypto operations available\n");

	/* Create the mbuf pool. */
	mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NUM_MBUFS,
				POOL_CACHE_SIZE, 0,
				(RTE_MBUF_DEFAULT_BUF_SIZE+1024*60), socket_id);
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	buff_size = buffer_size;
	if (options.auth_xform.auth.op == RTE_CRYPTO_AUTH_OP_VERIFY)
		buff_size = flen;

	if (rte_pktmbuf_alloc_bulk(mbuf_pool, mbufs, BURST_SIZE) < 0)
		rte_exit(EXIT_FAILURE, "Not enough mbufs available");

	/* Initialize the mbufs and append them to the crypto operations. */
	for (i = 0; i < BURST_SIZE; i++) {
		if (rte_pktmbuf_append(mbufs[i], buff_size) == NULL)
			rte_exit(EXIT_FAILURE, "Not enough room in the mbuf\n");
		crypto_ops[i]->sym->m_src = mbufs[i];
	}
	/* Set up the crypto operations. */
	for (i = 0; i < BURST_SIZE; i++) {
		struct rte_crypto_op *op = crypto_ops[i];
		if ((options.cipher_xform.cipher.op ==
			RTE_CRYPTO_CIPHER_OP_DECRYPT) ||
			(options.cipher_xform.cipher.op
				== RTE_CRYPTO_CIPHER_OP_ENCRYPT)) {
			op->sym->cipher.data.offset = 0;
			op->sym->cipher.data.length = buffer_size;
			if ((options.cipher_xform.cipher.algo !=
				RTE_CRYPTO_CIPHER_3DES_ECB) ||
				(options.cipher_xform.cipher.algo !=
					RTE_CRYPTO_CIPHER_AES_ECB)) {
				uint8_t *iv_ptr =
					rte_crypto_op_ctod_offset(op,
							uint8_t *, IV_OFFSET);
				rte_memcpy(iv_ptr, options.cipher_iv.data,
						options.cipher_iv.length);
			}
		}
		op->sym->auth.data.offset = 0;
		if (options.aead_xform.aead.op == RTE_CRYPTO_AEAD_OP_ENCRYPT) {
			uint8_t *iv_ptr = rte_crypto_op_ctod_offset(op,
					uint8_t *, IV_OFFSET);
			rte_memcpy(iv_ptr, options.aead_iv.data,
					options.aead_iv.length);
			op->sym->aead.data.offset = 0;
			op->sym->aead.data.length = buffer_size;
			op->sym->aead.aad.data = options.aad.data;
			op->sym->aead.digest.data =
			       (uint8_t *)rte_pktmbuf_append(mbufs[i],
						options.digest_size);
			rte_memcpy(op->sym->aead.digest.data,
					options.aad_digest.data,
					options.aead_xform.aead.digest_length);
		}
		if (options.aead_xform.aead.op == RTE_CRYPTO_AEAD_OP_DECRYPT) {
			uint8_t *iv_ptr = rte_crypto_op_ctod_offset(op,
							uint8_t *, IV_OFFSET);
			rte_memcpy(iv_ptr, options.aead_iv.data,
					options.aead_iv.length);
			op->sym->aead.data.offset = 0;
			op->sym->aead.data.length = flen;
			op->sym->aead.aad.data = options.aad.data;
			op->sym->aead.digest.data =
				(uint8_t *)rte_pktmbuf_mtod(mbufs[i], uint8_t *)
					+flen - options.digest_size;
		}
		if (options.auth_xform.auth.op == RTE_CRYPTO_AUTH_OP_GENERATE) {
			op->sym->auth.data.length = buffer_size;
			op->sym->auth.digest.data =
			  (uint8_t *)rte_pktmbuf_append(mbufs[i], md_size);
		}
		if (options.auth_xform.auth.op == RTE_CRYPTO_AUTH_OP_VERIFY) {
			op->sym->auth.data.length = flen-md_size;
			op->sym->auth.digest.data =
				rte_pktmbuf_mtod(mbufs[i], uint8_t *)
				  + (rte_pktmbuf_data_len(mbufs[i])-md_size);
		}
		/* Attach the crypto session to the operation */
		rte_crypto_op_attach_sym_session(op, session);
	}
	while (loop < 1) {
		if ((options.cipher_xform.cipher.op ==
				RTE_CRYPTO_CIPHER_OP_ENCRYPT)
			|| (options.auth_xform.auth.op ==
				RTE_CRYPTO_AUTH_OP_GENERATE)
			|| (options.aead_xform.aead.op ==
				RTE_CRYPTO_AEAD_OP_ENCRYPT)) {
			char *ch;
			for (int j = 0; j < BURST_SIZE; j++) {
				ch  = rte_pktmbuf_mtod(mbufs[j], char *);
				for (int k = 0; k < pt_length; k++)
					memset(ch+k, pt[k], sizeof(char));
			}
			printf("I/P =\n");
			ch  = rte_pktmbuf_mtod(mbufs[0], char *);
			for (int k = 1;
				k <= crypto_ops[0]->sym->m_src->data_len;
					k++) {
				printf("%02x", ch[k-1] & 0xff);
				if (k%16 == 0)
					printf("\n");
			}
			printf("\n");
		}
		if ((options.cipher_xform.cipher.op ==
					RTE_CRYPTO_CIPHER_OP_DECRYPT)
			|| (options.auth_xform.auth.op ==
				RTE_CRYPTO_AUTH_OP_VERIFY)
			|| (options.aead_xform.aead.op ==
				RTE_CRYPTO_AEAD_OP_DECRYPT)) {
			char *ch;
			for (int j = 0; j < BURST_SIZE; j++) {
				ch  = rte_pktmbuf_mtod(mbufs[j], char *);
				rte_memcpy(ch, input_file, flen);
			}
			printf("I/P =\n");
			ch  = rte_pktmbuf_mtod(mbufs[0], char *);
			for (int k = 1;
				k <= crypto_ops[0]->sym->m_src->data_len; k++) {
				printf("%02x", ch[k-1] & 0xff);
				if (k%16 == 0)
					printf("\n");
			}
			printf("\n");
		}
		/* Enqueue the crypto operations in the crypto device. */
		uint16_t num_enqueued_ops =
				rte_cryptodev_enqueue_burst(cdev_id,
						0, crypto_ops, BURST_SIZE);
		if (num_enqueued_ops == 0) {
			printf("continuing\n");
			continue;
		}
		uint16_t num_dequeued_ops, total_num_dequeued_ops = 0;

		do {
			num_dequeued_ops = rte_cryptodev_dequeue_burst(cdev_id,
						0, crypto_ops, BURST_SIZE);
			total_num_dequeued_ops += num_dequeued_ops;
			/* Check if operation was processed successfully */
			for (i = 0; i < num_dequeued_ops; i++) {
				if (crypto_ops[i]->status !=
						RTE_CRYPTO_OP_STATUS_SUCCESS) {
					printf("error @ i: %d\n", i);
				}
			}
			printf("%s",
				(char *)crypto_ops[0]->sym->m_src->buf_addr);
			rte_mempool_put_bulk(crypto_op_pool,
					(void **)crypto_ops, num_dequeued_ops);
		} while (total_num_dequeued_ops < num_enqueued_ops);
		char *ch;
		ch  = rte_pktmbuf_mtod(crypto_ops[0]->sym->m_src, char *);
		printf("O/P =\n");
		if (options.auth_xform.auth.op == RTE_CRYPTO_AUTH_OP_VERIFY)
			log_size = crypto_ops[0]->sym->m_src->data_len-md_size;
		else
			log_size = crypto_ops[0]->sym->m_src->data_len;
		for (int k = 1; k <= log_size; k++) {
			printf("%02x", ch[k-1] & 0xff);
			if (k%16 == 0)
				printf("\n");
		}
		printf("\n");
		if (options.auth_xform.auth.op ==
				RTE_CRYPTO_AUTH_OP_GENERATE) {
			if (save_file) {
				char *ch;
				ch  = rte_pktmbuf_mtod(
					crypto_ops[0]->sym->m_src, char *);
				FILE *f = fopen("sha.data", "wb");
				fwrite(ch, sizeof(char),
					crypto_ops[0]->sym->m_src->data_len, f);
				fclose(f);
				printf("\n sha buff:\n");
				ch  = rte_pktmbuf_mtod(
					crypto_ops[0]->sym->m_src, char *);
				for (int i = 0; i < md_size; i++)
					printf("%02x",
						ch[buffer_size+i] & 0xff);
				printf("\n");
			}
	}
	if (options.cipher_xform.cipher.op == RTE_CRYPTO_CIPHER_OP_ENCRYPT
		||  options.aead_xform.aead.op == RTE_CRYPTO_AEAD_OP_ENCRYPT) {
		if (save_file) {
			char *ch;
			ch  = rte_pktmbuf_mtod(
					crypto_ops[0]->sym->m_src, char *);
			FILE *f = fopen("encoded.data", "wb");
			fwrite(ch, sizeof(char),
				crypto_ops[0]->sym->m_src->data_len, f);
			fclose(f);
		}
	}
	loop++;
	}
	return 0;
}
