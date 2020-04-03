/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2017 Intel Corporation
 */

#include <stdio.h>
#include <unistd.h>

#include <rte_malloc.h>
#include <rte_random.h>
#include <rte_eal.h>
#include <rte_cryptodev.h>
#ifdef RTE_LIBRTE_PMD_CRYPTO_SCHEDULER
#include <rte_cryptodev_scheduler.h>
#endif
#ifdef MULTI_FN_SUPPORTED
#include <rte_rawdev.h>
#include <rte_multi_fn.h>
#endif /* MULTI_FN_SUPPORTED */

#include "cperf.h"
#include "cperf_options.h"
#include "cperf_test_vector_parsing.h"
#include "cperf_test_throughput.h"
#include "cperf_test_latency.h"
#include "cperf_test_verify.h"
#include "cperf_test_pmd_cyclecount.h"

static struct {
	struct rte_mempool *sess_mp;
	struct rte_mempool *priv_mp;
} session_pool_socket[RTE_MAX_NUMA_NODES];

const char *cperf_test_type_strs[] = {
	[CPERF_TEST_TYPE_THROUGHPUT] = "throughput",
	[CPERF_TEST_TYPE_LATENCY] = "latency",
	[CPERF_TEST_TYPE_VERIFY] = "verify",
	[CPERF_TEST_TYPE_PMDCC] = "pmd-cyclecount"
};

const char *cperf_op_type_strs[] = {
	[CPERF_CIPHER_ONLY] = "cipher-only",
	[CPERF_AUTH_ONLY] = "auth-only",
	[CPERF_CIPHER_THEN_AUTH] = "cipher-then-auth",
	[CPERF_AUTH_THEN_CIPHER] = "auth-then-cipher",
	[CPERF_AEAD] = "aead",
	[CPERF_PDCP] = "pdcp",
#ifdef MULTI_FN_SUPPORTED
	[CPERF_MULTI_FN] = "multi-fn"
#endif /* MULTI_FN_SUPPORTED */
};

#ifdef MULTI_FN_SUPPORTED
const char *cperf_multi_fn_ops_strs[] = {
	[CPERF_MULTI_FN_OPS_DOCSIS_CIPHER_CRC] = "docsis-cipher-crc",
	[CPERF_MULTI_FN_OPS_PON_CIPHER_CRC_BIP] = "pon-cipher-crc-bip"
};
#endif /* MULTI_FN_SUPPORTED */

const struct cperf_test cperf_testmap[] = {
		[CPERF_TEST_TYPE_THROUGHPUT] = {
				cperf_throughput_test_constructor,
				cperf_throughput_test_runner,
				cperf_throughput_test_destructor
		},
		[CPERF_TEST_TYPE_LATENCY] = {
				cperf_latency_test_constructor,
				cperf_latency_test_runner,
				cperf_latency_test_destructor
		},
		[CPERF_TEST_TYPE_VERIFY] = {
				cperf_verify_test_constructor,
				cperf_verify_test_runner,
				cperf_verify_test_destructor
		},
		[CPERF_TEST_TYPE_PMDCC] = {
				cperf_pmd_cyclecount_test_constructor,
				cperf_pmd_cyclecount_test_runner,
				cperf_pmd_cyclecount_test_destructor
		}
};

static int
fill_session_pool_socket(int32_t socket_id, uint32_t session_priv_size,
		uint32_t nb_sessions)
{
	char mp_name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *sess_mp;

	if (session_pool_socket[socket_id].priv_mp == NULL) {
		snprintf(mp_name, RTE_MEMPOOL_NAMESIZE,
			"priv_sess_mp_%u", socket_id);

		sess_mp = rte_mempool_create(mp_name,
					nb_sessions,
					session_priv_size,
					0, 0, NULL, NULL, NULL,
					NULL, socket_id,
					0);

		if (sess_mp == NULL) {
			printf("Cannot create pool \"%s\" on socket %d\n",
				mp_name, socket_id);
			return -ENOMEM;
		}

		printf("Allocated pool \"%s\" on socket %d\n",
			mp_name, socket_id);
		session_pool_socket[socket_id].priv_mp = sess_mp;
	}

	if (session_pool_socket[socket_id].sess_mp == NULL) {

		snprintf(mp_name, RTE_MEMPOOL_NAMESIZE,
			"sess_mp_%u", socket_id);

		sess_mp = rte_cryptodev_sym_session_pool_create(mp_name,
					nb_sessions, 0, 0, 0, socket_id);

		if (sess_mp == NULL) {
			printf("Cannot create pool \"%s\" on socket %d\n",
				mp_name, socket_id);
			return -ENOMEM;
		}

		printf("Allocated pool \"%s\" on socket %d\n",
			mp_name, socket_id);
		session_pool_socket[socket_id].sess_mp = sess_mp;
	}

	return 0;
}

static int
cperf_initialize_cryptodev(struct cperf_options *opts, uint8_t *enabled_cdevs)
{
	uint8_t enabled_cdev_count = 0, nb_lcores, cdev_id;
	uint32_t sessions_needed = 0;
	unsigned int i, j;
	int ret;

	enabled_cdev_count = rte_cryptodev_devices_get(opts->device_type,
			enabled_cdevs, RTE_CRYPTO_MAX_DEVS);
	if (enabled_cdev_count == 0) {
		printf("No crypto devices type %s available\n",
				opts->device_type);
		return -EINVAL;
	}

	nb_lcores = rte_lcore_count() - 1;

	if (nb_lcores < 1) {
		RTE_LOG(ERR, USER1,
			"Number of enabled cores need to be higher than 1\n");
		return -EINVAL;
	}

	/*
	 * Use less number of devices,
	 * if there are more available than cores.
	 */
	if (enabled_cdev_count > nb_lcores)
		enabled_cdev_count = nb_lcores;

	/* Create a mempool shared by all the devices */
	uint32_t max_sess_size = 0, sess_size;

	for (cdev_id = 0; cdev_id < rte_cryptodev_count(); cdev_id++) {
		sess_size = rte_cryptodev_sym_get_private_session_size(cdev_id);
		if (sess_size > max_sess_size)
			max_sess_size = sess_size;
	}

	/*
	 * Calculate number of needed queue pairs, based on the amount
	 * of available number of logical cores and crypto devices.
	 * For instance, if there are 4 cores and 2 crypto devices,
	 * 2 queue pairs will be set up per device.
	 */
	opts->nb_qps = (nb_lcores % enabled_cdev_count) ?
				(nb_lcores / enabled_cdev_count) + 1 :
				nb_lcores / enabled_cdev_count;

	for (i = 0; i < enabled_cdev_count &&
			i < RTE_CRYPTO_MAX_DEVS; i++) {
		cdev_id = enabled_cdevs[i];
#ifdef RTE_LIBRTE_PMD_CRYPTO_SCHEDULER
		/*
		 * If multi-core scheduler is used, limit the number
		 * of queue pairs to 1, as there is no way to know
		 * how many cores are being used by the PMD, and
		 * how many will be available for the application.
		 */
		if (!strcmp((const char *)opts->device_type, "crypto_scheduler") &&
				rte_cryptodev_scheduler_mode_get(cdev_id) ==
				CDEV_SCHED_MODE_MULTICORE)
			opts->nb_qps = 1;
#endif

		struct rte_cryptodev_info cdev_info;
		uint8_t socket_id = rte_cryptodev_socket_id(cdev_id);
		/* range check the socket_id - negative values become big
		 * positive ones due to use of unsigned value
		 */
		if (socket_id >= RTE_MAX_NUMA_NODES)
			socket_id = 0;

		rte_cryptodev_info_get(cdev_id, &cdev_info);
		if (opts->nb_qps > cdev_info.max_nb_queue_pairs) {
			printf("Number of needed queue pairs is higher "
				"than the maximum number of queue pairs "
				"per device.\n");
			printf("Lower the number of cores or increase "
				"the number of crypto devices\n");
			return -EINVAL;
		}
		struct rte_cryptodev_config conf = {
			.nb_queue_pairs = opts->nb_qps,
			.socket_id = socket_id,
			.ff_disable = RTE_CRYPTODEV_FF_SECURITY |
				      RTE_CRYPTODEV_FF_ASYMMETRIC_CRYPTO,
		};

		struct rte_cryptodev_qp_conf qp_conf = {
			.nb_descriptors = opts->nb_descriptors
		};

		/**
		 * Device info specifies the min headroom and tailroom
		 * requirement for the crypto PMD. This need to be honoured
		 * by the application, while creating mbuf.
		 */
		if (opts->headroom_sz < cdev_info.min_mbuf_headroom_req) {
			/* Update headroom */
			opts->headroom_sz = cdev_info.min_mbuf_headroom_req;
		}
		if (opts->tailroom_sz < cdev_info.min_mbuf_tailroom_req) {
			/* Update tailroom */
			opts->tailroom_sz = cdev_info.min_mbuf_tailroom_req;
		}

		/* Update segment size to include headroom & tailroom */
		opts->segment_sz += (opts->headroom_sz + opts->tailroom_sz);

		uint32_t dev_max_nb_sess = cdev_info.sym.max_nb_sessions;
		/*
		 * Two sessions objects are required for each session
		 * (one for the header, one for the private data)
		 */
		if (!strcmp((const char *)opts->device_type,
					"crypto_scheduler")) {
#ifdef RTE_LIBRTE_PMD_CRYPTO_SCHEDULER
			uint32_t nb_slaves =
				rte_cryptodev_scheduler_slaves_get(cdev_id,
								NULL);

			sessions_needed = enabled_cdev_count *
				opts->nb_qps * nb_slaves;
#endif
		} else
			sessions_needed = enabled_cdev_count *
						opts->nb_qps;

		/*
		 * A single session is required per queue pair
		 * in each device
		 */
		if (dev_max_nb_sess != 0 && dev_max_nb_sess < opts->nb_qps) {
			RTE_LOG(ERR, USER1,
				"Device does not support at least "
				"%u sessions\n", opts->nb_qps);
			return -ENOTSUP;
		}

		ret = fill_session_pool_socket(socket_id, max_sess_size,
				sessions_needed);
		if (ret < 0)
			return ret;

		qp_conf.mp_session = session_pool_socket[socket_id].sess_mp;
		qp_conf.mp_session_private =
				session_pool_socket[socket_id].priv_mp;

		ret = rte_cryptodev_configure(cdev_id, &conf);
		if (ret < 0) {
			printf("Failed to configure cryptodev %u", cdev_id);
			return -EINVAL;
		}

		for (j = 0; j < opts->nb_qps; j++) {
			ret = rte_cryptodev_queue_pair_setup(cdev_id, j,
				&qp_conf, socket_id);
			if (ret < 0) {
				printf("Failed to setup queue pair %u on "
					"cryptodev %u",	j, cdev_id);
				return -EINVAL;
			}
		}

		ret = rte_cryptodev_start(cdev_id);
		if (ret < 0) {
			printf("Failed to start device %u: error %d\n",
					cdev_id, ret);
			return -EPERM;
		}
	}

	return enabled_cdev_count;
}

static int
cperf_verify_crypto_devices_capabilities(struct cperf_options *opts,
		uint8_t *enabled_cdevs, uint8_t nb_cryptodevs)
{
	struct rte_cryptodev_sym_capability_idx cap_idx;
	const struct rte_cryptodev_symmetric_capability *capability;

	uint8_t i, cdev_id;
	int ret;

	for (i = 0; i < nb_cryptodevs; i++) {

		cdev_id = enabled_cdevs[i];

		if (opts->op_type == CPERF_AUTH_ONLY ||
				opts->op_type == CPERF_CIPHER_THEN_AUTH ||
				opts->op_type == CPERF_AUTH_THEN_CIPHER) {

			cap_idx.type = RTE_CRYPTO_SYM_XFORM_AUTH;
			cap_idx.algo.auth = opts->auth_algo;

			capability = rte_cryptodev_sym_capability_get(cdev_id,
					&cap_idx);
			if (capability == NULL)
				return -1;

			ret = rte_cryptodev_sym_capability_check_auth(
					capability,
					opts->auth_key_sz,
					opts->digest_sz,
					opts->auth_iv_sz);
			if (ret != 0)
				return ret;
		}

		if (opts->op_type == CPERF_CIPHER_ONLY ||
				opts->op_type == CPERF_CIPHER_THEN_AUTH ||
				opts->op_type == CPERF_AUTH_THEN_CIPHER) {

			cap_idx.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
			cap_idx.algo.cipher = opts->cipher_algo;

			capability = rte_cryptodev_sym_capability_get(cdev_id,
					&cap_idx);
			if (capability == NULL)
				return -1;

			ret = rte_cryptodev_sym_capability_check_cipher(
					capability,
					opts->cipher_key_sz,
					opts->cipher_iv_sz);
			if (ret != 0)
				return ret;
		}

		if (opts->op_type == CPERF_AEAD) {

			cap_idx.type = RTE_CRYPTO_SYM_XFORM_AEAD;
			cap_idx.algo.aead = opts->aead_algo;

			capability = rte_cryptodev_sym_capability_get(cdev_id,
					&cap_idx);
			if (capability == NULL)
				return -1;

			ret = rte_cryptodev_sym_capability_check_aead(
					capability,
					opts->aead_key_sz,
					opts->digest_sz,
					opts->aead_aad_sz,
					opts->aead_iv_sz);
			if (ret != 0)
				return ret;
		}
	}

#ifdef MULTI_FN_SUPPORTED
	if (opts->op_type == CPERF_MULTI_FN)
		return -1;
#endif /* MULTI_FN_SUPPORTED */

	return 0;
}

#ifdef MULTI_FN_SUPPORTED
static uint8_t
cperf_get_rawdevs(const char *driver_name, uint8_t *devices,
		uint8_t nb_devices)
{
	struct rte_rawdev_info rdev_info;
	uint8_t i, count = 0;

	for (i = 0; i < RTE_RAWDEV_MAX_DEVS && count < nb_devices; i++) {
		memset(&rdev_info, 0, sizeof(struct rte_rawdev_info));
		if (!rte_rawdev_info_get(i, &rdev_info) &&
			!strncmp(rdev_info.driver_name,
					driver_name,
					strlen(driver_name) + 1))
			devices[count++] = i;
	}

	return count;
}

static int
cperf_initialize_rawdev(struct cperf_options *opts, uint8_t *enabled_rdevs)
{
	uint8_t enabled_rdev_count = 0, nb_lcores, rdev_id;
	unsigned int i, j;
	int ret;

	enabled_rdev_count = cperf_get_rawdevs(opts->device_type,
			enabled_rdevs, RTE_RAWDEV_MAX_DEVS);
	if (enabled_rdev_count == 0) {
		printf("No raw devices type %s available\n",
				opts->device_type);
		return -EINVAL;
	}

	nb_lcores = rte_lcore_count() - 1;

	if (nb_lcores < 1) {
		RTE_LOG(ERR, USER1,
			"Number of enabled cores need to be higher than 1\n");
		return -EINVAL;
	}

	/*
	 * Calculate number of needed queue pairs, based on the amount
	 * of available number of logical cores and crypto devices.
	 * For instance, if there are 4 cores and 2 crypto devices,
	 * 2 queue pairs will be set up per device.
	 */
	opts->nb_qps = (nb_lcores % enabled_rdev_count) ?
				(nb_lcores / enabled_rdev_count) + 1 :
				nb_lcores / enabled_rdev_count;

	for (i = 0; i < enabled_rdev_count &&
			i < RTE_RAWDEV_MAX_DEVS; i++) {
		rdev_id = enabled_rdevs[i];

		struct rte_rawdev_info rdev_info = {0};
		struct rte_multi_fn_dev_info mf_info  = {0};
		struct rte_multi_fn_dev_config mf_dev_conf = {0};
		struct rte_multi_fn_qp_config qp_conf = {0};
		uint8_t socket_id = rte_cryptodev_socket_id(rdev_id);

		/*
		 * Range check the socket_id - negative values become big
		 * positive ones due to use of unsigned value
		 */
		if (socket_id >= RTE_MAX_NUMA_NODES)
			socket_id = 0;

		rdev_info.dev_private = &mf_info;
		rte_rawdev_info_get(rdev_id, &rdev_info);
		if (opts->nb_qps > mf_info.max_nb_queues) {
			printf("Number of needed queue pairs is higher "
				"than the maximum number of queue pairs "
				"per device.\n");
			printf("Lower the number of cores or increase "
				"the number of raw devices\n");
			return -EINVAL;
		}

		mf_dev_conf.nb_queues = opts->nb_qps;
		rdev_info.dev_private = &mf_dev_conf;
		qp_conf.nb_descriptors = opts->nb_descriptors;

		ret = rte_rawdev_configure(rdev_id, &rdev_info);
		if (ret < 0) {
			printf("Failed to configure rawdev %u", rdev_id);
			return -EINVAL;
		}

		for (j = 0; j < opts->nb_qps; j++) {
			ret = rte_rawdev_queue_setup(rdev_id, j, &qp_conf);
			if (ret < 0) {
				printf("Failed to setup queue pair %u on "
					"rawdev %u", j, rdev_id);
				return -EINVAL;
			}
		}

		ret = rte_rawdev_start(rdev_id);
		if (ret < 0) {
			printf("Failed to start raw device %u: error %d\n",
				rdev_id, ret);
			return -EPERM;
		}
	}

	return enabled_rdev_count;
}

static int
cperf_verify_raw_devices_capabilities(struct cperf_options *opts,
		__rte_unused uint8_t *enabled_rdevs,
		__rte_unused uint8_t nb_rawdevs)
{
	if (opts->op_type != CPERF_MULTI_FN)
		return -1;

	return 0;
}
#endif /* MULTI_FN_SUPPORTED */

static int
cperf_check_test_vector(struct cperf_options *opts,
		struct cperf_test_vector *test_vec)
{
	if (opts->op_type == CPERF_CIPHER_ONLY) {
		if (opts->cipher_algo == RTE_CRYPTO_CIPHER_NULL) {
			if (test_vec->plaintext.data == NULL)
				return -1;
		} else if (opts->cipher_algo != RTE_CRYPTO_CIPHER_NULL) {
			if (test_vec->plaintext.data == NULL)
				return -1;
			if (test_vec->plaintext.length < opts->max_buffer_size)
				return -1;
			if (test_vec->ciphertext.data == NULL)
				return -1;
			if (test_vec->ciphertext.length < opts->max_buffer_size)
				return -1;
			/* Cipher IV is only required for some algorithms */
			if (opts->cipher_iv_sz &&
					test_vec->cipher_iv.data == NULL)
				return -1;
			if (test_vec->cipher_iv.length != opts->cipher_iv_sz)
				return -1;
			if (test_vec->cipher_key.data == NULL)
				return -1;
			if (test_vec->cipher_key.length != opts->cipher_key_sz)
				return -1;
		}
	} else if (opts->op_type == CPERF_AUTH_ONLY) {
		if (opts->auth_algo != RTE_CRYPTO_AUTH_NULL) {
			if (test_vec->plaintext.data == NULL)
				return -1;
			if (test_vec->plaintext.length < opts->max_buffer_size)
				return -1;
			/* Auth key is only required for some algorithms */
			if (opts->auth_key_sz &&
					test_vec->auth_key.data == NULL)
				return -1;
			if (test_vec->auth_key.length != opts->auth_key_sz)
				return -1;
			if (test_vec->auth_iv.length != opts->auth_iv_sz)
				return -1;
			/* Auth IV is only required for some algorithms */
			if (opts->auth_iv_sz && test_vec->auth_iv.data == NULL)
				return -1;
			if (test_vec->digest.data == NULL)
				return -1;
			if (test_vec->digest.length < opts->digest_sz)
				return -1;
		}

	} else if (opts->op_type == CPERF_CIPHER_THEN_AUTH ||
			opts->op_type == CPERF_AUTH_THEN_CIPHER) {
		if (opts->cipher_algo == RTE_CRYPTO_CIPHER_NULL) {
			if (test_vec->plaintext.data == NULL)
				return -1;
			if (test_vec->plaintext.length < opts->max_buffer_size)
				return -1;
		} else if (opts->cipher_algo != RTE_CRYPTO_CIPHER_NULL) {
			if (test_vec->plaintext.data == NULL)
				return -1;
			if (test_vec->plaintext.length < opts->max_buffer_size)
				return -1;
			if (test_vec->ciphertext.data == NULL)
				return -1;
			if (test_vec->ciphertext.length < opts->max_buffer_size)
				return -1;
			if (test_vec->cipher_iv.data == NULL)
				return -1;
			if (test_vec->cipher_iv.length != opts->cipher_iv_sz)
				return -1;
			if (test_vec->cipher_key.data == NULL)
				return -1;
			if (test_vec->cipher_key.length != opts->cipher_key_sz)
				return -1;
		}
		if (opts->auth_algo != RTE_CRYPTO_AUTH_NULL) {
			if (test_vec->auth_key.data == NULL)
				return -1;
			if (test_vec->auth_key.length != opts->auth_key_sz)
				return -1;
			if (test_vec->auth_iv.length != opts->auth_iv_sz)
				return -1;
			/* Auth IV is only required for some algorithms */
			if (opts->auth_iv_sz && test_vec->auth_iv.data == NULL)
				return -1;
			if (test_vec->digest.data == NULL)
				return -1;
			if (test_vec->digest.length < opts->digest_sz)
				return -1;
		}
	} else if (opts->op_type == CPERF_AEAD) {
		if (test_vec->plaintext.data == NULL)
			return -1;
		if (test_vec->plaintext.length < opts->max_buffer_size)
			return -1;
		if (test_vec->ciphertext.data == NULL)
			return -1;
		if (test_vec->ciphertext.length < opts->max_buffer_size)
			return -1;
		if (test_vec->aead_key.data == NULL)
			return -1;
		if (test_vec->aead_key.length != opts->aead_key_sz)
			return -1;
		if (test_vec->aead_iv.data == NULL)
			return -1;
		if (test_vec->aead_iv.length != opts->aead_iv_sz)
			return -1;
		if (test_vec->aad.data == NULL)
			return -1;
		if (test_vec->aad.length != opts->aead_aad_sz)
			return -1;
		if (test_vec->digest.data == NULL)
			return -1;
		if (test_vec->digest.length < opts->digest_sz)
			return -1;
	}
	return 0;
}

int
main(int argc, char **argv)
{
	struct cperf_options opts = {0};
	struct cperf_test_vector *t_vec = NULL;
	struct cperf_op_fns op_fns;
	void *ctx[RTE_MAX_LCORE] = { };
	int nb_devs = 0;
	uint16_t total_nb_qps = 0;
	uint8_t dev_id, i;
#ifndef MULTI_FN_SUPPORTED
	uint8_t enabled_devs[RTE_CRYPTO_MAX_DEVS] = { 0 };
#else
	uint8_t max_devs = RTE_MAX(RTE_CRYPTO_MAX_DEVS, RTE_RAWDEV_MAX_DEVS);
	uint8_t enabled_devs[max_devs];
	memset(enabled_devs, 0x0, max_devs);
#endif /* MULTI_FN_SUPPORTED */

	uint8_t buffer_size_idx = 0;

	int ret;
	uint32_t lcore_id;

	/* Initialise DPDK EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments!\n");
	argc -= ret;
	argv += ret;

	cperf_options_default(&opts);

	ret = cperf_options_parse(&opts, argc, argv);
	if (ret) {
		RTE_LOG(ERR, USER1, "Parsing on or more user options failed\n");
		goto err;
	}

	ret = cperf_options_check(&opts);
	if (ret) {
		RTE_LOG(ERR, USER1,
				"Checking on or more user options failed\n");
		goto err;
	}

#ifdef MULTI_FN_SUPPORTED
	if (opts.op_type == CPERF_MULTI_FN) {
		nb_devs = cperf_initialize_rawdev(&opts, enabled_devs);

		if (!opts.silent)
			cperf_options_dump(&opts);

		if (nb_devs < 1) {
			RTE_LOG(ERR, USER1, "Failed to initialise requested "
					"raw device type\n");
			nb_devs = 0;
			goto err;
		}

		ret = cperf_verify_raw_devices_capabilities(&opts,
				enabled_devs, nb_devs);
		if (ret) {
			RTE_LOG(ERR, USER1, "Raw device type does not "
					"support capabilities requested\n");
			goto err;
		}
	} else
#endif /* MULTI_FN_SUPPORTED */
	{
		nb_devs = cperf_initialize_cryptodev(&opts, enabled_devs);

		if (!opts.silent)
			cperf_options_dump(&opts);

		if (nb_devs < 1) {
			RTE_LOG(ERR, USER1, "Failed to initialise requested "
					"crypto device type\n");
			nb_devs = 0;
			goto err;
		}

		ret = cperf_verify_crypto_devices_capabilities(&opts,
				enabled_devs, nb_devs);
		if (ret) {
			RTE_LOG(ERR, USER1, "Crypto device type does not "
					"support capabilities requested\n");
			goto err;
		}
	}

	if (opts.test_file != NULL) {
		t_vec = cperf_test_vector_get_from_file(&opts);
		if (t_vec == NULL) {
			RTE_LOG(ERR, USER1,
					"Failed to create test vector for"
					" specified file\n");
			goto err;
		}

		if (cperf_check_test_vector(&opts, t_vec)) {
			RTE_LOG(ERR, USER1, "Incomplete necessary test vectors"
					"\n");
			goto err;
		}
	} else {
		t_vec = cperf_test_vector_get_dummy(&opts);
		if (t_vec == NULL) {
			RTE_LOG(ERR, USER1,
					"Failed to create test vector for"
					" specified algorithms\n");
			goto err;
		}
	}

	ret = cperf_get_op_functions(&opts, &op_fns);
	if (ret) {
		RTE_LOG(ERR, USER1, "Failed to find function ops set for "
				"specified algorithms combination\n");
		goto err;
	}

	if (!opts.silent)
		show_test_vector(t_vec);

	total_nb_qps = nb_devs * opts.nb_qps;

	i = 0;
	uint8_t qp_id = 0, dev_index = 0;
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {

		if (i == total_nb_qps)
			break;

		dev_id = enabled_devs[dev_index];

		uint8_t socket_id;
#ifdef MULTI_FN_SUPPORTED
		if (opts.op_type == CPERF_MULTI_FN)
			socket_id = rte_rawdev_socket_id(dev_id);
		else
#endif /* MULTI_FN_SUPPORTED */
			socket_id = rte_cryptodev_socket_id(dev_id);

		ctx[i] = cperf_testmap[opts.test].constructor(
				session_pool_socket[socket_id].sess_mp,
				session_pool_socket[socket_id].priv_mp,
				dev_id, qp_id,
				&opts, t_vec, &op_fns);
		if (ctx[i] == NULL) {
			RTE_LOG(ERR, USER1, "Test run constructor failed\n");
			goto err;
		}
		qp_id = (qp_id + 1) % opts.nb_qps;
		if (qp_id == 0)
			dev_index++;
		i++;
	}

	if (opts.imix_distribution_count != 0) {
		uint8_t buffer_size_count = opts.buffer_size_count;
		uint16_t distribution_total[buffer_size_count];
		uint32_t op_idx;
		uint32_t test_average_size = 0;
		const uint32_t *buffer_size_list = opts.buffer_size_list;
		const uint32_t *imix_distribution_list = opts.imix_distribution_list;

		opts.imix_buffer_sizes = rte_malloc(NULL,
					sizeof(uint32_t) * opts.pool_sz,
					0);
		/*
		 * Calculate accumulated distribution of
		 * probabilities per packet size
		 */
		distribution_total[0] = imix_distribution_list[0];
		for (i = 1; i < buffer_size_count; i++)
			distribution_total[i] = imix_distribution_list[i] +
				distribution_total[i-1];

		/* Calculate a random sequence of packet sizes, based on distribution */
		for (op_idx = 0; op_idx < opts.pool_sz; op_idx++) {
			uint16_t random_number = rte_rand() %
				distribution_total[buffer_size_count - 1];
			for (i = 0; i < buffer_size_count; i++)
				if (random_number < distribution_total[i])
					break;

			opts.imix_buffer_sizes[op_idx] = buffer_size_list[i];
		}

		/* Calculate average buffer size for the IMIX distribution */
		for (i = 0; i < buffer_size_count; i++)
			test_average_size += buffer_size_list[i] *
				imix_distribution_list[i];

		opts.test_buffer_size = test_average_size /
				distribution_total[buffer_size_count - 1];

		i = 0;
		RTE_LCORE_FOREACH_SLAVE(lcore_id) {

			if (i == total_nb_qps)
				break;

			rte_eal_remote_launch(cperf_testmap[opts.test].runner,
				ctx[i], lcore_id);
			i++;
		}
		i = 0;
		RTE_LCORE_FOREACH_SLAVE(lcore_id) {

			if (i == total_nb_qps)
				break;
			ret |= rte_eal_wait_lcore(lcore_id);
			i++;
		}

		if (ret != EXIT_SUCCESS)
			goto err;
	} else {

		/* Get next size from range or list */
		if (opts.inc_buffer_size != 0)
			opts.test_buffer_size = opts.min_buffer_size;
		else
			opts.test_buffer_size = opts.buffer_size_list[0];

		while (opts.test_buffer_size <= opts.max_buffer_size) {
			i = 0;
			RTE_LCORE_FOREACH_SLAVE(lcore_id) {

				if (i == total_nb_qps)
					break;

				rte_eal_remote_launch(cperf_testmap[opts.test].runner,
					ctx[i], lcore_id);
				i++;
			}
			i = 0;
			RTE_LCORE_FOREACH_SLAVE(lcore_id) {

				if (i == total_nb_qps)
					break;
				ret |= rte_eal_wait_lcore(lcore_id);
				i++;
			}

			if (ret != EXIT_SUCCESS)
				goto err;

			/* Get next size from range or list */
			if (opts.inc_buffer_size != 0)
				opts.test_buffer_size += opts.inc_buffer_size;
			else {
				if (++buffer_size_idx == opts.buffer_size_count)
					break;
				opts.test_buffer_size =
					opts.buffer_size_list[buffer_size_idx];
			}
		}
	}

	i = 0;
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {

		if (i == total_nb_qps)
			break;

		cperf_testmap[opts.test].destructor(ctx[i]);
		i++;
	}

	for (i = 0; i < nb_devs &&
			i < RTE_DIM(enabled_devs); i++) {
#ifdef MULTI_FN_SUPPORTED
		if (opts.op_type == CPERF_MULTI_FN)
			rte_rawdev_stop(enabled_devs[i]);
		else
#endif /* MULTI_FN_SUPPORTED */
			rte_cryptodev_stop(enabled_devs[i]);
	}

	free_test_vector(t_vec, &opts);

	printf("\n");
	return EXIT_SUCCESS;

err:
	i = 0;
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (i == total_nb_qps)
			break;

		if (ctx[i] && cperf_testmap[opts.test].destructor)
			cperf_testmap[opts.test].destructor(ctx[i]);
		i++;
	}

	for (i = 0; i < nb_devs &&
			i < RTE_DIM(enabled_devs); i++) {
#ifdef MULTI_FN_SUPPORTED
		if (opts.op_type == CPERF_MULTI_FN)
			rte_rawdev_stop(enabled_devs[i]);
		else
#endif /* MULTI_FN_SUPPORTED */
			rte_cryptodev_stop(enabled_devs[i]);
	}
	rte_free(opts.imix_buffer_sizes);
	free_test_vector(t_vec, &opts);

	printf("\n");
	return EXIT_FAILURE;
}
