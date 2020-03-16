/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2017 NXP
 */
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_dev.h>
#include <rte_crypto.h>
#include <rte_rawdev.h>
#include <rte_multi_fn.h>
#include <rte_bus_vdev.h>

#include "test_rawdev_multi_fn_test_vectors.h"
#include "test.h"
#include "test_cryptodev.h"

struct raw_testsuite_params {
	struct rte_mempool *mbuf_pool;
	struct rte_mempool *op_mpool;
	struct rte_rawdev_info info;
	struct rte_multi_fn_device_info priv;
	struct rte_multi_fn_dev_config conf;
	struct rte_multi_fn_qp_config qp_conf;
	uint8_t valid_devs[RTE_RAWDEV_MAX_DEVS];
	uint8_t valid_dev_count;
};

struct raw_unittest_params {
	struct rte_crypto_sym_xform cipher_xform;
	struct rte_crypto_sym_xform auth_xform;
	struct rte_crypto_sym_xform aead_xform;
	struct rte_multi_fn_err_detect_xform err_detect;
	struct rte_multi_fn_session *sess;

	struct rte_crypto_op *op;
	struct rte_mbuf *obuf, *ibuf;

	uint8_t *digest;
};

static int
test_rawdev_selftest_impl(const char *pmd, const char *opts)
{
	rte_vdev_init(pmd, opts);
	return rte_rawdev_selftest(rte_rawdev_get_dev_id(pmd));
}

static int
test_rawdev_selftest_skeleton(void)
{
	return test_rawdev_selftest_impl("rawdev_skeleton", "");
}

REGISTER_TEST_COMMAND(rawdev_autotest, test_rawdev_selftest_skeleton);

static int
test_rawdev_selftest_ioat(void)
{
	const int count = rte_rawdev_count();
	int i;

	for (i = 0; i < count; i++) {
		struct rte_rawdev_info info = { .dev_private = NULL };
		if (rte_rawdev_info_get(i, &info) == 0 &&
				strstr(info.driver_name, "ioat") != NULL)
			return rte_rawdev_selftest(i) == 0 ?
					TEST_SUCCESS : TEST_FAILED;
	}

	printf("No IOAT rawdev found, skipping tests\n");
	return TEST_SKIPPED;
}

REGISTER_TEST_COMMAND(ioat_rawdev_autotest, test_rawdev_selftest_ioat);

static struct raw_testsuite_params testsuite_raw_params = { NULL };
static struct raw_unittest_params unittest_raw_params;

static int
testsuite_raw_setup(void)
{
	int ret;
	uint32_t i = 0, nb_devs, dev_id;
	struct raw_testsuite_params *ts_params = &testsuite_raw_params;
	struct rte_rawdev_info *info = &ts_params->info;
	struct rte_multi_fn_device_info *priv = &ts_params->priv;

	memset(ts_params, 0, sizeof(*ts_params));

	info->dev_private = priv;
	priv->config = &ts_params->conf;

	ts_params->mbuf_pool = rte_mempool_lookup("RAWDEV_MBUFPOOL");
	if (ts_params->mbuf_pool == NULL) {
		/* Not already created so create */
		ts_params->mbuf_pool = rte_pktmbuf_pool_create(
				"RAWDEV_MBUFPOOL",
				NUM_MBUFS, MBUF_CACHE_SIZE, 0, MBUF_SIZE,
				rte_socket_id());
		if (ts_params->mbuf_pool == NULL) {
			RTE_LOG(ERR, USER1, "Can't create RAWDEV_MBUFPOOL\n");
			return TEST_FAILED;
		}
	}

	ts_params->op_mpool = rte_pktmbuf_pool_create("RAWDEV_MULTI_FN_OP_POOL",
			NUM_MBUFS, MBUF_CACHE_SIZE, 0,
			sizeof(struct rte_multi_fn_op) +
			MAXIMUM_IV_LENGTH,
			rte_socket_id());

	if (ts_params->op_mpool == NULL) {
		RTE_LOG(ERR, USER1, "Can't create RAWDEV_MULTI_FN_OP_POOL\n");
		return TEST_FAILED;
	}

	/* Find 1st aesni rawdev. */
	for (i = 0; i < RTE_RAWDEV_MAX_DEVS; i++)
		if (rte_rawdevs[i].driver_name &&
		    (strncmp(rte_rawdevs[i].driver_name, "rawdev_aesni_mb",
		    RTE_RAWDEV_NAME_MAX_LEN) == 0))
			break;

	if (i == RTE_RAWDEV_MAX_DEVS)
		rte_exit(EXIT_FAILURE, "Cannot find any ntb device.\n");

	nb_devs = rte_rawdev_count();
	if (nb_devs < 1) {
		RTE_LOG(WARNING, USER1, "No rawdev devices found?\n");
		return TEST_SKIPPED;
	}

	/* Create list of valid crypto devs */
	for (i = 0; i < nb_devs; i++) {
		rte_rawdev_info_get(i, info);
		if (strncmp(rte_rawdevs[i].driver_name, "rawdev_aesni_mb",
				RTE_RAWDEV_NAME_MAX_LEN) == 0)
			ts_params->valid_devs[ts_params->valid_dev_count++]
					      = i;
	}

	if (ts_params->valid_dev_count < 1)
		return TEST_FAILED;

	/* Set up all the qps on the first of the valid devices found */

	dev_id = ts_params->valid_devs[0];

	ret = rte_rawdev_info_get(dev_id, info);
	if (ret)
		return ret;

	return TEST_SUCCESS;
}

static void
testsuite_raw_teardown(void)
{
	struct raw_testsuite_params *ts_params = &testsuite_raw_params;

	if (ts_params->mbuf_pool != NULL) {
		RTE_LOG(DEBUG, USER1, "CRYPTO_MBUFPOOL count %u\n",
		rte_mempool_avail_count(ts_params->mbuf_pool));
		rte_mempool_free(ts_params->mbuf_pool);
		ts_params->mbuf_pool = NULL;
	}

	if (ts_params->op_mpool != NULL) {
		RTE_LOG(DEBUG, USER1, "CRYPTO_OP_POOL count %u\n",
		rte_mempool_avail_count(ts_params->op_mpool));
		rte_mempool_free(ts_params->op_mpool);
		ts_params->op_mpool = NULL;
	}

	rte_vdev_uninit(RTE_STR(RAWDEV_NAME_AESNI_MB_PMD));
}

static int
ut_raw_setup(void)
{
	int ret;
	struct raw_testsuite_params *ts_params = &testsuite_raw_params;
	struct raw_unittest_params *ut_params = &unittest_raw_params;

	uint16_t qp_id;

	/* Clear unit test parameters before running test */
	memset(ut_params, 0, sizeof(*ut_params));

	/* Reconfigure device to default parameters */
	ts_params->qp_conf.nb_descriptors = MAX_NUM_OPS_INFLIGHT;

	TEST_ASSERT_SUCCESS(rte_rawdev_configure(ts_params->valid_devs[0],
			&ts_params->info),
			"Failed to configure rawdev %u",
			ts_params->valid_devs[0]);

	for (qp_id = 0; qp_id < ts_params->conf.nb_queues ; qp_id++) {
		TEST_ASSERT_SUCCESS(rte_rawdev_queue_setup(
			ts_params->valid_devs[0], qp_id,
			&ts_params->qp_conf),
			"Failed to setup queue pair %u on rawdev %u",
			qp_id, ts_params->valid_devs[0]);
	}

	ret = rte_rawdev_xstats_reset(ts_params->valid_devs[0], NULL, 0);

	TEST_ASSERT_SUCCESS(ret, "Failed to reset rawdev stats");

	/* Start the device */
	TEST_ASSERT_SUCCESS(rte_rawdev_start(ts_params->valid_devs[0]),
			"Failed to start rawdev %u", ts_params->valid_devs[0]);

	return 0;
}

static void
ut_raw_teardown(void)
{
	struct raw_testsuite_params *ts_params = &testsuite_raw_params;
	struct raw_unittest_params *ut_params = &unittest_raw_params;

	/* free crypto operation structure */
	if (ut_params->op)
		rte_crypto_op_free(ut_params->op);

	/*
	 * free mbuf - both obuf and ibuf are usually the same,
	 * so check if they point at the same address is necessary,
	 * to avoid freeing the mbuf twice.
	 */
	if (ut_params->obuf) {
		rte_pktmbuf_free(ut_params->obuf);
		if (ut_params->ibuf == ut_params->obuf)
			ut_params->ibuf = 0;
		ut_params->obuf = 0;
	}
	if (ut_params->ibuf) {
		rte_pktmbuf_free(ut_params->ibuf);
		ut_params->ibuf = 0;
	}

	if (ts_params->mbuf_pool != NULL)
		RTE_LOG(DEBUG, USER1, "CRYPTO_MBUFPOOL count %u\n",
			rte_mempool_avail_count(ts_params->mbuf_pool));

	/* Stop the device */
	rte_rawdev_stop(ts_params->valid_devs[0]);
}

static int
test_session_create_docsis_dl(struct docsis_test_data *d_tc)
{
	uint16_t qpid = 0, enqueued, dequeued = 0;
	uint16_t output_vec_len = 16;
	struct rte_multi_fn_op *ops[2];
	struct rte_multi_fn_op *results;
	struct rte_multi_fn_xform xfrm1 = {0};
	struct rte_multi_fn_xform xfrm2 = {0};
	uint8_t *plaintext = NULL, *ciphertext = NULL;
	struct rte_mbuf *m1, *m2;

	/* Operations */
	struct rte_crypto_sym_op *crypto_sym_op;
	struct rte_multi_fn_err_detect_op *err_detect_op;
	struct raw_testsuite_params *t_param = &testsuite_raw_params;
	struct raw_unittest_params *u_param = &unittest_raw_params;

	int i, ret = TEST_SUCCESS;
	int oop = 0;

	uint8_t key_128bit[16] = {0};
	uint64_t stats[4] = {0};
	const unsigned int stats_id[4] = {1, 2, 3, 4};
	int num_stats = 0;

	/* Docsis test params */
	uint8_t *cipher_iv = NULL;
	uint8_t cipher_iv_len = 0;
	unsigned int cipher_len = 0, auth_len = 0;

	uint8_t dev_id = t_param->valid_devs[0];

	/* Copy key from test vector */
	memcpy(key_128bit, d_tc->key.data, d_tc->key.len);

	debug_hexdump(stdout, "Key:", key_128bit, d_tc->key.len);

	/* multi-operation type session creation */
	xfrm1.type = RTE_MULTI_FN_XFORM_TYPE_CRYPTO_SYM;
	xfrm1.next = &xfrm2;

	xfrm1.crypto_sym.type = RTE_CRYPTO_SYM_XFORM_CIPHER;

	struct rte_crypto_cipher_xform *xfrm_cipher = &xfrm1.crypto_sym.cipher;

	xfrm_cipher->op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
	xfrm_cipher->algo = RTE_CRYPTO_CIPHER_AES_DOCSISBPI;
	xfrm_cipher->key.data = key_128bit;
	xfrm_cipher->key.length = RTE_DIM(key_128bit);
	/*sizeof(key_128bit)/sizeof(key_128bit[0]);*/
	xfrm_cipher->iv.offset = sizeof(struct rte_multi_fn_op);
	xfrm_cipher->iv.length = d_tc->cipher_iv.len;

	xfrm2.type = RTE_MULTI_FN_XFORM_TYPE_ERR_DETECT;
	xfrm2.err_detect.algo = RTE_MULTI_FN_ERR_DETECT_CRC32_ETH;
	xfrm2.err_detect.op = RTE_MULTI_FN_ERR_DETECT_OP_VERIFY;
	xfrm2.next = NULL;

	m1 = rte_pktmbuf_alloc(t_param->mbuf_pool);
	if (!m1) {
		printf("rte_pktmbuf_alloc failed\n");
		return -1;
	}

	/* clear mbuf payload */
	memset(rte_pktmbuf_mtod(m1, uint8_t *), 0, rte_pktmbuf_tailroom(m1));

	if (oop) {
		m2 = rte_pktmbuf_alloc(t_param->mbuf_pool);
		rte_pktmbuf_append(m2, output_vec_len);
	}

	ciphertext = (uint8_t *)rte_pktmbuf_append(m1, d_tc->ciphertext.len);

	memcpy(ciphertext, d_tc->ciphertext.data, d_tc->ciphertext.len);

	debug_hexdump(stdout, "ciphertext:", ciphertext, d_tc->ciphertext.len);

	u_param->sess = rte_multi_fn_session_create(dev_id,
			&t_param->info, &xfrm1, rte_socket_id());

	if ((u_param->sess == NULL) ||
			(u_param->sess->sess_private_data == NULL)) {
		printf("rte_multi_fn_session_create create failed\n");
		return -1;
	}

	/* Create combined DOCSIS operation */
	cipher_iv = d_tc->cipher_iv.data;
	cipher_iv_len = d_tc->cipher_iv.len;

	cipher_len = d_tc->ciphertext.no_cipher == false ?
					(d_tc->ciphertext.len -
					d_tc->ciphertext.cipher_offset) :
					0;
	auth_len = d_tc->ciphertext.no_auth == false ? (d_tc->ciphertext.len -
						d_tc->ciphertext.auth_offset -
						4) :	0;

	ret = rte_mempool_get_bulk(t_param->op_mpool, (void **)ops, 2);
	if (ret) {
		printf("rte_mempool_get_bulk failed to alloc ops\n");
		return -1;
	}

	ops[0]->next = ops[1];
	ops[0]->m_src = m1;
	ops[0]->m_dst = NULL;

	uint8_t *iv_ptr = (uint8_t *)ops[0] + sizeof(
		struct rte_multi_fn_op);
	rte_memcpy(iv_ptr, cipher_iv, cipher_iv_len);

	debug_hexdump(stdout, "iv:", iv_ptr, cipher_iv_len);

	/* crypto decrypt op config */
	crypto_sym_op = &ops[0]->crypto_sym;
	crypto_sym_op->cipher.data.offset = d_tc->ciphertext.cipher_offset;
	crypto_sym_op->cipher.data.length = cipher_len;

	/* error detect op config */
	err_detect_op = &ops[1]->err_detect;
	err_detect_op->data.offset = d_tc->ciphertext.auth_offset;
	err_detect_op->data.length = auth_len;

	/* Attach session to op */
	ops[0]->sess = u_param->sess;

	enqueued = rte_rawdev_enqueue_buffers(dev_id,
			(struct rte_rawdev_buf **) ops, 1,
			(rte_rawdev_obj_t)&qpid);

	if (enqueued != 1)
		printf("rte_accelerator_ops_enqueue failed\n");

	do {
		dequeued = rte_rawdev_dequeue_buffers(dev_id,
				(struct rte_rawdev_buf **)&results, 1,
				(rte_rawdev_obj_t)&qpid);
	} while (dequeued < 1);

	/* Check results. in-place operation */
	plaintext = ciphertext;
	debug_hexdump(stdout, "plaintext:", plaintext, d_tc->plaintext.len);

	/* Validate obuf */
	TEST_ASSERT_BUFFERS_ARE_EQUAL(
			plaintext,
			d_tc->plaintext.data,
			/* Check only plaintext, CRC is checked internally */
			d_tc->plaintext.len - 4,
			"DOCSIS Plaintext data not as expected");

	TEST_ASSERT_EQUAL(results->op_status,
			RTE_MULTI_FN_OP_STATUS_SUCCESS,
			"crypto op processing failed");

	num_stats = rte_rawdev_xstats_get(dev_id, stats_id, stats, 4);
	for (i = 0; i < num_stats; i++)
		printf("Stat num: %d = %"PRIu64"\n", i, stats[i]);

	ret = rte_multi_fn_session_destroy(dev_id, &t_param->info,
			u_param->sess);

	return ret;
}

static int
test_device_configure_docsis_decrypt(void)
{
	return test_session_create_docsis_dl(&docsis_test_case_1);
}

static struct unit_test_suite rawdev_aesni_testsuite  = {
	.suite_name = "Raw Unit Test Suite",
	.setup = testsuite_raw_setup,
	.teardown = testsuite_raw_teardown,
	.unit_test_cases = {
		TEST_CASE_ST(ut_raw_setup, ut_raw_teardown,
				test_device_configure_docsis_decrypt),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};

static int
test_rawdev_aesni(void /*argv __rte_unused, int argc __rte_unused*/)
{
	int i, ret;

	ret = rte_vdev_init(RTE_STR(RAWDEV_NAME_AESNI_MB_PMD), NULL);
	if (ret) {
		RTE_LOG(ERR, USER1, "aesni raw vdev init failed\n");
		return ret;
	}

	/* Find 1st ntb rawdev. */
	for (i = 0; i < RTE_RAWDEV_MAX_DEVS; i++)
		if (rte_rawdevs[i].driver_name &&
		    (strncmp(rte_rawdevs[i].driver_name, "rawdev_aesni_mb",
			RTE_RAWDEV_NAME_MAX_LEN) == 0) &&
			(rte_rawdevs[i].attached == 1))
			break;

	if (i == RTE_RAWDEV_MAX_DEVS) {
		RTE_LOG(ERR, USER1, "aesni raw driver needed to run test\n");
		return TEST_SKIPPED;
	}

	return unit_test_suite_runner(&rawdev_aesni_testsuite);
}

REGISTER_TEST_COMMAND(rawdev_aesni_autotest, test_rawdev_aesni);

