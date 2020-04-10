/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation.
 */

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_bus_vdev.h>
#include <rte_rawdev.h>
#include <rte_multi_fn.h>
#include <rte_ether.h>
#include <rte_test.h>

#include "aesni_mb_mfn_rawdev.h"
#include "aesni_mb_mfn_rawdev_test_vectors.h"

#define TEST(setup, teardown, run, data, suffix) \
	test_run(setup, teardown, run, data, RTE_STR(run)"_"suffix)

#define TEST_SUCCESS (0)
#define TEST_FAILED  (-1)

#define QP_NB_DESC (4096)

#define MBUF_POOL_NAME        "aesni_mb_mfn_mbuf_pool"
#define MBUF_POOL_SIZE        (8191)
#define MBUF_CACHE_SIZE       (256)
#define MBUF_DATAPAYLOAD_SIZE (2048)
#define MBUF_SIZE             (sizeof(struct rte_mbuf) + \
				RTE_PKTMBUF_HEADROOM + MBUF_DATAPAYLOAD_SIZE)

#define OP_POOL_NAME  "aesni_mb_mfn_op_pool"
#define OP_POOL_SIZE  (8191)
#define OP_PRIV_SIZE  (16)
#define OP_CACHE_SIZE (256)

#define MAX_OPS (3)

static int eal_log_level;

struct testsuite_params {
	uint16_t dev_id;
	struct rte_mempool *mbuf_pool;
	struct rte_mempool *op_pool;
};

struct unittest_params {
	struct rte_multi_fn_session *sess;
	struct rte_multi_fn_op *ops[MAX_OPS];
	struct rte_mbuf *ibuf;
	struct rte_mbuf *obuf;
};

static struct testsuite_params testsuite_params;
static struct unittest_params unittest_params;

static int total;
static int passed;
static int failed;
static int unsupported;

static int
testsuite_setup(uint16_t dev_id)
{
	struct testsuite_params *ts_params = &testsuite_params;
	uint8_t count = rte_rawdev_count();

	eal_log_level = rte_log_get_level(RTE_LOGTYPE_EAL);
	rte_log_set_level(RTE_LOGTYPE_EAL, RTE_LOG_DEBUG);

	memset(ts_params, 0, sizeof(*ts_params));

	if (!count) {
		AESNI_MB_MFN_INFO("No existing rawdev found - creating %s",
				  AESNI_MB_MFN_PMD_RAWDEV_NAME_STR);
		return rte_vdev_init(AESNI_MB_MFN_PMD_RAWDEV_NAME_STR, NULL);
	}

	ts_params->dev_id = dev_id;

	ts_params->mbuf_pool = rte_mempool_lookup(MBUF_POOL_NAME);
	if (ts_params->mbuf_pool == NULL) {
		/* Not already created so create */
		ts_params->mbuf_pool = rte_pktmbuf_pool_create(
						MBUF_POOL_NAME,
						MBUF_POOL_SIZE,
						MBUF_CACHE_SIZE,
						0,
						MBUF_SIZE,
						rte_socket_id());
		if (ts_params->mbuf_pool == NULL) {
			AESNI_MB_MFN_ERR("Cannot create AESNI-MB "
					 "Multi-Function rawdev mbuf pool");
			return TEST_FAILED;
		}
	}

	ts_params->op_pool = rte_multi_fn_op_pool_create(OP_POOL_NAME,
							  OP_POOL_SIZE,
							  OP_CACHE_SIZE,
							  OP_PRIV_SIZE,
							  rte_socket_id());

	if (ts_params->op_pool == NULL) {
		AESNI_MB_MFN_ERR("Cannot create AESNI-MB Multi-Function "
				 "rawdev operation pool");
		return TEST_FAILED;
	}

	return TEST_SUCCESS;
}

static void
testsuite_teardown(void)
{
	struct testsuite_params *ts_params = &testsuite_params;

	if (ts_params->mbuf_pool != NULL) {
		rte_mempool_free(ts_params->mbuf_pool);
		ts_params->mbuf_pool = NULL;
	}

	if (ts_params->op_pool != NULL) {
		rte_mempool_free(ts_params->op_pool);
		ts_params->op_pool = NULL;
	}

	rte_vdev_uninit(AESNI_MB_MFN_PMD_RAWDEV_NAME_STR);

	rte_log_set_level(RTE_LOGTYPE_EAL, eal_log_level);
}

static int
test_setup(void)
{
	struct testsuite_params *ts_params = &testsuite_params;
	struct unittest_params *ut_params = &unittest_params;

	struct rte_rawdev_info info = {0};
	struct rte_multi_fn_dev_config mf_dev_conf = {0};
	struct rte_multi_fn_qp_config qp_conf = {0};
	uint16_t qp_id;
	int ret;

	/* Clear unit test parameters before running test */
	memset(ut_params, 0, sizeof(*ut_params));

	/* Configure device and queue pairs */
	mf_dev_conf.nb_queues = 1;
	info.dev_private = &mf_dev_conf;
	qp_conf.nb_descriptors = QP_NB_DESC;

	ret = rte_rawdev_configure(ts_params->dev_id, &info);
	RTE_TEST_ASSERT_SUCCESS(ret,
				"Failed to configure rawdev %u",
				ts_params->dev_id);

	for (qp_id = 0; qp_id < mf_dev_conf.nb_queues; qp_id++) {
		ret = rte_rawdev_queue_setup(ts_params->dev_id,
					     qp_id,
					     &qp_conf);
		RTE_TEST_ASSERT_SUCCESS(ret,
					"Failed to setup queue pair %u on "
					"rawdev %u",
					qp_id,
					ts_params->dev_id);
	}

	ret = rte_rawdev_xstats_reset(ts_params->dev_id, NULL, 0);
	RTE_TEST_ASSERT_SUCCESS(ret,
				"Failed to reset stats on rawdev %u",
				ts_params->dev_id);

	/* Start the device */
	ret = rte_rawdev_start(ts_params->dev_id);
	RTE_TEST_ASSERT_SUCCESS(ret,
				"Failed to start rawdev %u",
				ts_params->dev_id);

	return 0;
}

static void
test_teardown(void)
{
	struct testsuite_params *ts_params = &testsuite_params;
	struct unittest_params *ut_params = &unittest_params;

	int i;

	/* Free multi-function operations */
	for (i = 0; i < MAX_OPS; i++) {
		if (ut_params->ops[i] != NULL) {
			rte_multi_fn_op_free(ut_params->ops[i]);
			ut_params->ops[i] = NULL;
		}
	}

	/* Free multi-function session */
	if (ut_params->sess != NULL) {
		rte_multi_fn_session_destroy(ts_params->dev_id,
					     ut_params->sess);
		ut_params->sess = NULL;
	}

	/*
	 * Free mbuf - both obuf and ibuf are usually the same,
	 * so check if they point at the same address is necessary,
	 * to avoid freeing the mbuf twice.
	 */
	if (ut_params->obuf != NULL) {
		rte_pktmbuf_free(ut_params->obuf);
		if (ut_params->ibuf == ut_params->obuf)
			ut_params->ibuf = NULL;
		ut_params->obuf = NULL;
	}
	if (ut_params->ibuf != NULL) {
		rte_pktmbuf_free(ut_params->ibuf);
		ut_params->ibuf = NULL;
	}

	/* Stop the device */
	rte_rawdev_stop(ts_params->dev_id);
}

static int
test_docsis_encrypt(void *vtdata)
{
	struct docsis_test_data *tdata = (struct docsis_test_data *)vtdata;
	struct testsuite_params *ts_params = &testsuite_params;
	struct unittest_params *ut_params = &unittest_params;

	/* Xforms */
	struct rte_multi_fn_xform xform1 = {0};
	struct rte_multi_fn_xform xform2 = {0};
	struct rte_crypto_cipher_xform *xform_cipher;

	/* Operations */
	struct rte_multi_fn_op *result;
	struct rte_crypto_sym_op *cipher_op;
	struct rte_multi_fn_err_detect_op *crc_op;

	/* Cipher params */
	int cipher_len = 0;
	uint8_t *iv_ptr;

	/* CRC params */
	int crc_len = 0, crc_data_len = 0;

	/* Test data */
	uint8_t *plaintext = NULL, *ciphertext = NULL;

	/* Stats */
	uint64_t stats[RTE_MULTI_FN_XSTAT_ID_NB] = {0};
	struct rte_rawdev_xstats_name stats_names[RTE_MULTI_FN_XSTAT_ID_NB];
	const unsigned int stats_id[RTE_MULTI_FN_XSTAT_ID_NB] = {0, 1, 2, 3};
	int num_stats = 0, num_names = 0;

	uint16_t qp_id = 0, nb_enq, nb_deq = 0, nb_ops;
	int i, ret = TEST_SUCCESS;

	memset(stats_names, 0, sizeof(stats_names));

	/* Setup source mbuf */
	ut_params->ibuf = rte_pktmbuf_alloc(ts_params->mbuf_pool);
	RTE_TEST_ASSERT_NOT_NULL(ut_params->ibuf,
				 "Failed to allocate source mbuf");
	memset(rte_pktmbuf_mtod(ut_params->ibuf, uint8_t *),
	       0,
	       rte_pktmbuf_tailroom(ut_params->ibuf));
	plaintext = (uint8_t *)rte_pktmbuf_append(ut_params->ibuf,
						  tdata->plaintext.len);
	memcpy(plaintext, tdata->plaintext.data, tdata->plaintext.len);

	/* Create session */
	xform1.type = RTE_MULTI_FN_XFORM_TYPE_ERR_DETECT;
	xform1.err_detect.algo = RTE_MULTI_FN_ERR_DETECT_CRC32_ETH;
	xform1.err_detect.op = RTE_MULTI_FN_ERR_DETECT_OP_GENERATE;
	xform1.next = &xform2;

	xform2.type = RTE_MULTI_FN_XFORM_TYPE_CRYPTO_SYM;
	xform2.crypto_sym.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	xform_cipher = &xform2.crypto_sym.cipher;
	xform_cipher->op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
	xform_cipher->algo = RTE_CRYPTO_CIPHER_AES_DOCSISBPI;
	xform_cipher->key.data = tdata->key.data;
	xform_cipher->key.length = tdata->key.len;
	xform_cipher->iv.offset = sizeof(struct rte_multi_fn_op);
	xform_cipher->iv.length = tdata->cipher_iv.len;
	xform2.next = NULL;

	ut_params->sess = rte_multi_fn_session_create(ts_params->dev_id,
						      &xform1,
						      rte_socket_id());

	RTE_TEST_ASSERT((ut_params->sess != NULL &&
			 ut_params->sess->sess_private_data != NULL),
			"Failed to create multi-function session");

	/* Create operations */
	nb_ops = rte_multi_fn_op_bulk_alloc(ts_params->op_pool,
					    ut_params->ops,
					    2);
	RTE_TEST_ASSERT_EQUAL(nb_ops,
			      2,
			      "Failed to allocate multi-function operations");

	ut_params->ops[0]->next = ut_params->ops[1];
	ut_params->ops[0]->m_src = ut_params->ibuf;
	ut_params->ops[0]->m_dst = NULL;
	ut_params->ops[1]->next = NULL;

	/* CRC op config */
	crc_len = tdata->plaintext.no_crc == false ?
					(tdata->plaintext.len -
					 tdata->plaintext.crc_offset -
					 RTE_ETHER_CRC_LEN) :
					0;
	crc_len = crc_len > 0 ? crc_len : 0;
	crc_data_len = crc_len == 0 ? 0 : RTE_ETHER_CRC_LEN;
	crc_op = &ut_params->ops[0]->err_detect;
	crc_op->data.offset = tdata->plaintext.crc_offset;
	crc_op->data.length = crc_len;
	crc_op->output.data = rte_pktmbuf_mtod_offset(
						ut_params->ibuf,
						uint8_t *,
						ut_params->ibuf->data_len -
							crc_data_len);

	/* Cipher encrypt op config */
	cipher_len = tdata->plaintext.no_cipher == false ?
					(tdata->plaintext.len -
					 tdata->plaintext.cipher_offset) :
					0;
	cipher_len = cipher_len > 0 ? cipher_len : 0;
	cipher_op = &ut_params->ops[1]->crypto_sym;
	cipher_op->cipher.data.offset = tdata->plaintext.cipher_offset;
	cipher_op->cipher.data.length = cipher_len;
	iv_ptr = (uint8_t *)(ut_params->ops[1]) +
				sizeof(struct rte_multi_fn_op);
	rte_memcpy(iv_ptr, tdata->cipher_iv.data, tdata->cipher_iv.len);

	/* Attach session to operation */
	ut_params->ops[0]->sess = ut_params->sess;

	/* Enqueue to device */
	nb_enq = rte_rawdev_enqueue_buffers(
				ts_params->dev_id,
				(struct rte_rawdev_buf **)ut_params->ops,
				1,
				(rte_rawdev_obj_t)&qp_id);

	RTE_TEST_ASSERT_EQUAL(nb_enq,
			      1,
			      "Failed to enqueue multi-function operations");

	/* Dequeue from device */
	do {
		nb_deq = rte_rawdev_dequeue_buffers(
					ts_params->dev_id,
					(struct rte_rawdev_buf **)&result,
					1,
					(rte_rawdev_obj_t)&qp_id);
	} while (nb_deq < 1);

	RTE_TEST_ASSERT_EQUAL(nb_deq,
			      1,
			      "Failed to dequeue multi-function operations");

	/* Check results */
	ciphertext = plaintext;

	/* Validate ciphertext */
	ret = memcmp(ciphertext, tdata->ciphertext.data, tdata->ciphertext.len);
	RTE_TEST_ASSERT_SUCCESS(ret, "Ciphertext not as expected");

	RTE_TEST_ASSERT_EQUAL(result->overall_status,
			      RTE_MULTI_FN_OP_STATUS_SUCCESS,
			      "Multi-function op processing failed");

	/* Print stats */
	num_stats = rte_rawdev_xstats_get(ts_params->dev_id,
					  stats_id,
					  stats,
					  RTE_MULTI_FN_XSTAT_ID_NB);
	num_names = rte_rawdev_xstats_names_get(ts_params->dev_id,
						stats_names,
						RTE_MULTI_FN_XSTAT_ID_NB);
	RTE_TEST_ASSERT_EQUAL(num_stats,
			      RTE_MULTI_FN_XSTAT_ID_NB,
			      "Failed to get stats");
	RTE_TEST_ASSERT_EQUAL(num_names,
			      RTE_MULTI_FN_XSTAT_ID_NB,
			      "Failed to get stats names");

	for (i = 0; i < num_stats; i++)
		AESNI_MB_MFN_DEBUG("%s:  %"PRIu64,
				   stats_names[i].name,
				   stats[i]);

	return 0;
}

static int
test_docsis_decrypt(void *vtdata)
{
	struct docsis_test_data *tdata = (struct docsis_test_data *)vtdata;
	struct testsuite_params *ts_params = &testsuite_params;
	struct unittest_params *ut_params = &unittest_params;

	/* Xforms */
	struct rte_multi_fn_xform xform1 = {0};
	struct rte_multi_fn_xform xform2 = {0};
	struct rte_crypto_cipher_xform *xform_cipher;

	/* Operations */
	struct rte_multi_fn_op *result;
	struct rte_crypto_sym_op *cipher_op;
	struct rte_multi_fn_err_detect_op *crc_op;

	/* Cipher params */
	int cipher_len = 0;
	uint8_t *iv_ptr;

	/* CRC params */
	int crc_len = 0, crc_data_len;

	/* Test data */
	uint8_t *plaintext = NULL, *ciphertext = NULL;

	/* Stats */
	uint64_t stats[RTE_MULTI_FN_XSTAT_ID_NB] = {0};
	struct rte_rawdev_xstats_name stats_names[RTE_MULTI_FN_XSTAT_ID_NB];
	const unsigned int stats_id[RTE_MULTI_FN_XSTAT_ID_NB] = {0, 1, 2, 3};
	int num_stats = 0, num_names = 0;

	uint16_t qp_id = 0, nb_enq, nb_deq = 0, nb_ops;
	int i, ret = TEST_SUCCESS;

	memset(stats_names, 0, sizeof(stats_names));

	/* Setup source mbuf */
	ut_params->ibuf = rte_pktmbuf_alloc(ts_params->mbuf_pool);
	RTE_TEST_ASSERT_NOT_NULL(ut_params->ibuf,
				 "Failed to allocate source mbuf");
	memset(rte_pktmbuf_mtod(ut_params->ibuf, uint8_t *),
	       0,
	       rte_pktmbuf_tailroom(ut_params->ibuf));
	ciphertext = (uint8_t *)rte_pktmbuf_append(ut_params->ibuf,
						   tdata->ciphertext.len);
	memcpy(ciphertext, tdata->ciphertext.data, tdata->ciphertext.len);

	/* Create session */
	xform1.type = RTE_MULTI_FN_XFORM_TYPE_CRYPTO_SYM;
	xform1.crypto_sym.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	xform_cipher = &xform1.crypto_sym.cipher;
	xform_cipher->op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
	xform_cipher->algo = RTE_CRYPTO_CIPHER_AES_DOCSISBPI;
	xform_cipher->key.data = tdata->key.data;
	xform_cipher->key.length = tdata->key.len;
	xform_cipher->iv.offset = sizeof(struct rte_multi_fn_op);
	xform_cipher->iv.length = tdata->cipher_iv.len;
	xform1.next = &xform2;

	xform2.type = RTE_MULTI_FN_XFORM_TYPE_ERR_DETECT;
	xform2.err_detect.algo = RTE_MULTI_FN_ERR_DETECT_CRC32_ETH;
	xform2.err_detect.op = RTE_MULTI_FN_ERR_DETECT_OP_VERIFY;
	xform2.next = NULL;

	ut_params->sess = rte_multi_fn_session_create(ts_params->dev_id,
						      &xform1,
						      rte_socket_id());

	RTE_TEST_ASSERT((ut_params->sess != NULL &&
			 ut_params->sess->sess_private_data != NULL),
			"Failed to create multi-function session");

	/* Create operations */
	nb_ops = rte_multi_fn_op_bulk_alloc(ts_params->op_pool,
					    ut_params->ops,
					    2);
	RTE_TEST_ASSERT_EQUAL(nb_ops,
			      2,
			      "Failed to allocate multi-function operations");

	ut_params->ops[0]->next = ut_params->ops[1];
	ut_params->ops[0]->m_src = ut_params->ibuf;
	ut_params->ops[0]->m_dst = NULL;
	ut_params->ops[1]->next = NULL;

	/* Cipher decrypt op config */
	cipher_len = tdata->ciphertext.no_cipher == false ?
					(tdata->ciphertext.len -
					 tdata->ciphertext.cipher_offset) :
					0;
	cipher_len = cipher_len > 0 ? cipher_len : 0;
	cipher_op = &ut_params->ops[0]->crypto_sym;
	cipher_op->cipher.data.offset = tdata->ciphertext.cipher_offset;
	cipher_op->cipher.data.length = cipher_len;
	iv_ptr = (uint8_t *)(ut_params->ops[1]) +
				sizeof(struct rte_multi_fn_op);
	rte_memcpy(iv_ptr, tdata->cipher_iv.data, tdata->cipher_iv.len);

	/* CRC op config */
	crc_len = tdata->plaintext.no_crc == false ?
					(tdata->ciphertext.len -
					 tdata->ciphertext.crc_offset -
					 RTE_ETHER_CRC_LEN) :
					0;
	crc_len = crc_len > 0 ? crc_len : 0;
	crc_data_len = crc_len == 0 ? 0 : RTE_ETHER_CRC_LEN;
	crc_op = &ut_params->ops[1]->err_detect;
	crc_op->data.offset = tdata->ciphertext.crc_offset;
	crc_op->data.length = crc_len;
	crc_op->output.data = rte_pktmbuf_mtod_offset(
						ut_params->ibuf,
						uint8_t *,
						ut_params->ibuf->data_len -
							crc_data_len);

	/* Attach session to operation */
	ut_params->ops[0]->sess = ut_params->sess;

	/* Enqueue to device */
	nb_enq = rte_rawdev_enqueue_buffers(
				ts_params->dev_id,
				(struct rte_rawdev_buf **)ut_params->ops,
				1,
				(rte_rawdev_obj_t)&qp_id);

	RTE_TEST_ASSERT_EQUAL(nb_enq,
			      1,
			      "Failed to enqueue multi-function operations");

	/* Dequeue to device */
	do {
		nb_deq = rte_rawdev_dequeue_buffers(
					ts_params->dev_id,
					(struct rte_rawdev_buf **)&result,
					1,
					(rte_rawdev_obj_t)&qp_id);
	} while (nb_deq < 1);

	RTE_TEST_ASSERT_EQUAL(nb_deq,
			      1,
			      "Failed to dequeue multi-function operations");

	/* Check results */
	plaintext = ciphertext;

	/* Validate plaintext */
	ret = memcmp(plaintext,
		     tdata->plaintext.data,
		     /* Check only as far as CRC - CRC is checked internally */
		     tdata->plaintext.len - crc_data_len);
	RTE_TEST_ASSERT_SUCCESS(ret, "Plaintext not as expected");

	RTE_TEST_ASSERT_EQUAL(result->overall_status,
			      RTE_MULTI_FN_OP_STATUS_SUCCESS,
			      "Multi-function op processing failed");

	/* Print stats */
	num_stats = rte_rawdev_xstats_get(ts_params->dev_id,
					  stats_id,
					  stats,
					  RTE_MULTI_FN_XSTAT_ID_NB);
	num_names = rte_rawdev_xstats_names_get(ts_params->dev_id,
						stats_names,
						RTE_MULTI_FN_XSTAT_ID_NB);
	RTE_TEST_ASSERT_EQUAL(num_stats,
			      RTE_MULTI_FN_XSTAT_ID_NB,
			      "Failed to get stats");
	RTE_TEST_ASSERT_EQUAL(num_names,
			      RTE_MULTI_FN_XSTAT_ID_NB,
			      "Failed to get stats names");

	for (i = 0; i < num_stats; i++)
		AESNI_MB_MFN_DEBUG("%s:  %"PRIu64,
				   stats_names[i].name,
				   stats[i]);

	return 0;
}

static int
test_gpon_encrypt(void *vtdata)
{
	struct gpon_test_data *tdata = (struct gpon_test_data *)vtdata;
	struct testsuite_params *ts_params = &testsuite_params;
	struct unittest_params *ut_params = &unittest_params;

	/* Xforms */
	struct rte_multi_fn_xform xform1 = {0};
	struct rte_multi_fn_xform xform2 = {0};
	struct rte_multi_fn_xform xform3 = {0};
	struct rte_crypto_cipher_xform *xform_cipher;

	/* Operations */
	struct rte_multi_fn_op *result;
	struct rte_crypto_sym_op *cipher_op;
	struct rte_multi_fn_err_detect_op *crc_op;
	struct rte_multi_fn_err_detect_op *bip_op;

	/* Cipher params */
	int cipher_len = 0;
	uint8_t *iv_ptr;

	/* CRC params */
	int crc_len = 0, crc_data_len = 0;

	/* BIP params */
	int bip_len = 0;

	/* Test data */
	uint8_t *plaintext = NULL, *ciphertext = NULL;

	/* Stats */
	uint64_t stats[RTE_MULTI_FN_XSTAT_ID_NB] = {0};
	struct rte_rawdev_xstats_name stats_names[RTE_MULTI_FN_XSTAT_ID_NB];
	const unsigned int stats_id[RTE_MULTI_FN_XSTAT_ID_NB] = {0, 1, 2, 3};
	int num_stats = 0, num_names = 0;

	uint16_t qp_id = 0, nb_enq, nb_deq = 0, nb_ops;
	int i, ret = TEST_SUCCESS;

	memset(stats_names, 0, sizeof(stats_names));

	/* Setup source mbuf */
	ut_params->ibuf = rte_pktmbuf_alloc(ts_params->mbuf_pool);
	RTE_TEST_ASSERT_NOT_NULL(ut_params->ibuf,
				 "Failed to allocate source mbuf");
	memset(rte_pktmbuf_mtod(ut_params->ibuf, uint8_t *),
	       0,
	       rte_pktmbuf_tailroom(ut_params->ibuf));
	plaintext = (uint8_t *)rte_pktmbuf_append(ut_params->ibuf,
						  tdata->plaintext.len);
	memcpy(plaintext, tdata->plaintext.data, tdata->plaintext.len);

	/* Create session */
	xform1.type = RTE_MULTI_FN_XFORM_TYPE_ERR_DETECT;
	xform1.err_detect.algo = RTE_MULTI_FN_ERR_DETECT_CRC32_ETH;
	xform1.err_detect.op = RTE_MULTI_FN_ERR_DETECT_OP_GENERATE;
	xform1.next = &xform2;

	xform2.type = RTE_MULTI_FN_XFORM_TYPE_CRYPTO_SYM;
	xform2.crypto_sym.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	xform_cipher = &xform2.crypto_sym.cipher;
	xform_cipher->op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
	xform_cipher->algo = RTE_CRYPTO_CIPHER_AES_CTR;
	xform_cipher->key.data = tdata->key.data;
	xform_cipher->key.length = tdata->key.len;
	xform_cipher->iv.offset = sizeof(struct rte_multi_fn_op);
	xform_cipher->iv.length = tdata->cipher_iv.len;
	xform2.next = &xform3;

	xform3.type = RTE_MULTI_FN_XFORM_TYPE_ERR_DETECT;
	xform3.err_detect.algo = RTE_MULTI_FN_ERR_DETECT_BIP32;
	xform3.err_detect.op = RTE_MULTI_FN_ERR_DETECT_OP_GENERATE;
	xform3.next = NULL;

	ut_params->sess = rte_multi_fn_session_create(ts_params->dev_id,
						      &xform1,
						      rte_socket_id());

	RTE_TEST_ASSERT((ut_params->sess != NULL &&
			 ut_params->sess->sess_private_data != NULL),
			"Failed to create multi-function session");

	/* Create operations */
	nb_ops = rte_multi_fn_op_bulk_alloc(ts_params->op_pool,
					    ut_params->ops,
					    3);
	RTE_TEST_ASSERT_EQUAL(nb_ops,
			      3,
			      "Failed to allocate multi-function operations");

	ut_params->ops[0]->next = ut_params->ops[1];
	ut_params->ops[0]->m_src = ut_params->ibuf;
	ut_params->ops[0]->m_dst = NULL;
	ut_params->ops[1]->next = ut_params->ops[2];
	ut_params->ops[2]->next = NULL;

	/* CRC op config */
	crc_len = tdata->plaintext.len -
			tdata->plaintext.crc_offset -
			tdata->plaintext.padding_len -
			RTE_ETHER_CRC_LEN;
	crc_len = crc_len > 0 ? crc_len : 0;
	crc_data_len = crc_len == 0 ? 0 : RTE_ETHER_CRC_LEN;
	crc_op = &ut_params->ops[0]->err_detect;
	crc_op->data.offset = tdata->plaintext.crc_offset;
	crc_op->data.length = crc_len;
	crc_op->output.data = rte_pktmbuf_mtod_offset(
					ut_params->ibuf,
					uint8_t *,
					ut_params->ibuf->data_len -
						tdata->plaintext.padding_len -
						crc_data_len);

	/* Cipher encrypt op config */
	cipher_len = tdata->plaintext.no_cipher == false ?
					(tdata->plaintext.len -
					 tdata->plaintext.cipher_offset) :
					0;
	cipher_len = cipher_len > 0 ? cipher_len : 0;
	cipher_op = &ut_params->ops[1]->crypto_sym;
	cipher_op->cipher.data.offset = tdata->plaintext.cipher_offset;
	cipher_op->cipher.data.length = cipher_len;
	iv_ptr = (uint8_t *)(ut_params->ops[1]) +
				sizeof(struct rte_multi_fn_op);
	rte_memcpy(iv_ptr, tdata->cipher_iv.data, tdata->cipher_iv.len);

	/* BIP op config */
	bip_len = tdata->plaintext.len - tdata->plaintext.bip_offset;
	bip_len = bip_len > 0 ? bip_len : 0;
	bip_op = &ut_params->ops[2]->err_detect;
	bip_op->data.offset = tdata->plaintext.bip_offset;
	bip_op->data.length = bip_len;
	bip_op->output.data = (uint8_t *)(ut_params->ops[2]) +
				sizeof(struct rte_multi_fn_op);

	/* Attach session to op */
	ut_params->ops[0]->sess = ut_params->sess;

	/* Enqueue to device */
	nb_enq = rte_rawdev_enqueue_buffers(
				ts_params->dev_id,
				(struct rte_rawdev_buf **)ut_params->ops,
				1,
				(rte_rawdev_obj_t)&qp_id);

	RTE_TEST_ASSERT_EQUAL(nb_enq,
			      1,
			      "Failed to enqueue multi-function operations");

	/* Dequeue from device */
	do {
		nb_deq = rte_rawdev_dequeue_buffers(
					ts_params->dev_id,
					(struct rte_rawdev_buf **)&result,
					1,
					(rte_rawdev_obj_t)&qp_id);
	} while (nb_deq < 1);

	/* Check results */
	ciphertext = plaintext;

	/* Validate ciphertext */
	ret = memcmp(ciphertext, tdata->ciphertext.data, tdata->ciphertext.len);
	RTE_TEST_ASSERT_SUCCESS(ret, "Ciphertext not as expected");

	ret = memcmp(bip_op->output.data,
		     tdata->output.data,
		     tdata->output.len);
	RTE_TEST_ASSERT_SUCCESS(ret, "BIP not as expected");

	RTE_TEST_ASSERT_EQUAL(result->overall_status,
			      RTE_MULTI_FN_OP_STATUS_SUCCESS,
			      "Multi-function op processing failed");

	/* Print stats */
	num_stats = rte_rawdev_xstats_get(ts_params->dev_id,
					  stats_id,
					  stats,
					  RTE_MULTI_FN_XSTAT_ID_NB);
	num_names = rte_rawdev_xstats_names_get(ts_params->dev_id,
						stats_names,
						RTE_MULTI_FN_XSTAT_ID_NB);
	RTE_TEST_ASSERT_EQUAL(num_stats,
			      RTE_MULTI_FN_XSTAT_ID_NB,
			      "Failed to get stats");
	RTE_TEST_ASSERT_EQUAL(num_names,
			      RTE_MULTI_FN_XSTAT_ID_NB,
			      "Failed to get stats names");

	for (i = 0; i < num_stats; i++)
		AESNI_MB_MFN_DEBUG("%s:  %"PRIu64,
				   stats_names[i].name,
				   stats[i]);

	return 0;
}

static int
test_gpon_decrypt(void *vtdata)
{
	struct gpon_test_data *tdata = (struct gpon_test_data *)vtdata;
	struct testsuite_params *ts_params = &testsuite_params;
	struct unittest_params *ut_params = &unittest_params;

	/* Xforms */
	struct rte_multi_fn_xform xform1 = {0};
	struct rte_multi_fn_xform xform2 = {0};
	struct rte_multi_fn_xform xform3 = {0};
	struct rte_crypto_cipher_xform *xform_cipher;

	/* Operations */
	struct rte_multi_fn_op *result;
	struct rte_crypto_sym_op *cipher_op;
	struct rte_multi_fn_err_detect_op *crc_op;
	struct rte_multi_fn_err_detect_op *bip_op;

	/* Cipher params */
	int cipher_len = 0;
	uint8_t *iv_ptr;

	/* CRC params */
	int crc_len = 0, crc_data_len = 0;

	/* BIP params */
	int bip_len = 0;

	/* Test data */
	uint8_t *plaintext = NULL, *ciphertext = NULL;

	/* Stats */
	uint64_t stats[RTE_MULTI_FN_XSTAT_ID_NB] = {0};
	struct rte_rawdev_xstats_name stats_names[RTE_MULTI_FN_XSTAT_ID_NB];
	const unsigned int stats_id[RTE_MULTI_FN_XSTAT_ID_NB] = {0, 1, 2, 3};
	int num_stats = 0, num_names = 0;

	uint16_t qp_id = 0, nb_enq, nb_deq = 0, nb_ops;
	int i, ret = TEST_SUCCESS;

	memset(stats_names, 0, sizeof(stats_names));

	/* Setup source mbuf */
	ut_params->ibuf = rte_pktmbuf_alloc(ts_params->mbuf_pool);
	RTE_TEST_ASSERT_NOT_NULL(ut_params->ibuf,
				 "Failed to allocate source mbuf");
	memset(rte_pktmbuf_mtod(ut_params->ibuf, uint8_t *),
	       0,
	       rte_pktmbuf_tailroom(ut_params->ibuf));
	ciphertext = (uint8_t *)rte_pktmbuf_append(ut_params->ibuf,
						   tdata->ciphertext.len);
	memcpy(ciphertext, tdata->ciphertext.data, tdata->ciphertext.len);

	/* Create session */
	xform1.type = RTE_MULTI_FN_XFORM_TYPE_ERR_DETECT;
	xform1.err_detect.algo = RTE_MULTI_FN_ERR_DETECT_BIP32;
	xform1.err_detect.op = RTE_MULTI_FN_ERR_DETECT_OP_GENERATE;
	xform1.next = &xform2;

	xform2.type = RTE_MULTI_FN_XFORM_TYPE_CRYPTO_SYM;
	xform2.crypto_sym.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	xform_cipher = &xform2.crypto_sym.cipher;
	xform_cipher->op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
	xform_cipher->algo = RTE_CRYPTO_CIPHER_AES_CTR;
	xform_cipher->key.data = tdata->key.data;
	xform_cipher->key.length = tdata->key.len;
	xform_cipher->iv.offset = sizeof(struct rte_multi_fn_op);
	xform_cipher->iv.length = tdata->cipher_iv.len;
	xform2.next = &xform3;

	xform3.type = RTE_MULTI_FN_XFORM_TYPE_ERR_DETECT;
	xform3.err_detect.algo = RTE_MULTI_FN_ERR_DETECT_CRC32_ETH;
	xform3.err_detect.op = RTE_MULTI_FN_ERR_DETECT_OP_VERIFY;
	xform3.next = NULL;

	ut_params->sess = rte_multi_fn_session_create(ts_params->dev_id,
						      &xform1,
						      rte_socket_id());

	RTE_TEST_ASSERT((ut_params->sess != NULL &&
			 ut_params->sess->sess_private_data != NULL),
			"Failed to create multi-function session");

	/* Create operations */
	nb_ops = rte_multi_fn_op_bulk_alloc(ts_params->op_pool,
					    ut_params->ops,
					    3);
	RTE_TEST_ASSERT_EQUAL(nb_ops,
			      3,
			      "Failed to allocate multi-function operations");

	ut_params->ops[0]->next = ut_params->ops[1];
	ut_params->ops[0]->m_src = ut_params->ibuf;
	ut_params->ops[0]->m_dst = NULL;
	ut_params->ops[1]->next = ut_params->ops[2];
	ut_params->ops[2]->next = NULL;

	/* BIP op config */
	bip_len = tdata->ciphertext.len - tdata->ciphertext.bip_offset;
	bip_len = bip_len > 0 ? bip_len : 0;
	bip_op = &ut_params->ops[0]->err_detect;
	bip_op->data.offset = tdata->ciphertext.bip_offset;
	bip_op->data.length = bip_len;
	bip_op->output.data = (uint8_t *)(ut_params->ops[0]) +
				sizeof(struct rte_multi_fn_op);

	/* Cipher encrypt op config */
	cipher_len = tdata->ciphertext.no_cipher == false ?
					(tdata->ciphertext.len -
					 tdata->ciphertext.cipher_offset) :
					0;
	cipher_len = cipher_len > 0 ? cipher_len : 0;
	cipher_op = &ut_params->ops[1]->crypto_sym;
	cipher_op->cipher.data.offset = tdata->ciphertext.cipher_offset;
	cipher_op->cipher.data.length = cipher_len;
	iv_ptr = (uint8_t *)(ut_params->ops[1]) +
				sizeof(struct rte_multi_fn_op);
	rte_memcpy(iv_ptr, tdata->cipher_iv.data, tdata->cipher_iv.len);

	/* CRC op config */
	crc_len = tdata->ciphertext.len -
			tdata->ciphertext.crc_offset -
			tdata->ciphertext.padding_len -
			RTE_ETHER_CRC_LEN;
	crc_len = crc_len > 0 ? crc_len : 0;
	crc_data_len = crc_len == 0 ? 0 : RTE_ETHER_CRC_LEN;
	crc_op = &ut_params->ops[2]->err_detect;
	crc_op->data.offset = tdata->ciphertext.crc_offset;
	crc_op->data.length = crc_len;
	crc_op->output.data = rte_pktmbuf_mtod_offset(
					ut_params->ibuf,
					uint8_t *,
					ut_params->ibuf->data_len -
						tdata->ciphertext.padding_len -
						crc_data_len);

	/* Attach session to op */
	ut_params->ops[0]->sess = ut_params->sess;

	/* Enqueue to device */
	nb_enq = rte_rawdev_enqueue_buffers(
				ts_params->dev_id,
				(struct rte_rawdev_buf **)ut_params->ops,
				1,
				(rte_rawdev_obj_t)&qp_id);

	RTE_TEST_ASSERT_EQUAL(nb_enq,
			      1,
			      "Failed to enqueue multi-function operations");

	/* Dequeue from device */
	do {
		nb_deq = rte_rawdev_dequeue_buffers(
					ts_params->dev_id,
					(struct rte_rawdev_buf **)&result,
					1,
					(rte_rawdev_obj_t)&qp_id);
	} while (nb_deq < 1);

	/* Check results */
	plaintext = ciphertext;

	/* Validate plaintext */
	ret = memcmp(plaintext,
		     tdata->plaintext.data,
		     /* Check only as far as CRC - CRC is checked internally */
		     tdata->plaintext.len -
			tdata->plaintext.padding_len -
			crc_data_len);
	RTE_TEST_ASSERT_SUCCESS(ret, "Plaintext not as expected");

	ret = memcmp(bip_op->output.data,
		     tdata->output.data,
		     tdata->output.len);
	RTE_TEST_ASSERT_SUCCESS(ret, "BIP not as expected");

	RTE_TEST_ASSERT_EQUAL(result->overall_status,
			      RTE_MULTI_FN_OP_STATUS_SUCCESS,
			      "Multi-function op processing failed");

	/* Print stats */
	num_stats = rte_rawdev_xstats_get(ts_params->dev_id,
					  stats_id,
					  stats,
					  RTE_MULTI_FN_XSTAT_ID_NB);
	num_names = rte_rawdev_xstats_names_get(ts_params->dev_id,
						stats_names,
						RTE_MULTI_FN_XSTAT_ID_NB);
	RTE_TEST_ASSERT_EQUAL(num_stats,
			      RTE_MULTI_FN_XSTAT_ID_NB,
			      "Failed to get stats");
	RTE_TEST_ASSERT_EQUAL(num_names,
			      RTE_MULTI_FN_XSTAT_ID_NB,
			      "Failed to get stats names");

	for (i = 0; i < num_stats; i++)
		AESNI_MB_MFN_DEBUG("%s:  %"PRIu64,
				   stats_names[i].name,
				   stats[i]);

	return 0;
}

static void
test_run(int (*setup)(void),
	 void (*teardown)(void),
	 int (*run)(void *),
	 void *data,
	 const char *name)
{
	int ret = 0;

	if (setup != NULL) {
		ret = setup();
		if (ret < 0) {
			AESNI_MB_MFN_INFO("Error setting up test %s", name);
			unsupported++;
		}
	}

	if (run != NULL) {
		ret = run(data);
		if (ret < 0) {
			failed++;
			AESNI_MB_MFN_INFO("%s Failed", name);
		} else {
			passed++;
			AESNI_MB_MFN_INFO("%s Passed", name);
		}
	}

	if (teardown != NULL)
		teardown();

	total++;
}

int
aesni_mb_mfn_test(uint16_t dev_id)
{
	if (testsuite_setup(dev_id) != TEST_SUCCESS) {
		AESNI_MB_MFN_ERR("Setup failed");
		testsuite_teardown();
		return TEST_FAILED;
	}

	/* DOCSIS: Crypto-CRC */
	TEST(test_setup, test_teardown, test_docsis_encrypt,
	     &docsis_test_case_1, "1");
	TEST(test_setup, test_teardown, test_docsis_encrypt,
	     &docsis_test_case_2, "2");
	TEST(test_setup, test_teardown, test_docsis_encrypt,
	     &docsis_test_case_3, "3");
	TEST(test_setup, test_teardown, test_docsis_encrypt,
	     &docsis_test_case_4, "4");
	TEST(test_setup, test_teardown, test_docsis_encrypt,
	     &docsis_test_case_5, "5");
	TEST(test_setup, test_teardown, test_docsis_encrypt,
	     &docsis_test_case_6, "6");
	TEST(test_setup, test_teardown, test_docsis_encrypt,
	     &docsis_test_case_7, "7");
	TEST(test_setup, test_teardown, test_docsis_encrypt,
	     &docsis_test_case_8, "8");
	TEST(test_setup, test_teardown, test_docsis_encrypt,
	     &docsis_test_case_9, "9");
	TEST(test_setup, test_teardown, test_docsis_encrypt,
	     &docsis_test_case_10, "10");
	TEST(test_setup, test_teardown, test_docsis_encrypt,
	     &docsis_test_case_11, "11");
	TEST(test_setup, test_teardown, test_docsis_encrypt,
	     &docsis_test_case_12, "12");
	TEST(test_setup, test_teardown, test_docsis_encrypt,
	     &docsis_test_case_13, "13");
	TEST(test_setup, test_teardown, test_docsis_decrypt,
	     &docsis_test_case_1, "1");
	TEST(test_setup, test_teardown, test_docsis_decrypt,
	     &docsis_test_case_2, "2");
	TEST(test_setup, test_teardown, test_docsis_decrypt,
	     &docsis_test_case_3, "3");
	TEST(test_setup, test_teardown, test_docsis_decrypt,
	     &docsis_test_case_4, "4");
	TEST(test_setup, test_teardown, test_docsis_decrypt,
	     &docsis_test_case_5, "5");
	TEST(test_setup, test_teardown, test_docsis_decrypt,
	     &docsis_test_case_6, "6");
	TEST(test_setup, test_teardown, test_docsis_decrypt,
	     &docsis_test_case_7, "7");
	TEST(test_setup, test_teardown, test_docsis_decrypt,
	     &docsis_test_case_8, "8");
	TEST(test_setup, test_teardown, test_docsis_decrypt,
	     &docsis_test_case_9, "9");
	TEST(test_setup, test_teardown, test_docsis_decrypt,
	     &docsis_test_case_10, "10");
	TEST(test_setup, test_teardown, test_docsis_decrypt,
	     &docsis_test_case_11, "11");
	TEST(test_setup, test_teardown, test_docsis_decrypt,
	     &docsis_test_case_12, "12");
	TEST(test_setup, test_teardown, test_docsis_decrypt,
	     &docsis_test_case_13, "13");

	/* GPON: Crypto-CRC-BIP */
	TEST(test_setup, test_teardown, test_gpon_encrypt,
	     &gpon_test_case_1, "1");
	TEST(test_setup, test_teardown, test_gpon_encrypt,
	     &gpon_test_case_2, "2");
	TEST(test_setup, test_teardown, test_gpon_encrypt,
	     &gpon_test_case_3, "3");
	TEST(test_setup, test_teardown, test_gpon_encrypt,
	     &gpon_test_case_4, "4");
	TEST(test_setup, test_teardown, test_gpon_encrypt,
	     &gpon_test_case_5, "5");
	TEST(test_setup, test_teardown, test_gpon_encrypt,
	     &gpon_test_case_6, "6");
	TEST(test_setup, test_teardown, test_gpon_decrypt,
	     &gpon_test_case_1, "1");
	TEST(test_setup, test_teardown, test_gpon_decrypt,
	     &gpon_test_case_2, "2");
	TEST(test_setup, test_teardown, test_gpon_decrypt,
	     &gpon_test_case_3, "3");
	TEST(test_setup, test_teardown, test_gpon_decrypt,
	     &gpon_test_case_4, "4");
	TEST(test_setup, test_teardown, test_gpon_decrypt,
	     &gpon_test_case_5, "5");
	TEST(test_setup, test_teardown, test_gpon_decrypt,
	     &gpon_test_case_6, "6");

	testsuite_teardown();

	printf("Total tests   : %d\n", total);
	printf("Passed        : %d\n", passed);
	printf("Failed        : %d\n", failed);
	printf("Not supported : %d\n", unsupported);

	if (failed)
		return TEST_FAILED;

	return TEST_SUCCESS;
}
