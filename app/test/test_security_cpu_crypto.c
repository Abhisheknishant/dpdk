/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#include <rte_common.h>
#include <rte_hexdump.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_pause.h>
#include <rte_bus_vdev.h>
#include <rte_random.h>

#include <rte_security.h>

#include <rte_crypto.h>
#include <rte_cryptodev.h>
#include <rte_cryptodev_pmd.h>

#include "test.h"
#include "test_cryptodev.h"
#include "test_cryptodev_aead_test_vectors.h"

#define CPU_CRYPTO_TEST_MAX_AAD_LENGTH	16
#define MAX_NB_SIGMENTS			4

enum buffer_assemble_option {
	SGL_MAX_SEG,
	SGL_ONE_SEG,
};

struct cpu_crypto_test_case {
	struct {
		uint8_t seg[MBUF_DATAPAYLOAD_SIZE];
		uint32_t seg_len;
	} seg_buf[MAX_NB_SIGMENTS];
	uint8_t iv[MAXIMUM_IV_LENGTH];
	uint8_t aad[CPU_CRYPTO_TEST_MAX_AAD_LENGTH];
	uint8_t digest[DIGEST_BYTE_LENGTH_SHA512];
} __rte_cache_aligned;

struct cpu_crypto_test_obj {
	struct iovec vec[MAX_NUM_OPS_INFLIGHT][MAX_NB_SIGMENTS];
	struct rte_security_vec sec_buf[MAX_NUM_OPS_INFLIGHT];
	void *iv[MAX_NUM_OPS_INFLIGHT];
	void *digest[MAX_NUM_OPS_INFLIGHT];
	void *aad[MAX_NUM_OPS_INFLIGHT];
	int status[MAX_NUM_OPS_INFLIGHT];
};

struct cpu_crypto_testsuite_params {
	struct rte_mempool *buf_pool;
	struct rte_mempool *session_priv_mpool;
	struct rte_security_ctx *ctx;
};

struct cpu_crypto_unittest_params {
	struct rte_security_session *sess;
	void *test_datas[MAX_NUM_OPS_INFLIGHT];
	struct cpu_crypto_test_obj test_obj;
	uint32_t nb_bufs;
};

static struct cpu_crypto_testsuite_params testsuite_params = { NULL };
static struct cpu_crypto_unittest_params unittest_params;

static int gbl_driver_id;

static int
testsuite_setup(void)
{
	struct cpu_crypto_testsuite_params *ts_params = &testsuite_params;
	struct rte_cryptodev_info info;
	uint32_t i;
	uint32_t nb_devs;
	uint32_t sess_sz;
	int ret;

	memset(ts_params, 0, sizeof(*ts_params));

	ts_params->buf_pool = rte_mempool_lookup("CPU_CRYPTO_MBUFPOOL");
	if (ts_params->buf_pool == NULL) {
		/* Not already created so create */
		ts_params->buf_pool = rte_pktmbuf_pool_create(
				"CRYPTO_MBUFPOOL",
				NUM_MBUFS, MBUF_CACHE_SIZE, 0,
				sizeof(struct cpu_crypto_test_case),
				rte_socket_id());
		if (ts_params->buf_pool == NULL) {
			RTE_LOG(ERR, USER1, "Can't create CRYPTO_MBUFPOOL\n");
			return TEST_FAILED;
		}
	}

	/* Create an AESNI MB device if required */
	if (gbl_driver_id == rte_cryptodev_driver_id_get(
			RTE_STR(CRYPTODEV_NAME_AESNI_MB_PMD))) {
		nb_devs = rte_cryptodev_device_count_by_driver(
				rte_cryptodev_driver_id_get(
				RTE_STR(CRYPTODEV_NAME_AESNI_MB_PMD)));
		if (nb_devs < 1) {
			ret = rte_vdev_init(
				RTE_STR(CRYPTODEV_NAME_AESNI_MB_PMD), NULL);

			TEST_ASSERT(ret == 0,
				"Failed to create instance of"
				" pmd : %s",
				RTE_STR(CRYPTODEV_NAME_AESNI_MB_PMD));
		}
	}

	/* Create an AESNI GCM device if required */
	if (gbl_driver_id == rte_cryptodev_driver_id_get(
			RTE_STR(CRYPTODEV_NAME_AESNI_GCM_PMD))) {
		nb_devs = rte_cryptodev_device_count_by_driver(
				rte_cryptodev_driver_id_get(
				RTE_STR(CRYPTODEV_NAME_AESNI_GCM_PMD)));
		if (nb_devs < 1) {
			TEST_ASSERT_SUCCESS(rte_vdev_init(
				RTE_STR(CRYPTODEV_NAME_AESNI_GCM_PMD), NULL),
				"Failed to create instance of"
				" pmd : %s",
				RTE_STR(CRYPTODEV_NAME_AESNI_GCM_PMD));
		}
	}

	nb_devs = rte_cryptodev_count();
	if (nb_devs < 1) {
		RTE_LOG(ERR, USER1, "No crypto devices found?\n");
		return TEST_FAILED;
	}

	/* Get security context */
	for (i = 0; i < nb_devs; i++) {
		rte_cryptodev_info_get(i, &info);
		if (info.driver_id != gbl_driver_id)
			continue;

		ts_params->ctx = rte_cryptodev_get_sec_ctx(i);
		if (!ts_params->ctx) {
			RTE_LOG(ERR, USER1, "Rte_security is not supported\n");
			return TEST_FAILED;
		}
	}

	sess_sz = rte_security_session_get_size(ts_params->ctx);
	ts_params->session_priv_mpool = rte_mempool_create(
			"cpu_crypto_test_sess_mp", 2, sess_sz, 0, 0,
			NULL, NULL, NULL, NULL,
			SOCKET_ID_ANY, 0);
	if (!ts_params->session_priv_mpool) {
		RTE_LOG(ERR, USER1, "Not enough memory\n");
		return TEST_FAILED;
	}

	return TEST_SUCCESS;
}

static void
testsuite_teardown(void)
{
	struct cpu_crypto_testsuite_params *ts_params = &testsuite_params;

	if (ts_params->buf_pool)
		rte_mempool_free(ts_params->buf_pool);

	if (ts_params->session_priv_mpool)
		rte_mempool_free(ts_params->session_priv_mpool);
}

static int
ut_setup(void)
{
	struct cpu_crypto_unittest_params *ut_params = &unittest_params;

	memset(ut_params, 0, sizeof(*ut_params));
	return TEST_SUCCESS;
}

static void
ut_teardown(void)
{
	struct cpu_crypto_testsuite_params *ts_params = &testsuite_params;
	struct cpu_crypto_unittest_params *ut_params = &unittest_params;

	if (ut_params->sess)
		rte_security_session_destroy(ts_params->ctx, ut_params->sess);

	if (ut_params->nb_bufs) {
		uint32_t i;

		for (i = 0; i < ut_params->nb_bufs; i++)
			memset(ut_params->test_datas[i], 0,
				sizeof(struct cpu_crypto_test_case));

		rte_mempool_put_bulk(ts_params->buf_pool, ut_params->test_datas,
				ut_params->nb_bufs);
	}
}

static int
allocate_buf(uint32_t n)
{
	struct cpu_crypto_testsuite_params *ts_params = &testsuite_params;
	struct cpu_crypto_unittest_params *ut_params = &unittest_params;
	int ret;

	ret = rte_mempool_get_bulk(ts_params->buf_pool, ut_params->test_datas,
			n);

	if (ret == 0)
		ut_params->nb_bufs = n;

	return ret;
}

static int
check_status(struct cpu_crypto_test_obj *obj, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (obj->status[i] < 0)
			return -1;

	return 0;
}

static struct rte_security_session *
create_aead_session(struct rte_security_ctx *ctx,
		struct rte_mempool *sess_mp,
		enum rte_crypto_aead_operation op,
		const struct aead_test_data *test_data,
		uint32_t is_unit_test)
{
	struct rte_security_session_conf sess_conf = {0};
	struct rte_crypto_sym_xform xform = {0};

	if (is_unit_test)
		debug_hexdump(stdout, "key:", test_data->key.data,
				test_data->key.len);

	/* Setup AEAD Parameters */
	xform.type = RTE_CRYPTO_SYM_XFORM_AEAD;
	xform.next = NULL;
	xform.aead.algo = test_data->algo;
	xform.aead.op = op;
	xform.aead.key.data = test_data->key.data;
	xform.aead.key.length = test_data->key.len;
	xform.aead.iv.offset = 0;
	xform.aead.iv.length = test_data->iv.len;
	xform.aead.digest_length = test_data->auth_tag.len;
	xform.aead.aad_length = test_data->aad.len;

	sess_conf.action_type = RTE_SECURITY_ACTION_TYPE_CPU_CRYPTO;
	sess_conf.crypto_xform = &xform;

	return rte_security_session_create(ctx, &sess_conf, sess_mp);
}

static inline int
assemble_aead_buf(struct cpu_crypto_test_case *data,
		struct cpu_crypto_test_obj *obj,
		uint32_t obj_idx,
		enum rte_crypto_aead_operation op,
		const struct aead_test_data *test_data,
		enum buffer_assemble_option sgl_option,
		uint32_t is_unit_test)
{
	const uint8_t *src;
	uint32_t src_len;
	uint32_t seg_idx;
	uint32_t bytes_per_seg;
	uint32_t left;

	if (op == RTE_CRYPTO_AEAD_OP_ENCRYPT) {
		src = test_data->plaintext.data;
		src_len = test_data->plaintext.len;
		if (is_unit_test)
			debug_hexdump(stdout, "plaintext:", src, src_len);
	} else {
		src = test_data->ciphertext.data;
		src_len = test_data->ciphertext.len;
		memcpy(data->digest, test_data->auth_tag.data,
				test_data->auth_tag.len);
		if (is_unit_test) {
			debug_hexdump(stdout, "ciphertext:", src, src_len);
			debug_hexdump(stdout, "digest:",
					test_data->auth_tag.data,
					test_data->auth_tag.len);
		}
	}

	if (src_len > MBUF_DATAPAYLOAD_SIZE)
		return -ENOMEM;

	switch (sgl_option) {
	case SGL_MAX_SEG:
		seg_idx = 0;
		bytes_per_seg = src_len / MAX_NB_SIGMENTS + 1;
		left = src_len;

		if (bytes_per_seg > (MBUF_DATAPAYLOAD_SIZE / MAX_NB_SIGMENTS))
			return -ENOMEM;

		while (left) {
			uint32_t cp_len = RTE_MIN(left, bytes_per_seg);
			memcpy(data->seg_buf[seg_idx].seg, src, cp_len);
			data->seg_buf[seg_idx].seg_len = cp_len;
			obj->vec[obj_idx][seg_idx].iov_base =
					(void *)data->seg_buf[seg_idx].seg;
			obj->vec[obj_idx][seg_idx].iov_len = cp_len;
			src += cp_len;
			left -= cp_len;
			seg_idx++;
		}

		if (left)
			return -ENOMEM;

		obj->sec_buf[obj_idx].vec = obj->vec[obj_idx];
		obj->sec_buf[obj_idx].num = seg_idx;

		break;
	case SGL_ONE_SEG:
		memcpy(data->seg_buf[0].seg, src, src_len);
		data->seg_buf[0].seg_len = src_len;
		obj->vec[obj_idx][0].iov_base =
				(void *)data->seg_buf[0].seg;
		obj->vec[obj_idx][0].iov_len = src_len;

		obj->sec_buf[obj_idx].vec = obj->vec[obj_idx];
		obj->sec_buf[obj_idx].num = 1;
		break;
	default:
		return -1;
	}

	if (test_data->algo == RTE_CRYPTO_AEAD_AES_CCM) {
		memcpy(data->iv + 1, test_data->iv.data, test_data->iv.len);
		memcpy(data->aad + 18, test_data->aad.data, test_data->aad.len);
	} else {
		memcpy(data->iv, test_data->iv.data, test_data->iv.len);
		memcpy(data->aad, test_data->aad.data, test_data->aad.len);
	}

	if (is_unit_test) {
		debug_hexdump(stdout, "iv:", test_data->iv.data,
				test_data->iv.len);
		debug_hexdump(stdout, "aad:", test_data->aad.data,
				test_data->aad.len);
	}

	obj->iv[obj_idx] = (void *)data->iv;
	obj->digest[obj_idx] = (void *)data->digest;
	obj->aad[obj_idx] = (void *)data->aad;

	return 0;
}

#define CPU_CRYPTO_ERR_EXP_CT	"expect ciphertext:"
#define CPU_CRYPTO_ERR_GEN_CT	"gen ciphertext:"
#define CPU_CRYPTO_ERR_EXP_PT	"expect plaintext:"
#define CPU_CRYPTO_ERR_GEN_PT	"gen plaintext:"

static int
check_aead_result(struct cpu_crypto_test_case *tcase,
		enum rte_crypto_aead_operation op,
		const struct aead_test_data *tdata)
{
	const char *err_msg1, *err_msg2;
	const uint8_t *src_pt_ct;
	const uint8_t *tmp_src;
	uint32_t src_len;
	uint32_t left;
	uint32_t i = 0;
	int ret;

	if (op == RTE_CRYPTO_AEAD_OP_ENCRYPT) {
		err_msg1 = CPU_CRYPTO_ERR_EXP_CT;
		err_msg2 = CPU_CRYPTO_ERR_GEN_CT;

		src_pt_ct = tdata->ciphertext.data;
		src_len = tdata->ciphertext.len;

		ret = memcmp(tcase->digest, tdata->auth_tag.data,
				tdata->auth_tag.len);
		if (ret != 0) {
			debug_hexdump(stdout, "expect digest:",
					tdata->auth_tag.data,
					tdata->auth_tag.len);
			debug_hexdump(stdout, "gen digest:",
					tcase->digest,
					tdata->auth_tag.len);
			return -1;
		}
	} else {
		src_pt_ct = tdata->plaintext.data;
		src_len = tdata->plaintext.len;
		err_msg1 = CPU_CRYPTO_ERR_EXP_PT;
		err_msg2 = CPU_CRYPTO_ERR_GEN_PT;
	}

	tmp_src = src_pt_ct;
	left = src_len;

	while (left && i < MAX_NB_SIGMENTS) {
		ret = memcmp(tcase->seg_buf[i].seg, tmp_src,
				tcase->seg_buf[i].seg_len);
		if (ret != 0)
			goto sgl_err_dump;
		tmp_src += tcase->seg_buf[i].seg_len;
		left -= tcase->seg_buf[i].seg_len;
		i++;
	}

	if (left) {
		ret = -ENOMEM;
		goto sgl_err_dump;
	}

	return 0;

sgl_err_dump:
	left = src_len;
	i = 0;

	debug_hexdump(stdout, err_msg1,
			tdata->ciphertext.data,
			tdata->ciphertext.len);

	while (left && i < MAX_NB_SIGMENTS) {
		debug_hexdump(stdout, err_msg2,
				tcase->seg_buf[i].seg,
				tcase->seg_buf[i].seg_len);
		left -= tcase->seg_buf[i].seg_len;
		i++;
	}
	return ret;
}

static inline void
run_test(struct rte_security_ctx *ctx, struct rte_security_session *sess,
		struct cpu_crypto_test_obj *obj, uint32_t n)
{
	rte_security_process_cpu_crypto_bulk(ctx, sess, obj->sec_buf,
			obj->iv, obj->aad, obj->digest, obj->status, n);
}

static int
cpu_crypto_test_aead(const struct aead_test_data *tdata,
		enum rte_crypto_aead_operation dir,
		enum buffer_assemble_option sgl_option)
{
	struct cpu_crypto_testsuite_params *ts_params = &testsuite_params;
	struct cpu_crypto_unittest_params *ut_params = &unittest_params;
	struct cpu_crypto_test_obj *obj = &ut_params->test_obj;
	struct cpu_crypto_test_case *tcase;
	int ret;

	ut_params->sess = create_aead_session(ts_params->ctx,
			ts_params->session_priv_mpool,
			dir,
			tdata,
			1);
	if (!ut_params->sess)
		return -1;

	ret = allocate_buf(1);
	if (ret)
		return ret;

	tcase = ut_params->test_datas[0];
	ret = assemble_aead_buf(tcase, obj, 0, dir, tdata, sgl_option, 1);
	if (ret < 0) {
		printf("Test is not supported by the driver\n");
		return ret;
	}

	run_test(ts_params->ctx, ut_params->sess, obj, 1);

	ret = check_status(obj, 1);
	if (ret < 0)
		return ret;

	ret = check_aead_result(tcase, dir, tdata);
	if (ret < 0)
		return ret;

	return 0;
}

/* test-vector/sgl-option */
#define all_gcm_unit_test_cases(type)		\
	TEST_EXPAND(gcm_test_case_1, type)	\
	TEST_EXPAND(gcm_test_case_2, type)	\
	TEST_EXPAND(gcm_test_case_3, type)	\
	TEST_EXPAND(gcm_test_case_4, type)	\
	TEST_EXPAND(gcm_test_case_5, type)	\
	TEST_EXPAND(gcm_test_case_6, type)	\
	TEST_EXPAND(gcm_test_case_7, type)	\
	TEST_EXPAND(gcm_test_case_8, type)	\
	TEST_EXPAND(gcm_test_case_192_1, type)	\
	TEST_EXPAND(gcm_test_case_192_2, type)	\
	TEST_EXPAND(gcm_test_case_192_3, type)	\
	TEST_EXPAND(gcm_test_case_192_4, type)	\
	TEST_EXPAND(gcm_test_case_192_5, type)	\
	TEST_EXPAND(gcm_test_case_192_6, type)	\
	TEST_EXPAND(gcm_test_case_192_7, type)	\
	TEST_EXPAND(gcm_test_case_256_1, type)	\
	TEST_EXPAND(gcm_test_case_256_2, type)	\
	TEST_EXPAND(gcm_test_case_256_3, type)	\
	TEST_EXPAND(gcm_test_case_256_4, type)	\
	TEST_EXPAND(gcm_test_case_256_5, type)	\
	TEST_EXPAND(gcm_test_case_256_6, type)	\
	TEST_EXPAND(gcm_test_case_256_7, type)


#define TEST_EXPAND(t, o)						\
static int								\
cpu_crypto_aead_enc_test_##t##_##o(void)				\
{									\
	return cpu_crypto_test_aead(&t, RTE_CRYPTO_AEAD_OP_ENCRYPT, o);	\
}									\
static int								\
cpu_crypto_aead_dec_test_##t##_##o(void)				\
{									\
	return cpu_crypto_test_aead(&t, RTE_CRYPTO_AEAD_OP_DECRYPT, o);	\
}									\

all_gcm_unit_test_cases(SGL_ONE_SEG)
all_gcm_unit_test_cases(SGL_MAX_SEG)
#undef TEST_EXPAND

static struct unit_test_suite security_cpu_crypto_aesgcm_testsuite  = {
	.suite_name = "Security CPU Crypto AESNI-GCM Unit Test Suite",
	.setup = testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {
#define TEST_EXPAND(t, o)						\
	TEST_CASE_ST(ut_setup, ut_teardown,				\
			cpu_crypto_aead_enc_test_##t##_##o),		\
	TEST_CASE_ST(ut_setup, ut_teardown,				\
			cpu_crypto_aead_dec_test_##t##_##o),		\

	all_gcm_unit_test_cases(SGL_ONE_SEG)
	all_gcm_unit_test_cases(SGL_MAX_SEG)
#undef TEST_EXPAND

	TEST_CASES_END() /**< NULL terminate unit test array */
	},
};

static int
test_security_cpu_crypto_aesni_gcm(void)
{
	gbl_driver_id =	rte_cryptodev_driver_id_get(
			RTE_STR(CRYPTODEV_NAME_AESNI_GCM_PMD));

	return unit_test_suite_runner(&security_cpu_crypto_aesgcm_testsuite);
}

REGISTER_TEST_COMMAND(security_aesni_gcm_autotest,
		test_security_cpu_crypto_aesni_gcm);
