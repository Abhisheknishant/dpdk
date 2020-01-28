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

#include <rte_crypto.h>
#include <rte_crypto_sym.h>
#include <rte_cryptodev.h>
#include <rte_cryptodev_pmd.h>

#include "test.h"
#include "test_cryptodev.h"
#include "test_cryptodev_blockcipher.h"
#include "test_cryptodev_aes_test_vectors.h"
#include "test_cryptodev_aead_test_vectors.h"
#include "test_cryptodev_des_test_vectors.h"
#include "test_cryptodev_hash_test_vectors.h"

#define CPU_CRYPTO_TEST_MAX_AAD_LENGTH	16
#define MAX_NB_SEGMENTS			4
#define CACHE_WARM_ITER			2048
#define MAX_SEG_SIZE			2048

#define TOP_ENC		BLOCKCIPHER_TEST_OP_ENCRYPT
#define TOP_DEC		BLOCKCIPHER_TEST_OP_DECRYPT
#define TOP_AUTH_GEN	BLOCKCIPHER_TEST_OP_AUTH_GEN
#define TOP_AUTH_VER	BLOCKCIPHER_TEST_OP_AUTH_VERIFY
#define TOP_ENC_AUTH	BLOCKCIPHER_TEST_OP_ENC_AUTH_GEN
#define TOP_AUTH_DEC	BLOCKCIPHER_TEST_OP_AUTH_VERIFY_DEC

enum buffer_assemble_option {
	SGL_MAX_SEG,
	SGL_ONE_SEG,
};

struct cpu_crypto_test_case {
	struct {
		uint8_t seg[MAX_SEG_SIZE];
		uint32_t seg_len;
	} seg_buf[MAX_NB_SEGMENTS];
	uint8_t iv[MAXIMUM_IV_LENGTH * 2];
	uint8_t aad[CPU_CRYPTO_TEST_MAX_AAD_LENGTH * 4];
	uint8_t digest[DIGEST_BYTE_LENGTH_SHA512];
} __rte_cache_aligned;

struct cpu_crypto_test_obj {
	struct rte_crypto_vec vec[MAX_NUM_OPS_INFLIGHT][MAX_NB_SEGMENTS];
	struct rte_crypto_sgl sec_buf[MAX_NUM_OPS_INFLIGHT];
	void *iv[MAX_NUM_OPS_INFLIGHT];
	void *digest[MAX_NUM_OPS_INFLIGHT];
	void *aad[MAX_NUM_OPS_INFLIGHT];
	int status[MAX_NUM_OPS_INFLIGHT];
};

struct cpu_crypto_testsuite_params {
	struct rte_mempool *buf_pool;
	struct rte_mempool *session_priv_mpool;
};

struct cpu_crypto_unittest_params {
	struct rte_cryptodev_sym_session *sess;
	void *test_datas[MAX_NUM_OPS_INFLIGHT];
	struct cpu_crypto_test_obj test_obj;
	uint32_t nb_bufs;
};

static struct cpu_crypto_testsuite_params testsuite_params;
static struct cpu_crypto_unittest_params unittest_params;

static int gbl_driver_id;

static uint32_t valid_dev;

static int
testsuite_setup(void)
{
	struct cpu_crypto_testsuite_params *ts_params = &testsuite_params;
	uint32_t i, nb_devs;
	size_t sess_sz;
	struct rte_cryptodev_info info;

	const char * const pool_name = "CPU_CRYPTO_MBUFPOOL";

	memset(ts_params, 0, sizeof(*ts_params));

	ts_params->buf_pool = rte_mempool_lookup(pool_name);
	if (ts_params->buf_pool == NULL) {
		/* Not already created so create */
		ts_params->buf_pool = rte_pktmbuf_pool_create(pool_name,
				NUM_MBUFS, MBUF_CACHE_SIZE, 0,
				sizeof(struct cpu_crypto_test_case),
				rte_socket_id());
		if (ts_params->buf_pool == NULL) {
			RTE_LOG(ERR, USER1, "Can't create %s\n", pool_name);
			return TEST_FAILED;
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

	/* get first valid crypto dev */
	valid_dev = UINT32_MAX;
	for (i = 0; i < nb_devs; i++) {
		rte_cryptodev_info_get(i, &info);
		if (info.driver_id == gbl_driver_id &&
				(info.feature_flags &
				RTE_CRYPTODEV_FF_SYM_CPU_CRYPTO) != 0) {
			valid_dev = i;
			break;
		}
	}

	RTE_LOG(INFO, USER1, "Crypto device %u selected for CPU mode test",
		valid_dev);

	if (valid_dev == UINT32_MAX) {
		RTE_LOG(ERR, USER1, "No crypto devices that support CPU mode");
		return TEST_FAILED;
	}

	/* get session size */
	sess_sz = rte_cryptodev_sym_get_private_session_size(valid_dev);

	ts_params->session_priv_mpool = rte_cryptodev_sym_session_pool_create(
		"CRYPTO_SESPOOL", 2, sess_sz, 0, 0, SOCKET_ID_ANY);
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
	struct cpu_crypto_testsuite_params *ts_params = &testsuite_params;
	struct cpu_crypto_unittest_params *ut_params = &unittest_params;

	memset(ut_params, 0, sizeof(*ut_params));

	ut_params->sess = rte_cryptodev_sym_session_create(
		ts_params->session_priv_mpool);

	return ut_params->sess ? TEST_SUCCESS : TEST_FAILED;
}

static void
ut_teardown(void)
{
	struct cpu_crypto_testsuite_params *ts_params = &testsuite_params;
	struct cpu_crypto_unittest_params *ut_params = &unittest_params;

	if (ut_params->sess) {
		rte_cryptodev_sym_session_clear(valid_dev, ut_params->sess);
		rte_cryptodev_sym_session_free(ut_params->sess);
		ut_params->sess = NULL;
	}

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
		if (obj->status[i] != 0)
			return -1;

	return 0;
}

static inline int
init_aead_session(struct rte_cryptodev_sym_session *ses,
		struct rte_mempool *sess_mp,
		enum rte_crypto_aead_operation op,
		const struct aead_test_data *test_data,
		uint32_t is_unit_test)
{
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

	return rte_cryptodev_sym_session_init(valid_dev, ses, &xform,
		sess_mp);
}

static inline int
init_gmac_session(struct rte_cryptodev_sym_session *ses,
		struct rte_mempool *sess_mp,
		enum rte_crypto_auth_operation op,
		const struct gmac_test_data *test_data,
		uint32_t is_unit_test)
{
	struct rte_crypto_sym_xform xform = {0};

	if (is_unit_test)
		debug_hexdump(stdout, "key:", test_data->key.data,
				test_data->key.len);

	/* Setup AEAD Parameters */
	xform.type = RTE_CRYPTO_SYM_XFORM_AUTH;
	xform.next = NULL;
	xform.auth.algo = RTE_CRYPTO_AUTH_AES_GMAC;
	xform.auth.op = op;
	xform.auth.digest_length = test_data->gmac_tag.len;
	xform.auth.key.length = test_data->key.len;
	xform.auth.key.data = test_data->key.data;
	xform.auth.iv.length = test_data->iv.len;
	xform.auth.iv.offset = 0;

	return rte_cryptodev_sym_session_init(valid_dev, ses, &xform, sess_mp);
}


static inline int
prepare_sgl(struct cpu_crypto_test_case *data,
	struct cpu_crypto_test_obj *obj,
	uint32_t obj_idx,
	enum buffer_assemble_option sgl_option,
	const uint8_t *src,
	uint32_t src_len)
{
	uint32_t seg_idx;
	uint32_t bytes_per_seg;
	uint32_t left;

	switch (sgl_option) {
	case SGL_MAX_SEG:
		seg_idx = 0;
		bytes_per_seg = src_len / MAX_NB_SEGMENTS + 1;
		left = src_len;

		if (bytes_per_seg > MAX_SEG_SIZE)
			return -ENOMEM;

		while (left) {
			uint32_t cp_len = RTE_MIN(left, bytes_per_seg);
			memcpy(data->seg_buf[seg_idx].seg, src, cp_len);
			data->seg_buf[seg_idx].seg_len = cp_len;
			obj->vec[obj_idx][seg_idx].base =
					(void *)data->seg_buf[seg_idx].seg;
			obj->vec[obj_idx][seg_idx].len = cp_len;
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
		obj->vec[obj_idx][0].base =
				(void *)data->seg_buf[0].seg;
		obj->vec[obj_idx][0].len = src_len;

		obj->sec_buf[obj_idx].vec = obj->vec[obj_idx];
		obj->sec_buf[obj_idx].num = 1;
		break;
	default:
		return -1;
	}

	return 0;
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
	int ret;

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

	if (src_len > MAX_SEG_SIZE)
		return -ENOMEM;

	ret = prepare_sgl(data, obj, obj_idx, sgl_option, src, src_len);
	if (ret < 0)
		return ret;

	memcpy(data->iv, test_data->iv.data, test_data->iv.len);
	memcpy(data->aad, test_data->aad.data, test_data->aad.len);

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

static inline int
assemble_gmac_buf(struct cpu_crypto_test_case *data,
		struct cpu_crypto_test_obj *obj,
		uint32_t obj_idx,
		enum rte_crypto_auth_operation op,
		const struct gmac_test_data *test_data,
		enum buffer_assemble_option sgl_option,
		uint32_t is_unit_test)
{
	const uint8_t *src;
	uint32_t src_len;
	int ret;

	if (op == RTE_CRYPTO_AUTH_OP_GENERATE) {
		src = test_data->plaintext.data;
		src_len = test_data->plaintext.len;
		if (is_unit_test)
			debug_hexdump(stdout, "plaintext:", src, src_len);
	} else {
		src = test_data->plaintext.data;
		src_len = test_data->plaintext.len;
		memcpy(data->digest, test_data->gmac_tag.data,
			test_data->gmac_tag.len);
		if (is_unit_test)
			debug_hexdump(stdout, "gmac_tag:", src, src_len);
	}

	if (src_len > MAX_SEG_SIZE)
		return -ENOMEM;

	ret = prepare_sgl(data, obj, obj_idx, sgl_option, src, src_len);
	if (ret < 0)
		return ret;

	memcpy(data->iv, test_data->iv.data, test_data->iv.len);

	if (is_unit_test) {
		debug_hexdump(stdout, "iv:", test_data->iv.data,
				test_data->iv.len);
	}

	obj->iv[obj_idx] = (void *)data->iv;
	obj->digest[obj_idx] = (void *)data->digest;

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

	while (left && i < MAX_NB_SEGMENTS) {
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

	while (left && i < MAX_NB_SEGMENTS) {
		debug_hexdump(stdout, err_msg2,
				tcase->seg_buf[i].seg,
				tcase->seg_buf[i].seg_len);
		left -= tcase->seg_buf[i].seg_len;
		i++;
	}
	return ret;
}

static int
check_gmac_result(struct cpu_crypto_test_case *tcase,
		enum rte_crypto_auth_operation op,
		const struct gmac_test_data *tdata)
{
	int ret;

	if (op == RTE_CRYPTO_AUTH_OP_GENERATE) {
		ret = memcmp(tcase->digest, tdata->gmac_tag.data,
				tdata->gmac_tag.len);
		if (ret != 0) {
			debug_hexdump(stdout, "expect digest:",
					tdata->gmac_tag.data,
					tdata->gmac_tag.len);
			debug_hexdump(stdout, "gen digest:",
					tcase->digest,
					tdata->gmac_tag.len);
			return -1;
		}
	}

	return 0;
}

static inline int32_t
run_test(struct rte_cryptodev_sym_session *sess, union rte_crypto_sym_ofs ofs,
		struct cpu_crypto_test_obj *obj, uint32_t n)
{
	struct rte_crypto_sym_vec symvec;

	symvec.sgl = obj->sec_buf;
	symvec.iv = obj->iv;
	symvec.aad = obj->aad;
	symvec.digest = obj->digest;
	symvec.status = obj->status;
	symvec.num = n;

	return rte_cryptodev_sym_cpu_crypto_process(valid_dev, sess, ofs,
		&symvec);
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
	union rte_crypto_sym_ofs ofs;
	int ret;

	ret = init_aead_session(ut_params->sess, ts_params->session_priv_mpool,
		dir, tdata, 1);
	if (ret < 0)
		return ret;

	ret = allocate_buf(1);
	if (ret)
		return ret;

	tcase = ut_params->test_datas[0];
	ret = assemble_aead_buf(tcase, obj, 0, dir, tdata, sgl_option, 1);
	if (ret < 0) {
		printf("Test is not supported by the driver\n");
		return ret;
	}

	/* prepare offset descriptor */
	ofs.raw = 0;

	run_test(ut_params->sess, ofs, obj, 1);

	ret = check_status(obj, 1);
	if (ret < 0)
		return ret;

	ret = check_aead_result(tcase, dir, tdata);
	if (ret < 0)
		return ret;

	return 0;
}

static int
cpu_crypto_test_gmac(const struct gmac_test_data *tdata,
		enum rte_crypto_auth_operation dir,
		enum buffer_assemble_option sgl_option)
{
	struct cpu_crypto_testsuite_params *ts_params = &testsuite_params;
	struct cpu_crypto_unittest_params *ut_params = &unittest_params;
	struct cpu_crypto_test_obj *obj = &ut_params->test_obj;
	struct cpu_crypto_test_case *tcase;
	union rte_crypto_sym_ofs ofs;
	int ret;

	ret = init_gmac_session(ut_params->sess, ts_params->session_priv_mpool,
		dir, tdata, 1);
	if (ret < 0)
		return ret;

	ret = allocate_buf(1);
	if (ret)
		return ret;

	tcase = ut_params->test_datas[0];
	ret = assemble_gmac_buf(tcase, obj, 0, dir, tdata, sgl_option, 1);
	if (ret < 0) {
		printf("Test is not supported by the driver\n");
		return ret;
	}

	/* prepare offset descriptor */
	ofs.raw = 0;

	run_test(ut_params->sess, ofs, obj, 1);

	ret = check_status(obj, 1);
	if (ret < 0)
		return ret;

	ret = check_gmac_result(tcase, dir, tdata);
	if (ret < 0)
		return ret;

	return 0;
}

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

#include "cpu_crypto_all_gcm_unit_test_cases.h"
#undef TEST_EXPAND

#define TEST_EXPAND(t, o)						\
static int								\
cpu_crypto_gmac_gen_test_##t##_##o(void)				\
{									\
	return cpu_crypto_test_gmac(&t, RTE_CRYPTO_AUTH_OP_GENERATE, o);\
}									\
static int								\
cpu_crypto_gmac_ver_test_##t##_##o(void)				\
{									\
	return cpu_crypto_test_gmac(&t, RTE_CRYPTO_AUTH_OP_VERIFY, o);	\
}

#include "cpu_crypto_all_gmac_unit_test_cases.h"
#undef TEST_EXPAND

static struct unit_test_suite cpu_crypto_aesgcm_testsuite  = {
	.suite_name = "CPU Crypto AESNI-GCM Unit Test Suite",
	.setup = testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {

#define TEST_EXPAND(t, o)	\
	TEST_CASE_ST(ut_setup, ut_teardown, cpu_crypto_aead_enc_test_##t##_##o),

#include "cpu_crypto_all_gcm_unit_test_cases.h"
#undef TEST_EXPAND

#define TEST_EXPAND(t, o)	\
	TEST_CASE_ST(ut_setup, ut_teardown, cpu_crypto_aead_dec_test_##t##_##o),

#include "cpu_crypto_all_gcm_unit_test_cases.h"
#undef TEST_EXPAND

#define TEST_EXPAND(t, o)	\
	TEST_CASE_ST(ut_setup, ut_teardown, cpu_crypto_gmac_gen_test_##t##_##o),

#include "cpu_crypto_all_gmac_unit_test_cases.h"
#undef TEST_EXPAND

#define TEST_EXPAND(t, o)	\
	TEST_CASE_ST(ut_setup, ut_teardown, cpu_crypto_gmac_ver_test_##t##_##o),

#include "cpu_crypto_all_gmac_unit_test_cases.h"
#undef TEST_EXPAND

	TEST_CASES_END() /**< NULL terminate unit test array */
	},
};

static int
test_cpu_crypto_aesni_gcm(void)
{
	gbl_driver_id =	rte_cryptodev_driver_id_get(
			RTE_STR(CRYPTODEV_NAME_AESNI_GCM_PMD));

	return unit_test_suite_runner(&cpu_crypto_aesgcm_testsuite);
}


static inline void
gen_rand(uint8_t *data, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < len; i++)
		data[i] = (uint8_t)rte_rand();
}

static inline void
switch_aead_enc_to_dec(struct aead_test_data *tdata,
		struct cpu_crypto_test_case *tcase,
		enum buffer_assemble_option sgl_option)
{
	uint32_t i;
	uint8_t *dst = tdata->ciphertext.data;

	switch (sgl_option) {
	case SGL_ONE_SEG:
		memcpy(dst, tcase->seg_buf[0].seg, tcase->seg_buf[0].seg_len);
		tdata->ciphertext.len = tcase->seg_buf[0].seg_len;
		break;
	case SGL_MAX_SEG:
		tdata->ciphertext.len = 0;
		for (i = 0; i < MAX_NB_SEGMENTS; i++) {
			memcpy(dst, tcase->seg_buf[i].seg,
					tcase->seg_buf[i].seg_len);
			tdata->ciphertext.len += tcase->seg_buf[i].seg_len;
		}
		break;
	}

	memcpy(tdata->auth_tag.data, tcase->digest, tdata->auth_tag.len);
}

static int
cpu_crypto_test_aead_perf(enum buffer_assemble_option sgl_option,
		uint32_t key_sz)
{
	struct aead_test_data tdata = {0};
	struct cpu_crypto_testsuite_params *ts_params = &testsuite_params;
	struct cpu_crypto_unittest_params *ut_params = &unittest_params;
	struct cpu_crypto_test_obj *obj = &ut_params->test_obj;
	struct cpu_crypto_test_case *tcase;
	union rte_crypto_sym_ofs ofs;
	uint64_t hz = rte_get_tsc_hz(), time_start, time_now;
	double rate, cycles_per_buf;
	uint32_t test_data_szs[] = {64, 128, 256, 512, 1024, 2048};
	uint32_t i, j;
	uint8_t aad[16];
	int ret;

	tdata.key.len = key_sz;
	gen_rand(tdata.key.data, tdata.key.len);
	tdata.algo = RTE_CRYPTO_AEAD_AES_GCM;
	tdata.aad.data = aad;
	ofs.raw = 0;

	if (!ut_params->sess)
		return -1;

	init_aead_session(ut_params->sess, ts_params->session_priv_mpool,
		RTE_CRYPTO_AEAD_OP_DECRYPT, &tdata, 0);

	ret = allocate_buf(MAX_NUM_OPS_INFLIGHT);
	if (ret)
		return ret;

	for (i = 0; i < RTE_DIM(test_data_szs); i++) {
		for (j = 0; j < MAX_NUM_OPS_INFLIGHT; j++) {
			tdata.plaintext.len = test_data_szs[i];
			gen_rand(tdata.plaintext.data,
					tdata.plaintext.len);

			tdata.aad.len = 12;
			gen_rand(tdata.aad.data, tdata.aad.len);

			tdata.auth_tag.len = 16;

			tdata.iv.len = 16;
			gen_rand(tdata.iv.data, tdata.iv.len);

			tcase = ut_params->test_datas[j];
			ret = assemble_aead_buf(tcase, obj, j,
					RTE_CRYPTO_AEAD_OP_ENCRYPT,
					&tdata, sgl_option, 0);
			if (ret < 0) {
				printf("Test is not supported by the driver\n");
				return ret;
			}
		}

		/* warm up cache */
		for (j = 0; j < CACHE_WARM_ITER; j++)
			run_test(ut_params->sess, ofs, obj,
				MAX_NUM_OPS_INFLIGHT);

		time_start = rte_rdtsc();

		run_test(ut_params->sess, ofs, obj, MAX_NUM_OPS_INFLIGHT);

		time_now = rte_rdtsc();

		rate = time_now - time_start;
		cycles_per_buf = rate / MAX_NUM_OPS_INFLIGHT;

		rate = ((hz / cycles_per_buf)) / 1000000;

		printf("AES-GCM-%u(%4uB) Enc %03.3fMpps (%03.3fGbps) ",
				key_sz * 8, test_data_szs[i], rate,
				rate  * test_data_szs[i] * 8 / 1000);
		printf("cycles per buf %03.3f per byte %03.3f\n",
				cycles_per_buf,
				cycles_per_buf / test_data_szs[i]);

		for (j = 0; j < MAX_NUM_OPS_INFLIGHT; j++) {
			tcase = ut_params->test_datas[j];

			switch_aead_enc_to_dec(&tdata, tcase, sgl_option);
			ret = assemble_aead_buf(tcase, obj, j,
					RTE_CRYPTO_AEAD_OP_DECRYPT,
					&tdata, sgl_option, 0);
			if (ret < 0) {
				printf("Test is not supported by the driver\n");
				return ret;
			}
		}

		time_start = rte_get_timer_cycles();

		run_test(ut_params->sess, ofs, obj, MAX_NUM_OPS_INFLIGHT);

		time_now = rte_get_timer_cycles();

		rate = time_now - time_start;
		cycles_per_buf = rate / MAX_NUM_OPS_INFLIGHT;

		rate = ((hz / cycles_per_buf)) / 1000000;

		printf("AES-GCM-%u(%4uB) Dec %03.3fMpps (%03.3fGbps) ",
				key_sz * 8, test_data_szs[i], rate,
				rate  * test_data_szs[i] * 8 / 1000);
		printf("cycles per buf %03.3f per byte %03.3f\n",
				cycles_per_buf,
				cycles_per_buf / test_data_szs[i]);
	}

	return 0;
}

/* test-perfix/key-size/sgl-type */
#define TEST_EXPAND(a, b, c)						\
static int								\
cpu_crypto_gcm_perf##a##_##c(void)					\
{									\
	return cpu_crypto_test_aead_perf(c, b);				\
}									\

#include "cpu_crypto_all_gcm_perf_test_cases.h"
#undef TEST_EXPAND

static struct unit_test_suite security_cpu_crypto_aesgcm_perf_testsuite  = {
		.suite_name = "Security CPU Crypto AESNI-GCM Perf Test Suite",
		.setup = testsuite_setup,
		.teardown = testsuite_teardown,
		.unit_test_cases = {
#define TEST_EXPAND(a, b, c)						\
		TEST_CASE_ST(ut_setup, ut_teardown,			\
				cpu_crypto_gcm_perf##a##_##c),		\

#include "cpu_crypto_all_gcm_perf_test_cases.h"
#undef TEST_EXPAND

		TEST_CASES_END() /**< NULL terminate unit test array */
		},
};

static int
test_cpu_crypto_aesni_gcm_perf(void)
{
	gbl_driver_id =	rte_cryptodev_driver_id_get(
			RTE_STR(CRYPTODEV_NAME_AESNI_GCM_PMD));

	return unit_test_suite_runner(
			&security_cpu_crypto_aesgcm_perf_testsuite);
}

REGISTER_TEST_COMMAND(cpu_crypto_aesni_gcm_autotest,
		test_cpu_crypto_aesni_gcm);

REGISTER_TEST_COMMAND(cpu_crypto_aesni_gcm_perftest,
		test_cpu_crypto_aesni_gcm_perf);
