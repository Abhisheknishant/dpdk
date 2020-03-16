/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation.
 */

#ifndef _RTE_MULTI_FN_H_
#define _RTE_MULTI_FN_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_compat.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_comp.h>
#include <rte_crypto.h>
#include <rte_rawdev.h>

/** Error Detection Algorithms */
enum rte_multi_fn_err_detect_algorithm {
	RTE_MULTI_FN_ERR_DETECT_CRC32_ETH,
	/**< CRC32 Ethernet */
	RTE_MULTI_FN_ERR_DETECT_BIP32
	/**< BIP32 */
};

/** Error Detection Operation Types */
enum rte_multi_fn_err_detect_operation {
	RTE_MULTI_FN_ERR_DETECT_OP_VERIFY,
	/**< Verify error detection result */
	RTE_MULTI_FN_ERR_DETECT_OP_GENERATE
	/**< Generate error detection result */
};

/** Error Detection Status */
enum rte_multi_fn_err_detect_op_status {
	RTE_MULTI_FN_ERR_DETECT_OP_STATUS_NOT_PROCESSED,
	/**< Operation has not yet been processed by a device */
	RTE_MULTI_FN_ERR_DETECT_OP_STATUS_SUCCESS,
	/**< Operation completed successfully */
	RTE_MULTI_FN_ERR_DETECT_OP_STATUS_VERIFY_FAILED,
	/**< Verification failed */
	RTE_MULTI_FN_ERR_DETECT_OP_STATUS_ERROR
	/**< Error handling operation */
};

struct rte_multi_fn_err_detect_xform {
	enum rte_multi_fn_err_detect_operation op;
	/**< Error detection operation type */
	enum rte_multi_fn_err_detect_algorithm algo;
	/**< Error detection algorithm */
	uint16_t err_detect_length;
};

/** Error Detection Operation */
struct rte_multi_fn_err_detect_op {
	struct rte_mbuf *m_src; /**< Source mbuf */
	enum rte_multi_fn_err_detect_op_status status;
	/**< Operation status */

	struct {
		uint16_t offset;
		/**<
		 * Starting point for error detection processing, specified
		 * as the number of bytes from start of the packet in the
		 * source mbuf
		 */
		uint16_t length;
		/**<
		 * The length, in bytes, of the source mbuf on which the error
		 * detection operation will be computed
		 */
	} data; /**< Data offset and length for error detection */

	struct {
		uint8_t *data;
		/**<
		 * This points to the location where the error detection
		 * result should be written (in the case of generation) or
		 * where the purported result exists (in the case of
		 * verification)
		 *
		 * The caller must ensure the required length of physically
		 * contiguous memory is available at this address
		 *
		 * For a CRC, this may point into the mbuf packet data. For
		 * an operation such as a BIP, this may point to a memory
		 * location after the op
		 *
		 * For generation, the result will overwrite any data at this
		 * location
		 */
		rte_iova_t phys_addr;
		/**< Physical address of output data */
	} output; /**< Output location */
};

/**
 * Multi-function transform types
 */
enum rte_multi_fn_xform_type {
	RTE_MULTI_FN_XFORM_TYPE_UNDEFINED,
	/**< Undefined transform type */
	RTE_MULTI_FN_XFORM_TYPE_CRYPTO_SYM,
	/**< Symmetric crypto transform type */
	RTE_MULTI_FN_XFORM_TYPE_CRYPTO_ASYM,
	/**< Asymmetric crypto transform type */
	RTE_MULTI_FN_XFORM_TYPE_COMP,
	/**< Compression transform type */
	RTE_MULTI_FN_XFORM_TYPE_ERR_DETECT
	/**< Error detection transform type */
};

/**
 * Multi-function transform setup data
 *
 * This structure is used to specify the multi-function transforms required.
 * Multiple transforms can be chained together to specify a chain of transforms
 * such as symmetric crypto followed by error detection, or compression followed
 * by symmetric crypto. Each transform structure holds a single transform, with
 * the type field specifying which transform is contained within the union.
 */
struct rte_multi_fn_xform {
	struct rte_multi_fn_xform *next;
	/**<
	 * Next transform in the chain
	 * - the last transform in the chain MUST set this to NULL
	 */
	enum rte_multi_fn_xform_type type;
	/**< Transform type */

	RTE_STD_C11
	union {
		struct rte_crypto_sym_xform crypto_sym;
		/**< Symmetric crypto transform */
		struct rte_crypto_asym_xform crypto_asym;
		/**< Asymmetric crypto transform */
		struct rte_comp_xform comp;
		/**< Compression transform */
		struct rte_multi_fn_err_detect_xform err_detect;
		/**< Error detection transform */
	};
};

/**
 * Multi-function operation status
 */
enum rte_multi_fn_op_status {
	RTE_MULTI_FN_OP_STATUS_SUCCESS = 0,
	/**< Operation completed successfully */
	RTE_MULTI_FN_OP_STATUS_FAILURE,
	/**< Operation completed with failure */
	RTE_MULTI_FN_STATUS_INVALID_SESSION,
	/**< Operation failed due to invalid session arguments */
	RTE_MULTI_FN_OP_STATUS_NOT_PROCESSED,
	/**< Operation has not yet been processed by a device */
};

/**
 * Multi-function session
 */
struct rte_multi_fn_session {
	void *sess_private_data;
};

/**
 * Operation data
 */
struct rte_multi_fn_op {
	struct rte_multi_fn_op *next;
	/**<
	 * Next operation in the chain
	 * - the last operation in the chain MUST set this to NULL
	 */
	struct rte_multi_fn_session *sess;
	/**< Handle for the associated multi fn session */

	struct rte_mempool *mempool;
	/**< Mempool from which the operation is allocated */

	struct rte_mbuf *m_src; /**< Source mbuf */
	struct rte_mbuf *m_dst; /**< Destination mbuf */

	enum rte_multi_fn_op_status overall_status;
	/**<
	 * Overall operation status
	 * - indicates if all the operations in the chain succeeded or if any
	 *   one of them failed
	 */

	uint8_t op_status;
	/**<
	 * Individual operation status
	 * - indicates the status of the individual operation in the chain
	 */

	RTE_STD_C11
	union {
		struct rte_crypto_sym_op crypto_sym;
		/**< Symmetric crypto operation */
		struct rte_crypto_asym_op crypto_asym;
		/**< Asymmetric crypto operation */
		struct rte_comp_op comp;
		/**< Compression operation */
		struct rte_multi_fn_err_detect_op err_detect;
		/**< Error detection operation */
	};
};

/**<
 * Typedef of session create function pointer
 */
typedef struct rte_multi_fn_session *(*session_create)(
		struct rte_rawdev *rawdev,
		struct rte_multi_fn_xform *,
		int);

/**<
 * Typedef of session destroy function pointer
 */
typedef int (*session_destroy)(
		struct rte_rawdev *rawdev,
		struct rte_multi_fn_session *);

/**<
 * Structure containing session create and destroy function
 * pointers and device configuration data.
 */
struct rte_multi_fn_device_info {
	session_create create;
	/**< Create session function pointer */
	session_destroy destroy;
	/**< Destroy session function pointer */
	rte_rawdev_obj_t config;
	/**< Device config info data pointer */
};

/**<
 * Device configuration struct. Pass to rte_rawdev_configure()
 */
struct rte_multi_fn_dev_config {
	uint16_t nb_queues; /**< Number of queue pairs to config */
	unsigned int socket_id; /**< Socket to allocate queue on */
};

/**<
 * Queue pair configuration struct. Passed to rte_rawdev_queue_setup()
 */
struct rte_multi_fn_qp_config {
	uint32_t nb_descriptors; /**< Number of descriptors per queue pair */
};

/**
 * Create multi-function session as specified by the transform chain
 *
 * @param   dev_id	The identifier of the device.
 * @param   dev_info	Device info, obtained by calling rte_info_get()
 * @param   xform	Pointer to the first element of the session transform
 *			chain
 * @param   socket_id	Socket to allocate the session on
 *
 * @return
 *  - Pointer to session, if successful
 *  - NULL, on failure
 */
__rte_experimental
struct rte_multi_fn_session *
rte_multi_fn_session_create(uint16_t dev_id,
				struct rte_rawdev_info *dev_info,
				struct rte_multi_fn_xform *xform,
				int socket_id);

/**
 * Free memory associated with a multi-function session
 *
 * @param   dev_id	The identifier of the device.
 * @param   dev_info	Device info, obtained by calling rte_info_get()
 * @param   sess	Multi-function session to be freed
 *
 * @return
 *  - 0, if successful
 *  - -EINVAL, if session is NULL
 *  - -EBUSY, if not all session data has been freed
 */
__rte_experimental
int
rte_multi_fn_session_destroy(uint16_t dev_id,
				struct rte_rawdev_info *dev_info,
				struct rte_multi_fn_session *sess);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_MULTI_FN_H_ */
