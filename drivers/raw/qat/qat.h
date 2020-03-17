/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation.
 */

#ifndef _QAT_H_
#define _QAT_H_

struct qar_raw_pmd_init_params {
	char name[RTE_CRYPTODEV_NAME_MAX_LEN];
	size_t private_data_size;
	int socket_id;
	unsigned int max_nb_queue_pairs;
};

struct qat_raw_dev_private {
	struct qat_pci_device *qat_dev;
	/**< The qat pci device hosting the service */
	uint8_t raw_dev_id;
	/**< Device instance for this rte_cryptodev */
	const struct rte_cryptodev_capabilities *qat_dev_capabilities;
	/* QAT device symmetric crypto capabilities */
	uint16_t min_enq_burst_threshold;
};

struct qat_private {
	struct qat_raw_dev_private raw_priv;
	uint64_t feature_flags;
	struct rte_cryptodev_data *data;
	/**< Pointer to device data */
	struct rte_cryptodev_ops *dev_ops;
	/**< Functions exported by PMD */
	/**< Feature flags exposes HW/SW features for the given device */
	struct rte_device *device;
	/**< Backing device */
	struct rte_cryptodev_cb_list link_intr_cbs;
	/**< User application callback for interrupts if present */
	__extension__
	uint8_t attached : 1;
	/**< Flag indicating the device is attached */
};

int
qat_raw_dev_create(struct qat_pci_device *qat_pci_dev,
		struct qat_dev_cmd_param *qat_dev_cmd_param);

int
qat_raw_dev_destroy(struct qat_pci_device *qat_pci_dev);

#endif /* _QAT_H_ */
