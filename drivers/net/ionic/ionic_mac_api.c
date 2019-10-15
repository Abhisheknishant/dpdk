/* SPDX-License-Identifier: GPL-2.0
 * Copyright(c) 2018-2019 Pensando Systems, Inc. All rights reserved.
 */

#include "ionic_mac_api.h"

int32_t
ionic_init_mac(struct ionic_hw *hw)
{
	int err = 0;

	ionic_drv_print_call();

	/*
	 * Set the mac type
	 */
	ionic_set_mac_type(hw);

	switch (hw->mac.type) {
	case IONIC_MAC_CAPRI:
		break;
	default:
		err = -EINVAL;
		break;
	}

	return err;
}

int32_t
ionic_set_mac_type(struct ionic_hw *hw)
{
	int err = 0;

	ionic_drv_print_call();

	if (hw->vendor_id != IONIC_PENSANDO_VENDOR_ID) {
		ionic_drv_print(ERR, "Unsupported vendor id: %x",
				hw->vendor_id);
		return -EINVAL;
	}

	switch (hw->device_id) {
	case IONIC_DEV_ID_ETH_PF:
	case IONIC_DEV_ID_ETH_VF:
	case IONIC_DEV_ID_ETH_MGMT:
		hw->mac.type = IONIC_MAC_CAPRI;
		break;
	default:
		err = -EINVAL;
		ionic_drv_print(ERR, "Unsupported device id: %x",
				hw->device_id);
		break;
	}

	ionic_drv_print(INFO, "Mac: %d (%d)\n",
			hw->mac.type, err);

	return err;
}

