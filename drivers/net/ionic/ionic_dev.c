/* SPDX-License-Identifier: GPL-2.0
 * Copyright(c) 2018-2019 Pensando Systems, Inc. All rights reserved.
 */

#include <rte_malloc.h>

#include "ionic_dev.h"
#include "ionic.h"

int
ionic_dev_setup(struct ionic_adapter *adapter)
{
	struct ionic_dev_bar *bar = adapter->bars;
	unsigned int num_bars = adapter->num_bars;
	struct ionic_dev *idev = &adapter->idev;
	uint32_t sig;

	/* BAR0: dev_cmd and interrupts */
	if (num_bars < 1) {
		ionic_init_print(ERR, "No bars found, aborting\n");
		return -EFAULT;
	}

	if (bar->len < IONIC_BAR0_SIZE) {
		ionic_init_print(ERR,
			"Resource bar size %lu too small, aborting\n",
			bar->len);
		return -EFAULT;
	}

	idev->dev_info = bar->vaddr + IONIC_BAR0_DEV_INFO_REGS_OFFSET;
	idev->dev_cmd = bar->vaddr + IONIC_BAR0_DEV_CMD_REGS_OFFSET;
	idev->intr_status = bar->vaddr + IONIC_BAR0_INTR_STATUS_OFFSET;
	idev->intr_ctrl = bar->vaddr + IONIC_BAR0_INTR_CTRL_OFFSET;

	sig = ioread32(&idev->dev_info->signature);
	if (sig != IONIC_DEV_INFO_SIGNATURE) {
		ionic_init_print(ERR, "Incompatible firmware signature %x",
			sig);
		return -EFAULT;
	}

	/* BAR1: doorbells */
	bar++;
	if (num_bars < 2) {
		ionic_init_print(ERR, "Doorbell bar missing, aborting\n");
		return -EFAULT;
	}

	idev->db_pages = bar->vaddr;
	idev->phy_db_pages = bar->bus_addr;

	return 0;
}

/* Devcmd Interface */

uint8_t
ionic_dev_cmd_status(struct ionic_dev *idev)
{
	return ioread8(&idev->dev_cmd->comp.comp.status);
}

bool
ionic_dev_cmd_done(struct ionic_dev *idev)
{
	return ioread32(&idev->dev_cmd->done) & IONIC_DEV_CMD_DONE;
}

void
ionic_dev_cmd_comp(struct ionic_dev *idev, void *mem)
{
	union ionic_dev_cmd_comp *comp = mem;
	unsigned int i;
	uint32_t comp_size = sizeof(comp->words) /
		sizeof(comp->words[0]);

	for (i = 0; i < comp_size; i++)
		comp->words[i] = ioread32(&idev->dev_cmd->comp.words[i]);
}

void
ionic_dev_cmd_go(struct ionic_dev *idev, union ionic_dev_cmd *cmd)
{
	unsigned int i;
	uint32_t cmd_size = sizeof(cmd->words) /
		sizeof(cmd->words[0]);

	for (i = 0; i < cmd_size; i++)
		iowrite32(cmd->words[i], &idev->dev_cmd->cmd.words[i]);

	iowrite32(0, &idev->dev_cmd->done);
	iowrite32(1, &idev->dev_cmd->doorbell);
}

/* Device commands */

void
ionic_dev_cmd_identify(struct ionic_dev *idev, uint8_t ver)
{
	union ionic_dev_cmd cmd = {
		.identify.opcode = IONIC_CMD_IDENTIFY,
		.identify.ver = ver,
	};

	ionic_dev_cmd_go(idev, &cmd);
}

void
ionic_dev_cmd_init(struct ionic_dev *idev)
{
	union ionic_dev_cmd cmd = {
		.init.opcode = IONIC_CMD_INIT,
		.init.type = 0,
	};

	ionic_dev_cmd_go(idev, &cmd);
}

void
ionic_dev_cmd_reset(struct ionic_dev *idev)
{
	union ionic_dev_cmd cmd = {
		.reset.opcode = IONIC_CMD_RESET,
	};

	ionic_dev_cmd_go(idev, &cmd);
}
