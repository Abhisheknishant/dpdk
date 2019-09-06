# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2019 Marvell International Ltd.

include $(RTE_SDK)/mk/rte.vars.mk

#
# module name and path
#
MODULE = vfio_pf

#
# CFLAGS
#
MODULE_CFLAGS += -I$(SRCDIR) --param max-inline-insns-single=100
MODULE_CFLAGS += -I$(RTE_OUTPUT)/include
MODULE_CFLAGS += -Winline -Wall -Werror
MODULE_CFLAGS += -include $(RTE_OUTPUT)/include/rte_config.h

#
# all source are stored in SRCS-y
#
SRCS-y := vfio_pf.c

include $(RTE_SDK)/mk/rte.module.mk
