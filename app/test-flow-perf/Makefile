# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020 Mellanox Technologies, Ltd

include $(RTE_SDK)/mk/rte.vars.mk

ifeq ($(CONFIG_RTE_TEST_FLOW_PERF),y)

#
# library name
#
APP = flow_perf

CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -Wno-deprecated-declarations
CFLAGS += -Wno-unused-function

#
# all source are stored in SRCS-y
#
SRCS-y += main.c

include $(RTE_SDK)/mk/rte.app.mk

endif
