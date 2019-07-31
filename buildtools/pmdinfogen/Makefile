# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2016 Neil Horman <nhorman@tuxdriver.com>
# All rights reserved.

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
HOSTAPP = dpdk-pmdinfogen

HOST_GCC_MAJOR = $(shell echo __GNUC__ | $(HOSTCC) -E -x c - | tail -n 1)
HOST_GCC_MINOR = $(shell echo __GNUC_MINOR__ | $(HOSTCC) -E -x c - | tail -n 1)
HOST_GCC_VERSION = $(HOST_GCC_MAJOR)$(HOST_GCC_MINOR)

ifeq ($(shell test $(HOST_GCC_VERSION) -gt 70 && echo 1), 1)
HOST_WERROR_FLAGS = $(filter-out -Wimplicit-fallthrough=2, $(WERROR_FLAGS))
endif

#
# all sources are stored in SRCS-y
#
SRCS-y += pmdinfogen.c

HOST_CFLAGS += $(HOST_WERROR_FLAGS) -g
HOST_CFLAGS += -I$(RTE_OUTPUT)/include

include $(RTE_SDK)/mk/rte.hostapp.mk
