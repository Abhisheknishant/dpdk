# SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
# Copyright(c) 2018-2019 Pensando Systems, Inc. All rights reserved.

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_pmd_ionic.a

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)

EXPORT_MAP := rte_pmd_ionic_version.map

ifeq ($(CONFIG_RTE_TOOLCHAIN_ICC),y)
#
# CFLAGS for icc
#

else ifeq ($(CONFIG_RTE_TOOLCHAIN_CLANG),y)
#
# CFLAGS for clang
#

else
#
# CFLAGS for gcc
#

endif

#
# all source are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_LIBRTE_IONIC_PMD) += ionic_ethdev.c

include $(RTE_SDK)/mk/rte.lib.mk
