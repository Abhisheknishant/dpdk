# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2020 Marvell International Ltd.

include $(RTE_SDK)/mk/rte.vars.mk

# library name
LIB = librte_if_proxy.a

CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS) -I$(SRCDIR)
LDLIBS += -lrte_eal -lrte_ethdev

EXPORT_MAP := rte_if_proxy_version.map

LIBABIVER := 1

# all source are stored in SRCS-y
SRCS-$(CONFIG_RTE_LIBRTE_IF_PROXY) := if_proxy_common.c

SYSDIR := $(patsubst "%app",%,$(CONFIG_RTE_EXEC_ENV))
include $(SRCDIR)/$(SYSDIR)/Makefile

SRCS-$(CONFIG_RTE_LIBRTE_IF_PROXY) += $(addprefix $(SYSDIR)/,$(SRCS))

# install this header file
SYMLINK-$(CONFIG_RTE_LIBRTE_IF_PROXY)-include := rte_if_proxy.h

include $(RTE_SDK)/mk/rte.lib.mk
