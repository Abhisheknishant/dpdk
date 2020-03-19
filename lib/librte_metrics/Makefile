# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

include $(RTE_SDK)/mk/rte.vars.mk

# library name
LIB = librte_metrics.a

CFLAGS += $(WERROR_FLAGS) -I$(SRCDIR) -O3
CFLAGS += -DALLOW_EXPERIMENTAL_API
LDLIBS += -lrte_eal

EXPORT_MAP := rte_metrics_version.map

# all source are stored in SRCS-y
SRCS-$(CONFIG_RTE_LIBRTE_METRICS) := rte_metrics.c

JANSSON_CFLAGS=$(shell $(PKG_CONFIG) --cflags jansson 2> /dev/null)
JANSSON_LINK=$(shell $(PKG_CONFIG) --libs jansson 2> /dev/null)
ifneq ($(JANSSON_LINK),)
SRCS-y += rte_metrics_telemetry.c
SYMLINK-$(CONFIG_RTE_LIBRTE_METRICS)-include += rte_metrics_telemetry.h

LDLIBS += -lrte_ethdev
LDLIBS += $(JANSSON_LINK)

CFLAGS += $(JANSSON_CFLAGS)
CFLAGS += -I$(RTE_SDK)/lib/librte_telemetry/
endif

# Install header file
SYMLINK-$(CONFIG_RTE_LIBRTE_METRICS)-include += rte_metrics.h

include $(RTE_SDK)/mk/rte.lib.mk
