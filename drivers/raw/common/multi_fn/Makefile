# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Intel Corporation

include $(RTE_SDK)/mk/rte.vars.mk

# library name
LIB = librte_multi_fn.a

# build flags
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -DALLOW_EXPERIMENTAL_API

# versioning export map
EXPORT_MAP := rte_common_multi_fn_version.map

# external library dependencies
LDLIBS += -lrte_eal
#LDLIBS += -lrte_rawdev
#LDLIBS += -lrte_bus_vdev

SRCS-y += rte_multi_fn.c

SYMLINK-y-include += rte_multi_fn.h

include $(RTE_SDK)/mk/rte.lib.mk
