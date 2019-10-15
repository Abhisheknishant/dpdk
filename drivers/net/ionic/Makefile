# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018-2019 Pensando Systems, Inc. All rights reserved.

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_pmd_ionic.a

CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)

EXPORT_MAP := rte_pmd_ionic_version.map

LIBABIVER := 2

ifeq ($(CONFIG_RTE_TOOLCHAIN_ICC),y)
#
# CFLAGS for icc
#
CFLAGS += -diag-disable 174 -diag-disable 593 -diag-disable 869
CFLAGS += -diag-disable 981 -diag-disable 2259 -diag-disable 3656

else ifeq ($(CONFIG_RTE_TOOLCHAIN_CLANG),y)
#
# CFLAGS for clang
#
CFLAGS += -Wno-unused-parameter -Wno-unused-value -Wno-strict-aliasing
CFLAGS += -Wno-format-extra-args

else
#
# CFLAGS for gcc
#
ifeq ($(shell test $(GCC_VERSION) -ge 44 && echo 1), 1)
CFLAGS += -Wno-deprecated -Wno-unused-parameter -Wno-unused-value
CFLAGS += -Wno-strict-aliasing -Wno-format-extra-args
CFLAGS += -Wno-missing-field-initializers -Wno-pointer-arith
endif

ifeq ($(shell test $(GCC_VERSION) -ge 70 && echo 1), 1)
CFLAGS += -Wno-implicit-fallthrough
endif

endif

LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring
LDLIBS += -lrte_ethdev -lrte_net -lrte_kvargs -lrte_hash
LDLIBS += -lrte_bus_pci

#
# all source are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_LIBRTE_IONIC_PMD) += ionic_mac_api.c
SRCS-$(CONFIG_RTE_LIBRTE_IONIC_PMD) += ionic_dev.c
SRCS-$(CONFIG_RTE_LIBRTE_IONIC_PMD) += ionic_ethdev.c
SRCS-$(CONFIG_RTE_LIBRTE_IONIC_PMD) += ionic_main.c

include $(RTE_SDK)/mk/rte.lib.mk
