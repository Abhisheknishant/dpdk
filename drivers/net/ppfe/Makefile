# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2019 NXP
#

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_pmd_ppfe.a

CFLAGS += -O3 $(WERROR_FLAGS)
CFLAGS += -Wno-pointer-arith
CFLAGS += -I$(RTE_SDK)/drivers/bus/dpaa/include/
CFLAGS += -I$(RTE_SDK)/drivers/net/ppfe/base/
CFLAGS += -I$(RTE_SDK)/drivers/common/dpaax

EXPORT_MAP := rte_pmd_ppfe_version.map
LIBABIVER := 1

# depends on v2p APIs which uses experimental API
CFLAGS += -DALLOW_EXPERIMENTAL_API

# Interfaces with DPDK
SRCS-$(CONFIG_RTE_LIBRTE_PPFE_PMD) += ppfe_ethdev.c
SRCS-$(CONFIG_RTE_LIBRTE_PPFE_PMD) += pfe_hal.c
SRCS-$(CONFIG_RTE_LIBRTE_PPFE_PMD) += pfe_hif_lib.c
SRCS-$(CONFIG_RTE_LIBRTE_PPFE_PMD) += pfe_hif.c

LDLIBS += -lrte_bus_vdev
LDLIBS += -lrte_bus_dpaa
LDLIBS += -lrte_common_dpaax
LDLIBS += -lrte_eal
LDLIBS += -lrte_ethdev -lrte_kvargs

include $(RTE_SDK)/mk/rte.lib.mk
