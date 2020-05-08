# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2015 Intel Corporation

include $(RTE_SDK)/mk/rte.vars.mk

# library name
LIB = librte_hash.a

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS) -I$(SRCDIR)
LDLIBS += -lrte_eal -lrte_ring -lrte_mempool

EXPORT_MAP := rte_hash_version.map

# all source are stored in SRCS-y
SRCS-$(CONFIG_RTE_LIBRTE_HASH) := rte_cuckoo_hash.c
SRCS-$(CONFIG_RTE_LIBRTE_HASH) += rte_fbk_hash.c
SRCS-$(CONFIG_RTE_LIBRTE_HASH) += rte_kv_hash.c
SRCS-$(CONFIG_RTE_LIBRTE_HASH) += k32v64_hash.c

# install this header file
SYMLINK-$(CONFIG_RTE_LIBRTE_HASH)-include := rte_hash.h
SYMLINK-$(CONFIG_RTE_LIBRTE_HASH)-include += rte_hash_crc.h
ifeq ($(CONFIG_RTE_ARCH_ARM64),y)
ifneq ($(findstring RTE_MACHINE_CPUFLAG_CRC32,$(CFLAGS)),)
SYMLINK-$(CONFIG_RTE_LIBRTE_HASH)-include += rte_crc_arm64.h
endif
endif
SYMLINK-$(CONFIG_RTE_LIBRTE_HASH)-include += rte_jhash.h
SYMLINK-$(CONFIG_RTE_LIBRTE_HASH)-include += rte_thash.h
SYMLINK-$(CONFIG_RTE_LIBRTE_HASH)-include += rte_fbk_hash.h
SYMLINK-$(CONFIG_RTE_LIBRTE_HASH)-include += rte_kv_hash.h

CC_AVX512VL_SUPPORT=$(shell $(CC) -mavx512vl -dM -E - </dev/null 2>&1 | \
grep -q __AVX512VL__ && echo 1)

ifeq ($(CC_AVX512VL_SUPPORT), 1)
	SRCS-$(CONFIG_RTE_LIBRTE_HASH) += k32v64_hash_avx512vl.c
	CFLAGS_k32v64_hash_avx512vl.o += -mavx512vl
	CFLAGS_k32v64_hash.o += -DCC_AVX512VL_SUPPORT
endif

include $(RTE_SDK)/mk/rte.lib.mk
