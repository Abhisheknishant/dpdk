#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <rte_errno.h>
#include <rte_log.h>
#include <rte_memory.h>

#include "eal_private.h"

static void *
mem_map(void *requested_addr, size_t size, int prot, int flags,
	int fd, size_t offset)
{
	void *virt = mmap(requested_addr, size, prot, flags, fd, offset);
	if (virt == MAP_FAILED) {
		RTE_LOG(ERR, EAL,
			"Cannot mmap(%p, 0x%zx, 0x%x, 0x%x, %d, 0x%zx): %s\n",
			requested_addr, size, prot, flags, fd, offset,
			strerror(errno));
		rte_errno = errno;
		return NULL;
	}
	return virt;
}

static int
mem_unmap(void *virt, size_t size)
{
	int ret = munmap(virt, size);
	if (ret < 0) {
		RTE_LOG(ERR, EAL, "Cannot munmap(%p, 0x%zx): %s\n",
			virt, size, strerror(errno));
		rte_errno = errno;
	}
	return ret;
}

void *
eal_mem_reserve(void *requested_addr, size_t size,
	enum eal_mem_reserve_flags flags)
{
	int sys_flags = MAP_PRIVATE | MAP_ANONYMOUS;

#ifdef MAP_HUGETLB
	if (flags & EAL_RESERVE_HUGEPAGES)
		sys_flags |= MAP_HUGETLB;
#endif
	if (flags & EAL_RESERVE_EXACT_ADDRESS)
		sys_flags |= MAP_FIXED;

	return mem_map(requested_addr, size, PROT_NONE, sys_flags, -1, 0);
}

void
eal_mem_free(void *virt, size_t size)
{
	mem_unmap(virt, size);
}

static int
mem_rte_to_sys_prot(enum rte_mem_prot prot)
{
	int sys_prot = 0;

	if (prot & RTE_PROT_READ)
		sys_prot |= PROT_READ;
	if (prot & RTE_PROT_WRITE)
		sys_prot |= PROT_WRITE;
	if (prot & RTE_PROT_EXECUTE)
		sys_prot |= PROT_EXEC;

	return sys_prot;
}

void *
rte_mem_map(void *requested_addr, size_t size, enum rte_mem_prot prot,
	enum rte_map_flags flags, int fd, size_t offset)
{
	int sys_prot = 0;
	int sys_flags = 0;

	sys_prot = mem_rte_to_sys_prot(prot);

	if (flags & RTE_MAP_SHARED)
		sys_flags |= MAP_SHARED;
	if (flags & RTE_MAP_ANONYMOUS)
		sys_flags |= MAP_ANONYMOUS;
	if (flags & RTE_MAP_PRIVATE)
		sys_flags |= MAP_PRIVATE;
	if (flags & RTE_MAP_FIXED)
		sys_flags |= MAP_FIXED;

	return mem_map(requested_addr, size, sys_prot, sys_flags, fd, offset);
}

int
rte_mem_unmap(void *virt, size_t size)
{
	return mem_unmap(virt, size);
}

int
rte_get_page_size(void)
{
	return getpagesize();
}

int
rte_mem_lock(const void *virt, size_t size)
{
	return mlock(virt, size);
}
