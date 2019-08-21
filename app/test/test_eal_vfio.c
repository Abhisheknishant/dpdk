/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <rte_vfio.h>
#include <rte_malloc.h>
#include <rte_eal_memconfig.h>

#include "test.h"

#if !defined(RTE_EXEC_ENV_LINUX) || !defined(RTE_EAL_VFIO)
static int
test_eal_vfio(void)
{
	printf("VFIO not supported, skipping test\n");
	return TEST_SKIPPED;
}

#else

#define PAGESIZE sysconf(_SC_PAGESIZE)
#define INVALID_CONTAINER_FD -5
#define THREE_PAGES 3
#define UNMAPPED_ADDR 0x1500

uint64_t virtaddr_64;
const char *name = "heap";
size_t map_length;
int container_fds[RTE_MAX_VFIO_CONTAINERS];

static int
check_get_mem(void *addr, rte_iova_t *iova)
{
	const struct rte_memseg_list *msl;
	const struct rte_memseg *ms;
	rte_iova_t expected_iova;

	msl = rte_mem_virt2memseg_list(addr);
	if (!msl->external) {
		printf("%s():%i: Memseg list is not marked as "
				"external\n", __func__, __LINE__);
		return -1;
	}
	ms = rte_mem_virt2memseg(addr, msl);
	if (ms == NULL) {
		printf("%s():%i: Failed to retrieve memseg for "
				"external mem\n", __func__, __LINE__);
		return -1;
	}
	if (ms->addr != addr) {
		printf("%s():%i: VA mismatch\n", __func__, __LINE__);
		return -1;
	}
	expected_iova = (iova == NULL) ? RTE_BAD_IOVA : iova[0];
	if (ms->iova != expected_iova) {
		printf("%s():%i: IOVA mismatch\n", __func__, __LINE__);
		return -1;
	}
	return 0;
}

/* Initialize container fds */
static int
initialize_container_fds(void)
{
	int i = 0;

	for (i = 0; i < RTE_MAX_VFIO_CONTAINERS; i++)
		container_fds[i] = -1;

	return TEST_SUCCESS;
}

/* To test vfio container create */
static int
test_vfio_container_create(void)
{
	int ret = 0, i = 0;

	/* check max containers limit */
	for (i = 1; i < RTE_MAX_VFIO_CONTAINERS; i++) {
		container_fds[i] = rte_vfio_container_create();
		TEST_ASSERT(container_fds[i] >  0, "Test to check "
				"rte_vfio_container_create with max "
				"containers limit: Failed\n");
	}

	/* check rte_vfio_container_create when exceeds max containers limit */
	ret = rte_vfio_container_create();
	TEST_ASSERT(ret == -1, "Test to check "
			"rte_vfio_container_create container "
			"when exceeds limit: Failed\n");

	return TEST_SUCCESS;
}

/* To test vfio container destroy */
static int
test_vfio_container_destroy(void)
{
	int i = 0, ret = 0;

	/* check to destroy max container limit */
	for (i = 1; i < RTE_MAX_VFIO_CONTAINERS; i++) {
		ret = rte_vfio_container_destroy(container_fds[i]);
		TEST_ASSERT(ret == 0, "Test to check "
				"rte_vfio_container_destroy: Failed\n");
		container_fds[i] = -1;
	}

	/* check rte_vfio_container_destroy with valid but non existing value */
	ret = rte_vfio_container_destroy(0);
	TEST_ASSERT(ret == -1, "Test to check rte_vfio_container_destroy with "
			"valid but non existing value: Failed\n");

	/* check rte_vfio_container_destroy with invalid value */
	ret = rte_vfio_container_destroy(-5);
	TEST_ASSERT(ret == -1, "Test to check rte_vfio_container_destroy "
			"with invalid value: Failed\n");

	return TEST_SUCCESS;
}

/* Test to bind a IOMMU group to a container*/
static int
test_rte_vfio_container_group_bind(void)
{
	int ret = 0;

	/* Test case to bind with invalid container fd */
	ret = rte_vfio_container_group_bind(INVALID_CONTAINER_FD, 0);
	TEST_ASSERT(ret == -1, "Test to bind a IOMMU group to a container "
			"with invalid fd: Failed\n");

	/* Test case to bind with non-existing container fd */
	ret = rte_vfio_container_group_bind(0, 0);
	TEST_ASSERT(ret == -1, "Test to bind a IOMMU group to a container "
			"with non existing fd: Failed\n");

	return TEST_SUCCESS;
}

/* Test to unbind a IOMMU group from a container*/
static int
test_rte_vfio_container_group_unbind(void)
{
	int ret = 0;

	/* Test case to unbind container from invalid group*/
	ret = rte_vfio_container_group_unbind(INVALID_CONTAINER_FD, 0);
	TEST_ASSERT(ret == -1, "Test to unbind a IOMMU group to a container "
			"with invalid fd: Failed\n");

	/* Test case to unbind container from group*/
	ret = rte_vfio_container_group_unbind(0, 0);
	TEST_ASSERT(ret == -1, "Test to unbind a IOMMU group to a container "
			"with  non existing fd: Failed\n");

	return TEST_SUCCESS;
}

/* Test to get IOMMU group number for a device*/
static int
test_rte_vfio_get_group_num(void)
{
	int ret = 0, invalid_group_num = 0;

	/* Test case to get IOMMU group num from invalid group */
	ret = rte_vfio_get_group_num(NULL, NULL, &invalid_group_num);
	TEST_ASSERT(ret == 0, "Test to get IOMMU group num: Failed\n");

	/* Test case to get IOMMU group num from invalid device address and
	 * valid sysfs_base
	 */
	ret = rte_vfio_get_group_num("/sys/bus/pci/devices/", NULL,
			&invalid_group_num);
	TEST_ASSERT(ret == 0, "Test to get IOMMU group num: Failed\n");

	return TEST_SUCCESS;
}

/* Test to perform DMA mapping for devices in a container */
static int
test_rte_vfio_container_dma_map(void)
{
	int ret = 0, container_fd;

	/* Test case to map device for non-existing container_fd, with
	 * non-zero map_length
	 */
	ret = rte_vfio_container_dma_map(0, 0, 0, map_length);
	TEST_ASSERT(ret == -1, "Test to check map device with invalid "
			"container: Failed\n");

	container_fd = rte_vfio_container_create();
	/* Test case to map device for existing fd with no device attached and
	 * non-zero map_length
	 */
	ret = rte_vfio_container_dma_map(container_fd, 0, 0, map_length);
	TEST_ASSERT(ret == -1, "Test to check  map device for existing fd "
			"with no device attached and non-zero "
			"map_length: Failed\n");

	/* Test to destroy for container fd */
	ret = rte_vfio_container_destroy(container_fd);
	TEST_ASSERT(ret == 0, "Container fd destroy failed\n");

	return TEST_SUCCESS;
}

/* Test to perform DMA unmapping for devices in a container*/
static int
test_rte_vfio_container_dma_unmap(void)
{
	int ret = 0, container_fd;

	/* Test case to unmap device for non-existing container_fd, with
	 * zero map_length
	 */
	ret = rte_vfio_container_dma_unmap(0, 0, 0, 0);
	TEST_ASSERT(ret == -1, "Test to check map device with non-existing "
			"container fd: Failed\n");

	/* Test case to unmap device for non-existing container_fd, with
	 * non-zero map_length
	 */
	ret = rte_vfio_container_dma_unmap(0, 0, 0, map_length);
	TEST_ASSERT(ret == -1, "Test to check map device with non-existing "
			"container fd: Failed\n");

	container_fd = rte_vfio_container_create();
	/* Test case to unmap device for existing fd with no device attached
	 * and with non-zero map_length
	 */
	ret = rte_vfio_container_dma_unmap(container_fd, 0, 0, map_length);
	TEST_ASSERT(ret == -1, "Test to check map device with unmapped "
			"container fd: Failed\n");

	/* Test case to unmap device for existing fd with no device attached
	 * and with zero map_length
	 */
	ret = rte_vfio_container_dma_unmap(container_fd, 0, 0, 0);
	TEST_ASSERT(ret == -1, "Test to check map device with unmapped "
			"container fd: Failed\n");

	/* Test to destroy for container fd */
	ret = rte_vfio_container_destroy(container_fd);
	TEST_ASSERT(ret == 0, "Container fd destroy failed\n");

	return TEST_SUCCESS;
}

/*Function to setup external memory */
static int
test_heap_mem_setup(size_t map_length, int n_pages)
{
	rte_iova_t iova[map_length / PAGESIZE];
	void *addr;

	addr = mmap(NULL, map_length, PROT_WRITE | PROT_READ,
			MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (addr == MAP_FAILED) {
		printf("%s():%i: Failed to create dummy memory area\n",
				__func__, __LINE__);
		return -1;
	}
	rte_iova_t tmp = 0x100000000 + PAGESIZE;
	iova[0] = tmp;

	if (rte_malloc_heap_create(name) != 0) {
		printf("%s():%i: Failed to Create heap with valid name\n",
				__func__, __LINE__);
		return -1;
	}
	if (rte_malloc_heap_memory_add(name, addr, map_length, iova, n_pages,
				PAGESIZE) != 0) {
		printf("%s():%i: Failed to add memory to heap\n",
				__func__, __LINE__);
		return -1;
	}
	if (check_get_mem(addr, iova) != 0) {
		printf("%s():%i: Failed to verify memory\n",
				__func__, __LINE__);

		return -1;
	}
	virtaddr_64 = (uint64_t)(uintptr_t)addr;

	return 0;
}

/* Function to free the external memory */
static void
test_heap_mem_free(void)
{
	if (rte_malloc_heap_memory_remove(name, (void *)virtaddr_64,
				map_length) != 0) {
		printf("%s():%i: Failed to remove memory\n",
				__func__, __LINE__);
		return;
	}
	rte_malloc_heap_destroy(name);

	munmap((void *)virtaddr_64, map_length);
}

/* Test to map memory region for use with VFIO*/
static int
test_rte_vfio_dma_map(void)
{
	int ret = 0;

	const int n_pages = 1;
	map_length = PAGESIZE;

	test_heap_mem_setup(map_length, n_pages);

	/* Test case to map memory for VFIO with zero  vaddr, iova addr
	 * and map_length
	 */
	ret = rte_vfio_dma_map(0, 0, 0);
	TEST_ASSERT(ret == -1, "Test to map devices within default container "
			"with incorrect inputs: Failed\n");

	/* Test case to map memory for VFIO with zero vaddr, iova addr
	 * and valid map_length
	 */
	ret = rte_vfio_dma_map(0, 0, map_length);
	TEST_ASSERT(ret == -1, "Test to map devices within default container "
			"with valid map_length: Failed\n");

	/* Test case to map memory for VFIO with valid iova addr, unmapped
	 * vaddr and valid map_length
	 */
	ret = rte_vfio_dma_map(1000000, 0, map_length);
	TEST_ASSERT(ret == -1, "Test to map devices within default container "
			"with valid map_length and "
			"unmapped virtual address: Failed\n");

	/* Test case to map memory for VFIO with valid iova addr, mapped
	 * vaddr and valid map_length
	 */
	ret = rte_vfio_dma_map(virtaddr_64, 0, map_length);
	TEST_ASSERT(ret == 0, "Test to map devices within default container "
			"with valid map_length and "
			"mapped valid virtual address: Failed\n");

	/* Test case to check already mapped virtual address */
	ret = rte_vfio_dma_map(virtaddr_64, 0, map_length);
	TEST_ASSERT(ret == -1, "Test to map devices within default container "
			"with valid map_length and "
			"mapped valid virtual address: Failed\n");

	/* Test case to check start virtual address + length range overlaps */
	ret = rte_vfio_dma_map((virtaddr_64 + UNMAPPED_ADDR), 0, map_length);
	TEST_ASSERT(ret == -1, "Test to map devices within default container "
			"with overlapping virtual address: Failed\n");

	/* Test case to check start virtual address before
	 * existing map, overlaps
	 */
	ret = rte_vfio_dma_map((virtaddr_64 - UNMAPPED_ADDR), 0, map_length);
	TEST_ASSERT(ret == -1, "Test to map devices within default container "
			"with start virtual address "
			"before existing map, overlaps: Failed\n");

	/* Test case to check invalid map length */
	ret = rte_vfio_dma_map((virtaddr_64 - UNMAPPED_ADDR), 0, 500);
	TEST_ASSERT(ret == -1, "Test to map devices within default container "
			"with invalid map length: Failed\n");

	/* Test case to check already mapped iova overlaps */
	ret = rte_vfio_dma_map((virtaddr_64 + 8192), 0, map_length);
	TEST_ASSERT(ret == -1, "Test to map devices within default container "
			"with already mapped iova overlaps: Failed\n");

	/* Test case to check start iova + length range overlaps */
	ret = rte_vfio_dma_map((virtaddr_64 + 8192), (0 + UNMAPPED_ADDR),
			map_length);
	TEST_ASSERT(ret == -1, "Test to map devices within default container "
			"with start iova + length range overlaps: Failed\n");

	/* Test case to check invalid iova */
	ret = rte_vfio_dma_map((virtaddr_64 + 8192), (0 + 5000), map_length);
	TEST_ASSERT(ret == -1, "Test to map devices within default container "
			"with invalid iova: Failed\n");

	/* Test case to check invalid map length */
	ret = rte_vfio_dma_map((virtaddr_64 + 8192), (0 + UNMAPPED_ADDR), 100);
	TEST_ASSERT(ret == -1, "Test to map devices within default container "
			"with invalid map length: Failed\n");

	/* Test case to map memory for VFIO with invalid vaddr, valid iova addr
	 * and valid map_length
	 */
	uint64_t invalid_addr = virtaddr_64 + 1;
	ret = rte_vfio_dma_map(invalid_addr, virtaddr_64, map_length);
	TEST_ASSERT(ret == -1, "Test to map devices within default container "
			"with mapped invalid virtual address: Failed\n");

	/* Test case to map memory for VFIO with invalid iova addr, valid vaddr
	 * and valid map_length
	 */
	ret = rte_vfio_dma_map(virtaddr_64, UNMAPPED_ADDR, map_length);
	TEST_ASSERT(ret == -1, "Test to map devices within default container "
			"with valid map_length and "
			"invalid iova address: Failed\n");

	/* Test case to unmap memory region from VFIO with valid iova,
	 * mapped vaddr and valid map_length
	 */
	ret = rte_vfio_dma_unmap(virtaddr_64, 0, map_length);
	TEST_ASSERT(ret == 0, "Test to unmap devices in default container "
			"with valid map_length and "
			"mapped valid virtual address: Failed\n");

	return TEST_SUCCESS;
}

/* Test to unmap memory region for use with VFIO*/
static int
test_rte_vfio_dma_unmap(void)
{
	int ret = 0;

	const int n_pages = 1;
	map_length = PAGESIZE;

	test_heap_mem_setup(map_length, n_pages);

	/* Test case to unmap memory region from VFIO with zero vaddr,
	 * iova addr and map_length
	 */
	ret = rte_vfio_dma_unmap(0, 0, 0);
	TEST_ASSERT(ret == -1, "Test to unmap devices in default container "
			"with incorrect input: Failed\n");

	/* Test case to unmap memory region from VFIO with zero vaddr,
	 * iova addr and valid map_length
	 */
	ret = rte_vfio_dma_unmap(0, 0, map_length);
	TEST_ASSERT(ret == -1, "Test to unmap devices in default container "
			"with valid map_length: Failed\n");

	/* Test case to unmap memory region from VFIO with zero iova addr,
	 * unmapped vaddr and valid map_length
	 */
	ret = rte_vfio_dma_unmap(virtaddr_64, 0, map_length);
	TEST_ASSERT(ret == -1, "Test to unmap devices in default container "
			"with valid map_length and unmapped addr: Failed\n");

	/* Test case to unmap memory region from VFIO with unmapped vaddr, iova
	 * and valid map_length
	 */
	ret = rte_vfio_dma_unmap(virtaddr_64, virtaddr_64, map_length);
	TEST_ASSERT(ret == -1, "Test to unmap devices in default container "
			"with valid map_length and "
			"unmapped addr, iova: Failed\n");

	/* Test case to map memory region from VFIO with valid iova,
	 * mapped vaddr and valid map_length
	 */
	ret = rte_vfio_dma_map(virtaddr_64, 0, map_length);
	TEST_ASSERT(ret == 0, "Test to unmap devices in default container "
			"with valid map_length and "
			"mapped valid virtual address: Failed\n");

	/* Test case to unmap memory region from VFIO with mapped invalid vaddr,
	 * valid IOVA and valid map_length
	 */
	ret = rte_vfio_dma_unmap((virtaddr_64 + 1), 0, map_length);
	TEST_ASSERT(ret == -1, "Test to unmap devices in default container "
			"with valid map_length and mapped "
			"invalid virtual address: Failed\n");

	/* Test case to unmap memory region from VFIO with mapped
	 * valid iova addr, vaddr and valid map_length
	 */
	ret = rte_vfio_dma_unmap(virtaddr_64, 0, map_length);
	TEST_ASSERT(ret == 0, "Test to unmap devices in default container "
			 "with valid map_length and mapped "
			 "valid virtual address: Failed\n");

	return TEST_SUCCESS;
}

static int
test_rte_vfio_dma_map_overlaps(void)
{
	int ret = 0;
	const int n_pages = THREE_PAGES;
	map_length = PAGESIZE * THREE_PAGES;

	test_heap_mem_setup(map_length, n_pages);

	/* Test case to map 1st page */
	ret = rte_vfio_dma_map(virtaddr_64, 0, PAGESIZE);
	TEST_ASSERT(ret == 0, "Test to map device in default container "
			"with valid address:Failed\n");

	/* Test case to map same start virtual address and
	 * extend beyond end virtual address
	 */
	ret = rte_vfio_dma_map(virtaddr_64, 0, (PAGESIZE * 2));
	TEST_ASSERT(ret == -1, "Test to map device in default container "
			"with same start virtual address and extend beyond end "
			"virtual address: Failed\n");

	/* Test case to map same start virtual address and same end address*/
	ret = rte_vfio_dma_map(virtaddr_64, 0, PAGESIZE);
	TEST_ASSERT(ret == -1, "Test to map device in default container "
			"with same start virtual address and "
			"same end address: Failed\n");

	/* Test case to unmap 1st page */
	ret = rte_vfio_dma_unmap(virtaddr_64, 0, PAGESIZE);
	TEST_ASSERT(ret == 0, "Test to unmap device in default container "
			"with valid map_length and "
		"mapped valid virtual address: Failed\n");

	/* Test case to map different virtual address */
	ret = rte_vfio_dma_map((virtaddr_64 + PAGESIZE), (0 + PAGESIZE),
			(PAGESIZE * 2));
	TEST_ASSERT(ret == 0, "Test to map device in default container "
			"with different virtual address: Failed\n");

	/* Test case to map different start virtual address and
	 * ends with same address
	 */
	ret = rte_vfio_dma_map((virtaddr_64 + (PAGESIZE * 2)),
			(0 + (PAGESIZE * 2)), PAGESIZE);
	TEST_ASSERT(ret == -1, "Test to map device in default container "
			"with different start virtual address and "
			"ends with same address: Failed\n");

	/* Test case to map three pages */
	ret = rte_vfio_dma_map(virtaddr_64, 0, map_length);
	TEST_ASSERT(ret == -1, "Test to map device in default container "
			"with overlapping virtual address range: Failed\n");

	/* Test case to map middle overlapping virtual address */
	ret = rte_vfio_dma_map((virtaddr_64 + PAGESIZE), (0 + PAGESIZE),
			PAGESIZE);
	TEST_ASSERT(ret == -1, "Test to map device in default container "
			"with overlapping virtual address: Failed\n");

	/* Test case to unmap 1st page */
	ret = rte_vfio_dma_unmap(virtaddr_64, 0, PAGESIZE);
	TEST_ASSERT(ret == -1, "Test to unmap 1st page: Failed\n");

	/* Test case to map 1st and 2nd page overlaps */
	ret = rte_vfio_dma_map(virtaddr_64, 0, (PAGESIZE * 2));
	TEST_ASSERT(ret == -1, "Test to map device in default container "
			"with 1st and 2nd page overlaps: Failed\n");

	/* Test case to map 3rd and 4th pages */
	ret = rte_vfio_dma_map((virtaddr_64 + (PAGESIZE * 2)),
			(0 + (PAGESIZE * 2)), (PAGESIZE * 2));
	TEST_ASSERT(ret == -1, "Test to map device in default container "
			"with 3rd and 4th pages: Failed\n");

	/* Test case to unmap 3rd page */
	ret = rte_vfio_dma_unmap((virtaddr_64 + (PAGESIZE * 2)),
			(0 + (PAGESIZE * 2)), PAGESIZE);
	TEST_ASSERT(ret == 0, "Test to unmap 3rd page: Failed\n");

	/* Test case to map 1st page with total length
	 * that overlaps middle page
	 */
	ret = rte_vfio_dma_map(virtaddr_64, 0, map_length);
	TEST_ASSERT(ret == -1, "Test to map device in default container "
			"with 1st page with total length "
			"that overlaps middle page: Failed\n");

	/* Test case to unmap 2nd page  */
	ret = rte_vfio_dma_unmap((virtaddr_64 + PAGESIZE), (0 + PAGESIZE),
			PAGESIZE);
	TEST_ASSERT(ret == 0, "Test to unmap 2nd page: Failed\n");

	return TEST_SUCCESS;
}

/*allocate three pages */
static int
test_rte_vfio_dma_map_threepages(void)
{
	int ret = 0;

	const int n_pages = THREE_PAGES;
	map_length = PAGESIZE * THREE_PAGES;
	uint64_t page1_va, page2_va, page3_va;
	rte_iova_t page1_iova, page2_iova, page3_iova;

	page1_va = virtaddr_64;
	page2_va = virtaddr_64 + PAGESIZE;
	page3_va = virtaddr_64 + (PAGESIZE * 2);

	page1_iova = 0;
	page2_iova = 0 + PAGESIZE;
	page3_iova = 0 + (PAGESIZE * 2);

	test_heap_mem_setup(map_length, n_pages);

	/* Test case to map three pages */
	ret = rte_vfio_dma_map(page1_va, page1_iova, map_length);
	TEST_ASSERT(ret == 0, "Test to map device in default container "
			"with valid map_length and "
			"mapped valid virtual address: Failed\n");

	/* Test case to unmap 1st page */
	ret = rte_vfio_dma_unmap(page1_va, page1_iova, PAGESIZE);
	TEST_ASSERT(ret == 0, "Test to unmap device in default container "
			"with valid 1st page map_length and "
			"mapped valid virtual address: Failed\n");

	/* Test case to map 1st page */
	ret = rte_vfio_dma_map(page1_va, page1_iova, PAGESIZE);
	TEST_ASSERT(ret == 0, "Test to map device in default container "
			"with valid map_length and "
			"mapped valid virtual address: Failed\n");

	/* Test case to unmap 2nd page */
	ret = rte_vfio_dma_unmap(page2_va, page2_iova, PAGESIZE);
	TEST_ASSERT(ret == 0, "Test to unmap device in default container "
			"with valid map_length and mapped "
			"valid 2nd page virtual address: Failed\n");

	/* Test case to map 2nd page */
	ret = rte_vfio_dma_map(page2_va, page2_iova, PAGESIZE);
	TEST_ASSERT(ret == 0, "Test to map device in default container "
			"with valid map_length and mapped "
			"valid 2nd page virtual address: Failed\n");

	/* Test case to unmap 3rd page */
	ret = rte_vfio_dma_unmap(page3_va, page3_iova, PAGESIZE);
	TEST_ASSERT(ret == 0, "Test to unmap device in default container "
			"with valid map_length and mapped "
			"valid 3rd page virtual address: Failed\n");

	/* Test case to map 3rd page */
	ret = rte_vfio_dma_map(page3_va, page3_iova, PAGESIZE);
	TEST_ASSERT(ret == 0, "Test to map device in default container "
			"with valid map_length and "
			"mapped 3rd page valid virtual address: Failed\n");

	/* Test case to unmap 1st page, but used IOVA address of 2nd page */
	ret = rte_vfio_dma_unmap(page1_va, page2_iova, PAGESIZE);
	TEST_ASSERT(ret == -1, "Test to unmap devices in default container "
			"with valid map_length and mapped "
			"valid virtual address: Failed\n");

	/* Test case to unmap memory region from VFIO with mapped
	 * valid iova addr, vaddr and valid map_length
	 */
	ret = rte_vfio_dma_unmap(page1_va, page1_iova, map_length);
	TEST_ASSERT(ret == 0, "Test to unmap devices in default container "
			 "with valid map_length and mapped "
			 "valid virtual address: Failed\n");

	return TEST_SUCCESS;
}

static struct
unit_test_suite eal_vfio_testsuite  = {
	.suite_name = "EAL VFIO Unit Test Suite",
	.setup = initialize_container_fds,
	.teardown = NULL,
	.unit_test_cases = {
		/* Test Case 1: To check vfio container create test cases */
		TEST_CASE(test_vfio_container_create),

		/* Test Case 2: To check vfio container destroy */
		TEST_CASE(test_vfio_container_destroy),

		/* Test Case 3: To  bind a IOMMU group to a container.*/
		TEST_CASE(test_rte_vfio_container_group_bind),

		/* Test Case 4: To get IOMMU group number for a device*/
		TEST_CASE(test_rte_vfio_get_group_num),

		/* Test Case 5: To unbind a IOMMU group to a container.*/
		TEST_CASE(test_rte_vfio_container_group_unbind),

		/* Test Case 6: To perform DMA mapping for devices in default
		 * container
		 */
		TEST_CASE_ST(NULL, test_heap_mem_free, test_rte_vfio_dma_map),

		/* Test Case 7: To perform DMA unmapping for devices in default
		 * container
		 */
		TEST_CASE_ST(NULL, test_heap_mem_free,
				test_rte_vfio_dma_unmap),

		/* Test Case 8: To perform map devices in specific container */
		TEST_CASE(test_rte_vfio_container_dma_map),

		/* Test Case 9: To perform unmap devices in specific container
		 */
		TEST_CASE(test_rte_vfio_container_dma_unmap),

		/* Test Case 10: To perform three pages */
		TEST_CASE_ST(NULL, test_heap_mem_free,
				test_rte_vfio_dma_map_threepages),

		/* Test Case 11: To check DMA overlaps */
		TEST_CASE_ST(NULL, test_heap_mem_free,
				test_rte_vfio_dma_map_overlaps),

		TEST_CASES_END()
	}
};

static int
test_eal_vfio(void)
{
	return unit_test_suite_runner(&eal_vfio_testsuite);
}

#endif

REGISTER_TEST_COMMAND(eal_vfio_autotest, test_eal_vfio);
