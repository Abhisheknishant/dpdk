/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2017 Intel Corporation
 */

#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <assert.h>
#include <semaphore.h>
#include <linux/virtio_blk.h>
#include <linux/virtio_ring.h>

#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_vhost.h>

#include "vhost_blk.h"
#include "blk_spec.h"

#define VHOST_BLK_FEATURES ((1ULL << VHOST_USER_F_PROTOCOL_FEATURES) | \
			    (1ULL << VIRTIO_F_NOTIFY_ON_EMPTY) | \
			    (1ULL << VIRTIO_F_VERSION_1) )
	
/* Path to folder where character device will be created. Can be set by user. */
static char dev_pathname[PATH_MAX] = "";
static sem_t exit_sem;

struct vhost_blk_ctrlr *
vhost_blk_ctrlr_find(__rte_unused const char *ctrlr_name)
{
	/* currently we only support 1 socket file fd */
	return g_vhost_ctrlr;
}

static uint64_t gpa_to_vva(int vid, uint64_t gpa, uint64_t *len)
{
	char path[PATH_MAX];
	struct vhost_blk_ctrlr *ctrlr;
	int ret = 0;

	ret = rte_vhost_get_ifname(vid, path, PATH_MAX);
	if (ret) {
		fprintf(stderr, "Cannot get socket name\n");
		assert(ret != 0);
	}

	ctrlr = vhost_blk_ctrlr_find(path);
	if (!ctrlr) {
		fprintf(stderr, "Controller is not ready\n");
		assert(ctrlr != NULL);
	}

	assert(ctrlr->mem != NULL);

	return rte_vhost_va_from_guest_pa(ctrlr->mem, gpa, len);
}

static struct vring_desc *
descriptor_get_next(struct vring_desc *vq_desc, struct vring_desc *cur_desc)
{
	return &vq_desc[cur_desc->next];
}

static bool
descriptor_has_next(struct vring_desc *cur_desc)
{
	return !!(cur_desc->flags & VRING_DESC_F_NEXT);
}

static bool
descriptor_is_wr(struct vring_desc *cur_desc)
{
	return !!(cur_desc->flags & VRING_DESC_F_WRITE);
}

static void
submit_completion(struct vhost_blk_task *task, uint32_t vid, uint32_t q_idx)
{
	struct rte_vhost_vring *vq;
	struct vring_used *used;

	vq = task->vq;
	used = vq->used;

	rte_vhost_set_last_inflight_io_split(vid, q_idx, task->req_idx);
	
	/* Fill out the next entry in the "used" ring.  id = the
	 * index of the descriptor that contained the blk request.
	 * len = the total amount of data transferred for the blk
	 * request. We must report the correct len, for variable
	 * length blk CDBs, where we may return less data than
	 * allocated by the guest VM.
	 */
	used->ring[used->idx & (vq->size - 1)].id = task->req_idx;
	used->ring[used->idx & (vq->size - 1)].len = task->data_len;
	used->idx++;
	
	rte_vhost_clr_inflight_desc_split(vid, q_idx, used->idx, task->req_idx);

	/* Send an interrupt back to the guest VM so that it knows
	 * a completion is ready to be processed.
	 */
	rte_vhost_vring_call(task->bdev->vid, q_idx);
}

static void
vhost_process_payload_chain(struct vhost_blk_task *task)
{
	void *data;
	uint64_t chunck_len;

	task->iovs_cnt = 0;

	do {
		chunck_len = task->desc->len;
		data = (void *)(uintptr_t)gpa_to_vva(task->bdev->vid,
						     task->desc->addr,
							 &chunck_len);
		if (!data || chunck_len != task->desc->len) {
			fprintf(stderr, "failed to translate desc address.\n");
			return;
		}

		task->iovs[task->iovs_cnt].iov_base = data;
		task->iovs[task->iovs_cnt].iov_len = task->desc->len;
		task->data_len += task->desc->len;
		task->iovs_cnt++;
		task->desc = descriptor_get_next(task->vq->desc, task->desc);
	} while (descriptor_has_next(task->desc));

	chunck_len = task->desc->len;
	task->status = (void *)(uintptr_t)gpa_to_vva(task->bdev->vid,
						   task->desc->addr,
						   &chunck_len);
	if (!task->status || chunck_len != task->desc->len)
		fprintf(stderr, "failed to translate desc address.\n");
}

static struct vhost_block_dev *
vhost_blk_bdev_construct(const char *bdev_name, const char *bdev_serial,
			  uint32_t blk_size, uint64_t blk_cnt,
			  bool wce_enable)
{
	struct vhost_block_dev *bdev;

	bdev = rte_zmalloc(NULL, sizeof(*bdev), RTE_CACHE_LINE_SIZE);
	if (!bdev)
		return NULL;

	strncpy(bdev->name, bdev_name, sizeof(bdev->name));
	strncpy(bdev->product_name, bdev_serial, sizeof(bdev->product_name));
	bdev->blocklen = blk_size;
	bdev->blockcnt = blk_cnt;
	bdev->write_cache = wce_enable;

	fprintf(stdout, "blocklen=%d, blockcnt=%d\n", bdev->blocklen, bdev->blockcnt);

	/* use memory as disk storage space */
	bdev->data = rte_zmalloc(NULL, blk_cnt * blk_size, 0);
	if (!bdev->data) {
		fprintf(stderr, "no enough reseverd huge memory for disk\n");
		free(bdev);
		return NULL;
	}

	return bdev;
}

static void
submit_inflight_vq(struct vhost_blk_ctrlr *ctrlr, uint32_t q_idx)
{
	struct vhost_blk_queue *blk_vq;
	struct rte_vhost_ring_inflight_split *inflight_vq;
	struct resubmit_info *resubmit_inflight;
	struct resubmit_desc *resubmit_list;
	int i, req_idx;
	
	blk_vq = &ctrlr->bdev->queues[q_idx];
	inflight_vq = &blk_vq->inflight_vq;

	resubmit_inflight = inflight_vq->resubmit_inflight_split;
	resubmit_list = resubmit_inflight->resubmit_list;

	while (resubmit_list && resubmit_inflight->resubmit_num) {
		struct vhost_blk_task *task;
		uint64_t chunck_len;
		int ret;
	
		i = (--resubmit_inflight->resubmit_num);
		req_idx = resubmit_list[i].index;

		task = rte_zmalloc(NULL, sizeof(*task), 0);
		assert(task != NULL);
	
		task->ctrlr = ctrlr;
		task->bdev = ctrlr->bdev;
		task->vq = &blk_vq->vq;
		task->req_idx = req_idx;
		task->desc = &task->vq->desc[task->req_idx];
	
		/* does not support indirect descriptors */
		assert((task->desc->flags & VRING_DESC_F_INDIRECT) == 0);
	
		chunck_len = task->desc->len;
		task->req = (void *)(uintptr_t)gpa_to_vva(task->bdev->vid,
							  task->desc->addr,
							  &chunck_len);
		if (!task->req || chunck_len != task->desc->len) {
			fprintf(stderr, "failed to translate desc address.\n");
			rte_free(task);
			return;
		}

		task->desc = descriptor_get_next(task->vq->desc, task->desc);
		if (!descriptor_has_next(task->desc)) {
			task->dxfer_dir = BLK_DIR_NONE;
			chunck_len = task->desc->len;
			task->status = (void *)(uintptr_t)
					      gpa_to_vva(task->bdev->vid,
							 task->desc->addr,
							 &chunck_len);
			if (!task->status || chunck_len != task->desc->len) {
				fprintf(stderr, "failed to translate desc address.\n");
				rte_free(task);
				return;
			}
		} else {
			task->readtype = descriptor_is_wr(task->desc);
			vhost_process_payload_chain(task);
		} 
		
		ret = vhost_bdev_process_blk_commands(ctrlr->bdev, task);
		if (ret) {
			/* invalid response */
			*task->status = VIRTIO_BLK_S_IOERR;
		} else {
			/* successfully */
			*task->status = VIRTIO_BLK_S_OK;
		}
		submit_completion(task, ctrlr->bdev->vid, q_idx);
		rte_free(task);
	}		
}

static void
process_requestq(struct vhost_blk_ctrlr *ctrlr, uint32_t q_idx)
{
	int ret;
	struct vhost_blk_queue *blk_vq;
	struct rte_vhost_vring *vq;

	blk_vq = &ctrlr->bdev->queues[q_idx];
	vq = &blk_vq->vq;

	while (vq->avail->idx != blk_vq->last_avail_idx) {
		int req_idx;
		uint16_t last_idx;
		struct vhost_blk_task *task;
		uint64_t chunck_len;

		last_idx = blk_vq->last_avail_idx & (vq->size - 1);
		req_idx = vq->avail->ring[last_idx];

		task = rte_zmalloc(NULL, sizeof(*task), 0);
		assert(task != NULL);

		task->ctrlr = ctrlr;
		task->bdev = ctrlr->bdev;
		task->vq = vq;
		task->req_idx = req_idx;
		task->desc = &task->vq->desc[task->req_idx];

		rte_vhost_set_inflight_desc_split(ctrlr->bdev->vid, q_idx, last_idx);

		/* does not support indirect descriptors */
		assert((task->desc->flags & VRING_DESC_F_INDIRECT) == 0);
		blk_vq->last_avail_idx++;

		chunck_len = task->desc->len;
		task->req = (void *)(uintptr_t)gpa_to_vva(task->bdev->vid,
							  task->desc->addr,
							  &chunck_len);
		if (!task->req || chunck_len != task->desc->len) {
			fprintf(stderr, "failed to translate desc address.\n");
			rte_free(task);
			return;
		}

		task->desc = descriptor_get_next(task->vq->desc, task->desc);
		if (!descriptor_has_next(task->desc)) {
			task->dxfer_dir = BLK_DIR_NONE;
			chunck_len = task->desc->len;
			task->status = (void *)(uintptr_t)
					      gpa_to_vva(task->bdev->vid,
							 task->desc->addr,
							 &chunck_len);
			if (!task->status || chunck_len != task->desc->len) {
				fprintf(stderr, "failed to translate desc address.\n");
				rte_free(task);
				return;
			}
		} else {
			task->readtype = descriptor_is_wr(task->desc);
			vhost_process_payload_chain(task);
		} 
		
		ret = vhost_bdev_process_blk_commands(ctrlr->bdev, task);
		if (ret) {
			/* invalid response */
			*task->status = VIRTIO_BLK_S_IOERR;
		} else {
			/* successfully */
			*task->status = VIRTIO_BLK_S_OK;
		}
		
		submit_completion(task, ctrlr->bdev->vid, q_idx);
		rte_free(task);
	}
}

/* Main framework for processing IOs */
static void *
ctrlr_worker(void *arg)
{
	struct vhost_blk_ctrlr *ctrlr = (struct vhost_blk_ctrlr *)arg;
	struct vhost_blk_queue *blk_vq;
	struct rte_vhost_ring_inflight_split *inflight_vq;
	struct resubmit_info *resubmit_inflight;
	cpu_set_t cpuset;
	pthread_t thread;
	int i, ret;

	fprintf(stdout, "Ctrlr Worker Thread start\n");

	if (ctrlr == NULL || ctrlr->bdev == NULL) {
		fprintf(stderr, "%s: Error, invalid argument passed to worker thread\n",
				__func__);
		exit(0);
	}

	thread = pthread_self();
	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);
	pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);

	for (i = 0; i < NUM_OF_BLK_QUEUES; i++) {
		blk_vq = &ctrlr->bdev->queues[i];
		inflight_vq = &blk_vq->inflight_vq;
		resubmit_inflight = inflight_vq->resubmit_inflight_split;
		if (resubmit_inflight && resubmit_inflight->resubmit_num) {
			submit_inflight_vq(ctrlr, i);
		}
	}

	while (!g_should_stop && ctrlr->bdev != NULL) {
		for(i = 0; i < NUM_OF_BLK_QUEUES; i++) {
			process_requestq(ctrlr, i);
		}
	}

	fprintf(stdout, "Ctrlr Worker Thread Exiting\n");
	sem_post(&exit_sem);
	return NULL;
}

static int
new_device(int vid)
{
	char path[PATH_MAX];
	struct vhost_blk_ctrlr *ctrlr;
	struct vhost_blk_queue *blk_vq;
	struct rte_vhost_vring *vq;
	struct rte_vhost_ring_inflight_split *inflight_vq;
	pthread_t tid;
	int i, ret;

	ctrlr = vhost_blk_ctrlr_find(path);
	if (!ctrlr) {
		fprintf(stderr, "Controller is not ready\n");
		return -1;
	}

	if (ctrlr->started)
		return 0;

	ctrlr->bdev->vid = vid;

	ret = rte_vhost_get_mem_table(vid, &ctrlr->mem);
	if (ret) {
		fprintf(stderr, "Get Controller memory region failed\n");
	}
	assert(ctrlr->mem != NULL);

	/* Disable Notifications and init last idx */
	for (i = 0; i < NUM_OF_BLK_QUEUES; i++) {
		rte_vhost_enable_guest_notification(vid, i, 0);

		blk_vq = &ctrlr->bdev->queues[i];
		vq = &blk_vq->vq;
		inflight_vq = &blk_vq->inflight_vq;
		ret = rte_vhost_get_vring_base(ctrlr->bdev->vid, i, &blk_vq->last_avail_idx, 
					       &blk_vq->last_used_idx);
		assert(ret == 0);
		ret = rte_vhost_get_vhost_vring(ctrlr->bdev->vid, i, vq);
		assert(ret == 0);
		ret = rte_vhost_get_vhost_ring_inflight_split(ctrlr->bdev->vid, i, inflight_vq);
		assert(ret == 0);
	}

	/* start polling vring */
	g_should_stop = 0;
	fprintf(stdout, "New Device %s, Device ID %d\n", path, vid);
	if (pthread_create(&tid, NULL, &ctrlr_worker, ctrlr) < 0) {
		fprintf(stderr, "Worker Thread Started Failed\n");
		return -1;
	}

	/* device has been started */
	ctrlr->started = 1;
	pthread_detach(tid);
	return 0;
}

static void
destroy_device(int vid)
{
	char path[PATH_MAX];
	struct vhost_blk_ctrlr *ctrlr;
	struct vhost_blk_queue *blk_vq;
	struct rte_vhost_vring *vq;
	int i, ret;

	ret = rte_vhost_get_ifname(vid, path, PATH_MAX);
	if (ret) {
		fprintf(stderr, "Destroy Ctrlr Failed\n");
		return;
	}
	fprintf(stdout, "Destroy %s Device ID %d\n", path, vid);
	ctrlr = vhost_blk_ctrlr_find(path);
	if (!ctrlr) {
		fprintf(stderr, "Destroy Ctrlr Failed\n");
		return;
	}

	if (!ctrlr->started)
		return;;
	
	g_should_stop = 1;

	for (i = 0; i < NUM_OF_BLK_QUEUES;i++) {
		blk_vq = &ctrlr->bdev->queues[i];
		rte_vhost_set_vring_base(ctrlr->bdev->vid, i,
					 blk_vq->last_avail_idx, blk_vq->last_used_idx);
	}

	free(ctrlr->mem);

	ctrlr->started = 0;
	sem_wait(&exit_sem);
}

static int
new_connection(int vid)
{
	/* extend the proper features for block device */
	vhost_session_install_rte_compat_hooks(vid);
}

struct vhost_device_ops vhost_blk_device_ops = {
	.new_device =  new_device,
	.destroy_device = destroy_device,
	.new_connection = new_connection,
};

static struct vhost_blk_ctrlr *
vhost_blk_ctrlr_construct(const char *ctrlr_name)
{
	int ret;
	struct vhost_blk_ctrlr *ctrlr;
	char *path;
	char cwd[PATH_MAX];

	/* always use current directory */
	path = getcwd(cwd, PATH_MAX);
	if (!path) {
		fprintf(stderr, "Cannot get current working directory\n");
		return NULL;
	}
	snprintf(dev_pathname, sizeof(dev_pathname), "%s/%s", path, ctrlr_name);

	if (access(dev_pathname, F_OK) != -1) {
		if (unlink(dev_pathname) != 0)
			rte_exit(EXIT_FAILURE, "Cannot remove %s.\n",
				 dev_pathname);
	}

	if (rte_vhost_driver_register(dev_pathname, 0) != 0) {
		fprintf(stderr, "socket %s already exists\n", dev_pathname);
		return NULL;
	}

	ret = rte_vhost_driver_set_features(dev_pathname, VHOST_BLK_FEATURES);
	if (ret != 0) {
		fprintf(stderr, "Set vhost driver features failed\n");
		rte_vhost_driver_unregister(dev_pathname);
		return NULL;
	}

	/* set proper features */
	vhost_dev_install_rte_compat_hooks(dev_pathname);

	ctrlr = rte_zmalloc(NULL, sizeof(*ctrlr), RTE_CACHE_LINE_SIZE);
	if (!ctrlr) {
		rte_vhost_driver_unregister(dev_pathname);
		return NULL;
	}

	/* hardcoded block device information with 128MiB */
	ctrlr->bdev = vhost_blk_bdev_construct("malloc0", "vhost_blk_malloc0",
						4096, 32768, 0);
	if (!ctrlr->bdev) {
		rte_free(ctrlr);
		rte_vhost_driver_unregister(dev_pathname);
		return NULL;
	}

	rte_vhost_driver_callback_register(dev_pathname,
					   &vhost_blk_device_ops);

	return ctrlr;
}

static void
signal_handler(__rte_unused int signum)
{
	struct vhost_blk_ctrlr *ctrlr;

	if (access(dev_pathname, F_OK) == 0)
		unlink(dev_pathname);

	g_should_stop = 1;

	ctrlr = vhost_blk_ctrlr_find(NULL);
	if (ctrlr != NULL) {
		fprintf(stderr, "never come in\n");
		if (ctrlr->bdev != NULL) {
			rte_free(ctrlr->bdev->data);
			rte_free(ctrlr->bdev);
		}
		rte_free(ctrlr);
	}

	rte_vhost_driver_unregister(dev_pathname);
	exit(0);
}

int main(int argc, char *argv[])
{
	int ret;

	signal(SIGINT, signal_handler);

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	g_vhost_ctrlr = vhost_blk_ctrlr_construct("vhost.socket");
	if (g_vhost_ctrlr == NULL) {
		fprintf(stderr, "Construct vhost blk controller failed\n");
		return 0;
	}

	if (sem_init(&exit_sem, 0, 0) < 0) {
		fprintf(stderr, "Error init exit_sem\n");
		return -1;
	}

	rte_vhost_driver_start(dev_pathname);

	/* loop for exit the application */
	while (1)
		sleep(1);

	return 0;
}

