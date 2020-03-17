#include <stdint.h>
#include <stdbool.h>
#include <linux/virtio_net.h>

#include <rte_malloc.h>
#include <rte_vhost.h>

#include "virtio_net.h"

int
vhost_dma_setup(struct pmd_internal *dev)
{
	struct dma_vring *dma_vr;
	int vid = dev->vid;
	int ret;
	uint16_t i, j, size;

	rte_vhost_get_negotiated_features(vid, &dev->features);

	if (dev->features & (1 << VIRTIO_NET_F_MRG_RXBUF))
		dev->hdr_len = sizeof(struct virtio_net_hdr_mrg_rxbuf);
	else
		dev->hdr_len = sizeof(struct virtio_net_hdr);

	dev->nr_vrings = rte_vhost_get_vring_num(vid);

	if (rte_vhost_get_mem_table(vid, &dev->mem) < 0) {
		VHOST_LOG(ERR, "Failed to get guest memory regions\n");
		return -1;
	}

	/* set up gpa and hpa mappings */
	if (setup_guest_pages(dev, dev->mem) < 0) {
		VHOST_LOG(ERR, "Failed to set up hpa and gpa mappings\n");
		free(dev->mem);
		return -1;
	}

	for (i = 0; i < dev->nr_vrings; i++) {
		dma_vr = &dev->dma_vrings[i];

		ret = rte_vhost_get_vring_base(vid, i, &dma_vr->last_avail_idx,
					       &dma_vr->last_used_idx);
		if (ret < 0) {
			VHOST_LOG(ERR, "Failed to get vring index.\n");
			goto err;
		}

		ret = rte_vhost_get_vhost_vring(vid, i, &dma_vr->vr);
		if (ret < 0) {
			VHOST_LOG(ERR, "Failed to get vring address.\n");
			goto err;
		}

		size = dma_vr->vr.size;
		dma_vr->shadow_used_split =
			rte_malloc(NULL, size * sizeof(struct vring_used_elem),
				   RTE_CACHE_LINE_SIZE);
		if (dma_vr->shadow_used_split == NULL)
			goto err;

		dma_vr->batch_copy_elems =
			rte_malloc(NULL, size * sizeof(struct batch_copy_elem),
				   RTE_CACHE_LINE_SIZE);
		if (dma_vr->batch_copy_elems == NULL)
			goto err;

		/* get HPA of used ring's index */
		dma_vr->used_idx_hpa =
			rte_mem_virt2iova(&dma_vr->vr.used->idx);

		dma_vr->copy_done_used = dma_vr->last_used_idx;
		dma_vr->signalled_used = dma_vr->last_used_idx;
		dma_vr->signalled_used_valid = false;
		dma_vr->shadow_used_idx = 0;
		dma_vr->batch_copy_nb_elems = 0;
	}

	return 0;

err:
	for (j = 0; j <= i; j++) {
		dma_vr = &dev->dma_vrings[j];
		rte_free(dma_vr->shadow_used_split);
		rte_free(dma_vr->batch_copy_elems);
		dma_vr->shadow_used_split = NULL;
		dma_vr->batch_copy_elems = NULL;
		dma_vr->used_idx_hpa = 0;
	}

	free(dev->mem);
	dev->mem = NULL;
	free(dev->guest_pages);
	dev->guest_pages = NULL;

	return -1;
}

void
vhost_dma_remove(struct pmd_internal *dev)
{
	struct dma_vring *dma_vr;
	uint16_t i;

	for (i = 0; i < dev->nr_vrings; i++) {
		dma_vr = &dev->dma_vrings[i];
		rte_free(dma_vr->shadow_used_split);
		rte_free(dma_vr->batch_copy_elems);
		dma_vr->shadow_used_split = NULL;
		dma_vr->batch_copy_elems = NULL;
		dma_vr->signalled_used_valid = false;
		dma_vr->used_idx_hpa = 0;
	}

	free(dev->mem);
	dev->mem = NULL;
	free(dev->guest_pages);
	dev->guest_pages = NULL;
}
