/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation.
 */
#include <unistd.h>
#include <errno.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <linux/if_ether.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include "af_xdp_deps.h"
#include <bpf/xsk.h>
#include <sys/stat.h>
#include <libgen.h>

#include <rte_ethdev.h>
#include <rte_ethdev_driver.h>
#include <rte_ethdev_vdev.h>
#include <rte_kvargs.h>
#include <rte_bus_vdev.h>
#include <rte_string_fns.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_dev.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ring.h>

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

static int af_xdp_logtype;

#define AF_XDP_LOG(level, fmt, args...)			\
	rte_log(RTE_LOG_ ## level, af_xdp_logtype,	\
		"%s(): " fmt, __func__, ##args)

#define ETH_AF_XDP_FRAME_SIZE		2048
#define ETH_AF_XDP_NUM_BUFFERS		4096
#define ETH_AF_XDP_DATA_HEADROOM	0
#define ETH_AF_XDP_DFLT_NUM_DESCS	XSK_RING_CONS__DEFAULT_NUM_DESCS
#define ETH_AF_XDP_DFLT_START_QUEUE_IDX	0
#define ETH_AF_XDP_DFLT_QUEUE_COUNT	1

#define ETH_AF_XDP_RX_BATCH_SIZE	32
#define ETH_AF_XDP_TX_BATCH_SIZE	32


struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	struct rte_ring *buf_ring;
	const struct rte_memzone *mz;
	int pmd_zc;
};

struct rx_stats {
	uint64_t rx_pkts;
	uint64_t rx_bytes;
	uint64_t rx_dropped;
};

struct pkt_rx_queue {
	struct xsk_ring_cons rx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;
	struct rte_mempool *mb_pool;

	struct rx_stats stats;

	struct pkt_tx_queue *pair;
	struct pollfd fds[1];
	int xsk_queue_idx;
};

struct tx_stats {
	uint64_t tx_pkts;
	uint64_t tx_bytes;
};

struct pkt_tx_queue {
	struct xsk_ring_prod tx;

	struct tx_stats stats;

	struct pkt_rx_queue *pair;
	int xsk_queue_idx;
};

struct pmd_internals {
	int if_index;
	char if_name[IFNAMSIZ];
	int start_queue_idx;
	int queue_cnt;
	int max_queue_cnt;
	int combined_queue_cnt;
	int queue_irqs[RTE_MAX_QUEUES_PER_PORT];

	int pmd_zc;
	struct rte_ether_addr eth_addr;

	struct pkt_rx_queue *rx_queues;
	struct pkt_tx_queue *tx_queues;
};

#define ETH_AF_XDP_IFACE_ARG			"iface"
#define ETH_AF_XDP_START_QUEUE_ARG		"start_queue"
#define ETH_AF_XDP_QUEUE_COUNT_ARG		"queue_count"
#define ETH_AF_XDP_PMD_ZC_ARG			"pmd_zero_copy"
#define ETH_AF_XDP_QUEUE_IRQ_ARG		"queue_irq"

static const char * const valid_arguments[] = {
	ETH_AF_XDP_IFACE_ARG,
	ETH_AF_XDP_START_QUEUE_ARG,
	ETH_AF_XDP_QUEUE_COUNT_ARG,
	ETH_AF_XDP_PMD_ZC_ARG,
	ETH_AF_XDP_QUEUE_IRQ_ARG,
	NULL
};

static const struct rte_eth_link pmd_link = {
	.link_speed = ETH_SPEED_NUM_10G,
	.link_duplex = ETH_LINK_FULL_DUPLEX,
	.link_status = ETH_LINK_DOWN,
	.link_autoneg = ETH_LINK_AUTONEG
};

/* drivers supported for the queue_irq option */
enum {I40E_DRIVER, IXGBE_DRIVER, MLX5_DRIVER, NUM_DRIVERS};
char driver_array[NUM_DRIVERS][NAME_MAX] = {"i40e", "ixgbe", "mlx5_core"};

/*
 * function pointer template to be implemented for each driver in 'driver_array'
 * to generate the appropriate regular expression to search for in
 * /proc/interrupts in order to identify the IRQ number for the netdev_qid of
 * the given interface.
 */
typedef
int (*generate_driver_regex_func)(char *iface_regex_str,
				  struct pmd_internals *internals,
				  uint16_t netdev_qid);

static inline int
reserve_fill_queue(struct xsk_umem_info *umem, uint16_t reserve_size)
{
	struct xsk_ring_prod *fq = &umem->fq;
	void *addrs[reserve_size];
	uint32_t idx;
	uint16_t i;

	if (rte_ring_dequeue_bulk(umem->buf_ring, addrs, reserve_size, NULL)
		    != reserve_size) {
		AF_XDP_LOG(DEBUG, "Failed to get enough buffers for fq.\n");
		return -1;
	}

	if (unlikely(!xsk_ring_prod__reserve(fq, reserve_size, &idx))) {
		AF_XDP_LOG(DEBUG, "Failed to reserve enough fq descs.\n");
		rte_ring_enqueue_bulk(umem->buf_ring, addrs,
				reserve_size, NULL);
		return -1;
	}

	for (i = 0; i < reserve_size; i++) {
		__u64 *fq_addr;

		fq_addr = xsk_ring_prod__fill_addr(fq, idx++);
		*fq_addr = (uint64_t)addrs[i];
	}

	xsk_ring_prod__submit(fq, reserve_size);

	return 0;
}

static void
umem_buf_release_to_fq(void *addr, void *opaque)
{
	struct xsk_umem_info *umem = (struct xsk_umem_info *)opaque;
	uint64_t umem_addr = (uint64_t)addr - umem->mz->addr_64;

	rte_ring_enqueue(umem->buf_ring, (void *)umem_addr);
}

static uint16_t
eth_af_xdp_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	struct pkt_rx_queue *rxq = queue;
	struct xsk_ring_cons *rx = &rxq->rx;
	struct xsk_umem_info *umem = rxq->umem;
	struct xsk_ring_prod *fq = &umem->fq;
	uint32_t idx_rx = 0;
	uint32_t free_thresh = fq->size >> 1;
	int pmd_zc = umem->pmd_zc;
	struct rte_mbuf *mbufs[ETH_AF_XDP_RX_BATCH_SIZE];
	unsigned long dropped = 0;
	unsigned long rx_bytes = 0;
	int rcvd, i;

	nb_pkts = RTE_MIN(nb_pkts, ETH_AF_XDP_RX_BATCH_SIZE);

	if (unlikely(rte_pktmbuf_alloc_bulk(rxq->mb_pool, mbufs, nb_pkts) != 0))
		return 0;

	rcvd = xsk_ring_cons__peek(rx, nb_pkts, &idx_rx);
	if (rcvd == 0) {
#if defined(XDP_USE_NEED_WAKEUP)
		if (xsk_ring_prod__needs_wakeup(fq))
			(void)poll(rxq->fds, 1, 1000);
#endif

		goto out;
	}

	if (xsk_prod_nb_free(fq, free_thresh) >= free_thresh)
		(void)reserve_fill_queue(umem, ETH_AF_XDP_RX_BATCH_SIZE);

	for (i = 0; i < rcvd; i++) {
		const struct xdp_desc *desc;
		uint64_t addr;
		uint32_t len;
		void *pkt;
		uint16_t buf_len = ETH_AF_XDP_FRAME_SIZE;
		struct rte_mbuf_ext_shared_info *shinfo;

		desc = xsk_ring_cons__rx_desc(rx, idx_rx++);
		addr = desc->addr;
		len = desc->len;
		pkt = xsk_umem__get_data(rxq->umem->mz->addr, addr);

		if (pmd_zc) {
			shinfo = rte_pktmbuf_ext_shinfo_init_helper(pkt,
					&buf_len, umem_buf_release_to_fq, umem);

			rte_pktmbuf_attach_extbuf(mbufs[i], pkt, 0, buf_len,
						  shinfo);
		} else {
			rte_memcpy(rte_pktmbuf_mtod(mbufs[i], void *),
							pkt, len);
			rte_ring_enqueue(umem->buf_ring, (void *)addr);
		}
		rte_pktmbuf_pkt_len(mbufs[i]) = len;
		rte_pktmbuf_data_len(mbufs[i]) = len;
		rx_bytes += len;
		bufs[i] = mbufs[i];
	}

	xsk_ring_cons__release(rx, rcvd);

	/* statistics */
	rxq->stats.rx_pkts += (rcvd - dropped);
	rxq->stats.rx_bytes += rx_bytes;

out:
	if (rcvd != nb_pkts)
		rte_mempool_put_bulk(rxq->mb_pool, (void **)&mbufs[rcvd],
				     nb_pkts - rcvd);

	return rcvd;
}

static void
pull_umem_cq(struct xsk_umem_info *umem, int size)
{
	struct xsk_ring_cons *cq = &umem->cq;
	size_t i, n;
	uint32_t idx_cq = 0;

	n = xsk_ring_cons__peek(cq, size, &idx_cq);

	for (i = 0; i < n; i++) {
		uint64_t addr;
		addr = *xsk_ring_cons__comp_addr(cq, idx_cq++);
		rte_ring_enqueue(umem->buf_ring, (void *)addr);
	}

	xsk_ring_cons__release(cq, n);
}

static void
kick_tx(struct pkt_tx_queue *txq)
{
	struct xsk_umem_info *umem = txq->pair->umem;

	while (send(xsk_socket__fd(txq->pair->xsk), NULL,
		    0, MSG_DONTWAIT) < 0) {
		/* some thing unexpected */
		if (errno != EBUSY && errno != EAGAIN && errno != EINTR)
			break;

		/* pull from completion queue to leave more space */
		if (errno == EAGAIN)
			pull_umem_cq(umem, ETH_AF_XDP_TX_BATCH_SIZE);
	}
	pull_umem_cq(umem, ETH_AF_XDP_TX_BATCH_SIZE);
}

static inline bool
in_umem_range(struct xsk_umem_info *umem, uint64_t addr)
{
	uint64_t mz_base_addr = umem->mz->addr_64;

	return addr >= mz_base_addr && addr < mz_base_addr + umem->mz->len;
}

static uint16_t
eth_af_xdp_tx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	struct pkt_tx_queue *txq = queue;
	struct xsk_umem_info *umem = txq->pair->umem;
	struct rte_mbuf *mbuf;
	int pmd_zc = umem->pmd_zc;
	void *addrs[ETH_AF_XDP_TX_BATCH_SIZE];
	unsigned long tx_bytes = 0;
	int i;
	uint32_t idx_tx;

	nb_pkts = RTE_MIN(nb_pkts, ETH_AF_XDP_TX_BATCH_SIZE);

	pull_umem_cq(umem, nb_pkts);

	nb_pkts = rte_ring_dequeue_bulk(umem->buf_ring, addrs,
					nb_pkts, NULL);
	if (nb_pkts == 0)
		return 0;

	if (xsk_ring_prod__reserve(&txq->tx, nb_pkts, &idx_tx) != nb_pkts) {
		kick_tx(txq);
		rte_ring_enqueue_bulk(umem->buf_ring, addrs, nb_pkts, NULL);
		return 0;
	}

	for (i = 0; i < nb_pkts; i++) {
		struct xdp_desc *desc;
		void *pkt;

		desc = xsk_ring_prod__tx_desc(&txq->tx, idx_tx + i);
		mbuf = bufs[i];
		desc->len = mbuf->pkt_len;

		/*
		 * We need to make sure the external mbuf address is within
		 * current port's umem memzone range
		 */
		if (pmd_zc && RTE_MBUF_HAS_EXTBUF(mbuf) &&
				in_umem_range(umem, (uint64_t)mbuf->buf_addr)) {
			desc->addr = (uint64_t)mbuf->buf_addr -
				umem->mz->addr_64;
			mbuf->buf_addr = xsk_umem__get_data(umem->mz->addr,
					(uint64_t)addrs[i]);
		} else {
			desc->addr = (uint64_t)addrs[i];
			pkt = xsk_umem__get_data(umem->mz->addr,
					desc->addr);
			rte_memcpy(pkt, rte_pktmbuf_mtod(mbuf, void *),
					desc->len);
		}
		tx_bytes += mbuf->pkt_len;
	}

	xsk_ring_prod__submit(&txq->tx, nb_pkts);

#if defined(XDP_USE_NEED_WAKEUP)
	if (xsk_ring_prod__needs_wakeup(&txq->tx))
#endif
		kick_tx(txq);

	txq->stats.tx_pkts += nb_pkts;
	txq->stats.tx_bytes += tx_bytes;

	for (i = 0; i < nb_pkts; i++)
		rte_pktmbuf_free(bufs[i]);

	return nb_pkts;
}

static int
eth_dev_start(struct rte_eth_dev *dev)
{
	dev->data->dev_link.link_status = ETH_LINK_UP;

	return 0;
}

/* This function gets called when the current port gets stopped. */
static void
eth_dev_stop(struct rte_eth_dev *dev)
{
	dev->data->dev_link.link_status = ETH_LINK_DOWN;
}

static int
eth_dev_configure(struct rte_eth_dev *dev)
{
	/* rx/tx must be paired */
	if (dev->data->nb_rx_queues != dev->data->nb_tx_queues)
		return -EINVAL;

	return 0;
}

static void
eth_dev_info(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
	struct pmd_internals *internals = dev->data->dev_private;

	dev_info->if_index = internals->if_index;
	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_pktlen = ETH_FRAME_LEN;
	dev_info->max_rx_queues = internals->queue_cnt;
	dev_info->max_tx_queues = internals->queue_cnt;

	dev_info->min_mtu = RTE_ETHER_MIN_MTU;
	dev_info->max_mtu = ETH_AF_XDP_FRAME_SIZE - ETH_AF_XDP_DATA_HEADROOM;

	dev_info->default_rxportconf.nb_queues = 1;
	dev_info->default_txportconf.nb_queues = 1;
	dev_info->default_rxportconf.ring_size = ETH_AF_XDP_DFLT_NUM_DESCS;
	dev_info->default_txportconf.ring_size = ETH_AF_XDP_DFLT_NUM_DESCS;
}

static int
eth_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	struct pmd_internals *internals = dev->data->dev_private;
	struct xdp_statistics xdp_stats;
	struct pkt_rx_queue *rxq;
	struct pkt_tx_queue *txq;
	socklen_t optlen;
	int i, ret;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		optlen = sizeof(struct xdp_statistics);
		rxq = &internals->rx_queues[i];
		txq = rxq->pair;
		stats->q_ipackets[i] = rxq->stats.rx_pkts;
		stats->q_ibytes[i] = rxq->stats.rx_bytes;

		stats->q_opackets[i] = txq->stats.tx_pkts;
		stats->q_obytes[i] = txq->stats.tx_bytes;

		stats->ipackets += stats->q_ipackets[i];
		stats->ibytes += stats->q_ibytes[i];
		stats->imissed += rxq->stats.rx_dropped;
		ret = getsockopt(xsk_socket__fd(rxq->xsk), SOL_XDP,
				XDP_STATISTICS, &xdp_stats, &optlen);
		if (ret != 0) {
			AF_XDP_LOG(ERR, "getsockopt() failed for XDP_STATISTICS.\n");
			return -1;
		}
		stats->imissed += xdp_stats.rx_dropped;

		stats->opackets += stats->q_opackets[i];
		stats->obytes += stats->q_obytes[i];
	}

	return 0;
}

static void
eth_stats_reset(struct rte_eth_dev *dev)
{
	struct pmd_internals *internals = dev->data->dev_private;
	int i;

	for (i = 0; i < internals->queue_cnt; i++) {
		memset(&internals->rx_queues[i].stats, 0,
					sizeof(struct rx_stats));
		memset(&internals->tx_queues[i].stats, 0,
					sizeof(struct tx_stats));
	}
}

static void
remove_xdp_program(struct pmd_internals *internals)
{
	uint32_t curr_prog_id = 0;

	if (bpf_get_link_xdp_id(internals->if_index, &curr_prog_id,
				XDP_FLAGS_UPDATE_IF_NOEXIST)) {
		AF_XDP_LOG(ERR, "bpf_get_link_xdp_id failed\n");
		return;
	}
	bpf_set_link_xdp_fd(internals->if_index, -1,
			XDP_FLAGS_UPDATE_IF_NOEXIST);
}

static void
xdp_umem_destroy(struct xsk_umem_info *umem)
{
	rte_memzone_free(umem->mz);
	umem->mz = NULL;

	rte_ring_free(umem->buf_ring);
	umem->buf_ring = NULL;

	rte_free(umem);
	umem = NULL;
}

static void
eth_dev_close(struct rte_eth_dev *dev)
{
	struct pmd_internals *internals = dev->data->dev_private;
	struct pkt_rx_queue *rxq;
	int i;

	AF_XDP_LOG(INFO, "Closing AF_XDP ethdev on numa socket %u\n",
		rte_socket_id());

	for (i = 0; i < internals->queue_cnt; i++) {
		rxq = &internals->rx_queues[i];
		if (rxq->umem == NULL)
			break;
		xsk_socket__delete(rxq->xsk);
		(void)xsk_umem__delete(rxq->umem->umem);
		xdp_umem_destroy(rxq->umem);

		/* free pkt_tx_queue */
		rte_free(rxq->pair);
		rte_free(rxq);
	}

	/*
	 * MAC is not allocated dynamically, setting it to NULL would prevent
	 * from releasing it in rte_eth_dev_release_port.
	 */
	dev->data->mac_addrs = NULL;

	remove_xdp_program(internals);
}

static void
eth_queue_release(void *q __rte_unused)
{
}

static int
eth_link_update(struct rte_eth_dev *dev __rte_unused,
		int wait_to_complete __rte_unused)
{
	return 0;
}

static struct
xsk_umem_info *xdp_umem_configure(struct pmd_internals *internals,
				  struct pkt_rx_queue *rxq)
{
	struct xsk_umem_info *umem;
	const struct rte_memzone *mz;
	struct xsk_umem_config usr_config = {
		.fill_size = ETH_AF_XDP_DFLT_NUM_DESCS,
		.comp_size = ETH_AF_XDP_DFLT_NUM_DESCS,
		.frame_size = ETH_AF_XDP_FRAME_SIZE,
		.frame_headroom = ETH_AF_XDP_DATA_HEADROOM };
	char ring_name[RTE_RING_NAMESIZE];
	char mz_name[RTE_MEMZONE_NAMESIZE];
	int ret;
	uint64_t i;

	umem = rte_zmalloc_socket("umem", sizeof(*umem), 0, rte_socket_id());
	if (umem == NULL) {
		AF_XDP_LOG(ERR, "Failed to allocate umem info");
		return NULL;
	}

	snprintf(ring_name, sizeof(ring_name), "af_xdp_ring_%s_%u",
		       internals->if_name, rxq->xsk_queue_idx);
	umem->buf_ring = rte_ring_create(ring_name,
					 ETH_AF_XDP_NUM_BUFFERS,
					 rte_socket_id(),
					 0x0);
	if (umem->buf_ring == NULL) {
		AF_XDP_LOG(ERR, "Failed to create rte_ring\n");
		goto err;
	}

	for (i = 0; i < ETH_AF_XDP_NUM_BUFFERS; i++)
		rte_ring_enqueue(umem->buf_ring,
				 (void *)(i * ETH_AF_XDP_FRAME_SIZE +
					  ETH_AF_XDP_DATA_HEADROOM));

	snprintf(mz_name, sizeof(mz_name), "af_xdp_umem_%s_%u",
		       internals->if_name, rxq->xsk_queue_idx);
	mz = rte_memzone_reserve_aligned(mz_name,
			ETH_AF_XDP_NUM_BUFFERS * ETH_AF_XDP_FRAME_SIZE,
			rte_socket_id(), RTE_MEMZONE_IOVA_CONTIG,
			getpagesize());
	if (mz == NULL) {
		AF_XDP_LOG(ERR, "Failed to reserve memzone for af_xdp umem.\n");
		goto err;
	}

	ret = xsk_umem__create(&umem->umem, mz->addr,
			       ETH_AF_XDP_NUM_BUFFERS * ETH_AF_XDP_FRAME_SIZE,
			       &umem->fq, &umem->cq,
			       &usr_config);

	if (ret) {
		AF_XDP_LOG(ERR, "Failed to create umem");
		goto err;
	}
	umem->mz = mz;

	return umem;

err:
	xdp_umem_destroy(umem);
	return NULL;
}

static int
xsk_configure(struct pmd_internals *internals, struct pkt_rx_queue *rxq,
	      int ring_size)
{
	struct xsk_socket_config cfg;
	struct pkt_tx_queue *txq = rxq->pair;
	int ret = 0;
	int reserve_size;

	rxq->umem = xdp_umem_configure(internals, rxq);
	if (rxq->umem == NULL)
		return -ENOMEM;

	cfg.rx_size = ring_size;
	cfg.tx_size = ring_size;
	cfg.libbpf_flags = 0;
	cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
	cfg.bind_flags = 0;

#if defined(XDP_USE_NEED_WAKEUP)
	cfg.bind_flags |= XDP_USE_NEED_WAKEUP;
#endif

	ret = xsk_socket__create(&rxq->xsk, internals->if_name,
			rxq->xsk_queue_idx, rxq->umem->umem, &rxq->rx,
			&txq->tx, &cfg);
	if (ret) {
		AF_XDP_LOG(ERR, "Failed to create xsk socket.\n");
		goto err;
	}

	reserve_size = ETH_AF_XDP_DFLT_NUM_DESCS / 2;
	ret = reserve_fill_queue(rxq->umem, reserve_size);
	if (ret) {
		xsk_socket__delete(rxq->xsk);
		AF_XDP_LOG(ERR, "Failed to reserve fill queue.\n");
		goto err;
	}

	return 0;

err:
	xdp_umem_destroy(rxq->umem);

	return ret;
}

/** get interface's driver name to determine /proc/interrupts entry format */
static int
get_driver_name(struct pmd_internals *internals, char *driver)
{
	char driver_path[PATH_MAX];
	struct stat s;
	char link[PATH_MAX];
	int len;

	snprintf(driver_path, sizeof(driver_path),
			"/sys/class/net/%s/device/driver", internals->if_name);
	if (lstat(driver_path, &s)) {
		AF_XDP_LOG(ERR, "Error reading %s: %s\n",
					driver_path, strerror(errno));
		return -errno;
	}

	/* driver_path should link to /sys/bus/pci/drivers/<driver_name> */
	len = readlink(driver_path, link, PATH_MAX - 1);
	if (len == -1) {
		AF_XDP_LOG(ERR, "Error reading symbolic link %s: %s\n",
					driver_path, strerror(errno));
		return -errno;
	}

	link[len] = '\0';
	strlcpy(driver, basename(link), NAME_MAX);
	if (!strncmp(driver, ".", strlen(driver))) {
		AF_XDP_LOG(ERR, "Error getting driver name from %s: %s\n",
					link, strerror(errno));
		return -errno;
	}

	return 0;
}

static int
generate_ixgbe_i40e_regex(char *iface_regex_str,
			  struct pmd_internals *internals, uint16_t netdev_qid)
{
	if (snprintf(iface_regex_str, 128,
			"-%s.*-%d", internals->if_name, netdev_qid) >= 128) {
		AF_XDP_LOG(INFO, "Cannot get interrupt for %s q %i\n",
					internals->if_name, netdev_qid);
		return -1;
	}

	return 0;
}

static int
generate_mlx5_regex(char *iface_regex_str, struct pmd_internals *internals,
		    uint16_t netdev_qid)
{
	char pci_path[PATH_MAX];
	char *pci;
	int ret = -1;
	struct stat s;
	char *link;
	int len;

	snprintf(pci_path, sizeof(pci_path),
			"/sys/class/net/%s/device", internals->if_name);
	if (lstat(pci_path, &s)) {
		AF_XDP_LOG(ERR, "Error reading %s: %s\n",
					pci_path, strerror(errno));
		return -errno;
	}

	/* pci_path should link to a directory whose name is the pci addr */
	link = malloc(s.st_size + 1);
	len = readlink(pci_path, link, PATH_MAX - 1);
	if (len == -1) {
		AF_XDP_LOG(ERR, "Error reading symbolic link %s: %s\n",
					pci_path, strerror(errno));
		ret = -errno;
		goto out;
	}

	link[len] = '\0';
	pci = basename(link);
	if (!strncmp(pci, ".", strlen(pci))) {
		AF_XDP_LOG(ERR, "Error getting pci from %s\n", link);
		goto out;
	}

	if (snprintf(iface_regex_str, 128, ".*p%i@pci:%s", netdev_qid, pci) >=
			128) {
		AF_XDP_LOG(INFO, "Cannot get interrupt for %s q %i\n",
					internals->if_name, netdev_qid);
		goto out;
	}

	ret = 0;

out:
	if (link)
		free(link);

	return ret;
}

/*
 * array of handlers for different drivers for generating appropriate regex
 * format for searching /proc/interrupts
 */
generate_driver_regex_func driver_handlers[NUM_DRIVERS] = {
					generate_ixgbe_i40e_regex,
					generate_ixgbe_i40e_regex,
					generate_mlx5_regex};

/*
 * function for getting the index into driver_handlers array that corresponds
 * to 'driver'
 */
static int
get_driver_idx(char *driver)
{
	for (int i = 0; i < NUM_DRIVERS; i++) {
		if (strncmp(driver, driver_array[i], strlen(driver_array[i])))
			continue;
		return i;
	}

	return -1;
}

/** generate /proc/interrupts search regex based on driver type */
static int
generate_search_regex(const char *driver, struct pmd_internals *internals,
		      uint16_t netdev_qid, regex_t *r)
{
	char iface_regex_str[128];
	int ret = -1;
	char *driver_dup = strdup(driver);
	int idx = get_driver_idx(driver_dup);

	if (idx == -1) {
		AF_XDP_LOG(ERR, "Error getting driver index for %s\n",
					internals->if_name);
		goto out;
	}

	if (driver_handlers[idx](iface_regex_str, internals, netdev_qid)) {
		AF_XDP_LOG(ERR, "Error getting regex string for %s\n",
					internals->if_name);
		goto out;
	}

	if (regcomp(r, iface_regex_str, 0)) {
		AF_XDP_LOG(ERR, "Error computing regex %s\n", iface_regex_str);
		goto out;
	}

	ret = 0;

out:
	free(driver_dup);
	return ret;
}

/** get interrupt number associated with the given interface qid */
static int
get_interrupt_number(regex_t *r, int *interrupt,
		     struct pmd_internals *internals)
{
	FILE *f_int_proc;
	int found = 0;
	char line[4096];
	int ret = 0;

	f_int_proc = fopen("/proc/interrupts", "r");
	if (f_int_proc == NULL) {
		AF_XDP_LOG(ERR, "Failed to open /proc/interrupts.\n");
		return -1;
	}

	while (!feof(f_int_proc) && !found) {
		/* Make sure to read a full line at a time */
		if (fgets(line, sizeof(line), f_int_proc) == NULL ||
				line[strlen(line) - 1] != '\n') {
			AF_XDP_LOG(ERR, "Error reading from interrupts file\n");
			ret = -1;
			break;
		}

		/* Extract interrupt number from line */
		if (regexec(r, line, 0, NULL, 0) == 0) {
			*interrupt = atoi(line);
			found = true;
			AF_XDP_LOG(INFO, "Got interrupt %d for %s\n",
						*interrupt, internals->if_name);
		}
	}

	fclose(f_int_proc);

	return ret;
}

/** affinitise interrupts for the given qid to the given coreid */
static int
set_irq_affinity(int coreid, struct pmd_internals *internals,
		 uint16_t rx_queue_id, uint16_t netdev_qid, int interrupt)
{
	char bitmask[128];
	char smp_affinity_filename[NAME_MAX];
	FILE *f_int_smp_affinity;
	int i;

	/* Create affinity bitmask. Every 32 bits are separated by a comma */
	snprintf(bitmask, sizeof(bitmask), "%x", 1 << (coreid % 32));
	for (i = 0; i < coreid / 32; i++)
		strlcat(bitmask, ",00000000", sizeof(bitmask));

	/* Write the new affinity bitmask */
	snprintf(smp_affinity_filename, sizeof(smp_affinity_filename),
			"/proc/irq/%d/smp_affinity", interrupt);
	f_int_smp_affinity = fopen(smp_affinity_filename, "w");
	if (f_int_smp_affinity == NULL) {
		AF_XDP_LOG(ERR, "Error opening %s\n", smp_affinity_filename);
		return -1;
	}
	fwrite(bitmask, strlen(bitmask), 1, f_int_smp_affinity);
	fclose(f_int_smp_affinity);
	AF_XDP_LOG(INFO, "IRQs for %s ethdev queue %i (netdev queue %i)"
				" affinitised to core %i\n",
				internals->if_name, rx_queue_id,
				netdev_qid, coreid);

	return 0;
}

static void
configure_irqs(struct pmd_internals *internals, uint16_t rx_queue_id)
{
	int coreid = internals->queue_irqs[rx_queue_id];
	char driver[NAME_MAX];
	uint16_t netdev_qid = rx_queue_id + internals->start_queue_idx;
	regex_t r;
	int interrupt;

	if (coreid < 0)
		return;

	if (coreid > (get_nprocs() - 1)) {
		AF_XDP_LOG(ERR, "Affinitisation failed - invalid coreid %i\n",
					coreid);
		return;
	}

	if (get_driver_name(internals, driver)) {
		AF_XDP_LOG(ERR, "Error retrieving driver name for %s\n",
					internals->if_name);
		return;
	}

	if (generate_search_regex(driver, internals, netdev_qid, &r)) {
		AF_XDP_LOG(ERR, "Error generating search regex for %s\n",
					internals->if_name);
		return;
	}

	if (get_interrupt_number(&r, &interrupt, internals)) {
		AF_XDP_LOG(ERR, "Error getting interrupt number for %s\n",
					internals->if_name);
		return;
	}

	if (set_irq_affinity(coreid, internals, rx_queue_id, netdev_qid,
				interrupt)) {
		AF_XDP_LOG(ERR, "Error setting interrupt affinity for %s\n",
					internals->if_name);
		return;
	}
}

static int
eth_rx_queue_setup(struct rte_eth_dev *dev,
		   uint16_t rx_queue_id,
		   uint16_t nb_rx_desc,
		   unsigned int socket_id __rte_unused,
		   const struct rte_eth_rxconf *rx_conf __rte_unused,
		   struct rte_mempool *mb_pool)
{
	struct pmd_internals *internals = dev->data->dev_private;
	uint32_t buf_size, data_size;
	struct pkt_rx_queue *rxq;
	int ret;

	rxq = &internals->rx_queues[rx_queue_id];

	AF_XDP_LOG(INFO, "Set up rx queue, rx queue id: %d, xsk queue id: %d\n",
		   rx_queue_id, rxq->xsk_queue_idx);
	/* Now get the space available for data in the mbuf */
	buf_size = rte_pktmbuf_data_room_size(mb_pool) -
		RTE_PKTMBUF_HEADROOM;
	data_size = ETH_AF_XDP_FRAME_SIZE - ETH_AF_XDP_DATA_HEADROOM;

	if (data_size > buf_size) {
		AF_XDP_LOG(ERR, "%s: %d bytes will not fit in mbuf (%d bytes)\n",
			dev->device->name, data_size, buf_size);
		ret = -ENOMEM;
		goto err;
	}

	rxq->mb_pool = mb_pool;

	if (xsk_configure(internals, rxq, nb_rx_desc)) {
		AF_XDP_LOG(ERR, "Failed to configure xdp socket\n");
		ret = -EINVAL;
		goto err;
	}

	configure_irqs(internals, rx_queue_id);

	rxq->fds[0].fd = xsk_socket__fd(rxq->xsk);
	rxq->fds[0].events = POLLIN;

	rxq->umem->pmd_zc = internals->pmd_zc;

	dev->data->rx_queues[rx_queue_id] = rxq;
	return 0;

err:
	return ret;
}

static int
eth_tx_queue_setup(struct rte_eth_dev *dev,
		   uint16_t tx_queue_id,
		   uint16_t nb_tx_desc __rte_unused,
		   unsigned int socket_id __rte_unused,
		   const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct pmd_internals *internals = dev->data->dev_private;
	struct pkt_tx_queue *txq;

	txq = &internals->tx_queues[tx_queue_id];

	dev->data->tx_queues[tx_queue_id] = txq;
	return 0;
}

static int
eth_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct pmd_internals *internals = dev->data->dev_private;
	struct ifreq ifr = { .ifr_mtu = mtu };
	int ret;
	int s;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return -EINVAL;

	strlcpy(ifr.ifr_name, internals->if_name, IFNAMSIZ);
	ret = ioctl(s, SIOCSIFMTU, &ifr);
	close(s);

	return (ret < 0) ? -errno : 0;
}

static void
eth_dev_change_flags(char *if_name, uint32_t flags, uint32_t mask)
{
	struct ifreq ifr;
	int s;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return;

	strlcpy(ifr.ifr_name, if_name, IFNAMSIZ);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
		goto out;
	ifr.ifr_flags &= mask;
	ifr.ifr_flags |= flags;
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
		goto out;
out:
	close(s);
}

static void
eth_dev_promiscuous_enable(struct rte_eth_dev *dev)
{
	struct pmd_internals *internals = dev->data->dev_private;

	eth_dev_change_flags(internals->if_name, IFF_PROMISC, ~0);
}

static void
eth_dev_promiscuous_disable(struct rte_eth_dev *dev)
{
	struct pmd_internals *internals = dev->data->dev_private;

	eth_dev_change_flags(internals->if_name, 0, ~IFF_PROMISC);
}

static const struct eth_dev_ops ops = {
	.dev_start = eth_dev_start,
	.dev_stop = eth_dev_stop,
	.dev_close = eth_dev_close,
	.dev_configure = eth_dev_configure,
	.dev_infos_get = eth_dev_info,
	.mtu_set = eth_dev_mtu_set,
	.promiscuous_enable = eth_dev_promiscuous_enable,
	.promiscuous_disable = eth_dev_promiscuous_disable,
	.rx_queue_setup = eth_rx_queue_setup,
	.tx_queue_setup = eth_tx_queue_setup,
	.rx_queue_release = eth_queue_release,
	.tx_queue_release = eth_queue_release,
	.link_update = eth_link_update,
	.stats_get = eth_stats_get,
	.stats_reset = eth_stats_reset,
};

/** parse integer from integer argument */
static int
parse_integer_arg(const char *key __rte_unused,
		  const char *value, void *extra_args)
{
	int *i = (int *)extra_args;
	char *end;

	*i = strtol(value, &end, 10);
	if (*i < 0) {
		AF_XDP_LOG(ERR, "Argument has to be positive.\n");
		return -EINVAL;
	}

	return 0;
}

/** parse name argument */
static int
parse_name_arg(const char *key __rte_unused,
	       const char *value, void *extra_args)
{
	char *name = extra_args;

	if (strnlen(value, IFNAMSIZ) > IFNAMSIZ - 1) {
		AF_XDP_LOG(ERR, "Invalid name %s, should be less than %u bytes.\n",
			   value, IFNAMSIZ);
		return -EINVAL;
	}

	strlcpy(name, value, IFNAMSIZ);

	return 0;
}

/** parse queue irq argument */
static int
parse_queue_irq_arg(const char *key __rte_unused,
		   const char *value, void *extra_args)
{
	int (*queue_irqs)[RTE_MAX_QUEUES_PER_PORT] = extra_args;
	char *parse_str = strdup(value);
	char delimiter[] = ":";
	char *queue_str;

	queue_str = strtok(parse_str, delimiter);
	if (queue_str != NULL && strncmp(queue_str, value, strlen(value))) {
		char *end;
		long queue = strtol(queue_str, &end, 10);

		if (*end == '\0' && queue >= 0 &&
				queue < RTE_MAX_QUEUES_PER_PORT) {
			char *core_str = strtok(NULL, delimiter);
			long core = strtol(core_str, &end, 10);

			if (*end == '\0' && core >= 0 && core < get_nprocs()) {
				(*queue_irqs)[queue] = core;
				free(parse_str);
				return 0;
			}
		}
	}

	AF_XDP_LOG(ERR, "Invalid queue_irq argument.\n");
	free(parse_str);
	return -1;
}

static int
xdp_get_channels_info(const char *if_name, int *max_queues,
				int *combined_queues)
{
	struct ethtool_channels channels;
	struct ifreq ifr;
	int fd, ret;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	channels.cmd = ETHTOOL_GCHANNELS;
	ifr.ifr_data = (void *)&channels;
	strncpy(ifr.ifr_name, if_name, IFNAMSIZ);
	ret = ioctl(fd, SIOCETHTOOL, &ifr);
	if (ret) {
		if (errno == EOPNOTSUPP) {
			ret = 0;
		} else {
			ret = -errno;
			goto out;
		}
	}

	if (channels.max_combined == 0 || errno == EOPNOTSUPP) {
		/* If the device says it has no channels, then all traffic
		 * is sent to a single stream, so max queues = 1.
		 */
		*max_queues = 1;
		*combined_queues = 1;
	} else {
		*max_queues = channels.max_combined;
		*combined_queues = channels.combined_count;
	}

 out:
	close(fd);
	return ret;
}

static int
parse_parameters(struct rte_kvargs *kvlist, char *if_name, int *start_queue,
			int *queue_cnt, int *pmd_zc,
			int (*queue_irqs)[RTE_MAX_QUEUES_PER_PORT])
{
	int ret;

	ret = rte_kvargs_process(kvlist, ETH_AF_XDP_IFACE_ARG,
				 &parse_name_arg, if_name);
	if (ret < 0)
		goto free_kvlist;

	ret = rte_kvargs_process(kvlist, ETH_AF_XDP_START_QUEUE_ARG,
				 &parse_integer_arg, start_queue);
	if (ret < 0)
		goto free_kvlist;

	ret = rte_kvargs_process(kvlist, ETH_AF_XDP_QUEUE_COUNT_ARG,
				 &parse_integer_arg, queue_cnt);
	if (ret < 0 || *queue_cnt <= 0) {
		ret = -EINVAL;
		goto free_kvlist;
	}

	ret = rte_kvargs_process(kvlist, ETH_AF_XDP_PMD_ZC_ARG,
				 &parse_integer_arg, pmd_zc);
	if (ret < 0)
		goto free_kvlist;

	ret = rte_kvargs_process(kvlist, ETH_AF_XDP_QUEUE_IRQ_ARG,
				 &parse_queue_irq_arg, queue_irqs);
	if (ret < 0)
		goto free_kvlist;

free_kvlist:
	rte_kvargs_free(kvlist);
	return ret;
}

static int
get_iface_info(const char *if_name,
	       struct rte_ether_addr *eth_addr,
	       int *if_index)
{
	struct ifreq ifr;
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

	if (sock < 0)
		return -1;

	strlcpy(ifr.ifr_name, if_name, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFINDEX, &ifr))
		goto error;

	*if_index = ifr.ifr_ifindex;

	if (ioctl(sock, SIOCGIFHWADDR, &ifr))
		goto error;

	rte_memcpy(eth_addr, ifr.ifr_hwaddr.sa_data, RTE_ETHER_ADDR_LEN);

	close(sock);
	return 0;

error:
	close(sock);
	return -1;
}

static struct rte_eth_dev *
init_internals(struct rte_vdev_device *dev, const char *if_name,
			int start_queue_idx, int queue_cnt, int pmd_zc,
			int queue_irqs[RTE_MAX_QUEUES_PER_PORT])
{
	const char *name = rte_vdev_device_name(dev);
	const unsigned int numa_node = dev->device.numa_node;
	struct pmd_internals *internals;
	struct rte_eth_dev *eth_dev;
	int ret;
	int i;

	internals = rte_zmalloc_socket(name, sizeof(*internals), 0, numa_node);
	if (internals == NULL)
		return NULL;

	internals->start_queue_idx = start_queue_idx;
	internals->queue_cnt = queue_cnt;
	internals->pmd_zc = pmd_zc;
	strlcpy(internals->if_name, if_name, IFNAMSIZ);
	memcpy(internals->queue_irqs, queue_irqs,
		sizeof(int) * RTE_MAX_QUEUES_PER_PORT);

	if (xdp_get_channels_info(if_name, &internals->max_queue_cnt,
				  &internals->combined_queue_cnt)) {
		AF_XDP_LOG(ERR, "Failed to get channel info of interface: %s\n",
				if_name);
		goto err_free_internals;
	}

	if (queue_cnt > internals->combined_queue_cnt) {
		AF_XDP_LOG(ERR, "Specified queue count %d is larger than combined queue count %d.\n",
				queue_cnt, internals->combined_queue_cnt);
		goto err_free_internals;
	}

	internals->rx_queues = rte_zmalloc_socket(NULL,
					sizeof(struct pkt_rx_queue) * queue_cnt,
					0, numa_node);
	if (internals->rx_queues == NULL) {
		AF_XDP_LOG(ERR, "Failed to allocate memory for rx queues.\n");
		goto err_free_internals;
	}

	internals->tx_queues = rte_zmalloc_socket(NULL,
					sizeof(struct pkt_tx_queue) * queue_cnt,
					0, numa_node);
	if (internals->tx_queues == NULL) {
		AF_XDP_LOG(ERR, "Failed to allocate memory for tx queues.\n");
		goto err_free_rx;
	}
	for (i = 0; i < queue_cnt; i++) {
		internals->tx_queues[i].pair = &internals->rx_queues[i];
		internals->rx_queues[i].pair = &internals->tx_queues[i];
		internals->rx_queues[i].xsk_queue_idx = start_queue_idx + i;
		internals->tx_queues[i].xsk_queue_idx = start_queue_idx + i;
	}

	ret = get_iface_info(if_name, &internals->eth_addr,
			     &internals->if_index);
	if (ret)
		goto err_free_tx;

	eth_dev = rte_eth_vdev_allocate(dev, 0);
	if (eth_dev == NULL)
		goto err_free_tx;

	eth_dev->data->dev_private = internals;
	eth_dev->data->dev_link = pmd_link;
	eth_dev->data->mac_addrs = &internals->eth_addr;
	eth_dev->dev_ops = &ops;
	eth_dev->rx_pkt_burst = eth_af_xdp_rx;
	eth_dev->tx_pkt_burst = eth_af_xdp_tx;
	/* Let rte_eth_dev_close() release the port resources. */
	eth_dev->data->dev_flags |= RTE_ETH_DEV_CLOSE_REMOVE;

	if (internals->pmd_zc)
		AF_XDP_LOG(INFO, "Zero copy between umem and mbuf enabled.\n");

	return eth_dev;

err_free_tx:
	rte_free(internals->tx_queues);
err_free_rx:
	rte_free(internals->rx_queues);
err_free_internals:
	rte_free(internals);
	return NULL;
}

static int
rte_pmd_af_xdp_probe(struct rte_vdev_device *dev)
{
	struct rte_kvargs *kvlist;
	char if_name[IFNAMSIZ] = {'\0'};
	int xsk_start_queue_idx = ETH_AF_XDP_DFLT_START_QUEUE_IDX;
	int xsk_queue_cnt = ETH_AF_XDP_DFLT_QUEUE_COUNT;
	struct rte_eth_dev *eth_dev = NULL;
	const char *name;
	int pmd_zc = 0;
	int queue_irqs[RTE_MAX_QUEUES_PER_PORT];

	memset(queue_irqs, -1, sizeof(int) * RTE_MAX_QUEUES_PER_PORT);

	AF_XDP_LOG(INFO, "Initializing pmd_af_xdp for %s\n",
		rte_vdev_device_name(dev));

	name = rte_vdev_device_name(dev);
	if (rte_eal_process_type() == RTE_PROC_SECONDARY &&
		strlen(rte_vdev_device_args(dev)) == 0) {
		eth_dev = rte_eth_dev_attach_secondary(name);
		if (eth_dev == NULL) {
			AF_XDP_LOG(ERR, "Failed to probe %s\n", name);
			return -EINVAL;
		}
		eth_dev->dev_ops = &ops;
		rte_eth_dev_probing_finish(eth_dev);
		return 0;
	}

	kvlist = rte_kvargs_parse(rte_vdev_device_args(dev), valid_arguments);
	if (kvlist == NULL) {
		AF_XDP_LOG(ERR, "Invalid kvargs key\n");
		return -EINVAL;
	}

	if (dev->device.numa_node == SOCKET_ID_ANY)
		dev->device.numa_node = rte_socket_id();

	if (parse_parameters(kvlist, if_name, &xsk_start_queue_idx,
			     &xsk_queue_cnt, &pmd_zc, &queue_irqs) < 0) {
		AF_XDP_LOG(ERR, "Invalid kvargs value\n");
		return -EINVAL;
	}

	if (strlen(if_name) == 0) {
		AF_XDP_LOG(ERR, "Network interface must be specified\n");
		return -EINVAL;
	}

	eth_dev = init_internals(dev, if_name, xsk_start_queue_idx,
					xsk_queue_cnt, pmd_zc, queue_irqs);
	if (eth_dev == NULL) {
		AF_XDP_LOG(ERR, "Failed to init internals\n");
		return -1;
	}

	rte_eth_dev_probing_finish(eth_dev);

	return 0;
}

static int
rte_pmd_af_xdp_remove(struct rte_vdev_device *dev)
{
	struct rte_eth_dev *eth_dev = NULL;

	AF_XDP_LOG(INFO, "Removing AF_XDP ethdev on numa socket %u\n",
		rte_socket_id());

	if (dev == NULL)
		return -1;

	/* find the ethdev entry */
	eth_dev = rte_eth_dev_allocated(rte_vdev_device_name(dev));
	if (eth_dev == NULL)
		return 0;

	eth_dev_close(eth_dev);
	rte_eth_dev_release_port(eth_dev);


	return 0;
}

static struct rte_vdev_driver pmd_af_xdp_drv = {
	.probe = rte_pmd_af_xdp_probe,
	.remove = rte_pmd_af_xdp_remove,
};

RTE_PMD_REGISTER_VDEV(net_af_xdp, pmd_af_xdp_drv);
RTE_PMD_REGISTER_PARAM_STRING(net_af_xdp,
			      "iface=<string> "
			      "start_queue=<int> "
			      "queue_count=<int> "
			      "pmd_zero_copy=<0|1> "
			      "queue_irq=<int>:<int>");

RTE_INIT(af_xdp_init_log)
{
	af_xdp_logtype = rte_log_register("pmd.net.af_xdp");
	if (af_xdp_logtype >= 0)
		rte_log_set_level(af_xdp_logtype, RTE_LOG_NOTICE);
}
