/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2018
 */

#ifndef _VIRTCHNL_H_
#define _VIRTCHNL_H_

/* Description:
 * This header file describes the VF-PF communication protocol used
 * by the drivers for all devices starting from our 40G product line
 *
 * Admin queue buffer usage:
 * desc->opcode is always aqc_opc_send_msg_to_pf
 * flags, retval, datalen, and data addr are all used normally.
 * The Firmware copies the cookie fields when sending messages between the
 * PF and VF, but uses all other fields internally. Due to this limitation,
 * we must send all messages as "indirect", i.e. using an external buffer.
 *
 * All the VSI indexes are relative to the VF. Each VF can have maximum of
 * three VSIs. All the queue indexes are relative to the VSI.  Each VF can
 * have a maximum of sixteen queues for all of its VSIs.
 *
 * The PF is required to return a status code in v_retval for all messages
 * except RESET_VF, which does not require any response. The return value
 * is of status_code type, defined in the shared type.h.
 *
 * In general, VF driver initialization should roughly follow the order of
 * these opcodes. The VF driver must first validate the API version of the
 * PF driver, then request a reset, then get resources, then configure
 * queues and interrupts. After these operations are complete, the VF
 * driver may start its queues, optionally add MAC and VLAN filters, and
 * process traffic.
 */

/* START GENERIC DEFINES
 * Need to ensure the following enums and defines hold the same meaning and
 * value in current and future projects
 */

/* Error Codes */
enum virtchnl_status_code {
	VIRTCHNL_STATUS_SUCCESS				= 0,
	VIRTCHNL_STATUS_ERR_PARAM			= -5,
	VIRTCHNL_STATUS_ERR_NO_MEMORY			= -18,
	VIRTCHNL_STATUS_ERR_OPCODE_MISMATCH		= -38,
	VIRTCHNL_STATUS_ERR_CQP_COMPL_ERROR		= -39,
	VIRTCHNL_STATUS_ERR_INVALID_VF_ID		= -40,
	VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR		= -53,
	VIRTCHNL_STATUS_ERR_NOT_SUPPORTED		= -64,
};

/* Backward compatibility */
#define VIRTCHNL_ERR_PARAM VIRTCHNL_STATUS_ERR_PARAM
#define VIRTCHNL_STATUS_NOT_SUPPORTED VIRTCHNL_STATUS_ERR_NOT_SUPPORTED

#define VIRTCHNL_LINK_SPEED_100MB_SHIFT		0x1
#define VIRTCHNL_LINK_SPEED_1000MB_SHIFT	0x2
#define VIRTCHNL_LINK_SPEED_10GB_SHIFT		0x3
#define VIRTCHNL_LINK_SPEED_40GB_SHIFT		0x4
#define VIRTCHNL_LINK_SPEED_20GB_SHIFT		0x5
#define VIRTCHNL_LINK_SPEED_25GB_SHIFT		0x6

enum virtchnl_link_speed {
	VIRTCHNL_LINK_SPEED_UNKNOWN	= 0,
	VIRTCHNL_LINK_SPEED_100MB	= BIT(VIRTCHNL_LINK_SPEED_100MB_SHIFT),
	VIRTCHNL_LINK_SPEED_1GB		= BIT(VIRTCHNL_LINK_SPEED_1000MB_SHIFT),
	VIRTCHNL_LINK_SPEED_10GB	= BIT(VIRTCHNL_LINK_SPEED_10GB_SHIFT),
	VIRTCHNL_LINK_SPEED_40GB	= BIT(VIRTCHNL_LINK_SPEED_40GB_SHIFT),
	VIRTCHNL_LINK_SPEED_20GB	= BIT(VIRTCHNL_LINK_SPEED_20GB_SHIFT),
	VIRTCHNL_LINK_SPEED_25GB	= BIT(VIRTCHNL_LINK_SPEED_25GB_SHIFT),
};

/* for hsplit_0 field of Rx HMC context */
/* deprecated with AVF 1.0 */
enum virtchnl_rx_hsplit {
	VIRTCHNL_RX_HSPLIT_NO_SPLIT      = 0,
	VIRTCHNL_RX_HSPLIT_SPLIT_L2      = 1,
	VIRTCHNL_RX_HSPLIT_SPLIT_IP      = 2,
	VIRTCHNL_RX_HSPLIT_SPLIT_TCP_UDP = 4,
	VIRTCHNL_RX_HSPLIT_SPLIT_SCTP    = 8,
};

#define VIRTCHNL_ETH_LENGTH_OF_ADDRESS	6
/* END GENERIC DEFINES */

/* Opcodes for VF-PF communication. These are placed in the v_opcode field
 * of the virtchnl_msg structure.
 */
enum virtchnl_ops {
/* The PF sends status change events to VFs using
 * the VIRTCHNL_OP_EVENT opcode.
 * VFs send requests to the PF using the other ops.
 * Use of "advanced opcode" features must be negotiated as part of capabilities
 * exchange and are not considered part of base mode feature set.
 */
	VIRTCHNL_OP_UNKNOWN = 0,
	VIRTCHNL_OP_VERSION = 1, /* must ALWAYS be 1 */
	VIRTCHNL_OP_RESET_VF = 2,
	VIRTCHNL_OP_GET_VF_RESOURCES = 3,
	VIRTCHNL_OP_CONFIG_TX_QUEUE = 4,
	VIRTCHNL_OP_CONFIG_RX_QUEUE = 5,
	VIRTCHNL_OP_CONFIG_VSI_QUEUES = 6,
	VIRTCHNL_OP_CONFIG_IRQ_MAP = 7,
	VIRTCHNL_OP_ENABLE_QUEUES = 8,
	VIRTCHNL_OP_DISABLE_QUEUES = 9,
	VIRTCHNL_OP_ADD_ETH_ADDR = 10,
	VIRTCHNL_OP_DEL_ETH_ADDR = 11,
	VIRTCHNL_OP_ADD_VLAN = 12,
	VIRTCHNL_OP_DEL_VLAN = 13,
	VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE = 14,
	VIRTCHNL_OP_GET_STATS = 15,
	VIRTCHNL_OP_RSVD = 16,
	VIRTCHNL_OP_EVENT = 17, /* must ALWAYS be 17 */
#ifdef VIRTCHNL_SOL_VF_SUPPORT
	VIRTCHNL_OP_GET_ADDNL_SOL_CONFIG = 19,
#else
	/* opcode 19 is reserved */
#endif
#ifdef VIRTCHNL_IWARP
	VIRTCHNL_OP_IWARP = 20, /* advanced opcode */
	VIRTCHNL_OP_CONFIG_IWARP_IRQ_MAP = 21, /* advanced opcode */
	VIRTCHNL_OP_RELEASE_IWARP_IRQ_MAP = 22, /* advanced opcode */
#else
	/* opcodes 20, 21, and 22 are reserved */
#endif
	VIRTCHNL_OP_CONFIG_RSS_KEY = 23,
	VIRTCHNL_OP_CONFIG_RSS_LUT = 24,
	VIRTCHNL_OP_GET_RSS_HENA_CAPS = 25,
	VIRTCHNL_OP_SET_RSS_HENA = 26,
	VIRTCHNL_OP_ENABLE_VLAN_STRIPPING = 27,
	VIRTCHNL_OP_DISABLE_VLAN_STRIPPING = 28,
	VIRTCHNL_OP_REQUEST_QUEUES = 29,
	VIRTCHNL_OP_ENABLE_CHANNELS = 30,
	VIRTCHNL_OP_DISABLE_CHANNELS = 31,
	VIRTCHNL_OP_ADD_CLOUD_FILTER = 32,
	VIRTCHNL_OP_DEL_CLOUD_FILTER = 33,
#ifdef VIRTCHNL_EXT_FEATURES
	/* New major set of opcodes introduced and so leaving room for
	* old misc opcodes to be added in future. Also these opcodes may only
	* be used if both the PF and VF have successfully negotiated the
	* VIRTCHNL_VF_CAP_EXT_FEATURES capability during initial capabilities
	* exchange.
	*/
       VIRTCHNL_OP_GET_CAPS = 100,
       VIRTCHNL_OP_CREATE_VPORT = 101,
       VIRTCHNL_OP_DESTROY_VPORT = 102,
       VIRTCHNL_OP_ENABLE_VPORT = 103,
       VIRTCHNL_OP_DISABLE_VPORT = 104,
       VIRTCHNL_OP_CONFIG_TX_QUEUES = 105,
       VIRTCHNL_OP_CONFIG_RX_QUEUES = 106,
       VIRTCHNL_OP_ENABLE_QUEUES_V2 = 107,
       VIRTCHNL_OP_DISABLE_QUEUES_V2 = 108,
       VIRTCHNL_OP_ADD_QUEUES = 109,
       VIRTCHNL_OP_DEL_QUEUES = 110,
       VIRTCHNL_OP_MAP_VECTOR_QUEUE = 111,
       VIRTCHNL_OP_UNMAP_VECTOR_QUEUE = 112,
       VIRTCHNL_OP_MAP_VECTOR_ITR = 113,
       VIRTCHNL_OP_GET_RSS_KEY = 114,
       VIRTCHNL_OP_GET_RSS_LUT = 115,
       VIRTCHNL_OP_GET_RSS_HASH = 116,
       VIRTCHNL_OP_SET_RSS_HASH = 117,
       VIRTCHNL_OP_CREATE_VFS = 118,
       VIRTCHNL_OP_DESTROY_VFS = 119,
#endif /* VIRTCHNL_EXT_FEATURES */
};

/* These macros are used to generate compilation errors if a structure/union
 * is not exactly the correct length. It gives a divide by zero error if the
 * structure/union is not of the correct size, otherwise it creates an enum
 * that is never used.
 */
#define VIRTCHNL_CHECK_STRUCT_LEN(n, X) enum virtchnl_static_assert_enum_##X \
	{ virtchnl_static_assert_##X = (n)/((sizeof(struct X) == (n)) ? 1 : 0) }
#define VIRTCHNL_CHECK_UNION_LEN(n, X) enum virtchnl_static_asset_enum_##X \
	{ virtchnl_static_assert_##X = (n)/((sizeof(union X) == (n)) ? 1 : 0) }

/* Virtual channel message descriptor. This overlays the admin queue
 * descriptor. All other data is passed in external buffers.
 */

struct virtchnl_msg {
	u8 pad[8];			 /* AQ flags/opcode/len/retval fields */
	enum virtchnl_ops v_opcode; /* avoid confusion with desc->opcode */
	enum virtchnl_status_code v_retval;  /* ditto for desc->retval */
	u32 vfid;			 /* used by PF when sending to VF */
};

VIRTCHNL_CHECK_STRUCT_LEN(20, virtchnl_msg);

/* Message descriptions and data structures. */

/* VIRTCHNL_OP_VERSION
 * VF posts its version number to the PF. PF responds with its version number
 * in the same format, along with a return code.
 * Reply from PF has its major/minor versions also in param0 and param1.
 * If there is a major version mismatch, then the VF cannot operate.
 * If there is a minor version mismatch, then the VF can operate but should
 * add a warning to the system log.
 *
 * This enum element MUST always be specified as == 1, regardless of other
 * changes in the API. The PF must always respond to this message without
 * error regardless of version mismatch.
 */
#define VIRTCHNL_VERSION_MAJOR		1
#define VIRTCHNL_VERSION_MINOR		1
#define VIRTCHNL_VERSION_MINOR_NO_VF_CAPS	0

struct virtchnl_version_info {
	u32 major;
	u32 minor;
};

VIRTCHNL_CHECK_STRUCT_LEN(8, virtchnl_version_info);

#define VF_IS_V10(_v) (((_v)->major == 1) && ((_v)->minor == 0))
#define VF_IS_V11(_ver) (((_ver)->major == 1) && ((_ver)->minor == 1))

/* VIRTCHNL_OP_RESET_VF
 * VF sends this request to PF with no parameters
 * PF does NOT respond! VF driver must delay then poll VFGEN_RSTAT register
 * until reset completion is indicated. The admin queue must be reinitialized
 * after this operation.
 *
 * When reset is complete, PF must ensure that all queues in all VSIs associated
 * with the VF are stopped, all queue configurations in the HMC are set to 0,
 * and all MAC and VLAN filters (except the default MAC address) on all VSIs
 * are cleared.
 */

/* VSI types that use VIRTCHNL interface for VF-PF communication. VSI_SRIOV
 * vsi_type should always be 6 for backward compatibility. Add other fields
 * as needed.
 */
enum virtchnl_vsi_type {
	VIRTCHNL_VSI_TYPE_INVALID = 0,
	VIRTCHNL_VSI_SRIOV = 6,
};

/* VIRTCHNL_OP_GET_VF_RESOURCES
 * Version 1.0 VF sends this request to PF with no parameters
 * Version 1.1 VF sends this request to PF with u32 bitmap of its capabilities
 * PF responds with an indirect message containing
 * virtchnl_vf_resource and one or more
 * virtchnl_vsi_resource structures.
 */

struct virtchnl_vsi_resource {
	u16 vsi_id;
	u16 num_queue_pairs;
	enum virtchnl_vsi_type vsi_type;
	u16 qset_handle;
	u8 default_mac_addr[VIRTCHNL_ETH_LENGTH_OF_ADDRESS];
};

VIRTCHNL_CHECK_STRUCT_LEN(16, virtchnl_vsi_resource);

/* VF capability flags
 * VIRTCHNL_VF_OFFLOAD_L2 flag is inclusive of base mode L2 offloads including
 * TX/RX Checksum offloading and TSO for non-tunnelled packets.
 */
#define VIRTCHNL_VF_OFFLOAD_L2			0x00000001
#define VIRTCHNL_VF_OFFLOAD_IWARP		0x00000002
#define VIRTCHNL_VF_OFFLOAD_RSVD		0x00000004
#define VIRTCHNL_VF_OFFLOAD_RSS_AQ		0x00000008
#define VIRTCHNL_VF_OFFLOAD_RSS_REG		0x00000010
#define VIRTCHNL_VF_OFFLOAD_WB_ON_ITR		0x00000020
#define VIRTCHNL_VF_OFFLOAD_REQ_QUEUES		0x00000040
#define VIRTCHNL_VF_OFFLOAD_CRC			0x00000080
#define VIRTCHNL_VF_OFFLOAD_VLAN		0x00010000
#define VIRTCHNL_VF_OFFLOAD_RX_POLLING		0x00020000
#define VIRTCHNL_VF_OFFLOAD_RSS_PCTYPE_V2	0x00040000
#define VIRTCHNL_VF_OFFLOAD_RSS_PF		0X00080000
#define VIRTCHNL_VF_OFFLOAD_ENCAP		0X00100000
#define VIRTCHNL_VF_OFFLOAD_ENCAP_CSUM		0X00200000
#define VIRTCHNL_VF_OFFLOAD_RX_ENCAP_CSUM	0X00400000
#define VIRTCHNL_VF_OFFLOAD_ADQ			0X00800000
/* Define below the capability flags that are not offloads */
#ifdef VIRTCHNL_EXT_FEATURES
#define VIRTCHNL_VF_CAP_EXT_FEATURES		0x01000000
#endif /* VIRTCHNL_EXT_FEATURES */
#define VIRTCHNL_VF_CAP_ADV_LINK_SPEED		0x00000080
#define VF_BASE_MODE_OFFLOADS (VIRTCHNL_VF_OFFLOAD_L2 | \
			       VIRTCHNL_VF_OFFLOAD_VLAN | \
			       VIRTCHNL_VF_OFFLOAD_RSS_PF)

struct virtchnl_vf_resource {
	u16 num_vsis;
	u16 num_queue_pairs;
	u16 max_vectors;
	u16 max_mtu;

	u32 vf_cap_flags;
	u32 rss_key_size;
	u32 rss_lut_size;

	struct virtchnl_vsi_resource vsi_res[1];
};

VIRTCHNL_CHECK_STRUCT_LEN(36, virtchnl_vf_resource);

/* VIRTCHNL_OP_CONFIG_TX_QUEUE
 * VF sends this message to set up parameters for one TX queue.
 * External data buffer contains one instance of virtchnl_txq_info.
 * PF configures requested queue and returns a status code.
 */

/* Tx queue config info */
struct virtchnl_txq_info {
	u16 vsi_id;
	u16 queue_id;
	u16 ring_len;		/* number of descriptors, multiple of 8 */
	u16 headwb_enabled; /* deprecated with AVF 1.0 */
	u64 dma_ring_addr;
	u64 dma_headwb_addr; /* deprecated with AVF 1.0 */
};

VIRTCHNL_CHECK_STRUCT_LEN(24, virtchnl_txq_info);

/* VIRTCHNL_OP_CONFIG_RX_QUEUE
 * VF sends this message to set up parameters for one RX queue.
 * External data buffer contains one instance of virtchnl_rxq_info.
 * PF configures requested queue and returns a status code. The
 * crc_disable flag disables CRC stripping on the VF. Setting
 * the crc_disable flag to 1 will disable CRC stripping for each
 * queue in the VF where the flag is set. The VIRTCHNL_VF_OFFLOAD_CRC
 * offload must have been set prior to sending this info or the PF
 * will ignore the request. This flag should be set the same for
 * all of the queues for a VF.
 */

/* Rx queue config info */
struct virtchnl_rxq_info {
	u16 vsi_id;
	u16 queue_id;
	u32 ring_len;		/* number of descriptors, multiple of 32 */
	u16 hdr_size;
	u16 splithdr_enabled; /* deprecated with AVF 1.0 */
	u32 databuffer_size;
	u32 max_pkt_size;
	u8 crc_disable;
	u8 pad1[3];
	u64 dma_ring_addr;
	enum virtchnl_rx_hsplit rx_split_pos; /* deprecated with AVF 1.0 */
	u32 pad2;
};

VIRTCHNL_CHECK_STRUCT_LEN(40, virtchnl_rxq_info);

/* VIRTCHNL_OP_CONFIG_VSI_QUEUES
 * VF sends this message to set parameters for all active TX and RX queues
 * associated with the specified VSI.
 * PF configures queues and returns status.
 * If the number of queues specified is greater than the number of queues
 * associated with the VSI, an error is returned and no queues are configured.
 */
struct virtchnl_queue_pair_info {
	/* NOTE: vsi_id and queue_id should be identical for both queues. */
	struct virtchnl_txq_info txq;
	struct virtchnl_rxq_info rxq;
};

VIRTCHNL_CHECK_STRUCT_LEN(64, virtchnl_queue_pair_info);

struct virtchnl_vsi_queue_config_info {
	u16 vsi_id;
	u16 num_queue_pairs;
	u32 pad;
	struct virtchnl_queue_pair_info qpair[1];
};

VIRTCHNL_CHECK_STRUCT_LEN(72, virtchnl_vsi_queue_config_info);

/* VIRTCHNL_OP_REQUEST_QUEUES
 * VF sends this message to request the PF to allocate additional queues to
 * this VF.  Each VF gets a guaranteed number of queues on init but asking for
 * additional queues must be negotiated.  This is a best effort request as it
 * is possible the PF does not have enough queues left to support the request.
 * If the PF cannot support the number requested it will respond with the
 * maximum number it is able to support.  If the request is successful, PF will
 * then reset the VF to institute required changes.
 */

/* VF resource request */
struct virtchnl_vf_res_request {
	u16 num_queue_pairs;
};

/* VIRTCHNL_OP_CONFIG_IRQ_MAP
 * VF uses this message to map vectors to queues.
 * The rxq_map and txq_map fields are bitmaps used to indicate which queues
 * are to be associated with the specified vector.
 * The "other" causes are always mapped to vector 0.
 * PF configures interrupt mapping and returns status.
 */
struct virtchnl_vector_map {
	u16 vsi_id;
	u16 vector_id;
	u16 rxq_map;
	u16 txq_map;
	u16 rxitr_idx;
	u16 txitr_idx;
};

VIRTCHNL_CHECK_STRUCT_LEN(12, virtchnl_vector_map);

struct virtchnl_irq_map_info {
	u16 num_vectors;
	struct virtchnl_vector_map vecmap[1];
};

VIRTCHNL_CHECK_STRUCT_LEN(14, virtchnl_irq_map_info);

/* VIRTCHNL_OP_ENABLE_QUEUES
 * VIRTCHNL_OP_DISABLE_QUEUES
 * VF sends these message to enable or disable TX/RX queue pairs.
 * The queues fields are bitmaps indicating which queues to act upon.
 * (Currently, we only support 16 queues per VF, but we make the field
 * u32 to allow for expansion.)
 * PF performs requested action and returns status.
 */
struct virtchnl_queue_select {
	u16 vsi_id;
	u16 pad;
	u32 rx_queues;
	u32 tx_queues;
};

VIRTCHNL_CHECK_STRUCT_LEN(12, virtchnl_queue_select);

/* VIRTCHNL_OP_ADD_ETH_ADDR
 * VF sends this message in order to add one or more unicast or multicast
 * address filters for the specified VSI.
 * PF adds the filters and returns status.
 */

/* VIRTCHNL_OP_DEL_ETH_ADDR
 * VF sends this message in order to remove one or more unicast or multicast
 * filters for the specified VSI.
 * PF removes the filters and returns status.
 */

struct virtchnl_ether_addr {
	u8 addr[VIRTCHNL_ETH_LENGTH_OF_ADDRESS];
	u8 pad[2];
};

VIRTCHNL_CHECK_STRUCT_LEN(8, virtchnl_ether_addr);

struct virtchnl_ether_addr_list {
	u16 vsi_id;
	u16 num_elements;
	struct virtchnl_ether_addr list[1];
};

VIRTCHNL_CHECK_STRUCT_LEN(12, virtchnl_ether_addr_list);

#ifdef VIRTCHNL_SOL_VF_SUPPORT
/* VIRTCHNL_OP_GET_ADDNL_SOL_CONFIG
 * VF sends this message to get the default MTU and list of additional ethernet
 * addresses it is allowed to use.
 * PF responds with an indirect message containing
 * virtchnl_addnl_solaris_config with zero or more
 * virtchnl_ether_addr structures.
 *
 * It is expected that this operation will only ever be needed for Solaris VFs
 * running under a Solaris PF.
 */
struct virtchnl_addnl_solaris_config {
	u16 default_mtu;
	struct virtchnl_ether_addr_list al;
};

#endif
/* VIRTCHNL_OP_ADD_VLAN
 * VF sends this message to add one or more VLAN tag filters for receives.
 * PF adds the filters and returns status.
 * If a port VLAN is configured by the PF, this operation will return an
 * error to the VF.
 */

/* VIRTCHNL_OP_DEL_VLAN
 * VF sends this message to remove one or more VLAN tag filters for receives.
 * PF removes the filters and returns status.
 * If a port VLAN is configured by the PF, this operation will return an
 * error to the VF.
 */

struct virtchnl_vlan_filter_list {
	u16 vsi_id;
	u16 num_elements;
	u16 vlan_id[1];
};

VIRTCHNL_CHECK_STRUCT_LEN(6, virtchnl_vlan_filter_list);

/* VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE
 * VF sends VSI id and flags.
 * PF returns status code in retval.
 * Note: we assume that broadcast accept mode is always enabled.
 */
struct virtchnl_promisc_info {
	u16 vsi_id;
	u16 flags;
};

VIRTCHNL_CHECK_STRUCT_LEN(4, virtchnl_promisc_info);

#define FLAG_VF_UNICAST_PROMISC	0x00000001
#define FLAG_VF_MULTICAST_PROMISC	0x00000002

/* VIRTCHNL_OP_GET_STATS
 * VF sends this message to request stats for the selected VSI. VF uses
 * the virtchnl_queue_select struct to specify the VSI. The queue_id
 * field is ignored by the PF.
 *
 * PF replies with struct virtchnl_eth_stats in an external buffer.
 */

struct virtchnl_eth_stats {
	u64 rx_bytes;			/* received bytes */
	u64 rx_unicast;			/* received unicast pkts */
	u64 rx_multicast;		/* received multicast pkts */
	u64 rx_broadcast;		/* received broadcast pkts */
	u64 rx_discards;
	u64 rx_unknown_protocol;
	u64 tx_bytes;			/* transmitted bytes */
	u64 tx_unicast;			/* transmitted unicast pkts */
	u64 tx_multicast;		/* transmitted multicast pkts */
	u64 tx_broadcast;		/* transmitted broadcast pkts */
	u64 tx_discards;
	u64 tx_errors;
};

/* VIRTCHNL_OP_CONFIG_RSS_KEY
 * VIRTCHNL_OP_CONFIG_RSS_LUT
 * VF sends these messages to configure RSS. Only supported if both PF
 * and VF drivers set the VIRTCHNL_VF_OFFLOAD_RSS_PF bit during
 * configuration negotiation. If this is the case, then the RSS fields in
 * the VF resource struct are valid.
 * Both the key and LUT are initialized to 0 by the PF, meaning that
 * RSS is effectively disabled until set up by the VF.
 */
struct virtchnl_rss_key {
	u16 vsi_id;
	u16 key_len;
	u8 key[1];         /* RSS hash key, packed bytes */
};

VIRTCHNL_CHECK_STRUCT_LEN(6, virtchnl_rss_key);

struct virtchnl_rss_lut {
	u16 vsi_id;
	u16 lut_entries;
	u8 lut[1];        /* RSS lookup table */
};

VIRTCHNL_CHECK_STRUCT_LEN(6, virtchnl_rss_lut);

/* VIRTCHNL_OP_GET_RSS_HENA_CAPS
 * VIRTCHNL_OP_SET_RSS_HENA
 * VF sends these messages to get and set the hash filter enable bits for RSS.
 * By default, the PF sets these to all possible traffic types that the
 * hardware supports. The VF can query this value if it wants to change the
 * traffic types that are hashed by the hardware.
 */
struct virtchnl_rss_hena {
	u64 hena;
};

VIRTCHNL_CHECK_STRUCT_LEN(8, virtchnl_rss_hena);

/* VIRTCHNL_OP_ENABLE_CHANNELS
 * VIRTCHNL_OP_DISABLE_CHANNELS
 * VF sends these messages to enable or disable channels based on
 * the user specified queue count and queue offset for each traffic class.
 * This struct encompasses all the information that the PF needs from
 * VF to create a channel.
 */
struct virtchnl_channel_info {
	u16 count; /* number of queues in a channel */
	u16 offset; /* queues in a channel start from 'offset' */
	u32 pad;
	u64 max_tx_rate;
};

VIRTCHNL_CHECK_STRUCT_LEN(16, virtchnl_channel_info);

struct virtchnl_tc_info {
	u32	num_tc;
	u32	pad;
	struct	virtchnl_channel_info list[1];
};

VIRTCHNL_CHECK_STRUCT_LEN(24, virtchnl_tc_info);

/* VIRTCHNL_ADD_CLOUD_FILTER
 * VIRTCHNL_DEL_CLOUD_FILTER
 * VF sends these messages to add or delete a cloud filter based on the
 * user specified match and action filters. These structures encompass
 * all the information that the PF needs from the VF to add/delete a
 * cloud filter.
 */

struct virtchnl_l4_spec {
	u8	src_mac[ETH_ALEN];
	u8	dst_mac[ETH_ALEN];
	__be16	vlan_id;
	__be16	pad; /* reserved for future use */
	__be32	src_ip[4];
	__be32	dst_ip[4];
	__be16	src_port;
	__be16	dst_port;
};

VIRTCHNL_CHECK_STRUCT_LEN(52, virtchnl_l4_spec);

union virtchnl_flow_spec {
	struct	virtchnl_l4_spec tcp_spec;
	u8	buffer[128]; /* reserved for future use */
};

VIRTCHNL_CHECK_UNION_LEN(128, virtchnl_flow_spec);

enum virtchnl_action {
	/* action types */
	VIRTCHNL_ACTION_DROP = 0,
	VIRTCHNL_ACTION_TC_REDIRECT,
};

enum virtchnl_flow_type {
	/* flow types */
	VIRTCHNL_TCP_V4_FLOW = 0,
	VIRTCHNL_TCP_V6_FLOW,
};

struct virtchnl_filter {
	union	virtchnl_flow_spec data;
	union	virtchnl_flow_spec mask;
	enum	virtchnl_flow_type flow_type;
	enum	virtchnl_action action;
	u32	action_meta;
	u8	field_flags;
};

VIRTCHNL_CHECK_STRUCT_LEN(272, virtchnl_filter);

/* VIRTCHNL_OP_EVENT
 * PF sends this message to inform the VF driver of events that may affect it.
 * No direct response is expected from the VF, though it may generate other
 * messages in response to this one.
 */
enum virtchnl_event_codes {
	VIRTCHNL_EVENT_UNKNOWN = 0,
	VIRTCHNL_EVENT_LINK_CHANGE,
	VIRTCHNL_EVENT_RESET_IMPENDING,
	VIRTCHNL_EVENT_PF_DRIVER_CLOSE,
};

#define PF_EVENT_SEVERITY_INFO		0
#define PF_EVENT_SEVERITY_ATTENTION	1
#define PF_EVENT_SEVERITY_ACTION_REQUIRED	2
#define PF_EVENT_SEVERITY_CERTAIN_DOOM	255

struct virtchnl_pf_event {
	enum virtchnl_event_codes event;
	union {
		/* If the PF driver does not support the new speed reporting
		 * capabilities then use link_event else use link_event_adv to
		 * get the speed and link information. The ability to understand
		 * new speeds is indicated by setting the capability flag
		 * VIRTCHNL_VF_CAP_ADV_LINK_SPEED in vf_cap_flags parameter
		 * in virtchnl_vf_resource struct and can be used to determine
		 * which link event struct to use below.
		 */
		struct {
			enum virtchnl_link_speed link_speed;
			u8 link_status;
		} link_event;
		struct {
			/* link_speed provided in Mbps */
			u32 link_speed;
			u8 link_status;
		} link_event_adv;
	} event_data;

	int severity;
};

VIRTCHNL_CHECK_STRUCT_LEN(16, virtchnl_pf_event);

#ifdef VIRTCHNL_IWARP

/* VIRTCHNL_OP_CONFIG_IWARP_IRQ_MAP
 * VF uses this message to request PF to map IWARP vectors to IWARP queues.
 * The request for this originates from the VF IWARP driver through
 * a client interface between VF LAN and VF IWARP driver.
 * A vector could have an AEQ and CEQ attached to it although
 * there is a single AEQ per VF IWARP instance in which case
 * most vectors will have an INVALID_IDX for aeq and valid idx for ceq.
 * There will never be a case where there will be multiple CEQs attached
 * to a single vector.
 * PF configures interrupt mapping and returns status.
 */
struct virtchnl_iwarp_qv_info {
	u32 v_idx; /* msix_vector */
	u16 ceq_idx;
	u16 aeq_idx;
	u8 itr_idx;
};

VIRTCHNL_CHECK_STRUCT_LEN(12, virtchnl_iwarp_qv_info);

struct virtchnl_iwarp_qvlist_info {
	u32 num_vectors;
	struct virtchnl_iwarp_qv_info qv_info[1];
};

VIRTCHNL_CHECK_STRUCT_LEN(16, virtchnl_iwarp_qvlist_info);

#endif

/* Since VF messages are limited by u16 size, precalculate the maximum possible
 * values of nested elements in virtchnl structures that virtual channel can
 * possibly handle in a single message.
 */
enum virtchnl_vector_limits {
	VIRTCHNL_OP_CONFIG_VSI_QUEUES_MAX	=
		((u16)(~0) - sizeof(struct virtchnl_vsi_queue_config_info)) /
		sizeof(struct virtchnl_queue_pair_info),

	VIRTCHNL_OP_CONFIG_IRQ_MAP_MAX		=
		((u16)(~0) - sizeof(struct virtchnl_irq_map_info)) /
		sizeof(struct virtchnl_vector_map),

	VIRTCHNL_OP_ADD_DEL_ETH_ADDR_MAX	=
		((u16)(~0) - sizeof(struct virtchnl_ether_addr_list)) /
		sizeof(struct virtchnl_ether_addr),

	VIRTCHNL_OP_ADD_DEL_VLAN_MAX		=
		((u16)(~0) - sizeof(struct virtchnl_vlan_filter_list)) /
		sizeof(u16),

#ifdef VIRTCHNL_IWARP
	VIRTCHNL_OP_CONFIG_IWARP_IRQ_MAP_MAX	=
		((u16)(~0) - sizeof(struct virtchnl_iwarp_qvlist_info)) /
		sizeof(struct virtchnl_iwarp_qv_info),
#endif

	VIRTCHNL_OP_ENABLE_CHANNELS_MAX		=
		((u16)(~0) - sizeof(struct virtchnl_tc_info)) /
		sizeof(struct virtchnl_channel_info),
};

/* VF reset states - these are written into the RSTAT register:
 * VFGEN_RSTAT on the VF
 * When the PF initiates a reset, it writes 0
 * When the reset is complete, it writes 1
 * When the PF detects that the VF has recovered, it writes 2
 * VF checks this register periodically to determine if a reset has occurred,
 * then polls it to know when the reset is complete.
 * If either the PF or VF reads the register while the hardware
 * is in a reset state, it will return DEADBEEF, which, when masked
 * will result in 3.
 */
enum virtchnl_vfr_states {
	VIRTCHNL_VFR_INPROGRESS = 0,
	VIRTCHNL_VFR_COMPLETED,
	VIRTCHNL_VFR_VFACTIVE,
};

#ifdef VIRTCHNL_EXT_FEATURES
/* PF capability flags
 * VIRTCHNL_CAP_STATELESS_OFFLOADS flag indicates stateless offloads
 * such as TX/RX Checksum offloading and TSO for non-tunneled packets. Please
 * note that old and new capabilities are exclusive and not supposed to be
 * mixed
 */
#define VIRTCHNL_CAP_STATELESS_OFFLOADS	BIT(1)
#define VIRTCHNL_CAP_UDP_SEG_OFFLOAD	BIT(2)
#define VIRTCHNL_CAP_RSS		BIT(3)
#define VIRTCHNL_CAP_TCP_RSC		BIT(4)
#define VIRTCHNL_CAP_HEADER_SPLIT	BIT(5)
#define VIRTCHNL_CAP_RDMA		BIT(6)
#define VIRTCHNL_CAP_SRIOV		BIT(7)
/* Earliest Departure Time capability used for Timing Wheel */
#define VIRTCHNL_CAP_EDT		BIT(8)

/* Type of virtual port */
enum virtchnl_vport_type {
	VIRTCHNL_VPORT_TYPE_DEFAULT	= 0,
};

/* Type of queue model */
enum virtchnl_queue_model {
	VIRTCHNL_QUEUE_MODEL_SINGLE	= 0,
	VIRTCHNL_QUEUE_MODEL_SPLIT	= 1,
};

/* TX and RX queue types are valid in legacy as well as split queue models.
 * With Split Queue model, 2 additional types are introduced - TX_COMPLETION
 * and RX_BUFFER. In split queue model, RX corresponds to the queue where HW
 * posts completions.
 */
enum virtchnl_queue_type {
	VIRTCHNL_QUEUE_TYPE_TX			= 0,
	VIRTCHNL_QUEUE_TYPE_RX			= 1,
	VIRTCHNL_QUEUE_TYPE_TX_COMPLETION	= 2,
	VIRTCHNL_QUEUE_TYPE_RX_BUFFER		= 3,
};

/* RX Queue Feature bits */
#define VIRTCHNL_RXQ_RSC			BIT(1)
#define VIRTCHNL_RXQ_HDR_SPLIT			BIT(2)
#define VIRTCHNL_RXQ_IMMEDIATE_WRITE_BACK	BIT(4)

/* RX Queue Descriptor Types */
enum virtchnl_rxq_desc_size {
	VIRTCHNL_RXQ_DESC_SIZE_16BYTE		= 0,
	VIRTCHNL_RXQ_DESC_SIZE_32BYTE		= 1,
};

/* TX Queue Scheduling Modes  Queue mode is the legacy type i.e. inorder
 * and Flow mode is out of order packet processing
 */
enum virtchnl_txq_sched_mode {
	VIRTCHNL_TXQ_SCHED_MODE_QUEUE		= 0,
	VIRTCHNL_TXQ_SCHED_MODE_FLOW		= 1,
};

/* Queue Descriptor Profiles  Base mode is the legacy and Native is the
 * flex descriptors
 */
enum virtchnl_desc_profile {
	VIRTCHNL_TXQ_DESC_PROFILE_BASE		= 0,
	VIRTCHNL_TXQ_DESC_PROFILE_NATIVE	= 1,
};

/* Type of RSS algorithm */
enum virtchnl_rss_algorithm {
	VIRTCHNL_RSS_ALG_TOEPLITZ_ASYMMETRIC	= 0,
	VIRTCHNL_RSS_ALG_R_ASYMMETRIC		= 1,
	VIRTCHNL_RSS_ALG_TOEPLITZ_SYMMETRIC	= 2,
	VIRTCHNL_RSS_ALG_XOR_SYMMETRIC		= 3,
};

/* VIRTCHNL_OP_GET_CAPS
 * PF sends this message to CP to negotiate capabilities by filling
 * in the u64 bitmap of its desired capabilities.
 * CP responds with an updated virtchnl_get_capabilities structure
 * with allowed capabilities and possible max number of vfs it can create.
 */
struct virtchnl_get_capabilities {
	u64 cap_flags;
	u16 max_num_vfs;
};

VIRTCHNL_CHECK_STRUCT_LEN(16, virtchnl_get_capabilities);

/* structure to specify a chunk of contiguous queues */
struct virtchnl_queue_chunk {
	enum virtchnl_queue_type type;
	u16 start_queue_id;
	u16 num_queues;
};

VIRTCHNL_CHECK_STRUCT_LEN(8, virtchnl_queue_chunk);

/* structure to specify several chunks of contiguous queues */
struct virtchnl_queue_chunks {
	u16 num_chunks;
	struct virtchnl_queue_chunk chunks[];
};

VIRTCHNL_CHECK_STRUCT_LEN(4, virtchnl_queue_chunks);

/* VIRTCHNL_OP_CREATE_VPORT
 * PF sends this message to CP to create a vport by filling in the first 8
 * fields of virtchnl_create_vport structure (vport type, tx, rx queue models
 * and desired number of queues and vectors). CP responds with the updated
 * virtchnl_create_vport structure containing the number of assigned queues,
 * vectors, vport id, max mtu, default mac addr followed by chunks which in turn
 * will have an array of num_chunks entries of virtchnl_queue_chunk structures.
 */
struct virtchnl_create_vport {
	enum virtchnl_vport_type vport_type;
	/* single or split */
	enum virtchnl_queue_model txq_model;
	/* single or split */
	enum virtchnl_queue_model rxq_model;
	u16 num_tx_q;
	/* valid only if txq_model is split Q */
	u16 num_tx_complq;
	u16 num_rx_q;
	/* valid only if rxq_model is split Q */
	u16 num_rx_bufq;
	u16 num_vectors;
	u16 vport_id;
	u16 max_mtu;
	u8 default_mac_addr[ETH_ALEN];
	enum virtchnl_rss_algorithm rss_algorithm;
	u16 rss_key_size;
	u16 rss_lut_size;
	u16 qset_handle;
	struct virtchnl_queue_chunks chunks;
};

VIRTCHNL_CHECK_STRUCT_LEN(48, virtchnl_create_vport);

/* VIRTCHNL_OP_DESTROY_VPORT
 * VIRTCHNL_OP_ENABLE_VPORT
 * VIRTCHNL_OP_DISABLE_VPORT
 * PF sends this message to CP to destroy, enable or disable a vport by filling
 * in the vport_id in virtchnl_vport structure.
 * CP responds with the status of the requested operation.
 */
struct virtchnl_vport {
	u16 vport_id;
};

VIRTCHNL_CHECK_STRUCT_LEN(2, virtchnl_vport);

/* Tx queue config info */
struct virtchnl_txq_info_v2 {
	u16 queue_id;
	/* single or split */
	enum virtchnl_queue_model model;
	/* tx or tx_completion */
	enum virtchnl_queue_type type;
	/* queue or flow based */
	enum virtchnl_txq_sched_mode sched_mode;
	/* base or native */
	enum virtchnl_desc_profile desc_profile;
	u16 ring_len;
	u64 dma_ring_addr;
	/* valid only if queue model is split and type is tx */
	u16 tx_compl_queue_id;
};

VIRTCHNL_CHECK_STRUCT_LEN(40, virtchnl_txq_info_v2);

/* VIRTCHNL_OP_CONFIG_TX_QUEUES
 * PF sends this message to set up parameters for one or more TX queues.
 * This message contains an array of num_qinfo instances of virtchnl_txq_info_v2
 * structures. CP configures requested queues and returns a status code. If
 * num_qinfo specified is greater than the number of queues associated with the
 * vport, an error is returned and no queues are configured.
 */
struct virtchnl_config_tx_queues {
	u16 vport_id;
	u16 num_qinfo;
	struct virtchnl_txq_info_v2 txq_info[];
};

VIRTCHNL_CHECK_STRUCT_LEN(8, virtchnl_config_tx_queues);

/* Rx queue config info */
struct virtchnl_rxq_info_v2 {
	u16 queue_id;
	/* single or split */
	enum virtchnl_queue_model model;
	/* rx or rx buffer */
	enum virtchnl_queue_type type;
	/* base or native */
	enum virtchnl_desc_profile desc_profile;
	/* rsc, header-split, immediate write back */
	u16 queue_flags;
	/* 16 or 32 byte */
	enum virtchnl_rxq_desc_size desc_size;
	u16 ring_len;
	u16 hdr_buffer_size;
	u32 data_buffer_size;
	u32 max_pkt_size;
	u64 dma_ring_addr;
	u64 dma_head_wb_addr;
	u16 rsc_low_watermark;
	u8 buffer_notif_stride;
	enum virtchnl_rx_hsplit rx_split_pos;
	/* valid only if queue model is split and type is rx buffer*/
	u16 rx_bufq1_id;
	/* valid only if queue model is split and type is rx buffer*/
	u16 rx_bufq2_id;
};

VIRTCHNL_CHECK_STRUCT_LEN(72, virtchnl_rxq_info_v2);

/* VIRTCHNL_OP_CONFIG_RX_QUEUES
 * PF sends this message to set up parameters for one or more RX queues.
 * This message contains an array of num_qinfo instances of virtchnl_rxq_info_v2
 * structures. CP configures requested queues and returns a status code.
 * If the number of queues specified is greater than the number of queues
 * associated with the vport, an error is returned and no queues are configured.
 */
struct virtchnl_config_rx_queues {
	u16 vport_id;
	u16 num_qinfo;
	struct virtchnl_rxq_info_v2 rxq_info[];
};

VIRTCHNL_CHECK_STRUCT_LEN(8, virtchnl_config_rx_queues);

/* VIRTCHNL_OP_ADD_QUEUES
 * PF sends this message to request additional TX/RX queues beyond the ones
 * that were assigned via CREATE_VPORT request. virtchnl_add_queues structure is
 * used to specify the number of each type of queues.
 * CP responds with the same structure with the actual number of queues assigned
 * followed by num_chunks of virtchnl_queue_chunk structures.
 */
struct virtchnl_add_queues {
	u16 vport_id;
	u16 num_tx_q;
	u16 num_tx_complq;
	u16 num_rx_q;
	u16 num_rx_bufq;
	struct virtchnl_queue_chunks chunks;
};

VIRTCHNL_CHECK_STRUCT_LEN(16, virtchnl_add_queues);

/* VIRTCHNL_OP_ENABLE_QUEUES
 * VIRTCHNL_OP_DISABLE_QUEUES
 * VIRTCHNL_OP_DEL_QUEUES
 * PF sends these messages to enable, disable or delete queues specified in
 * chunks. PF sends virtchnl_del_ena_dis_queues struct to specify the queues
 * to be enabled/disabled/deleted. Also applicable to single queue RX or
 * TX. CP performs requested action and returns status.
 */
struct virtchnl_del_ena_dis_queues {
	u16 vport_id;
	struct virtchnl_queue_chunks chunks;
};

VIRTCHNL_CHECK_STRUCT_LEN(8, virtchnl_del_ena_dis_queues);

/* Vector to Queue mapping */
struct virtchnl_vector_queue {
	u16 vector_id;
	u16 queue_id;
	enum virtchnl_queue_type queue_type;
};

VIRTCHNL_CHECK_STRUCT_LEN(8, virtchnl_vector_queue);

/* VIRTCHNL_OP_MAP_VECTOR_QUEUE
 * VIRTCHNL_OP_UNMAP_VECTOR_QUEUE
 * PF sends this message to map or unmap vectors to queues.
 * This message contains an array of num_vector_queue_pairs instances of
 * virtchnl_vector_queue structures. CP configures interrupt mapping and returns
 * a status code. If the number of vectors specified is greater than the number
 * of vectors associated with the vport, an error is returned and no vectors are
 * mapped.
 */
struct virtchnl_vector_queue_pairs {
	u16 vport_id;
	u16 num_vector_queue_pairs;
	struct virtchnl_vector_queue vq[];
};

VIRTCHNL_CHECK_STRUCT_LEN(4, virtchnl_vector_queue_pairs);

/* Vector to ITR index registers mapping */
struct virtchnl_vector_itr {
	u16 vector_id;
	u16 rxitr_idx;
	u16 txitr_idx;
};

VIRTCHNL_CHECK_STRUCT_LEN(6, virtchnl_vector_itr);

/* VIRTCHNL_OP_MAP_VECTOR_ITR
 * PF sends this message to map vectors to RX and TX ITR index registers.
 * This message contains an array of num_vector_itr_pairs instances of
 * virtchnl_vector_itr structures. CP configures requested queues and returns a
 * status code. If the number of vectors specified is greater than the number of
 * vectors associated with the VSI, an error is returned and no vectors are
 * mapped.
 */
struct virtchnl_vector_itr_pairs {
	u16 vport_id;
	u16 num_vector_itr_pairs;
	struct virtchnl_vector_itr vitr[];
};

VIRTCHNL_CHECK_STRUCT_LEN(4, virtchnl_vector_itr_pairs);

/* VIRTCHNL_OP_GET_RSS_LUT
 * PF sends this message to get RSS lookup table. Only supported if
 * both PF and CP drivers set the VIRTCHNL_CAP_RSS bit during configuration
 * negotiation. Uses the virtchnl_rss_lut structure
 */

/* VIRTCHNL_OP_GET_RSS_KEY
 * PF sends this message to get RSS key. Only supported if
 * both PF and CP drivers set the VIRTCHNL_CAP_RSS bit during configuration
 * negotiation. Used the virtchnl_rss_key structure
 */

/* VIRTCHNL_OP_GET_RSS_HASH
 * VIRTCHNL_OP_SET_RSS_HASH
 * PF sends these messages to get and set the hash filter enable bits for RSS.
 * By default, the CP sets these to all possible traffic types that the
 * hardware supports. The PF can query this value if it wants to change the
 * traffic types that are hashed by the hardware.
 * Only supported if both PF and CP drivers set the VIRTCHNL_CAP_RSS bit
 * during configuration negotiation.
 */
struct virtchnl_rss_hash {
	u16 vport_id;
	u64 hash;
};

VIRTCHNL_CHECK_STRUCT_LEN(16, virtchnl_rss_hash);

/* VIRTCHNL_OP_CREATE_SRIOV_VFS
 * VIRTCHNL_OP_DESTROY_SRIOV_VFS
 * This message is used to let the CP know how many SRIOV VFs need to be
 * created. The actual allocation of resources for the VFs in terms of VSI,
 * Queues and Interrupts is done by CP. When this call completes, the APF driver
 * calls pci_enable_sriov to let the OS instantiate the SRIOV PCIE devices.
 */
struct virtchnl_sriov_vfs_info {
	u16 num_vfs;
};

VIRTCHNL_CHECK_STRUCT_LEN(2, virtchnl_sriov_vfs_info);

#endif /* VIRTCHNL_EXT_FEATURES */
/**
 * virtchnl_vc_validate_vf_msg
 * @ver: Virtchnl version info
 * @v_opcode: Opcode for the message
 * @msg: pointer to the msg buffer
 * @msglen: msg length
 *
 * validate msg format against struct for each opcode
 */
static inline int
virtchnl_vc_validate_vf_msg(struct virtchnl_version_info *ver, u32 v_opcode,
			    u8 *msg, u16 msglen)
{
	bool err_msg_format = false;
	int valid_len = 0;

	/* Validate message length. */
	switch (v_opcode) {
	case VIRTCHNL_OP_VERSION:
		valid_len = sizeof(struct virtchnl_version_info);
		break;
	case VIRTCHNL_OP_RESET_VF:
		break;
	case VIRTCHNL_OP_GET_VF_RESOURCES:
		if (VF_IS_V11(ver))
			valid_len = sizeof(u32);
		break;
	case VIRTCHNL_OP_CONFIG_TX_QUEUE:
		valid_len = sizeof(struct virtchnl_txq_info);
		break;
	case VIRTCHNL_OP_CONFIG_RX_QUEUE:
		valid_len = sizeof(struct virtchnl_rxq_info);
		break;
	case VIRTCHNL_OP_CONFIG_VSI_QUEUES:
		valid_len = sizeof(struct virtchnl_vsi_queue_config_info);
		if (msglen >= valid_len) {
			struct virtchnl_vsi_queue_config_info *vqc =
			    (struct virtchnl_vsi_queue_config_info *)msg;

			if (vqc->num_queue_pairs >
			    VIRTCHNL_OP_CONFIG_VSI_QUEUES_MAX) {
				err_msg_format = true;
				break;
			}

			valid_len += (vqc->num_queue_pairs *
				      sizeof(struct
					     virtchnl_queue_pair_info));
			if (vqc->num_queue_pairs == 0)
				err_msg_format = true;
		}
		break;
	case VIRTCHNL_OP_CONFIG_IRQ_MAP:
		valid_len = sizeof(struct virtchnl_irq_map_info);
		if (msglen >= valid_len) {
			struct virtchnl_irq_map_info *vimi =
			    (struct virtchnl_irq_map_info *)msg;

			if (vimi->num_vectors >
			    VIRTCHNL_OP_CONFIG_IRQ_MAP_MAX) {
				err_msg_format = true;
				break;
			}

			valid_len += (vimi->num_vectors *
				      sizeof(struct virtchnl_vector_map));

			if (vimi->num_vectors == 0)
				err_msg_format = true;
		}
		break;
	case VIRTCHNL_OP_ENABLE_QUEUES:
	case VIRTCHNL_OP_DISABLE_QUEUES:
		valid_len = sizeof(struct virtchnl_queue_select);
		break;
	case VIRTCHNL_OP_ADD_ETH_ADDR:
	case VIRTCHNL_OP_DEL_ETH_ADDR:
		valid_len = sizeof(struct virtchnl_ether_addr_list);
		if (msglen >= valid_len) {
			struct virtchnl_ether_addr_list *veal =
			    (struct virtchnl_ether_addr_list *)msg;

			if (veal->num_elements >
			    VIRTCHNL_OP_ADD_DEL_ETH_ADDR_MAX) {
				err_msg_format = true;
				break;
			}

			valid_len += veal->num_elements *
			    sizeof(struct virtchnl_ether_addr);
			if (veal->num_elements == 0)
				err_msg_format = true;
		}
		break;
	case VIRTCHNL_OP_ADD_VLAN:
	case VIRTCHNL_OP_DEL_VLAN:
		valid_len = sizeof(struct virtchnl_vlan_filter_list);
		if (msglen >= valid_len) {
			struct virtchnl_vlan_filter_list *vfl =
			    (struct virtchnl_vlan_filter_list *)msg;

			if (vfl->num_elements >
			    VIRTCHNL_OP_ADD_DEL_VLAN_MAX) {
				err_msg_format = true;
				break;
			}

			valid_len += vfl->num_elements * sizeof(u16);

			if (vfl->num_elements == 0)
				err_msg_format = true;
		}
		break;
	case VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE:
		valid_len = sizeof(struct virtchnl_promisc_info);
		break;
	case VIRTCHNL_OP_GET_STATS:
		valid_len = sizeof(struct virtchnl_queue_select);
		break;
#ifdef VIRTCHNL_IWARP
	case VIRTCHNL_OP_IWARP:
		/* These messages are opaque to us and will be validated in
		 * the RDMA client code. We just need to check for nonzero
		 * length. The firmware will enforce max length restrictions.
		 */
		if (msglen)
			valid_len = msglen;
		else
			err_msg_format = true;
		break;
	case VIRTCHNL_OP_RELEASE_IWARP_IRQ_MAP:
		break;
	case VIRTCHNL_OP_CONFIG_IWARP_IRQ_MAP:
		valid_len = sizeof(struct virtchnl_iwarp_qvlist_info);
		if (msglen >= valid_len) {
			struct virtchnl_iwarp_qvlist_info *qv =
				(struct virtchnl_iwarp_qvlist_info *)msg;

			if (qv->num_vectors >
			    VIRTCHNL_OP_CONFIG_IWARP_IRQ_MAP_MAX) {
				err_msg_format = true;
				break;
			}

			if (qv->num_vectors == 0) {
				err_msg_format = true;
				break;
			}
			valid_len += ((qv->num_vectors - 1) *
				sizeof(struct virtchnl_iwarp_qv_info));
		}
		break;
#endif
	case VIRTCHNL_OP_CONFIG_RSS_KEY:
		valid_len = sizeof(struct virtchnl_rss_key);
		if (msglen >= valid_len) {
			struct virtchnl_rss_key *vrk =
				(struct virtchnl_rss_key *)msg;
			valid_len += vrk->key_len - 1;
		}
		break;
	case VIRTCHNL_OP_CONFIG_RSS_LUT:
		valid_len = sizeof(struct virtchnl_rss_lut);
		if (msglen >= valid_len) {
			struct virtchnl_rss_lut *vrl =
				(struct virtchnl_rss_lut *)msg;
			valid_len += vrl->lut_entries - 1;
		}
		break;
	case VIRTCHNL_OP_GET_RSS_HENA_CAPS:
		break;
	case VIRTCHNL_OP_SET_RSS_HENA:
		valid_len = sizeof(struct virtchnl_rss_hena);
		break;
	case VIRTCHNL_OP_ENABLE_VLAN_STRIPPING:
	case VIRTCHNL_OP_DISABLE_VLAN_STRIPPING:
		break;
	case VIRTCHNL_OP_REQUEST_QUEUES:
		valid_len = sizeof(struct virtchnl_vf_res_request);
		break;
	case VIRTCHNL_OP_ENABLE_CHANNELS:
		valid_len = sizeof(struct virtchnl_tc_info);
		if (msglen >= valid_len) {
			struct virtchnl_tc_info *vti =
				(struct virtchnl_tc_info *)msg;

			if (vti->num_tc >
			    VIRTCHNL_OP_ENABLE_CHANNELS_MAX) {
				err_msg_format = true;
				break;
			}

			valid_len += (vti->num_tc - 1) *
				     sizeof(struct virtchnl_channel_info);
			if (vti->num_tc == 0)
				err_msg_format = true;
		}
		break;
	case VIRTCHNL_OP_DISABLE_CHANNELS:
		break;
	case VIRTCHNL_OP_ADD_CLOUD_FILTER:
	case VIRTCHNL_OP_DEL_CLOUD_FILTER:
		valid_len = sizeof(struct virtchnl_filter);
		break;
#ifdef VIRTCHNL_SOL_VF_SUPPORT
	case VIRTCHNL_OP_GET_ADDNL_SOL_CONFIG:
		break;
#endif
#ifdef VIRTCHNL_EXT_FEATURES
	case VIRTCHNL_OP_GET_CAPS:
		valid_len = sizeof(struct virtchnl_get_capabilities);
		break;
	case VIRTCHNL_OP_CREATE_VPORT:
		valid_len = sizeof(struct virtchnl_create_vport);
		if (msglen >= valid_len) {
			struct virtchnl_create_vport *cvport =
				(struct virtchnl_create_vport *)msg;

			valid_len += cvport->chunks.num_chunks *
				      sizeof(struct virtchnl_queue_chunk);
		}
		break;
	case VIRTCHNL_OP_DESTROY_VPORT:
	case VIRTCHNL_OP_ENABLE_VPORT:
	case VIRTCHNL_OP_DISABLE_VPORT:
		valid_len = sizeof(struct virtchnl_vport);
		break;
	case VIRTCHNL_OP_CONFIG_TX_QUEUES:
		valid_len = sizeof(struct virtchnl_config_tx_queues);
		if (msglen >= valid_len) {
			struct virtchnl_config_tx_queues *ctq =
				(struct virtchnl_config_tx_queues *)msg;
			if (ctq->num_qinfo == 0) {
				err_msg_format = true;
				break;
			}
			valid_len += ctq->num_qinfo *
				     sizeof(struct virtchnl_txq_info_v2);
		}
		break;
	case VIRTCHNL_OP_CONFIG_RX_QUEUES:
		valid_len = sizeof(struct virtchnl_config_rx_queues);
		if (msglen >= valid_len) {
			struct virtchnl_config_rx_queues *crq =
				(struct virtchnl_config_rx_queues *)msg;
			if (crq->num_qinfo == 0) {
				err_msg_format = true;
				break;
			}
			valid_len += crq->num_qinfo *
				     sizeof(struct virtchnl_rxq_info_v2);
		}
		break;
	case VIRTCHNL_OP_ADD_QUEUES:
		valid_len = sizeof(struct virtchnl_add_queues);
		if (msglen >= valid_len) {
			struct virtchnl_add_queues *add_q =
				(struct virtchnl_add_queues *)msg;

			valid_len += add_q->chunks.num_chunks *
				      sizeof(struct virtchnl_queue_chunk);
		}
		break;
	case VIRTCHNL_OP_ENABLE_QUEUES_V2:
	case VIRTCHNL_OP_DISABLE_QUEUES_V2:
	case VIRTCHNL_OP_DEL_QUEUES:
		valid_len = sizeof(struct virtchnl_del_ena_dis_queues);
		if (msglen >= valid_len) {
			struct virtchnl_del_ena_dis_queues *qs =
				(struct virtchnl_del_ena_dis_queues *)msg;
			if (qs->chunks.num_chunks == 0) {
				err_msg_format = true;
				break;
			}
			valid_len += qs->chunks.num_chunks *
				      sizeof(struct virtchnl_queue_chunk);
		}
		break;
	case VIRTCHNL_OP_MAP_VECTOR_QUEUE:
	case VIRTCHNL_OP_UNMAP_VECTOR_QUEUE:
		valid_len = sizeof(struct virtchnl_vector_queue_pairs);
		if (msglen >= valid_len) {
			struct virtchnl_vector_queue_pairs *v_qp =
				(struct virtchnl_vector_queue_pairs *)msg;
			if (v_qp->num_vector_queue_pairs == 0) {
				err_msg_format = true;
				break;
			}
			valid_len += v_qp->num_vector_queue_pairs *
				      sizeof(struct virtchnl_vector_queue);
		}
		break;
	case VIRTCHNL_OP_MAP_VECTOR_ITR:
		valid_len = sizeof(struct virtchnl_vector_itr_pairs);
		if (msglen >= valid_len) {
			struct virtchnl_vector_itr_pairs *v_itrp =
				(struct virtchnl_vector_itr_pairs *)msg;
			if (v_itrp->num_vector_itr_pairs == 0) {
				err_msg_format = true;
				break;
			}
			valid_len += v_itrp->num_vector_itr_pairs *
				      sizeof(struct virtchnl_vector_itr);
		}
		break;
	case VIRTCHNL_OP_GET_RSS_KEY:
		valid_len = sizeof(struct virtchnl_rss_key);
		if (msglen >= valid_len) {
			struct virtchnl_rss_key *vrk =
				(struct virtchnl_rss_key *)msg;
			valid_len += vrk->key_len - 1;
		}
		break;
	case VIRTCHNL_OP_GET_RSS_LUT:
		valid_len = sizeof(struct virtchnl_rss_lut);
		if (msglen >= valid_len) {
			struct virtchnl_rss_lut *vrl =
				(struct virtchnl_rss_lut *)msg;
			valid_len += vrl->lut_entries - 1;
		}
		break;
	case VIRTCHNL_OP_GET_RSS_HASH:
	case VIRTCHNL_OP_SET_RSS_HASH:
		valid_len = sizeof(struct virtchnl_rss_hash);
		break;
	case VIRTCHNL_OP_CREATE_VFS:
	case VIRTCHNL_OP_DESTROY_VFS:
		valid_len = sizeof(struct virtchnl_sriov_vfs_info);
		break;
#endif /* VIRTCHNL_EXT_FEATURES */
	/* These are always errors coming from the VF. */
	case VIRTCHNL_OP_EVENT:
	case VIRTCHNL_OP_UNKNOWN:
	default:
		return VIRTCHNL_STATUS_ERR_PARAM;
	}
	/* few more checks */
	if (err_msg_format || valid_len != msglen)
		return VIRTCHNL_STATUS_ERR_OPCODE_MISMATCH;

	return 0;
}
#endif /* _VIRTCHNL_H_ */
