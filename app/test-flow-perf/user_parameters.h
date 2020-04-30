/* SPDX-License-Identifier: BSD-3-Claus
 *
 * This file will hold the user parameters values
 *
 * Copyright 2020 Mellanox Technologies, Ltd
 */

/** Configuration **/
#define RXQs 4
#define TXQs 4
#define HAIRPIN_QUEUES 4
#define TOTAL_MBUF_NUM 32000
#define MBUF_SIZE 2048
#define MBUF_CACHE_SIZE 512
#define NR_RXD  256
#define NR_TXD  256

/** Items/Actions parameters **/
#define JUMP_ACTION_TABLE 2
#define VLAN_VALUE 1
#define VNI_VALUE 1
#define GRE_PROTO  0x6558
#define META_DATA 1
#define TAG_INDEX 0
#define PORT_ID_DST 1
#define MARK_ID 1
#define TEID_VALUE 1

/** Flow items/acctions max size **/
#define MAX_ITEMS_NUM 20
#define MAX_ACTIONS_NUM 20
