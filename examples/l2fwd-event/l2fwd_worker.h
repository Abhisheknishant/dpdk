/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2019 Marvell International Ltd.
 */
#ifndef _L2FWD_WORKER_H_
#define _L2FWD_WORKER_H_

struct tsc_tracker {
	uint64_t prev_tsc;
	uint64_t timer_tsc;
	uint64_t drain_tsc;
};

int
l2fwd_launch_one_lcore(__attribute__((unused)) void *dummy);

#endif /* _L2FWD_WORKER_H_ */
