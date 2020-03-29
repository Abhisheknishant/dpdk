/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 * Copyright(C) 2020 Mellanox International Ltd.
 */

#include <string.h>

#include <rte_spinlock.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_string_fns.h>

#include "rte_regexdev.h"
#include "rte_regexdev_driver.h"

static struct rte_regexdev *regex_devices[RTE_MAX_REGEXDEV_DEVS];

int rte_regexdev_logtype;

static uint16_t
regexdev_find_free_dev(void)
{
	uint16_t i;

	for (i = 0; i < RTE_MAX_REGEXDEV_DEVS; i++) {
		if (regex_devices[i] == NULL)
			return i;
	}
	return RTE_MAX_REGEXDEV_DEVS;
}

static const struct rte_regexdev*
regexdev_allocated(const char *name)
{
	uint16_t i;

	for (i = 0; i < RTE_MAX_REGEXDEV_DEVS; i++) {
		if (regex_devices[i] != NULL)
			if (!strcmp(name, regex_devices[i]->dev_name))
				return regex_devices[i];
	}
	return NULL;
}

int
rte_regexdev_register(struct rte_regexdev *dev)
{
	uint16_t dev_id;
	int res;

	if (dev->dev_ops == NULL) {
		RTE_REGEXDEV_LOG(ERR, "RegEx device invalid device ops\n");
		return -EINVAL;
	}
	if (regexdev_allocated(dev->dev_name) != NULL) {
		RTE_REGEXDEV_LOG
			(ERR, "RegEx device with name %s already allocated\n",
			 dev->dev_name);
		return -ENOMEM;
	}
	dev_id = regexdev_find_free_dev();
	if (dev_id == RTE_MAX_REGEXDEV_DEVS) {
		RTE_REGEXDEV_LOG
			(ERR, "Reached maximum number of regex devs\n");
		return -ENOMEM;
	}
	dev->dev_id = dev_id;
	regex_devices[dev_id] = dev;
	res = dev_id;
	return res;
}

void
rte_regexdev_unregister(struct rte_regexdev *dev)
{
	regex_devices[dev->dev_id] = NULL;
}

uint8_t
rte_regexdev_count(void)
{
	int i;
	int count = 0;

	for (i = 0; i < RTE_MAX_REGEXDEV_DEVS; i++) {
		if (regex_devices[i] != NULL)
			count++;
	}
	return count;
}

int
rte_regexdev_get_dev_id(const char *name)
{
	int i;
	int id = -EINVAL;

	if (name == NULL)
		return -EINVAL;
	for (i = 0; i < RTE_MAX_REGEXDEV_DEVS; i++) {
		if (regex_devices[i] != NULL)
			if (strcmp(name, regex_devices[i]->dev_name)) {
				id = regex_devices[i]->dev_id;
				break;
			}
	}
	return id;
}

int
rte_regexdev_info_get(uint8_t dev_id, struct rte_regexdev_info *dev_info)
{
	if (dev_id >= RTE_MAX_REGEXDEV_DEVS)
		return -EINVAL;
	if (regex_devices[dev_id] == NULL)
		return -EINVAL;
	if (dev_info == NULL)
		return -EINVAL;
	if (regex_devices[dev_id]->dev_ops->dev_info_get == NULL)
		return -ENOTSUP;
	return regex_devices[dev_id]->dev_ops->dev_info_get
		(regex_devices[dev_id], dev_info);
}

int
rte_regexdev_configure(uint8_t dev_id, const struct rte_regexdev_config *cfg)
{
	if (dev_id >= RTE_MAX_REGEXDEV_DEVS)
		return -EINVAL;
	if (regex_devices[dev_id] == NULL)
		return -EINVAL;
	if (cfg == NULL)
		return -EINVAL;
	if (regex_devices[dev_id]->dev_ops->dev_configure == NULL)
		return -ENOTSUP;
	return regex_devices[dev_id]->dev_ops->dev_configure
		(regex_devices[dev_id], cfg);
}

int
rte_regexdev_queue_pair_setup(uint8_t dev_id, uint16_t queue_pair_id,
			   const struct rte_regexdev_qp_conf *qp_conf)
{
	if (dev_id >= RTE_MAX_REGEXDEV_DEVS)
		return -EINVAL;
	if (regex_devices[dev_id] == NULL)
		return -EINVAL;
	if (regex_devices[dev_id]->dev_ops->dev_qp_setup == NULL)
		return -ENOTSUP;
	return regex_devices[dev_id]->dev_ops->dev_qp_setup
		(regex_devices[dev_id], queue_pair_id, qp_conf);
}

int
rte_regexdev_start(uint8_t dev_id)
{
	if (dev_id >= RTE_MAX_REGEXDEV_DEVS)
		return -EINVAL;
	if (regex_devices[dev_id] == NULL)
		return -EINVAL;
	if (regex_devices[dev_id]->dev_ops->dev_start == NULL)
		return -ENOTSUP;
	return regex_devices[dev_id]->dev_ops->dev_start(regex_devices[dev_id]);
}

void
rte_regexdev_stop(uint8_t dev_id)
{
	if (dev_id >= RTE_MAX_REGEXDEV_DEVS)
		return;
	if (regex_devices[dev_id] == NULL)
		return;
	regex_devices[dev_id]->dev_ops->dev_stop(regex_devices[dev_id]);
}

int
rte_regexdev_close(uint8_t dev_id)
{
	if (dev_id >= RTE_MAX_REGEXDEV_DEVS)
		return -EINVAL;
	if (regex_devices[dev_id] == NULL)
		return -EINVAL;
	if (regex_devices[dev_id]->dev_ops->dev_close == NULL)
		return -ENOTSUP;
	regex_devices[dev_id]->dev_ops->dev_close(regex_devices[dev_id]);
	return 0;
}

int
rte_regexdev_attr_get(uint8_t dev_id, enum rte_regexdev_attr_id attr_id,
		      void *attr_value)
{
	if (dev_id >= RTE_MAX_REGEXDEV_DEVS)
		return -EINVAL;
	if (regex_devices[dev_id] == NULL)
		return -EINVAL;
	if (regex_devices[dev_id]->dev_ops->dev_attr_get == NULL)
		return -ENOTSUP;
	return regex_devices[dev_id]->dev_ops->dev_attr_get
		(regex_devices[dev_id], attr_id, attr_value);
}

int
rte_regexdev_attr_set(uint8_t dev_id, enum rte_regexdev_attr_id attr_id,
		      const void *attr_value)
{
	if (dev_id >= RTE_MAX_REGEXDEV_DEVS)
		return -EINVAL;
	if (regex_devices[dev_id] == NULL)
		return -EINVAL;
	if (regex_devices[dev_id]->dev_ops->dev_attr_set == NULL)
		return -ENOTSUP;
	return regex_devices[dev_id]->dev_ops->dev_attr_set
		(regex_devices[dev_id], attr_id, attr_value);
}

int
rte_regexdev_rule_db_update(uint8_t dev_id,
			    const struct rte_regexdev_rule *rules,
			    uint32_t nb_rules)
{
	if (dev_id >= RTE_MAX_REGEXDEV_DEVS)
		return -EINVAL;
	if (regex_devices[dev_id] == NULL)
		return -EINVAL;
	if (regex_devices[dev_id]->dev_ops->dev_rule_db_update == NULL)
		return -ENOTSUP;
	return regex_devices[dev_id]->dev_ops->dev_rule_db_update
		(regex_devices[dev_id], rules, nb_rules);
}

int
rte_regexdev_rule_db_compile_activate(uint8_t dev_id)
{
	if (dev_id >= RTE_MAX_REGEXDEV_DEVS)
		return -EINVAL;
	if (regex_devices[dev_id] == NULL)
		return -EINVAL;
	if (regex_devices[dev_id]->dev_ops->dev_rule_db_compile_activate ==
	    NULL)
		return -ENOTSUP;
	return regex_devices[dev_id]->dev_ops->dev_rule_db_compile_activate
		(regex_devices[dev_id]);
}

int
rte_regexdev_rule_db_import(uint8_t dev_id, const char *rule_db,
			    uint32_t rule_db_len)
{
	if (dev_id >= RTE_MAX_REGEXDEV_DEVS)
		return -EINVAL;
	if (regex_devices[dev_id] == NULL)
		return -EINVAL;
	if (rule_db == NULL)
		return -EINVAL;
	if (regex_devices[dev_id]->dev_ops->dev_db_import == NULL)
		return -ENOTSUP;
	return regex_devices[dev_id]->dev_ops->dev_db_import
		(regex_devices[dev_id], rule_db, rule_db_len);
}

int
rte_regexdev_rule_db_export(uint8_t dev_id, char *rule_db)
{
	if (dev_id >= RTE_MAX_REGEXDEV_DEVS)
		return -EINVAL;
	if (regex_devices[dev_id] == NULL)
		return -EINVAL;
	if (regex_devices[dev_id]->dev_ops->dev_db_export == NULL)
		return -ENOTSUP;
	return regex_devices[dev_id]->dev_ops->dev_db_export
		(regex_devices[dev_id], rule_db);
}

int
rte_regexdev_xstats_names_get(uint8_t dev_id,
			      struct rte_regexdev_xstats_map *xstats_map)
{
	if (dev_id >= RTE_MAX_REGEXDEV_DEVS)
		return -EINVAL;
	if (regex_devices[dev_id] == NULL)
		return -EINVAL;
	if (xstats_map == NULL)
		return -EINVAL;
	if (regex_devices[dev_id]->dev_ops->dev_xstats_names_get == NULL)
		return -ENOTSUP;
	return regex_devices[dev_id]->dev_ops->dev_xstats_names_get
		(regex_devices[dev_id], xstats_map);
}

int
rte_regexdev_xstats_get(uint8_t dev_id, const uint16_t *ids,
			uint64_t *values, uint16_t n)
{
	if (dev_id >= RTE_MAX_REGEXDEV_DEVS)
		return -EINVAL;
	if (regex_devices[dev_id] == NULL)
		return -EINVAL;
	if (regex_devices[dev_id]->dev_ops->dev_xstats_get == NULL)
		return -ENOTSUP;
	return regex_devices[dev_id]->dev_ops->dev_xstats_get
		(regex_devices[dev_id], ids, values, n);
}

int
rte_regexdev_xstats_by_name_get(uint8_t dev_id, const char *name,
				uint16_t *id, uint64_t *value)
{
	if (dev_id >= RTE_MAX_REGEXDEV_DEVS)
		return -EINVAL;
	if (regex_devices[dev_id] == NULL)
		return -EINVAL;
	if (regex_devices[dev_id]->dev_ops->dev_xstats_by_name_get == NULL)
		return -ENOTSUP;
	return regex_devices[dev_id]->dev_ops->dev_xstats_by_name_get
		(regex_devices[dev_id], name, id, value);
}

int
rte_regexdev_xstats_reset(uint8_t dev_id, const uint16_t *ids,
			  uint16_t nb_ids)
{
	if (dev_id >= RTE_MAX_REGEXDEV_DEVS)
		return -EINVAL;
	if (regex_devices[dev_id] == NULL)
		return -EINVAL;
	if (regex_devices[dev_id]->dev_ops->dev_xstats_reset == NULL)
		return -ENOTSUP;
	return regex_devices[dev_id]->dev_ops->dev_xstats_reset
		(regex_devices[dev_id], ids, nb_ids);
}

int
rte_regexdev_selftest(uint8_t dev_id)
{
	if (dev_id >= RTE_MAX_REGEXDEV_DEVS)
		return -EINVAL;
	if (regex_devices[dev_id] == NULL)
		return -EINVAL;
	if (regex_devices[dev_id]->dev_ops->dev_selftest == NULL)
		return -ENOTSUP;
	return regex_devices[dev_id]->dev_ops->dev_selftest
		(regex_devices[dev_id]);
}

int
rte_regexdev_dump(uint8_t dev_id, FILE *f)
{
	if (dev_id >= RTE_MAX_REGEXDEV_DEVS)
		return -EINVAL;
	if (regex_devices[dev_id] == NULL)
		return -EINVAL;
	if (f == NULL)
		return -EINVAL;
	if (regex_devices[dev_id]->dev_ops->dev_dump == NULL)
		return -ENOTSUP;
	return regex_devices[dev_id]->dev_ops->dev_dump
		(regex_devices[dev_id], f);
}

uint16_t
rte_regexdev_enqueue_burst(uint8_t dev_id, uint16_t qp_id,
			   struct rte_regex_ops **ops, uint16_t nb_ops)
{
	return regex_devices[dev_id]->enqueue(regex_devices[dev_id], qp_id,
					      ops, nb_ops);
}

uint16_t
rte_regexdev_dequeue_burst(uint8_t dev_id, uint16_t qp_id,
			   struct rte_regex_ops **ops, uint16_t nb_ops)
{
	return regex_devices[dev_id]->dequeue(regex_devices[dev_id], qp_id,
					      ops, nb_ops);
}
