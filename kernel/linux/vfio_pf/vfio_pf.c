/* SPDX-License-Identifier: GPL-2.0
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include <linux/device.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>

struct vfio_pf_group {
	struct kobject *kobj;
	struct kobj_attribute add_pf;
	struct kobj_attribute remove_pf;
	struct mutex lock;
	struct list_head head;
};

static struct vfio_pf_group *pf_group;

#define FMT_NVAL 4
#define PCI_STR_SIZE sizeof("XXXXXXXX:XX:XX.X")

struct pci_addr {
	char name[PCI_STR_SIZE + 1];
	uint32_t domain;
	uint8_t bus;
	uint8_t devid;
	uint8_t function;
};

struct pf_obj {
	struct list_head node;
	struct pci_dev *pdev;
	struct kobject *kobj;
	struct kobj_attribute sysfs;
	struct pci_addr paddr;
};

static int
str_split(char *string, int stringlen,
	  char **tokens, int maxtokens, char delim)
{
	int tokstart = 1;
	int i, tok = 0;

	if (string == NULL || tokens == NULL)
		goto error;

	for (i = 0; i < stringlen; i++) {
		if (string[i] == '\0' || tok >= maxtokens)
			break;
		if (tokstart) {
			tokstart = 0;
			tokens[tok++] = &string[i];
		}
		if (string[i] == delim) {
			string[i] = '\0';
			tokstart = 1;
		}
	}
	return tok;

error:
	return -1;
}

static int
parse_pci_addr(const char *buf, int bufsize, struct pci_addr *paddr)
{
	union splitaddr {
		struct {
			char *domain;
			char *bus;
			char *devid;
			char *function;
		};
		char *str[FMT_NVAL];
	} splitaddr;

	char *buf_copy = kstrndup(buf, bufsize, GFP_KERNEL);
	if (buf_copy == NULL)
		return -ENOMEM;

	if (str_split(buf_copy, bufsize, splitaddr.str, FMT_NVAL, ':')
			!= FMT_NVAL - 1)
		goto error;
	/* final split is on '.' between devid and function */
	splitaddr.function = strchr(splitaddr.devid, '.');
	if (splitaddr.function == NULL)
		goto error;
	*splitaddr.function++ = '\0';

	if (kstrtou32(splitaddr.domain, 16, &paddr->domain) ||
		kstrtou8(splitaddr.bus, 16, &paddr->bus) ||
		kstrtou8(splitaddr.devid, 16, &paddr->devid) ||
		kstrtou8(splitaddr.function, 10, &paddr->function))
		goto error;

	snprintf(paddr->name, sizeof(paddr->name), "%.4x:%.2x:%.2x.%.x",
		 paddr->domain, paddr->bus, paddr->devid, paddr->function);

	kfree(buf_copy);
	return 0;
error:
	kfree(buf_copy);
	return -EINVAL;
}

static ssize_t
show_num_vfs(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct pf_obj *obj;

	obj = container_of(attr, struct pf_obj, sysfs);

	return snprintf(buf, 10, "%u\n", pci_num_vf(obj->pdev));
}

static ssize_t
store_num_vfs(struct kobject *kobj, struct kobj_attribute *attr,
	      const char *buf, size_t count)
{
	struct pf_obj *obj;
	int num_vfs, err = 0;

	obj = container_of(attr, struct pf_obj, sysfs);

	if (kstrtoint(buf, 0, &num_vfs)) {
		pr_err("Invalid %s,  %s\n", attr->attr.name, buf);
		err = -EIO;
	}
	if (num_vfs < 0) {
		pr_err("Invalid %s,  %d < 0\n", attr->attr.name,
			num_vfs);
		err = -EIO;
	}

	if (num_vfs == 0)
		pci_disable_sriov(obj->pdev);
	else if (pci_num_vf(obj->pdev) == 0)
		err = pci_enable_sriov(obj->pdev, num_vfs);
	else
		err = -EINVAL;

	return err ? err : count;
}

static int
pf_sysfs_create(char *name, struct pf_obj *obj)
{
	int err;

	if (name == NULL || obj == NULL)
		return -EINVAL;

	obj->sysfs.show = show_num_vfs;
	obj->sysfs.store = store_num_vfs;
	obj->sysfs.attr.name = name;
	obj->sysfs.attr.mode = 0644;

	sysfs_attr_init(&obj->sysfs.attr);
	err = sysfs_create_file(obj->kobj, &obj->sysfs.attr);
	if (err) {
		pr_err("Failed to create '%s' sysfs for '%s'\n",
			name, kobject_name(obj->kobj));
		return -EFAULT;
	}

	return 0;
}

static int
probe_pf_dev(struct pf_obj *obj)
{
	struct pci_dev *pdev = NULL;
	struct pci_addr *paddr;

	paddr = &obj->paddr;

	pdev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, pdev);
	if (pdev == NULL)
		return -ENODEV;

	while (pdev) {
		if ((paddr->domain == pci_domain_nr(pdev->bus)) &&
		    (pdev->bus->number == paddr->bus) &&
		    (PCI_SLOT(pdev->devfn) == paddr->devid) &&
		    (PCI_FUNC(pdev->devfn) == paddr->function))
			break;

		pdev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, pdev);
	};

	if (pdev) {
		obj->pdev = pdev;
		return 0;
	} else
		return -ENODEV;
}

static ssize_t
add_device(struct kobject *kobj, struct kobj_attribute *attr,
	   const char *buf, size_t count)
{
	struct pf_obj *obj;
	int err = 0;

	obj = kzalloc(sizeof(struct pf_obj), GFP_KERNEL);
	if (obj == NULL) {
		err = -ENOMEM;
		goto exit;
	}

	if (parse_pci_addr(buf, strlen(buf), &obj->paddr)) {
		err = -EINVAL;
		goto exit;
	}

	if (probe_pf_dev(obj)) {
		err = -ENXIO;
		goto exit;
	}

	obj->kobj = kobject_create_and_add(obj->paddr.name, pf_group->kobj);

	if (pf_sysfs_create("num_vfs", obj)) {
		pci_dev_put(obj->pdev);
		pr_err("Failed to create the sysfs for pdev:%s\n",
			obj->paddr.name);
		return -EFAULT;
	}

	mutex_lock(&pf_group->lock);
	list_add(&obj->node, &pf_group->head);
	mutex_unlock(&pf_group->lock);

exit:
	if (err && obj)
		kfree(obj);

	return err ? err : count;
}

static void
remove_pf_obj(struct pf_obj *obj)
{
	if (pci_num_vf(obj->pdev))
		pci_disable_sriov(obj->pdev);
	sysfs_remove_file(obj->kobj, &obj->sysfs.attr);
	kobject_del(obj->kobj);
	list_del(&obj->node);
	pci_dev_put(obj->pdev);
	kfree(obj);
}

static ssize_t
remove_device(struct kobject *kobj, struct kobj_attribute *attr,
	      const char *buf, size_t count)
{
	struct list_head *pos, *tmp;
	struct pci_addr paddr;
	struct pf_obj *obj;
	int err = 0;

	if (parse_pci_addr(buf, strlen(buf), &paddr)) {
		err = -EINVAL;
		goto exit;
	}

	list_for_each_safe(pos, tmp, &pf_group->head) {
		obj = list_entry(pos, struct pf_obj, node);
		if (!strncmp(obj->paddr.name, paddr.name, sizeof(paddr.name))) {
			remove_pf_obj(obj);
			break;
		}
	}

exit:
	return err ? err : count;
}

static void
destroy_pf_objs(void)
{
	struct list_head *pos, *tmp;
	struct pf_obj *obj;

	list_for_each_safe(pos, tmp, &pf_group->head) {
		obj = list_entry(pos, struct pf_obj, node);
		remove_pf_obj(obj);
	}
}

static void
__exit vfio_pf_cleanup(void)
{
	if (pf_group == NULL)
		return;

	destroy_pf_objs();
	sysfs_remove_file(pf_group->kobj, &pf_group->add_pf.attr);
	sysfs_remove_file(pf_group->kobj, &pf_group->remove_pf.attr);
	kobject_del(pf_group->kobj);
	mutex_destroy(&pf_group->lock);
	kfree(pf_group);
}

static int
__init vfio_pf_init(void)
{
	int err;

	pf_group = kzalloc(sizeof(struct vfio_pf_group), GFP_KERNEL);
	if (pf_group == NULL)
		return -ENOMEM;

	pf_group->kobj = kobject_create_and_add("vfio_pf", NULL);
	pf_group->add_pf.store = add_device;
	pf_group->add_pf.attr.name = "add_device";
	pf_group->add_pf.attr.mode = 0644;
	pf_group->remove_pf.store = remove_device;
	pf_group->remove_pf.attr.name = "remove_device";
	pf_group->remove_pf.attr.mode = 0644;

	sysfs_attr_init(&pf_group->add_pf.attr);
	err = sysfs_create_file(pf_group->kobj, &pf_group->add_pf.attr);
	if (err) {
		pr_err("Failed to create sysfs '%s' for '%s'\n",
			pf_group->add_pf.attr.name,
			kobject_name(pf_group->kobj));
		goto exit;
	}

	sysfs_attr_init(&pf_group->remove_pf.attr);
	err = sysfs_create_file(pf_group->kobj, &pf_group->remove_pf.attr);
	if (err) {
		pr_err("Failed to create sysfs '%s' for '%s'\n",
			pf_group->remove_pf.attr.name,
			kobject_name(pf_group->kobj));
		sysfs_remove_file(pf_group->kobj, &pf_group->add_pf.attr);
		goto exit;
	}

	INIT_LIST_HEAD(&pf_group->head);

	mutex_init(&pf_group->lock);

	return 0;

exit:
	kfree(pf_group);
	return -EFAULT;
}

module_init(vfio_pf_init);
module_exit(vfio_pf_cleanup);

MODULE_DESCRIPTION("Kernel module for enabling SRIOV");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marvell International Ltd");
