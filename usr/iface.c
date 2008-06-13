/*
 * iSCSI iface helpers
 *
 * Copyright (C) 2008 Mike Christie
 * Copyright (C) 2008 Red Hat, Inc. All rights reserved.
 * maintained by open-iscsi@@googlegroups.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * See the file COPYING included with this distribution for more details.
 */
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "log.h"
#include "list.h"
#include "iscsi_sysfs.h"
#include "iscsi_settings.h"
#include "config.h"
#include "transport.h"
#include "idbm.h"
#include "iface.h"

/*
 * Default ifaces for use with transports that do not bind to hardware
 * by defaults (transports that let the interconnect layer to the routing
 * by defaults).
 */

/*
 * iSCSI over TCP/IP
 */
static struct iface_rec iface_default = {
	.name		= "default",
	.transport_name	= "tcp",
	.netdev		= DEFAULT_NETDEV,
	.hwaddress	= DEFAULT_HWADDRESS,
};

/*
 * iSER
 */
static struct iface_rec iface_iser = {
	.name		= "iser",
	.transport_name	= "iser",
	.netdev		= DEFAULT_NETDEV,
	.hwaddress	= DEFAULT_HWADDRESS,
};

/*
 * Broadcom bnx2i
 */
static struct iface_rec iface_bnx2i = {
	.name		= "bnx2i",
	.transport_name	= "bnx2i",
	.netdev		= DEFAULT_NETDEV,
	.hwaddress	= DEFAULT_HWADDRESS,
};

static struct iface_rec *default_ifaces[] = {
	&iface_default,
	&iface_iser,
	&iface_bnx2i,
	NULL,
};

static struct iface_rec *iface_match_default(struct iface_rec *iface)
{
	struct iface_rec *def_iface;
	int i = 0;

	while ((def_iface = default_ifaces[i++])) {
		if (!strcmp(iface->name, def_iface->name))
			return def_iface;
	}
	return NULL;
}

static void iface_init(struct iface_rec *iface)
{
	if (!strlen(iface->name))
		sprintf(iface->name, DEFAULT_IFACENAME);
}

/*
 * default is to use tcp through whatever the network layer
 * selects for us with the /etc/iscsi/initiatorname.iscsi iname.
 */
void iface_setup_defaults(struct iface_rec *iface)
{
	sprintf(iface->netdev, DEFAULT_NETDEV);
//	sprintf(iface->ipaddress, DEFAULT_IPADDRESS);
	sprintf(iface->hwaddress, DEFAULT_HWADDRESS);
	sprintf(iface->transport_name, DEFAULT_TRANSPORT);
	iface_init(iface);
}

struct iface_rec *iface_alloc(char *ifname, int *err)
{
	struct iface_rec *iface;

	if (!strlen(ifname) || strlen(ifname) + 1 > ISCSI_MAX_IFACE_LEN) {
		*err = EINVAL;
		return NULL;
	}

	iface = calloc(1, sizeof(*iface));
	if (!iface) {
		*err = ENOMEM;
		return NULL;
	}

	strncpy(iface->name, ifname, ISCSI_MAX_IFACE_LEN);
	INIT_LIST_HEAD(&iface->list);
	return iface;
}

static int __iface_conf_read(struct iface_rec *iface)
{
	char *iface_conf;
	recinfo_t *info;
	FILE *f;
	int rc = 0;

	iface_conf = calloc(1, PATH_MAX);
	if (!iface_conf)
		return ENOMEM;

	info = idbm_recinfo_alloc(MAX_KEYS);
	if (!info) {
		rc = ENOMEM;
		goto free_conf;
	}

	snprintf(iface_conf, PATH_MAX, "%s/%s", IFACE_CONFIG_DIR,
		 iface->name);

	log_debug(5, "looking for iface conf %s", iface_conf);
	f = fopen(iface_conf, "r");
	if (!f) {
		/*
		 * if someone passes in default but has not defined
		 * a iface with default then we do it for them
		 */
		if (!strcmp(iface->name, DEFAULT_IFACENAME)) {
			iface_setup_defaults(iface);
			rc = 0;
		} else
			rc = errno;
		goto free_info;
	}

	iface_init(iface);
	idbm_recinfo_iface(iface, info);
	idbm_recinfo_config(info, f);
	fclose(f);

free_info:
	free(info);
free_conf:
	free(iface_conf);
	return rc;
}

int iface_conf_read(struct iface_rec *iface)
{
	struct iface_rec *def_iface;
	int rc;

	def_iface = iface_match_default(iface);
	if (def_iface) {
		/*
		 * older tools allowed default to have different
		 * transport_names so we do not want to overwrite
		 * it.
		 */
		if (!strcmp(def_iface->name, DEFAULT_IFACENAME)) {
			if (!strlen(iface->name))
				strcpy(iface->name, def_iface->name);
			if (!strlen(iface->netdev))
				strcpy(iface->netdev, def_iface->netdev);
			if (!strlen(iface->hwaddress))
				strcpy(iface->hwaddress, def_iface->hwaddress);
			if (!strlen(iface->transport_name))
				strcpy(iface->transport_name,
				       def_iface->transport_name);
			if (!strlen(iface->iname))
				strcpy(iface->iname, def_iface->iname);
		} else {
			iface_init(iface);
			iface_copy(iface, def_iface);
		}
		return 0;
	}

	idbm_lock();
	rc = __iface_conf_read(iface);
	idbm_unlock();
	return rc;
}

int iface_conf_delete(struct iface_rec *iface)
{
	struct iface_rec *def_iface;
	char *iface_conf;
	int rc = 0;

	def_iface = iface_match_default(iface);
	if (def_iface) {
		log_error("iface %s is a special interface and "
			  "cannot be deleted.\n", iface->name);
		return EINVAL;
	}

	iface_conf = calloc(1, PATH_MAX);
	if (!iface_conf)
		return ENOMEM;

	sprintf(iface_conf, "%s/%s", IFACE_CONFIG_DIR, iface->name);
	idbm_lock();
	if (unlink(iface_conf))
		rc = errno;
	idbm_unlock();

	free(iface_conf);
	return rc;
}

int iface_conf_write(struct iface_rec *iface)
{
	struct iface_rec *def_iface;
	char *iface_conf;
	FILE *f;
	int rc = 0;

	def_iface = iface_match_default(iface);
	if (def_iface) {
		log_error("iface %s is a special interface and "
			  "is not stored in %s.\n", iface->name,
			  IFACE_CONFIG_DIR);
		return EINVAL;
	}

	iface_conf = calloc(1, PATH_MAX);
	if (!iface_conf)
		return ENOMEM;

	sprintf(iface_conf, "%s/%s", IFACE_CONFIG_DIR, iface->name);
	f = fopen(iface_conf, "w");
	if (!f) {
		rc = errno;
		goto free_conf;
	}

	idbm_lock();
	idbm_print(IDBM_PRINT_TYPE_IFACE, iface, 1, f);
	idbm_unlock();

	fclose(f);
free_conf:
	free(iface_conf);
	return rc;
}

int iface_conf_update(struct db_set_param *param,
		       struct iface_rec *iface)
{
	struct iface_rec *def_iface;
	recinfo_t *info;
	int rc = 0;

	def_iface = iface_match_default(iface);
	if (def_iface) {
		log_error("iface %s is a special interface and "
			  "cannot be modified.\n", iface->name);
		return EINVAL;
	}

	info = idbm_recinfo_alloc(MAX_KEYS);
	if (!info)
		return ENOMEM;

	idbm_recinfo_iface(iface, info);
	rc = idbm_verify_param(info, param->name);
	if (rc)
		goto free_info;

	rc = idbm_rec_update_param(info, param->name, param->value, 0);
	if (rc) {
		rc = EIO;
		goto free_info;
	}

	rc = iface_conf_write(iface);
free_info:
	free(info);
	return rc;
}

static int iface_get_next_id(void)
{
	struct stat statb;
	char *iface_conf;
	int i, rc = ENOSPC;

	iface_conf = calloc(1, PATH_MAX);
	if (!iface_conf)
		return ENOMEM;

	for (i = 0; i < INT_MAX; i++) {
		memset(iface_conf, 0, PATH_MAX);
		/* check len */
		snprintf(iface_conf, PATH_MAX, "iface%d", i);
		if (strlen(iface_conf) > ISCSI_MAX_IFACE_LEN - 1) {
			log_error("iface namespace is full. Remove unused "
				  "iface definitions from %s or send mail "
				  "to open-iscsi@googlegroups.com to report "
				  "the problem", IFACE_CONFIG_DIR);
			rc = ENOSPC;
			break;
		}
		memset(iface_conf, 0, PATH_MAX);
		snprintf(iface_conf, PATH_MAX, "%s/iface%d", IFACE_CONFIG_DIR,
			i);

		if (!stat(iface_conf, &statb))
			continue;
		if (errno == ENOENT) {
			rc = i;
			break;
		}
	}

	free(iface_conf);
        return rc;
}

struct iface_search {
	struct iface_rec *pattern;
	struct iface_rec *found;
};

static int __iface_get_by_net_binding(void *data, struct iface_rec *iface)
{
	struct iface_search *search = data;

	if (!strcmp(search->pattern->name, iface->name)) {
		iface_copy(search->found, iface);
		return 1;
	}

	if (iface_is_bound_by_hwaddr(search->pattern)) {
		if (!strcmp(iface->hwaddress, search->pattern->hwaddress)) {
			iface_copy(search->found, iface);
			return 1;
		} else
			return 0;
	}

	if (iface_is_bound_by_netdev(search->pattern)) {
		if (!strcmp(iface->netdev, search->pattern->netdev)) {
			iface_copy(search->found, iface);
			return 1;
		} else
			return 0;
	}

/*
	if (iface_is_bound_by_ipaddr(search->pattern)) {
		if (!strcmp(iface->ipaddress, search->pattern->ipaddress)) {
			iface_copy(search->found, iface);
			return 1;
		} else
			return 0;
	}
*/
	return 0;
}

/*
 * Before 2.0.870, we only could bind by netdeivce or hwaddress,
 * so we did a simple reverse lookup to go from sysfs info to
 * the iface name. After 2.0.870 we added a lot of options to the
 * iface binding so we added the ifacename to the kernel.
 *
 * This function is for older kernels that do not export the ifacename.
 * If the user was doing iscsi_tcp session binding we will find
 * the iface by matching net info.
 */
int iface_get_by_net_binding(struct iface_rec *pattern,
			     struct iface_rec *out_rec)
{
	int num_found = 0, rc;
	struct iface_search search;

	if (!iface_is_bound_by_hwaddr(pattern) &&
	    !iface_is_bound_by_netdev(pattern)) {
		sprintf(out_rec->name, DEFAULT_IFACENAME);
		return 0;
	}

	search.pattern = pattern;
	search.found = out_rec;

	rc = iface_for_each_iface(&search, &num_found,
				  __iface_get_by_net_binding);
	if (rc == 1)
		return 0;
	return ENODEV;
}

static int __iface_setup_host_bindings(void *data, struct host_info *info)
{
	struct iface_rec iface;
	struct iscsi_transport *t;
	int id;

	t = iscsi_sysfs_get_transport_by_hba(info->host_no);
	if (!t)
		return 0;
	/*
	 * if software or partial offload do not touch the bindngs.
	 * They do not need it and may not support it
	 */
	if (!(t->caps & CAP_FW_DB))
		return 0;

	/*
	 * since this is only for qla4xxx we only care about finding
	 * a iface with a matching hwaddress.
	 */
	if (iface_get_by_net_binding(&info->iface, &iface) == ENODEV) {
		/* Must be a new port */
		id = iface_get_next_id();
		if (id < 0) {
			log_error("Could not add iface for %s.",
				  info->iface.hwaddress);
			return 0;
		}
		memset(&iface, 0, sizeof(struct iface_rec));
		strcpy(iface.hwaddress, info->iface.hwaddress);
		strcpy(iface.transport_name, info->iface.transport_name);
		sprintf(iface.name, "iface%d", id);
		if (iface_conf_write(&iface))
			log_error("Could not write iface conf for %s %s",
				  iface.name, iface.hwaddress);
			/* fall through - will not be persistent */
	}
	return 0;
}

/*
 * sync hw/offload iscsi scsi_hosts with iface values
 */
void iface_setup_host_bindings(void)
{
	int nr_found = 0;

	idbm_lock();
	if (access(IFACE_CONFIG_DIR, F_OK) != 0) {
		if (mkdir(IFACE_CONFIG_DIR, 0660) != 0) {
			log_error("Could not make %s. HW/OFFLOAD iscsi "
				  "may not be supported", IFACE_CONFIG_DIR);
			idbm_unlock();
			return;
		}
	}
	idbm_unlock();

	if (iscsi_sysfs_for_each_host(NULL, &nr_found,
				      __iface_setup_host_bindings))
		log_error("Could not scan scsi hosts. HW/OFFLOAD iscsi "
			  "operations may not be supported.");
}

void iface_copy(struct iface_rec *dst, struct iface_rec *src)
{
	if (strlen(src->name))
		strcpy(dst->name, src->name);
	if (strlen(src->netdev))
		strcpy(dst->netdev, src->netdev);
//	if (strlen(src->ipaddress))
//		strcpy(dst->ipaddress, src->ipaddress);
	if (strlen(src->hwaddress))
		strcpy(dst->hwaddress, src->hwaddress);
	if (strlen(src->transport_name))
		strcpy(dst->transport_name, src->transport_name);
	if (strlen(src->iname))
		strcpy(dst->iname, src->iname);
}

int iface_is_valid(struct iface_rec *iface)
{
	if (!iface)
		return 0;

	if (!strlen(iface->name))
		return 0;

	if (!strlen(iface->transport_name))
		return 0;

	if (iface_is_bound_by_hwaddr(iface))
		return 1;

	if (iface_is_bound_by_netdev(iface))
		return 1;
//	if (iface_is_bound_by_ipaddr(iface))
//		return 1;

	/* bound by transport name */
	return 1;
}

int iface_match(struct iface_rec *pattern, struct iface_rec *iface)
{
	if (!pattern || !iface)
		return 1;

	if (!strlen(pattern->name))
		return 1;

	if (!strcmp(pattern->name, iface->name)) {
		if (strcmp(pattern->name, DEFAULT_IFACENAME))
			return 1;
		/*
		 * For default we allow the same name, but different
		 * transports.
		 */
		if (!strlen(pattern->transport_name))
			return 1;

		if (!strcmp(pattern->transport_name, iface->transport_name))
			return 1;
		/* fall through */
	}
	return 0;
}

int iface_is_bound_by_hwaddr(struct iface_rec *iface)
{
	if (iface && strlen(iface->hwaddress) &&
	    strcmp(iface->hwaddress, DEFAULT_HWADDRESS))
		return 1;
	return 0;
}

int iface_is_bound_by_netdev(struct iface_rec *iface)
{
	if (iface && strlen(iface->netdev) &&
	   strcmp(iface->netdev, DEFAULT_NETDEV))
		return 1;
	return 0;
}

int iface_is_bound_by_ipaddr(struct iface_rec *iface)
{
	return 0;
/*	if (iface && strlen(iface->ipaddress) &&
	   strcmp(iface->ipaddress, DEFAULT_NETDEV))
		return 1;
	return 0;
*/
}

/**
 * iface_print_node_tree - print out binding info
 * @iface: iface to print out
 *
 * Currently this looks like the iface conf print, because we only
 * have the binding info. When we store the iface specific node settings
 * in the iface record then it will look different.
 */
int iface_print_tree(void *data, struct iface_rec *iface)
{
	printf("Name: %s\n", iface->name);
	printf("\tTransport Name: %s\n",
	       strlen(iface->transport_name) ? iface->transport_name :
	       UNKNOWN_VALUE);
	printf("\tHW Address: %s\n",
	       strlen(iface->hwaddress) ? iface->hwaddress : UNKNOWN_VALUE);
	printf("\tNetdev: %s\n",
	       strlen(iface->netdev) ? iface->netdev : UNKNOWN_VALUE);
	printf("\tInitiator Name: %s\n",
	       strlen(iface->iname) ? iface->iname : UNKNOWN_VALUE);
	return 0;
}

int iface_print_flat(void *data, struct iface_rec *iface)
{
	printf("%s %s,%s,%s,%s\n",
		strlen(iface->name) ? iface->name : UNKNOWN_VALUE,
		strlen(iface->transport_name) ? iface->transport_name :
							UNKNOWN_VALUE,
		strlen(iface->hwaddress) ? iface->hwaddress : UNKNOWN_VALUE,
		strlen(iface->netdev) ? iface->netdev : UNKNOWN_VALUE,
		strlen(iface->iname) ? iface->iname : UNKNOWN_VALUE);
	return 0;
}

int iface_for_each_iface(void *data, int *nr_found, iface_op_fn *fn)
{
	DIR *iface_dirfd;
	struct dirent *iface_dent;
	struct iface_rec *iface, *def_iface;
	int err = 0, i = 0;

	while ((def_iface = default_ifaces[i++])) {
		iface = iface_alloc(def_iface->name, &err);
		if (!iface) {
			log_error("Could not add iface %s.", def_iface->name);
			continue;
		}
		iface_copy(iface, def_iface); 
		err = fn(data, iface);
		free(iface);
		if (err)
			return err;
		(*nr_found)++;
	}

	iface_dirfd = opendir(IFACE_CONFIG_DIR);
	if (!iface_dirfd)
		return errno;

	while ((iface_dent = readdir(iface_dirfd))) {
		if (!strcmp(iface_dent->d_name, ".") ||
		    !strcmp(iface_dent->d_name, ".."))
			continue;

		log_debug(5, "iface_for_each_iface found %s",
			 iface_dent->d_name);
		iface = iface_alloc(iface_dent->d_name, &err);
		if (!iface || err) {
			if (err == EINVAL)
				log_error("Invalid iface name %s. Must be "
					  "from 1 to %d characters.",
					   iface_dent->d_name,
					   ISCSI_MAX_IFACE_LEN - 1);
			else
				log_error("Could not add iface %s.",
					  iface_dent->d_name);
			continue;
		}

		idbm_lock();
		err = __iface_conf_read(iface);
		idbm_unlock();
		if (err) {
			log_error("Could not read def iface %s (err %d)",
				  iface->name, err);
			free(iface);
			continue;
		}

		if (!iface_is_valid(iface)) {
			log_debug(5, "iface is not valid "
				  "Iface settings " iface_fmt,
				  iface_str(iface));
			free(iface);
			continue;
		}

		err = fn(data, iface);
		free(iface);
		if (err)
			break;
		(*nr_found)++;
	}

	closedir(iface_dirfd);
	return err;
}

static int iface_link(void *data, struct iface_rec *iface)
{
	struct list_head *ifaces = data;
	struct iface_rec *iface_copy;

	iface_copy = calloc(1, sizeof(*iface_copy));
	if (!iface_copy)
		return ENOMEM;

	memcpy(iface_copy, iface, sizeof(*iface_copy));
	INIT_LIST_HEAD(&iface_copy->list);
	list_add_tail(&iface_copy->list, ifaces);
	return 0;
}

void iface_link_ifaces(struct list_head *ifaces)
{
	int nr_found = 0;

	iface_for_each_iface(ifaces, &nr_found, iface_link);
}


