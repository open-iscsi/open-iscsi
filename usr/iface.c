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
#include "session_info.h"
#include "host.h"
#include "fw_context.h"
#include "sysdeps.h"

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
};

/*
 * iSER
 */
static struct iface_rec iface_iser = {
	.name		= "iser",
	.transport_name	= "iser",
};

static struct iface_rec *default_ifaces[] = {
	&iface_default,
	&iface_iser,
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

	strlcpy(iface->name, ifname, ISCSI_MAX_IFACE_LEN);
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

	rc = idbm_lock();
	if (rc)
		return rc;

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
	rc = idbm_lock();
	if (rc)
		goto free_conf;

	if (unlink(iface_conf))
		rc = errno;
	idbm_unlock();

free_conf:
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

	rc = idbm_lock();
	if (rc)
		goto close_f;

	idbm_print(IDBM_PRINT_TYPE_IFACE, iface, 1, f);
	idbm_unlock();

close_f:
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

	rc = iface_for_each_iface(&search, 0, &num_found,
				  __iface_get_by_net_binding);
	if (rc == 1)
		return 0;
	return ENODEV;
}

static int __iface_setup_host_bindings(void *data, struct host_info *hinfo)
{
	struct iface_rec *def_iface;
	struct iface_rec iface;
	struct iscsi_transport *t;
	int i = 0;

	t = iscsi_sysfs_get_transport_by_hba(hinfo->host_no);
	if (!t)
		return 0;

	/* do not setup binding for hosts using non offload drivers */
	while ((def_iface = default_ifaces[i++])) {
		if (!strcmp(t->name, def_iface->transport_name))
			return 0;
	}

	if (iface_get_by_net_binding(&hinfo->iface, &iface) == ENODEV) {
		/* Must be a new port */
		if (!strlen(hinfo->iface.hwaddress)) {
			log_error("Invalid offload iSCSI host %u. Missing "
				  "hwaddress. Try upgrading %s driver.\n",
				  hinfo->host_no, t->name);
			return 0;
		}

		memset(&iface, 0, sizeof(struct iface_rec));
		strcpy(iface.hwaddress, hinfo->iface.hwaddress);
		strcpy(iface.transport_name, hinfo->iface.transport_name);
		snprintf(iface.name, sizeof(iface.name), "%s.%s",
			 t->name, hinfo->iface.hwaddress);
		if (iface_conf_write(&iface))
			log_error("Could not create default iface conf %s.",
				  iface.name);
			/* fall through - will not be persistent */
	}
	return 0;
}

/*
 * Create a default iface for offload cards. We assume that we will
 * be able identify each host by MAC.
 */
void iface_setup_host_bindings(void)
{
	int nr_found = 0;

	if (idbm_lock())
		return;

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
			  "operations may not be supported, or please "
			  "see README for instructions on setting up ifaces.");
}

void iface_copy(struct iface_rec *dst, struct iface_rec *src)
{
	if (strlen(src->name))
		strcpy(dst->name, src->name);
	if (strlen(src->netdev))
		strcpy(dst->netdev, src->netdev);
	if (strlen(src->ipaddress))
		strcpy(dst->ipaddress, src->ipaddress);
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
	if (iface && strlen(iface->ipaddress) &&
	   strcmp(iface->ipaddress, DEFAULT_IPADDRESS))
		return 1;
	return 0;
}

void iface_print(struct iface_rec *iface, char *prefix)
{
	if (strlen(iface->name))
		printf("%sIface Name: %s\n", prefix, iface->name);
	else
		printf("%sIface Name: %s\n", prefix, UNKNOWN_VALUE);

	if (strlen(iface->transport_name))
		printf("%sIface Transport: %s\n", prefix,
		      iface->transport_name);
	else
		printf("%sIface Transport: %s\n", prefix, UNKNOWN_VALUE);

	if (strlen(iface->iname))
		printf("%sIface Initiatorname: %s\n", prefix, iface->iname);
	else
		printf("%sIface Initiatorname: %s\n", prefix, UNKNOWN_VALUE);

	if (!strlen(iface->ipaddress))
		printf("%sIface IPaddress: %s\n", prefix, UNKNOWN_VALUE);
	else if (strchr(iface->ipaddress, '.'))
		printf("%sIface IPaddress: %s\n", prefix, iface->ipaddress);
	else
		printf("%sIface IPaddress: [%s]\n", prefix, iface->ipaddress);

	if (strlen(iface->hwaddress))
		printf("%sIface HWaddress: %s\n", prefix, iface->hwaddress);
	else
		printf("%sIface HWaddress: %s\n", prefix, UNKNOWN_VALUE);

	if (strlen(iface->netdev))
		printf("%sIface Netdev: %s\n", prefix, iface->netdev);
	else
		printf("%sIface Netdev: %s\n", prefix, UNKNOWN_VALUE);
}

struct iface_print_node_data {
	struct node_rec *last_rec;
	struct iface_rec *match_iface;
};

static int iface_print_nodes(void *data, node_rec_t *rec)
{
	struct iface_print_node_data *print_data = data;

	if (!iface_match(print_data->match_iface, &rec->iface))
		return -1;

	idbm_print_node_tree(print_data->last_rec, rec, "\t");
	return 0;
}

/**
 * iface_print_tree - print out binding info
 * @iface: iface to print out
 *
 * Currently this looks like the iface conf print, because we only
 * have the binding info. When we store the iface specific node settings
 * in the iface record then it will look different.
 */
int iface_print_tree(void *data, struct iface_rec *iface)
{
	struct node_rec last_rec;
	struct iface_print_node_data print_data;
	int num_found = 0;

	printf("Iface: %s\n", iface->name);

	memset(&last_rec, 0, sizeof(struct node_rec ));

	print_data.match_iface = iface;
	print_data.last_rec = &last_rec;

	idbm_for_each_rec(&num_found, &print_data, iface_print_nodes);
	return 0;
}

int iface_print_flat(void *data, struct iface_rec *iface)
{
	printf("%s %s,%s,%s,%s,%s\n",
		strlen(iface->name) ? iface->name : UNKNOWN_VALUE,
		strlen(iface->transport_name) ? iface->transport_name :
							UNKNOWN_VALUE,
		strlen(iface->hwaddress) ? iface->hwaddress : UNKNOWN_VALUE,
		strlen(iface->ipaddress) ? iface->ipaddress : UNKNOWN_VALUE,
		strlen(iface->netdev) ? iface->netdev : UNKNOWN_VALUE,
		strlen(iface->iname) ? iface->iname : UNKNOWN_VALUE);
	return 0;
}

int iface_for_each_iface(void *data, int skip_def, int *nr_found,
			 iface_op_fn *fn)
{
	DIR *iface_dirfd;
	struct dirent *iface_dent;
	struct iface_rec *iface, *def_iface;
	int err = 0, i = 0;

	if (!skip_def) {
		while ((def_iface = default_ifaces[i++])) {
			iface = iface_alloc(def_iface->name, &err);
			if (!iface) {
				log_error("Could not add iface %s.",
					  def_iface->name);
				continue;
			}
			iface_copy(iface, def_iface);
			err = fn(data, iface);
			free(iface);
			if (err)
				return err;
			(*nr_found)++;
		}
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

		err = idbm_lock();
		if (err) {
			free(iface);
			continue;
		}

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

/**
 * iface_link_ifaces - link non default ifaces
 * @ifaces: list to add ifaces to
 *
 * This will return a list of the ifaces created by iscsiadm
 * or the user. It does not return the static default ones.
 */
void iface_link_ifaces(struct list_head *ifaces)
{
	int nr_found = 0;

	iface_for_each_iface(ifaces, 1, &nr_found, iface_link);
}

/**
 * iface_setup_from_boot_context - setup iface from boot context info
 * @iface: iface t setup
 * @context: boot context info
 *
 * Returns 1 if setup for offload.
 */
int iface_setup_from_boot_context(struct iface_rec *iface,
				   struct boot_context *context)
{
	if (strlen(context->initiatorname))
		strlcpy(iface->iname, context->initiatorname,
			sizeof(iface->iname));

	if (strlen(context->scsi_host_name)) {
		struct iscsi_transport *t;
		uint32_t hostno;

		if (sscanf(context->scsi_host_name, "iscsi_boot%u", &hostno) != 		    1) {
			log_error("Could not parse %s's host no.",
				  context->scsi_host_name);
			return 0;
		}
		t = iscsi_sysfs_get_transport_by_hba(hostno);
		if (!t) {
			log_error("Could not get transport for %s. "
				  "Make sure the iSCSI driver is loaded.",
				  context->scsi_host_name);
			return 0;
		}

		log_debug(3, "boot context has %s transport %s",
			  context->scsi_host_name, t->name);
		strcpy(iface->transport_name, t->name);
	} else if (strlen(context->iface) &&
		 (!net_get_transport_name_from_netdev(context->iface,
						iface->transport_name))) {
		log_debug(3, "boot context has netdev %s",
			  context->iface);
		strlcpy(iface->netdev, context->iface,
			sizeof(iface->netdev));
	} else
		return 0;
	/*
	 * set up for access through a offload card.
	 */
	memset(iface->name, 0, sizeof(iface->name));
	snprintf(iface->name, sizeof(iface->name), "%s.%s",
		 iface->transport_name, context->mac);

	strlcpy(iface->hwaddress, context->mac,
		sizeof(iface->hwaddress));
	strlcpy(iface->ipaddress, context->ipaddr,
		sizeof(iface->ipaddress));
	log_debug(1, "iface " iface_fmt "\n", iface_str(iface));
	return 1;
}

/**
 * iface_create_ifaces_from_boot_contexts - create ifaces based on boot info
 * @ifaces: list to store ifaces in
 * @targets: list of targets to create ifaces from
 *
 * This function will create a iface struct based on the boot info
 * and it will create (or update if existing already) a iface rec in
 * the ifaces dir based on the info.
 */
int iface_create_ifaces_from_boot_contexts(struct list_head *ifaces,
					   struct list_head *targets)
{
	struct boot_context *context;
	struct iface_rec *iface, *tmp_iface;
	int rc = 0;

	list_for_each_entry(context, targets, list) {
		rc = 0;
		/* use dummy name. If valid it will get overwritten below */
		iface = iface_alloc(DEFAULT_IFACENAME, &rc);
		if (!iface) {
			log_error("Could not setup iface %s for boot\n",
				  context->iface);
			goto fail;
		}
		if (!iface_setup_from_boot_context(iface, context)) {
			/* no offload so forget it */
			free(iface);
			continue;
		}

		rc = iface_conf_write(iface);
		if (rc) {
			log_error("Could not setup default iface conf "
				  "for %s.", iface->name);
			free(iface);
			goto fail;
		}
		list_add_tail(&iface->list, ifaces);
	}

	return 0;
fail:
	list_for_each_entry_safe(iface, tmp_iface, ifaces, list) {
		list_del(&iface->list);
		free(iface);
	}
	return rc;
}
