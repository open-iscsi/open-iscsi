/*
 * Copyright (C) IBM Corporation. 2007
 * Author: Konrad Rzeszutek <konradr@linux.vnet.ibm.com>
 * Copyright (C) Red Hat, Inc.  All rights reserved. 2008 - 2010
 * Copyright (C) Mike Christie 2008 - 2010
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define  _XOPEN_SOURCE 500
#define _SVID_SOURCE
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "sysfs.h"
#include "fw_context.h"
#include "fwparam.h"
#include "sysdeps.h"
#include "iscsi_net_util.h"

#define ISCSI_BOOT_MAX		255
#define IBFT_SYSFS_ROOT		"/sys/firmware/ibft/"
#define IBFT_SUBSYS		"ibft"

#define ISCSI_LLD_ROOT		"/sys/firmware/"
#define ISCSI_LLD_SUBSYS_PREFIX	"iscsi_boot"

static char *target_list[ISCSI_BOOT_MAX];
static char *nic_list[ISCSI_BOOT_MAX];
static int nic_cnt;
static int tgt_cnt;

static int file_exist(const char *file)
{
	struct stat bootpath_stat;

	return !stat(file, &bootpath_stat);
}

/*
 * Finds the etherrnetX and targetX under the sysfs directory.
 */
static int find_sysfs_dirs(const char *fpath, const struct stat *sb,
			   int tflag, struct FTW *ftw)
{
	if (tflag == FTW_D && (strstr(fpath + ftw->base, "target"))) {
		if (tgt_cnt == ISCSI_BOOT_MAX) {
			printf("Too many targets found in iSCSI boot data."
			       "Max number of targets %d\n", ISCSI_BOOT_MAX);
			return 0;
		}
		target_list[tgt_cnt++] = strdup(strstr(fpath, "target"));
	}

	if (tflag == FTW_D && (strstr(fpath + ftw->base, "ethernet"))) {
		if (nic_cnt == ISCSI_BOOT_MAX) {
			printf("Too many nics found in iSCSI boot data."
			       "Max number of nics %d\n", ISCSI_BOOT_MAX);
			return 0;
		}
		nic_list[nic_cnt++] = strdup(strstr(fpath, "ethernet"));
	}

	return 0;
}
 
static int get_iface_from_device(char *id, struct boot_context *context)
{
	char dev_dir[FILENAMESZ];
	int rc = ENODEV;
	DIR *dirfd;
	struct dirent *dent;

	memset(dev_dir, 0, FILENAMESZ);
	snprintf(dev_dir, FILENAMESZ, IBFT_SYSFS_ROOT"/%s/device", id);

	if (!file_exist(dev_dir))
		return 0;

	dirfd = opendir(dev_dir);
	if (!dirfd)
		return errno;

	while ((dent = readdir(dirfd))) {
		if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, "..") ||
		    strncmp(dent->d_name, "net:", 4))
			continue;

		if (!strncmp(dent->d_name, "net:", 4)) {
			if ((strlen(dent->d_name) - 4) >
			    (sizeof(context->iface) - 1)) {
				rc = EINVAL;
				printf("Net device %s too big for iface "
				       "buffer.\n", dent->d_name);
				break;
			}

			if (sscanf(dent->d_name, "net:%s", context->iface) != 1)
				rc = EINVAL;
			rc = 0;
			break;
		} else {
			printf("Could not read ethernet to net link.\n");
			rc = EOPNOTSUPP;
			break;
		}
	}

	closedir(dirfd);

	if (rc != ENODEV)
		return rc;

	/* If not found try again with newer kernel networkdev sysfs layout */
	strlcat(dev_dir, "/net", FILENAMESZ);

	if (!file_exist(dev_dir))
		return rc;

	dirfd = opendir(dev_dir);
	if (!dirfd)
		return errno;

	while ((dent = readdir(dirfd))) {
		if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
			continue;

		/* Take the first "regular" directory entry */
		if (strlen(dent->d_name) > (sizeof(context->iface) - 1)) {
			rc = EINVAL;
			printf("Net device %s too big for iface buffer.\n",
			       dent->d_name);
			break;
		}

		strcpy(context->iface, dent->d_name);
		rc = 0;
		break;
	}

	closedir(dirfd);
	return rc;
}

/*
 * Routines to fill in the context values.
 */
static int fill_nic_context(char *subsys, char *id,
			    struct boot_context *context)
{
	int rc;

	rc = sysfs_get_str(id, subsys, "mac", context->mac,
			   sizeof(context->mac));
	if (rc)
		return rc;

	/*
	 * Some offload cards like bnx2i use different MACs for the net and
	 * iscsi functions, so we have to follow the sysfs links.
	 *
	 * Other ibft implementations may not be tied to a pci function,
	 * so there will not be any device/net link, so we drop down to
	 * the MAC matching.
	 *
	 * And finally, some cards like be2iscsi and qla4xxx do not have
	 * any linux network subsys representation. These hosts will
	 * not have the ibft subsys. Instead the subsys is the scsi host
	 * number.
	 */
	if (!strcmp(IBFT_SUBSYS, subsys)) {
		rc = get_iface_from_device(id, context);
		if (rc) {
			rc = net_get_netdev_from_hwaddress(context->mac,
							   context->iface);
			if (rc)
				return rc;
		}
	} else
		strlcpy(context->scsi_host_name, subsys,
			sizeof(context->scsi_host_name));

	sysfs_get_str(id, subsys, "ip-addr", context->ipaddr,
		      sizeof(context->ipaddr));
	sysfs_get_str(id, subsys, "vlan", context->vlan,
		      sizeof(context->vlan));
	sysfs_get_str(id, subsys, "subnet-mask", context->mask,
		      sizeof(context->mask));
	sysfs_get_str(id, subsys, "gateway", context->gateway,
		      sizeof(context->gateway));
	sysfs_get_str(id, subsys, "primary-dns", context->primary_dns,
		      sizeof(context->primary_dns));
	sysfs_get_str(id, subsys, "secondary-dns", context->secondary_dns,
		      sizeof(context->secondary_dns));
	sysfs_get_str(id, subsys, "dhcp", context->dhcp,
		      sizeof(context->dhcp));
	return 0;
}

static void fill_initiator_context(char *subsys, struct boot_context *context)
{
	sysfs_get_str("initiator", subsys, "initiator-name",
		      context->initiatorname,
		      sizeof(context->initiatorname));
	sysfs_get_str("initiator", subsys, "isid", context->isid,
		      sizeof(context->isid));
}
static int fill_tgt_context(char *subsys, char *id,
			    struct boot_context *context)
{
	int rc;

	rc = sysfs_get_str(id, subsys, "target-name", context->targetname,
			   sizeof(context->targetname));
	if (rc)
		return rc;

	rc = sysfs_get_str(id, subsys, "ip-addr", context->target_ipaddr,
			   sizeof(context->target_ipaddr));
	if (rc)
		return rc;

	/*
	 * We can live without the rest of they do not exist. If we
	 * failed to get them we will figure it out when we login.
	 */
	if (sysfs_get_int(id, subsys, "port", &context->target_port))
		context->target_port = ISCSI_LISTEN_PORT;

	sysfs_get_str(id, subsys, "lun", context->lun,
		      sizeof(context->lun));
	sysfs_get_str(id, subsys, "chap-name", context->chap_name,
		      sizeof(context->chap_name));
	sysfs_get_str(id, subsys, "chap-secret", context->chap_password,
		      sizeof(context->chap_password));
	sysfs_get_str(id, subsys, "rev-chap-name", context->chap_name_in,
		      sizeof(context->chap_name_in));
	sysfs_get_str(id, subsys, "rev-chap-name-secret",
		      context->chap_password_in,
		      sizeof(context->chap_password_in));
	return 0;
}

#define IBFT_SYSFS_FLAG_FW_SEL_BOOT 2

static int find_boot_flag(char *subsys, char *list[], ssize_t size,
			  int *boot_idx)
{
	int rc = ENODEV;
	int i, flag = 0;

	for (i = 0; i < size; i++, flag = -1) {
		rc = sysfs_get_int(list[i], subsys, "flags", &flag);
		if (rc)
			continue;

		if (flag & IBFT_SYSFS_FLAG_FW_SEL_BOOT) {
			*boot_idx = i;
			rc = 0;
			break;
		}
		rc = ENODEV;
		flag = 0;

	}

	return rc;
}

static void deallocate_lists(void)
{
	int i;

	for (i = 0; i < nic_cnt; i++)
		free(nic_list[i]);

	nic_cnt = 0;
	for (i = 0; i < tgt_cnt; i++)
		free(target_list[i]);

	tgt_cnt = 0;

}

static int get_boot_info(struct boot_context *context, char *rootdir,
			 char *subsys)
{
	char initiator_dir[FILENAMESZ];
	int rc = ENODEV;
	int nic_idx = -1, tgt_idx = -1;

	memset(&initiator_dir, 0 , FILENAMESZ);
	snprintf(initiator_dir, FILENAMESZ, "%sinitiator", rootdir);

	nic_cnt = 0;
	tgt_cnt = 0;
	if (file_exist(initiator_dir)) {
		/* Find the target's and the ethernet's */
		rc = nftw(rootdir, find_sysfs_dirs, 20, 1);

		/* Find wihch target and which ethernet have
		the boot flag set. */
		rc = find_boot_flag(subsys, nic_list, nic_cnt, &nic_idx);
		if (rc)
			goto free;

		rc = find_boot_flag(subsys, target_list, tgt_cnt, &tgt_idx);
		if (rc)
			goto free;

		/* Fill in the context values */
		rc = fill_nic_context(subsys, nic_list[nic_idx], context);
		rc |= fill_tgt_context(subsys, target_list[tgt_idx], context);
		fill_initiator_context(subsys, context);
	}
free:
	deallocate_lists();
	return rc;
}

int fwparam_sysfs_boot_info(struct boot_context *context)
{
	struct dirent *dent;
	DIR *dirfd;
	int rc = 0;

	if (!get_boot_info(context, IBFT_SYSFS_ROOT, IBFT_SUBSYS))
		return 0;
	/*
	 * We could have multiple iscsi llds and each lld could have
	 * multiple targets/ethernet ports
	 */
	dirfd = opendir(ISCSI_LLD_ROOT);
	if (!dirfd)
		return errno;

	while ((dent = readdir(dirfd))) {
		char lld_root[FILENAMESZ];

		memset(&lld_root, 0 , FILENAMESZ);

		if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
			continue;

		if (strncmp(dent->d_name, ISCSI_LLD_SUBSYS_PREFIX, 10))
			continue;

		snprintf(lld_root, FILENAMESZ, ISCSI_LLD_ROOT"%s",
			 dent->d_name);
		if (!get_boot_info(context, lld_root, dent->d_name))
			goto done;
	}
	rc = ENODEV;
done:
	closedir(dirfd);
	return rc;
}

static int get_targets(struct list_head *list, char *rootdir, char *subsys)
{
	struct boot_context *context;
	int rc = 0, i, nic_idx, nic;
	char initiator_dir[FILENAMESZ];

	memset(&initiator_dir, 0 , FILENAMESZ);
	snprintf(initiator_dir, FILENAMESZ, "%sinitiator", rootdir);

	if (!file_exist(initiator_dir))
		return ENODEV;

	nic_cnt = 0;
	tgt_cnt = 0;

	/* Find the target's and the ethernet's */
	nftw(rootdir, find_sysfs_dirs, 20, 1);
	for (i = 0; i < tgt_cnt; i++) {
		context = calloc(1, sizeof(*context));
		if (!context) {
			rc = ENOMEM;
			break;
		}

		rc = fill_tgt_context(subsys, target_list[i], context);
		if (rc)
			break;

		rc = sysfs_get_int(target_list[i], subsys, "nic-assoc",
				   &nic_idx);
		if (rc)
			break;

		for (nic = 0; nic < nic_cnt; nic++) {
			int id;

			rc = sysfs_get_int(nic_list[nic], subsys, "index",
					   &id);
			if (!rc && (id == nic_idx))
				break;
		}

		if (nic == nic_cnt) {
			printf("Invalid nic-assoc of %d. Max id %d.\n",
			       nic_idx, nic_cnt);
			break;
		}

		rc = fill_nic_context(subsys, nic_list[nic], context);
		if (rc)
			break;

		fill_initiator_context(subsys, context);
		list_add_tail(&context->list, list);
	}

	if (rc) {
		if (context)
			free(context);
		fw_free_targets(list);
	}

	deallocate_lists();
	return rc;
}

int fwparam_sysfs_get_targets(struct list_head *list)
{
	struct dirent *dent;
	DIR *dirfd;
	int rc = 0;

	/* ibft only has one instance */
	get_targets(list, IBFT_SYSFS_ROOT, IBFT_SUBSYS);
	/*
	 * We could have multiple iscsi llds and each lld could have
	 * multiple targets/ethernet ports
	 */
	dirfd = opendir(ISCSI_LLD_ROOT);
	if (!dirfd) {
		rc = errno;
		goto done;
	}

	while ((dent = readdir(dirfd))) {
		char lld_root[FILENAMESZ];

		memset(&lld_root, 0 , FILENAMESZ);

		if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
			continue;

		if (strncmp(dent->d_name, ISCSI_LLD_SUBSYS_PREFIX, 10))
			continue;

		snprintf(lld_root, FILENAMESZ, ISCSI_LLD_ROOT"%s",
			 dent->d_name);
		get_targets(list, lld_root, dent->d_name);
	}
	closedir(dirfd);
done:
	if (!rc && list_empty(list))
		rc = ENODEV;
	if (rc)
		fw_free_targets(list);
	return rc;
}
