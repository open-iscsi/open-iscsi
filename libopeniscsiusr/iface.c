/*
 * Copyright (C) 2017-2018 Red Hat, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Gris Ge <fge@redhat.com>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE			/* For NI_MAXHOST */
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>
#include <net/if.h>
#include <assert.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <libkmod.h>
#include <limits.h>

#include "libopeniscsiusr/libopeniscsiusr.h"
#include "misc.h"
#include "sysfs.h"
#include "iface.h"
#include "context.h"
#include "idbm.h"
#include "default.h"

#ifndef SBINDIR
#define SBINDIR "/sbin"
#endif
#define ISCSIUIO_PATH SBINDIR "/iscsiuio"

struct _iscsi_net_drv {
	const char *net_driver_name;		// Ethernet driver.
	const char *iscsi_driver_name;		// iSCSI offload driver.
	const char *transport_name;		// iSCSI transport name.
};

static struct _iscsi_net_drv _ISCSI_NET_DRVS[] = {
	{"cxgb3", "cxgb3i", "cxgb3i"},
	{"cxgb4", "cxgb4i", "cxgb4i"},
	{"bnx2", "bnx2i" , "bnx2i"},
	{"bnx2x", "bnx2i", "bnx2i"},
};

const struct iscsi_iface _DEFAULT_IFACES[] = {
	{
		.name = "default",
		.transport_name	= "tcp",
	},
	{
		.name		= "iser",
		.transport_name	= "iser",
	},
};

static int _load_kernel_module(struct iscsi_context *ctx, const char *drv_name);
static int _iface_conf_write(struct iscsi_context *ctx,
			     struct iscsi_iface *iface);
static int _fill_hw_iface_from_sys(struct iscsi_context *ctx,
				   struct iscsi_iface *iface,
				   const char *iface_kern_id);

_iscsi_getter_func_gen(iscsi_iface, hwaddress, const char *);
_iscsi_getter_func_gen(iscsi_iface, transport_name, const char *);
_iscsi_getter_func_gen(iscsi_iface, ipaddress, const char *);
_iscsi_getter_func_gen(iscsi_iface, netdev, const char *);
_iscsi_getter_func_gen(iscsi_iface, iname, const char *);
_iscsi_getter_func_gen(iscsi_iface, port_state, const char *);
_iscsi_getter_func_gen(iscsi_iface, port_speed, const char *);
_iscsi_getter_func_gen(iscsi_iface, name, const char *);

/*
 * ipv6 address strings will have at least two colons
 *
 * NOTE: does NOT validate the IP address
 */
static bool lib_ipaddr_is_ipv6(struct iscsi_context *ctx, char *ipaddr)
{
	char *first_colon, *second_colon;
	bool res = false;

	if (ipaddr) {
		first_colon = strchr(ipaddr, ':');
		if (first_colon) {
			second_colon = strchr(first_colon+1, ':');
			if (second_colon &&
			    (second_colon != first_colon))
				res = true;
		}
	}
	_debug(ctx, "ipaddr=\"%s\" -> %u", ipaddr, res);
	return res;
}

int _iscsi_iface_get_from_sysfs(struct iscsi_context *ctx, uint32_t host_id,
				uint32_t sid, char *iface_kern_id,
				struct iscsi_iface **iface)
{
	int rc = LIBISCSI_OK;
	char *sysfs_se_dir_path = NULL;
	char *sysfs_sh_dir_path = NULL;
	char *sysfs_scsi_host_dir_path = NULL;
	char proc_name[ISCSI_TRANSPORT_NAME_MAXLEN];
	struct iscsi_iface **ifaces = NULL;
	uint32_t iface_count = 0;
	uint32_t i = 0;
	struct iscsi_iface *tmp_iface = NULL;
	bool bound_by_hwaddr = false;
	bool bound_by_netdev = false;
	bool matched = false;

	assert(ctx != NULL);
	assert(iface != NULL);

	*iface = NULL;

	if (sid != 0) {
		_good(_asprintf(&sysfs_se_dir_path, "%s/session%" PRIu32,
			        _ISCSI_SYS_SESSION_DIR, sid), rc, out);
	}

	_good(_asprintf(&sysfs_sh_dir_path, "%s/host%" PRIu32,
		        _ISCSI_SYS_HOST_DIR, host_id),rc, out);

	_good(_asprintf(&sysfs_scsi_host_dir_path, "%s/host%" PRIu32,
		 _SCSI_SYS_HOST_DIR, host_id), rc, out);

	*iface = (struct iscsi_iface *) calloc(1, sizeof(struct iscsi_iface));
	_alloc_null_check(ctx, *iface, rc, out);

	_good(_sysfs_prop_get_str(ctx, sysfs_scsi_host_dir_path, "proc_name",
				  proc_name, sizeof(proc_name) / sizeof(char),
				  NULL /* raise error if failed */),
	      rc, out);

	if (strncmp(proc_name, "iscsi_", strlen("iscsi_")) == 0)
		_strncpy((*iface)->transport_name, proc_name + strlen("iscsi_"),
			 sizeof((*iface)->transport_name) / sizeof(char));
	else
		_strncpy((*iface)->transport_name, proc_name,
			sizeof((*iface)->transport_name) / sizeof(char));

	_good(_sysfs_prop_get_str(ctx, sysfs_sh_dir_path, "hwaddress",
				  (*iface)->hwaddress,
				  sizeof((*iface)->hwaddress) / sizeof(char),
				  DEFAULT_HWADDRESS),
	      rc, out);
	if (strcmp((*iface)->hwaddress, DEFAULT_HWADDRESS) != 0)
		bound_by_hwaddr = true;

	_good(_sysfs_prop_get_str(ctx, sysfs_sh_dir_path, "netdev",
				  (*iface)->netdev,
				  sizeof((*iface)->netdev) / sizeof(char),
				  DEFAULT_NETDEV),
	      rc, out);
	if (strcmp((*iface)->netdev, DEFAULT_NETDEV) != 0)
		bound_by_netdev = true;

	if (sysfs_se_dir_path)
		_sysfs_prop_get_str(ctx, sysfs_se_dir_path, "initiatorname",
				    (*iface)->iname,
				    sizeof((*iface)->iname) / sizeof(char), "");
	if (strcmp((*iface)->iname, "") == 0)
		_good(_sysfs_prop_get_str(ctx, sysfs_sh_dir_path,
					  "initiatorname", (*iface)->iname,
					  sizeof((*iface)->iname) /
					  sizeof(char), ""),
		      rc, out);

	_good(_sysfs_prop_get_str(ctx, sysfs_sh_dir_path, "port_state",
				  (*iface)->port_state,
				  sizeof((*iface)->port_state) / sizeof(char),
				  "unknown"),
	      rc, out);

	if (strcmp((*iface)->port_state, "Unknown!") == 0)
		_strncpy((*iface)->port_state, "unknown",
			 sizeof((*iface)->port_state) / sizeof(char));

	_good(_sysfs_prop_get_str(ctx, sysfs_sh_dir_path, "port_speed",
				  (*iface)->port_speed,
				  sizeof((*iface)->port_speed) / sizeof(char),
				  "unknown"),
	      rc, out);

	if (strncmp((*iface)->port_speed, "Unknown", strlen("Unknown")) == 0)
		_strncpy((*iface)->port_speed, "unknown",
			 sizeof((*iface)->port_speed) / sizeof(char));

	if (sysfs_se_dir_path != NULL)
	    _sysfs_prop_get_str(ctx, sysfs_se_dir_path, "ifacename",
				(*iface)->name,
				sizeof((*iface)->name)/sizeof(char), "");

	if (iface_kern_id != NULL) {
		_good(_fill_hw_iface_from_sys(ctx, *iface, iface_kern_id),
		      rc, out);
	} else {
		_good(_sysfs_prop_get_str(ctx, sysfs_sh_dir_path, "ipaddress",
					(*iface)->ipaddress,
					sizeof((*iface)->ipaddress) /
					sizeof(char), DEFAULT_IPADDRESS),
		      rc, out);
		/* bnx2i does not create
		 * /sys/class/iscsi_iface/<iface_kernl_id>
		 * We need to use transport_name.hwaddress as iface name.
		 */
		_debug(ctx, "HAHA: hwaddress %s", (*iface)->hwaddress);
		if (bound_by_hwaddr)
			snprintf((*iface)->name,
				 sizeof((*iface)->name)/sizeof(char),
				 "%s.%s.%s.%u", (*iface)->transport_name,
				 (*iface)->hwaddress,
				 lib_ipaddr_is_ipv6(ctx, (*iface)->ipaddress) ? "ipv6" : "ipv4",
				 (*iface)->iface_num);
	}

	if (strcmp((*iface)->name, "") == 0) {
		/*
		 * Before 2.0.870, we only could bind by netdeivce or hwaddress,
		 * so we did a simple reverse lookup to go from sysfs info to
		 * the iface name. After 2.0.870 we added a lot of options to
		 * the iface binding so we added the ifacename to the kernel.
		 *
		 * Below codes are for older kernels that do not export the
		 * ifacename.  If the user was doing iscsi_tcp session binding
		 * we will find the iface by matching net info.
		 */

		_good(iscsi_ifaces_get(ctx, &ifaces, &iface_count), rc, out);

		for (i = 0; i < iface_count; ++i) {
			tmp_iface = ifaces[i];
			if ((bound_by_hwaddr == true) &&
			    (strcmp(tmp_iface->hwaddress, (*iface)->hwaddress)
			     == 0)) {
				_strncpy((*iface)->name, tmp_iface->name,
					 sizeof((*iface)->name)/sizeof(char));
				matched = true;
				break;
			}
			if ((bound_by_netdev == true) &&
			    (strcmp(tmp_iface->netdev, (*iface)->netdev)
			     == 0)) {
				_strncpy((*iface)->name, tmp_iface->name,
					 sizeof((*iface)->name)/sizeof(char));
				matched = true;
				break;
			}
		}
		if (!matched)
			_strncpy((*iface)->name, DEFAULT_IFACENAME,
				 sizeof((*iface)->name) / sizeof(char));
	}

out:
	if (rc != LIBISCSI_OK) {
		iscsi_iface_free(*iface);
		*iface = NULL;
	}
	free(sysfs_se_dir_path);
	free(sysfs_sh_dir_path);
	free(sysfs_scsi_host_dir_path);
	iscsi_ifaces_free(ifaces, iface_count);
	return rc;
}

/* create all ifaces for a host from sysfs */
int _iscsi_ifaces_get_from_sysfs(struct iscsi_context *ctx, uint32_t host_id,
				 struct iscsi_iface ***ifaces, uint32_t *iface_count)
{
	int rc = LIBISCSI_OK;
	char **iface_kern_ids = NULL;
	uint32_t i = 0;

	assert(ctx != NULL);
	assert(ifaces != NULL);

	*ifaces = NULL;
	*iface_count = 0;

	_good(_iscsi_iface_kern_ids_of_host_id(ctx, host_id, &iface_kern_ids, iface_count),
	      rc, out);
	if (*iface_count > 0) {
		*ifaces = (struct iscsi_iface **) calloc(*iface_count,
							 sizeof(struct iscsi_iface *));
		_alloc_null_check(ctx, *ifaces, rc, out);
		for (i = 0; i < *iface_count; i++) {
			_good(_iscsi_iface_get_from_sysfs(ctx, host_id, 0,
					iface_kern_ids[i], &(*ifaces)[i]), rc, out);
		}
	} else {
		/* if there's no iface exported in sysfs,
		 * we should still be able to create one record per host */
		*ifaces = (struct iscsi_iface **) calloc(1, sizeof(struct iscsi_iface *));
		_alloc_null_check(ctx, *ifaces, rc, out);
		*iface_count = 1;
		_good(_iscsi_iface_get_from_sysfs(ctx, host_id, 0, NULL, &(*ifaces)[0]), rc, out);
	}
out:
	if (iface_kern_ids != NULL) {
		for (i = 0; i < *iface_count; i++) {
			free(iface_kern_ids[i]);
		}
		free(iface_kern_ids);
	}
	if (rc != LIBISCSI_OK) {
		iscsi_ifaces_free(*ifaces, *iface_count);
		*ifaces = NULL;
		*iface_count = 0;
	}
	return rc;
}

int iscsi_default_iface_setup(struct iscsi_context *ctx)
{
	int rc = LIBISCSI_OK;
	char strerr_buff[_STRERR_BUFF_LEN];
	int errno_save = 0;
	struct _eth_if **eifs = NULL;
	uint32_t eif_count = 0;
	uint32_t i = 0;
	uint32_t n = 0;
	size_t j = 0;
	struct _iscsi_net_drv *ind = NULL;
	uint32_t *hids = NULL;
	uint32_t hid_count = 0;
	struct iscsi_iface **ifaces = NULL;
	uint32_t iface_count = 0;
	char *path = NULL;

	assert(ctx != NULL);

	_good(_idbm_lock(ctx), rc, out);

	if ((access(IFACE_CONFIG_DIR, F_OK) != 0) &&
	    (mkdir(IFACE_CONFIG_DIR, 0770) != 0)) {
		errno_save = errno;
		_idbm_unlock(ctx);
		_error(ctx, "Could not make %s folder(%d %s). "
		       "HW/OFFLOAD iscsi may not be supported.",
		       IFACE_CONFIG_DIR, errno_save,
		       _strerror(errno_save, strerr_buff));
		if (errno_save == EACCES)
			return LIBISCSI_ERR_ACCESS;
		return LIBISCSI_ERR_BUG;
	}
	_idbm_unlock(ctx);

	/* Load kernel driver for iSCSI offload cards, like cxgb3i */
	_good(_eth_ifs_get(ctx, &eifs, &eif_count), rc, out);

	for (i = 0; i < eif_count; ++i) {
		for (j = 0;
		     j < sizeof(_ISCSI_NET_DRVS)/sizeof(struct _iscsi_net_drv);
		     ++j) {
			ind = &(_ISCSI_NET_DRVS[j]);
			if ((ind->net_driver_name == NULL) ||
			    (strcmp(eifs[i]->driver_name,
				   ind->net_driver_name) != 0))
				continue;
			/*
			* iSCSI hardware offload for bnx2{,x} is only supported
			* if the iscsiuio executable is available.
			*/
			if ((strcmp(eifs[i]->driver_name, "bnx2x") == 0) ||
			    (strcmp(eifs[i]->driver_name, "bnx2") == 0)) {
				if (access(ISCSIUIO_PATH, F_OK) != 0) {
					_debug(ctx, "iSCSI offload on %s(%s) "
					       "via %s is not supported due to "
					       "missing %s", eifs[i]->if_name,
					       eifs[i]->driver_name,
					       ind->iscsi_driver_name,
					       ISCSIUIO_PATH);
					continue;
				}
			}

			if (_iscsi_transport_is_loaded(ind->transport_name))
				continue;

			_debug(ctx, "Loading kernel module %s for iSCSI "
			       "offload on %s(%s)", ind->iscsi_driver_name,
			       eifs[i]->if_name, eifs[i]->driver_name);
			_good(_load_kernel_module(ctx, ind->iscsi_driver_name),
			      rc, out);
		}
	}

	_good(_iscsi_hids_get(ctx, &hids, &hid_count), rc, out);
	for (i = 0; i < hid_count; ++i) {
		/* Create /etc/iscsi/ifaces/<iface_name> file if not found
		 */
		_good(_iscsi_ifaces_get_from_sysfs(ctx, hids[i], &ifaces, &iface_count),
			rc, out);
		for (n = 0; n < iface_count; n++) {
			if ( ! iscsi_is_default_iface(ifaces[n])) {
				_good(_asprintf(&path, "%s/%s", IFACE_CONFIG_DIR,
						ifaces[n]->name), rc, out);
				if (access(path, F_OK) != 0)
					rc = _iface_conf_write(ctx, ifaces[n]);
				free(path);
				path = NULL;
			}
			iscsi_iface_free(ifaces[n]);
			ifaces[n] = NULL;
			if (rc != LIBISCSI_OK)
				goto out;
		}
		free(ifaces);
		ifaces = NULL;
	}

out:
	if (ifaces != NULL) {
		for (i = 0; i < iface_count; i++)
			free(ifaces[i]);
		free(ifaces);
	}
	_eth_ifs_free(eifs, eif_count);
	free(path);
	free(hids);
	return rc;
}

static int _load_kernel_module(struct iscsi_context *ctx, const char *drv_name)
{
	struct kmod_ctx *kctx = NULL;
	struct kmod_module *mod = NULL;
	int rc = LIBISCSI_OK;

	kctx = kmod_new(NULL, NULL);
	_alloc_null_check(ctx, kctx, rc, out);

	kmod_load_resources(kctx);

	if (kmod_module_new_from_name(kctx, drv_name, &mod)) {
		_error(ctx, "Failed to load module %s.", drv_name);
		rc = LIBISCSI_ERR_TRANS_NOT_FOUND;
		goto out;
	}

	if (kmod_module_probe_insert_module(mod, KMOD_PROBE_APPLY_BLACKLIST,
					    NULL, NULL, NULL, NULL)) {
		_error(ctx, "Could not insert module %s. Kmod error %d",
		       drv_name, rc);
		rc = LIBISCSI_ERR_TRANS_NOT_FOUND;
	}
	kmod_module_unref(mod);

out:
	if (kctx != NULL)
		kmod_unref(kctx);
	return rc;
}

static int _iface_conf_write(struct iscsi_context *ctx,
			     struct iscsi_iface *iface)
{
	char *conf_path = NULL;
	char strerr_buff[_STRERR_BUFF_LEN];
	int errno_save = 0;
	FILE *f = NULL;
	int rc = 0;

	if (iscsi_is_default_iface(iface)) {
		_error(ctx, "iface %s is not a special interface and "
		       "is not stored in %s", iface->name, IFACE_CONFIG_DIR);
		return LIBISCSI_ERR_INVAL;
	}

	_good(_idbm_lock(ctx), rc, out);

	_good(_asprintf(&conf_path, "%s/%s", IFACE_CONFIG_DIR,
			iface->name), rc, out);
	_debug(ctx, "Creating iSCSI interface configuration file '%s' "
	       "using kernel information", conf_path);
	f = fopen(conf_path, "w");
	errno_save = errno;
	if (!f) {
		_error(ctx, "Failed to open %s using write mode: %d %s",
		       conf_path, errno_save,
		       _strerror(errno_save, strerr_buff));
		rc = LIBISCSI_ERR_IDBM;
		goto out;
	}

	_idbm_iface_print(iface, f);

	_idbm_unlock(ctx);

out:
	free(conf_path);
	if (f != NULL)
		fclose(f);
	return rc;
}

// mimic of iscsi_sysfs_read_iface() in iscsi_sysfs.c.
static int _fill_hw_iface_from_sys(struct iscsi_context *ctx,
				   struct iscsi_iface *iface,
				   const char *iface_kern_id)
{
	int rc = LIBISCSI_OK;
	char *sysfs_iface_dir_path = NULL;
	uint32_t tmp_host_no = 0;
	uint32_t iface_num = 0;
	int iface_type = 0;

	assert(ctx != NULL);
	assert(iface != NULL);
	assert(iface_kern_id != NULL);

	_good(_asprintf(&sysfs_iface_dir_path, "%s/%s", _ISCSI_SYS_IFACE_DIR,
			iface_kern_id), rc, out);

	_good(_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				  "ipaddress",
				  iface->ipaddress,
				  sizeof(iface->ipaddress) /
				  sizeof(char), DEFAULT_IPADDRESS),
		      rc, out);

	if (strncmp(iface_kern_id, "ipv4", strlen("ipv4")) == 0) {
		iface->is_ipv6 = false;
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "bootproto", iface->bootproto,
				    sizeof(iface->bootproto) / sizeof(char),
				    "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "gateway",
				    iface->gateway,
				    sizeof(iface->gateway) / sizeof(char),
				    "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "subnet",
				    iface->subnet_mask,
				    sizeof(iface->subnet_mask) / sizeof(char),
				    "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "dhcp_alt_client_id_en",
				    iface->dhcp_alt_client_id,
				    sizeof(iface->dhcp_alt_client_id) /
				    sizeof(char),
				    "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "dhcp_alt_client_id",
				    iface->dhcp_alt_client_id,
				    sizeof(iface->dhcp_alt_client_id) /
				    sizeof(char),
				    "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "dhcp_dns_address_en", iface->dhcp_dns,
				    sizeof(iface->dhcp_dns) / sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "dhcp_learn_iqn_en", iface->dhcp_learn_iqn,
				    sizeof(iface->dhcp_learn_iqn) /
				    sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "dhcp_req_vendor_id_en",
				    iface->dhcp_req_vendor_id_state,
				    sizeof(iface->dhcp_req_vendor_id_state) /
				    sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "dhcp_use_vendor_id_en",
				    iface->dhcp_vendor_id_state,
				    sizeof(iface->dhcp_vendor_id_state) /
				    sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "dhcp_vendor_id", iface->dhcp_vendor_id,
				    sizeof(iface->dhcp_vendor_id) /
				    sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "dhcp_slp_da_info_en", iface->dhcp_slp_da,
				    sizeof(iface->dhcp_slp_da) / sizeof(char),
				    "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "fragment_disable", iface->fragmentation,
				    sizeof(iface->fragmentation) / sizeof(char),
				    "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "grat_arp_en", iface->gratuitous_arp,
				    sizeof(iface->gratuitous_arp) /
				    sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "incoming_forwarding_en",
				    iface->incoming_forwarding,
				    sizeof(iface->incoming_forwarding) /
				    sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "tos_en",
				    iface->tos_state, sizeof(iface->tos_state) /
				    sizeof(char), "");
		_sysfs_prop_get_u8(ctx, sysfs_iface_dir_path, "tos",
				   &iface->tos, 0, true);
		_sysfs_prop_get_u8(ctx, sysfs_iface_dir_path, "ttl",
				   &iface->ttl, 0, true);
	} else {
		iface->is_ipv6 = true;
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "ipaddr_autocfg",
				    iface->ipv6_autocfg,
				    sizeof(iface->ipv6_autocfg) / sizeof(char),
				    "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "link_local_addr", iface->ipv6_linklocal,
				    sizeof(iface->ipv6_linklocal) /
				    sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "link_local_autocfg",
				    iface->linklocal_autocfg,
				    sizeof(iface->linklocal_autocfg) /
				    sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "router_addr", iface->ipv6_router,
				    sizeof(iface->ipv6_router) / sizeof(char),
				    "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "router_state", iface->router_autocfg,
				    sizeof(iface->router_autocfg) /
				    sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "grat_neighbor_adv_en",
				    iface->gratuitous_neighbor_adv,
				    sizeof(iface->gratuitous_neighbor_adv) /
				    sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "mld_en",
				    iface->mld, sizeof(iface->mld) /
				    sizeof(char), "");
		_sysfs_prop_get_u8(ctx, sysfs_iface_dir_path,
				   "dup_addr_detect_cnt",
				   &iface->dup_addr_detect_cnt, 0, true);
		_sysfs_prop_get_u8(ctx, sysfs_iface_dir_path, "hop_limit",
				   &iface->hop_limit, 0, true);
		_sysfs_prop_get_u32(ctx, sysfs_iface_dir_path,
				    "flow_label", &iface->flow_label, 0, true);
		_sysfs_prop_get_u32(ctx, sysfs_iface_dir_path,
				    "nd_reachable_tmo",
				    &iface->nd_reachable_tmo, 0, true);
		_sysfs_prop_get_u32(ctx, sysfs_iface_dir_path, "nd_rexmit_time",
				    &iface->nd_rexmit_time, 0, true);
		_sysfs_prop_get_u32(ctx, sysfs_iface_dir_path, "nd_stale_tmo",
				    &iface->nd_stale_tmo, 0, true);
		_sysfs_prop_get_u32(ctx, sysfs_iface_dir_path,
				    "router_adv_link_mtu",
				    &iface->router_adv_link_mtu, 0, true);
		_sysfs_prop_get_u32(ctx, sysfs_iface_dir_path, "traffic_class",
				    &iface->traffic_class, 0, true);
	}

	_sysfs_prop_get_u16(ctx, sysfs_iface_dir_path, "port", &iface->port, 0,
			    true);
	_sysfs_prop_get_u16(ctx, sysfs_iface_dir_path, "mtu", &iface->mtu, 0,
			    true);
	_sysfs_prop_get_u16(ctx, sysfs_iface_dir_path, "vlan_id",
			    &iface->vlan_id, UINT16_MAX, true);
	_sysfs_prop_get_u8(ctx, sysfs_iface_dir_path, "vlan_priority",
			    &iface->vlan_priority, UINT8_MAX, true);
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "vlan_enabled",
			    iface->vlan_state, sizeof(iface->vlan_state) /
			    sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "enabled", iface->state,
			    sizeof(iface->state) / sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "delayed_ack_en",
			    iface->delayed_ack,
			    sizeof(iface->delayed_ack) / sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "tcp_nagle_disable",
			    iface->nagle, sizeof(iface->nagle) / sizeof(char),
			    "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "tcp_wsf_disable",
			    iface->tcp_wsf_state,
			    sizeof(iface->tcp_wsf_state) / sizeof(char), "");
	_sysfs_prop_get_u8(ctx, sysfs_iface_dir_path, "tcp_wsf",
			   &iface->tcp_wsf, 0, true);
	_sysfs_prop_get_u8(ctx, sysfs_iface_dir_path, "tcp_timer_scale",
			   &iface->tcp_timer_scale, 0, true);
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "tcp_timestamp_en",
			    iface->tcp_timestamp,
			    sizeof(iface->tcp_timestamp) / sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "redirect_en",
			    iface->redirect,
			    sizeof(iface->redirect) / sizeof(char), "");
	_sysfs_prop_get_u16(ctx, sysfs_iface_dir_path, "def_taskmgmt_tmo",
			    &iface->def_task_mgmt_tmo, 0, true);
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "header_digest",
			    iface->header_digest,
			    sizeof(iface->header_digest) / sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "data_digest",
			    iface->data_digest,
			    sizeof(iface->data_digest) / sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "immediate_data",
			    iface->immediate_data,
			    sizeof(iface->immediate_data) / sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "initial_r2t",
			    iface->initial_r2t,
			    sizeof(iface->initial_r2t) / sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "data_seq_in_order",
			    iface->data_seq_inorder,
			    sizeof(iface->data_seq_inorder) / sizeof(char),
			    "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "data_pdu_in_order",
			    iface->data_pdu_inorder,
			    sizeof(iface->data_pdu_inorder) / sizeof(char), "");
	_sysfs_prop_get_u8(ctx, sysfs_iface_dir_path, "erl", &iface->erl, 0,
			    true);
	_sysfs_prop_get_u32(ctx, sysfs_iface_dir_path, "max_recv_dlength",
			    &iface->max_recv_dlength, 0, true);
	_sysfs_prop_get_u32(ctx, sysfs_iface_dir_path, "first_burst_len",
			    &iface->first_burst_len, 0, true);
	_sysfs_prop_get_u16(ctx, sysfs_iface_dir_path, "max_outstanding_r2t",
			    &iface->max_out_r2t, 0, true);
	_sysfs_prop_get_u32(ctx, sysfs_iface_dir_path, "max_burst_len",
			    &iface->max_burst_len, 0, true);
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "chap_auth",
			    iface->chap_auth,
			    sizeof(iface->chap_auth) / sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "bidi_chap",
			    iface->bidi_chap,
			    sizeof(iface->bidi_chap) / sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "strict_login_comp_en",
			    iface->strict_login_comp,
			    sizeof(iface->strict_login_comp) / sizeof(char),
			    "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
			    "discovery_auth_optional",
			    iface->discovery_auth,
			    sizeof(iface->discovery_auth) / sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
			    "discovery_logout",
			    iface->discovery_logout,
			    sizeof(iface->discovery_logout) / sizeof(char), "");

	if (sscanf(iface_kern_id, "ipv%d-iface-%" SCNu32 "-%" SCNu32,
		   &iface_type, &tmp_host_no, &iface_num) == 3)
		iface->iface_num = iface_num;

	snprintf(iface->name, sizeof(iface->name)/sizeof(char),
		 "%s.%s.%s.%u", iface->transport_name,
		 iface->hwaddress, iface->is_ipv6 ?  "ipv6" : "ipv4",
		 iface->iface_num);

out:
	free(sysfs_iface_dir_path);
	return rc;
}

int iscsi_ifaces_get(struct iscsi_context *ctx, struct iscsi_iface ***ifaces,
		     uint32_t *iface_count)
{
	int rc = LIBISCSI_OK;
	struct dirent **namelist = NULL;
	int n = 0;
	size_t i = 0;
	struct iscsi_iface *iface = NULL;
	int j = 0;
	uint32_t real_iface_count = 0;

	assert(ctx != NULL);
	assert(ifaces != NULL);
	assert(iface_count != NULL);

	*ifaces = NULL;
	*iface_count = 0;

	_good(_idbm_lock(ctx), rc, out);

	_good(_scandir(ctx, IFACE_CONFIG_DIR, &namelist, &n), rc, out);
	_debug(ctx, "Got %d iface from %s folder", n, IFACE_CONFIG_DIR);
	*iface_count = (n + sizeof(_DEFAULT_IFACES)/sizeof(struct iscsi_iface))
		& UINT32_MAX;
	*ifaces = (struct iscsi_iface **) calloc(*iface_count,
						sizeof(struct iscsi_iface *));
	_alloc_null_check(ctx, *ifaces, rc, out);

	for (j = 0; j < n; ++j) {
		_good(_idbm_iface_get(ctx, namelist[j]->d_name, &iface),
		      rc, out);
		if (iface != NULL) {
			(*ifaces)[real_iface_count++] = iface;
		}
	}

	for (i = 0; i < sizeof(_DEFAULT_IFACES)/sizeof(struct iscsi_iface);
	     ++i) {
		iface = calloc(1, sizeof(struct iscsi_iface));
		_alloc_null_check(ctx, iface, rc, out);
		(*ifaces)[real_iface_count++] = iface;
		memcpy(iface, &_DEFAULT_IFACES[i], sizeof(struct iscsi_iface));
	}

	*iface_count = real_iface_count;

out:
	_scandir_free(namelist, n);
	_idbm_unlock(ctx);
	if (rc != LIBISCSI_OK) {
		iscsi_ifaces_free(*ifaces, *iface_count);
		*ifaces = NULL;
		*iface_count = 0;
	}
	return rc;
}

void iscsi_ifaces_free(struct iscsi_iface **ifaces, uint32_t iface_count)
{
	uint32_t i = 0;

	if ((ifaces == NULL) || (iface_count == 0))
		return;

	for (i = 0; i < iface_count; ++i)
		iscsi_iface_free(ifaces[i]);
	free (ifaces);
}

static bool _iface_is_bound_by_hwaddr(struct iscsi_iface *iface)
{
	if (iface && strlen(iface->hwaddress) &&
	    strcmp(iface->hwaddress, DEFAULT_HWADDRESS))
		return true;
	return false;
}

static bool _iface_is_bound_by_netdev(struct iscsi_iface *iface)
{
	if (iface && strlen(iface->netdev) &&
	   strcmp(iface->netdev, DEFAULT_NETDEV))
		return true;
	return false;
}

bool _iface_is_valid(struct iscsi_iface *iface)
{
	if (!iface)
		return false;

	if (strlen(iface->name) == 0)
		return false;

	if (strlen(iface->transport_name) == 0)
		return false;

	if (_iface_is_bound_by_hwaddr(iface))
		return true;

	if (_iface_is_bound_by_netdev(iface))
		return true;

	/* bound by transport name */
	return true;
}

bool iscsi_is_default_iface(struct iscsi_iface *iface)
{
	size_t i = 0;
	for (; i < sizeof(_DEFAULT_IFACES)/sizeof(struct iscsi_iface); ++i) {
		if (strcmp(iface->name, _DEFAULT_IFACES[i].name) == 0)
			return true;
	}
	return false;
}

const char *iscsi_iface_dump_config(struct iscsi_iface *iface)
{
	FILE *f = NULL;
	char *buff = NULL;

	assert(iface != NULL);

	buff = calloc(1, IDBM_DUMP_SIZE);
	if (buff == NULL)
		return NULL;

	f = fmemopen(buff, IDBM_DUMP_SIZE - 1, "w");
	if (f == NULL) {
		free(buff);
		return NULL;
	}

	_idbm_iface_print(iface, f);

	fclose(f);

	return buff;
}

void iscsi_iface_print_config(struct iscsi_iface *iface)
{
	assert(iface != NULL);
	_idbm_iface_print(iface, stdout);
}

int iscsi_iface_get(struct iscsi_context *ctx, const char *iface_name,
		    struct iscsi_iface **iface)
{
	int rc = LIBISCSI_OK;
	assert(ctx != NULL);
	assert(iface_name != NULL);
	assert(strlen(iface_name) != 0);
	assert(iface != NULL);

	*iface = NULL;

	size_t i = 0;
	for (; i < sizeof(_DEFAULT_IFACES)/sizeof(struct iscsi_iface); ++i) {
		if (strcmp(iface_name, _DEFAULT_IFACES[i].name) == 0) {
			*iface = calloc(1, sizeof(struct iscsi_iface));
			_alloc_null_check(ctx, *iface, rc, out);
			memcpy(*iface, &_DEFAULT_IFACES[i],
			       sizeof(struct iscsi_iface));
			goto out;
		}
	}

	rc = _idbm_lock(ctx);
	if (rc != LIBISCSI_OK)
		return rc;

	rc = _idbm_iface_get(ctx, iface_name, iface);
	if (*iface == NULL)
		rc = LIBISCSI_ERR_IDBM;

	_idbm_unlock(ctx);

out:
	return rc;
}

void iscsi_iface_free(struct iscsi_iface *iface)
{
	free(iface);
}
