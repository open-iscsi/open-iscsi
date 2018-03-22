/*
 * Copyright (C) 2017 Red Hat, Inc.
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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/ethtool.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <net/if_arp.h>

#include "libopeniscsiusr/libopeniscsiusr.h"
#include "misc.h"
#include "context.h"

#define _UNUSED(x) (void)(x)

#define _ISCSI_LOG_STRERR_ALIGN_WIDTH	80
/* ^ Only used in _iscsi_log_stderr() for pretty log output.
 *   When provided log message is less than 80 bytes, fill it with space, then
 *   print code file name, function name, line after the 80th bytes.
 */

struct _num_str_conv {
	const uint32_t value;
	const char *str;
};

#define _iscsi_str_func_gen(func_name, var_type, var, conv_array) \
const char *func_name(var_type var) { \
	size_t i = 0; \
	uint32_t tmp_var = var & UINT32_MAX; \
	errno = 0; \
	/* In the whole libopeniscsiusr, we don't have negative value */ \
	for (; i < sizeof(conv_array)/sizeof(conv_array[0]); ++i) { \
		if ((conv_array[i].value) == tmp_var) \
			return conv_array[i].str; \
	} \
	errno = EINVAL; \
	return "Invalid argument"; \
}

static const struct _num_str_conv _ISCSI_RC_MSG_CONV[] = {
	{LIBISCSI_OK, "OK"},
	{LIBISCSI_ERR_BUG, "BUG of libopeniscsiusr library"},
	{LIBISCSI_ERR_SESS_NOT_FOUND, "Specified iSCSI session not found"},
	{LIBISCSI_ERR_ACCESS, "Permission deny"},
	{LIBISCSI_ERR_NOMEM, "Out of memory"},
	{LIBISCSI_ERR_SYSFS_LOOKUP, "Could not lookup object in sysfs"},
	{LIBISCSI_ERR_IDBM, "Error accessing/managing iSCSI DB"},
	{LIBISCSI_ERR_TRANS_NOT_FOUND,
		"iSCSI transport module not loaded in kernel or iscsid"},
	{LIBISCSI_ERR_INVAL, "Invalid argument"},
};

_iscsi_str_func_gen(iscsi_strerror, int, rc, _ISCSI_RC_MSG_CONV);

static const struct _num_str_conv _ISCSI_PRI_CONV[] = {
	{LIBISCSI_LOG_PRIORITY_DEBUG, "DEBUG"},
	{LIBISCSI_LOG_PRIORITY_INFO, "INFO"},
	{LIBISCSI_LOG_PRIORITY_WARNING, "WARNING"},
	{LIBISCSI_LOG_PRIORITY_ERROR, "ERROR"},
};

_iscsi_str_func_gen(iscsi_log_priority_str, int, priority, _ISCSI_PRI_CONV);

void _iscsi_log_stderr(struct iscsi_context *ctx, int priority,
		       const char *file, int line, const char *func_name,
		       const char *format, va_list args)
{
	int printed_bytes = 0;

	_UNUSED(ctx);

	printed_bytes += fprintf(stderr, "iSCSI %s: ",
				 iscsi_log_priority_str(priority));
	printed_bytes += vfprintf(stderr, format, args);

	if (printed_bytes < _ISCSI_LOG_STRERR_ALIGN_WIDTH) {
		fprintf(stderr, "%*s # %s:%s():%d\n",
			_ISCSI_LOG_STRERR_ALIGN_WIDTH - printed_bytes, "", file,
			func_name, line);
	} else {
		fprintf(stderr, " # %s:%s():%d\n", file, func_name, line);
	}
}

void _iscsi_log(struct iscsi_context *ctx, int priority, const char *file,
		int line, const char *func_name, const char *format, ...)
{
	va_list args;

	if (ctx->log_func == NULL)
		return;

	va_start(args, format);
	ctx->log_func(ctx, priority, file, line, func_name, format, args);
	va_end(args);
}

int _scan_filter_skip_dot(const struct dirent *dir)
{
	return strcmp(dir->d_name, ".") && strcmp(dir->d_name, "..");
}

bool _file_exists(const char *path)
{
	if (access(path, F_OK) == 0)
		return true;
	else
		return false;
}

static bool _is_eth(struct iscsi_context *ctx, const char *if_name)
{
	struct ifreq ifr;
	int sockfd = -1;
	char strerr_buff[_STRERR_BUFF_LEN];

	assert(if_name != NULL);

	memset(&ifr, 0, sizeof(ifr));

	_strncpy(ifr.ifr_name, if_name, IFNAMSIZ);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		_warn(ctx, "Failed to create SOCK_DGRAM AF_INET socket: %d %s",
		      errno, _strerror(errno, strerr_buff));
		return false;
	}

	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) != 0) {
		_warn(ctx, "IOCTL SIOCGIFHWADDR to %s failed: %d %s", if_name,
		      errno, _strerror(errno, strerr_buff));
		close(sockfd);
		return false;
	}

	close(sockfd);

	if (ifr.ifr_hwaddr.sa_family == ARPHRD_ETHER)
		return true;

	return false;
}

/*
 * driver_name should be char[_ETH_DRIVER_NAME_MAX_LEN]
 */
static int _eth_driver_get(struct iscsi_context *ctx, const char *if_name,
			   char *driver_name)
{
	int sockfd = -1;
	struct ethtool_drvinfo drvinfo;
	struct ifreq ifr;
	char strerr_buff[_STRERR_BUFF_LEN];

	assert(ctx != NULL);
	assert(if_name != NULL);
	assert(driver_name != NULL);

	memset(&ifr, 0, sizeof(ifr));
	memset(&drvinfo, 0, sizeof(drvinfo));

	_strncpy(ifr.ifr_name, if_name, IFNAMSIZ);
	drvinfo.cmd = ETHTOOL_GDRVINFO;
	ifr.ifr_data = (caddr_t) &drvinfo;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		_error(ctx, "Failed to create SOCK_DGRAM AF_INET socket: %d %s",
		       errno, _strerror(errno, strerr_buff));
		return LIBISCSI_ERR_BUG;
	}

	if (ioctl(sockfd, SIOCETHTOOL, &ifr) != 0) {
		_warn(ctx, "IOCTL SIOCETHTOOL to %s failed: %d %s", if_name,
		      errno, _strerror(errno, strerr_buff));
		close(sockfd);
		return LIBISCSI_ERR_BUG;
	}
	close(sockfd);
	snprintf(driver_name, _ETH_DRIVER_NAME_MAX_LEN, "%s", drvinfo.driver);

	return LIBISCSI_OK;
}

int _eth_ifs_get(struct iscsi_context *ctx, struct _eth_if ***eifs,
		 uint32_t *eif_count)
{
	int rc = LIBISCSI_OK;
	struct if_nameindex *if_ni = NULL;
	struct if_nameindex *if_i = NULL;
	struct _eth_if *eif = NULL;
	uint32_t tmp_count = 0;

	assert(ctx != NULL);
	assert(eifs != NULL);
	assert(eif_count != NULL);

	*eifs = NULL;
	*eif_count = 0;

	if_ni = if_nameindex();
	_alloc_null_check(ctx, if_ni, rc, out);

	for (if_i = if_ni; if_i && if_i->if_index && if_i->if_name; ++if_i)
		tmp_count++;

	if (tmp_count == 0)
		goto out;

	*eifs = calloc(tmp_count, sizeof(struct _eth_if *));
	_alloc_null_check(ctx, *eifs, rc, out);

	for (if_i = if_ni; if_i && if_i->if_index && if_i->if_name; ++if_i) {
		if (! _is_eth(ctx, if_i->if_name))
			continue;
		eif = calloc(1, sizeof(struct _eth_if));
		_alloc_null_check(ctx, eif, rc, out);
		(*eifs)[(*eif_count)++] = eif;
		snprintf(eif->if_name, sizeof(eif->if_name)/sizeof(char),
			 "%s", if_i->if_name);
		_good(_eth_driver_get(ctx, eif->if_name, eif->driver_name),
		      rc, out);
	}

out:
	if (rc != LIBISCSI_OK) {
		_eth_ifs_free(*eifs, *eif_count);
		*eifs = NULL;
		*eif_count = 0;
	}
	if (if_ni != NULL)
		if_freenameindex(if_ni);
	return rc;
}

void _eth_ifs_free(struct _eth_if **eifs, uint32_t eif_count)
{
	uint32_t i = 0;

	if ((eif_count == 0) || (eifs == NULL))
		return;

	for (; i < eif_count; ++i)
		free(eifs[i]);
	free(eifs);
}

void _scandir_free(struct dirent **namelist, int count)
{
	int i = 0;

	if ((namelist == NULL) || (count == 0))
		return;

	for (i = count - 1; i >= 0; --i)
		free(namelist[i]);
	free(namelist);
}

int _scandir(struct iscsi_context *ctx, const char *dir_path,
	     struct dirent ***namelist, int *count)
{
	int rc = LIBISCSI_OK;
	int errno_save = 0;

	assert(ctx != NULL);
	assert(dir_path != NULL);
	assert(namelist != NULL);
	assert(count != NULL);

	*namelist = NULL;
	*count = 0;

	*count = scandir(dir_path, namelist, _scan_filter_skip_dot, alphasort);
	if (*count < 0) {
		errno_save = errno;
		if (errno_save == ENOENT) {
			*count = 0;
			goto out;
		}
		if (errno_save == ENOMEM) {
			rc = LIBISCSI_ERR_NOMEM;
			goto out;
		}
		if (errno_save == ENOTDIR) {
			rc = LIBISCSI_ERR_BUG;
			_error(ctx, "Got ENOTDIR error when scandir %s",
			       dir_path);
			goto out;
		}
		rc = LIBISCSI_ERR_BUG;
		_error(ctx, "Got unexpected error %d when scandir %s",
		       errno_save, dir_path);
		goto out;
	}

out:
	if (rc != LIBISCSI_OK) {
		_scandir_free(*namelist, *count);
		*namelist = NULL;
		*count = 0;
	}

	return rc;
}
