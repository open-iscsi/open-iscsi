/*
 * Copyright (C) IBM Corporation. 2007
 * Author: Doug Maxey <dwm@austin.ibm.com>
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

#define	 _XOPEN_SOURCE 500
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "fwparam.h"
#include "fw_context.h"
#include "iscsi_obp.h"
#include "prom_parse.h"
#include "sysdeps.h"

void* yy_scan_string(const char *str);
int yyparse(struct ofw_dev *ofwdev);

#define BOOTPATH "/chosen/bootpath"
#define DT_TOP "/proc/device-tree"
#define LOCAL_MAC_FILE "/local-mac-address"

static int devtree_offset;
static char *bootpath_val;
static int bytes_read;
#define OFWDEV_MAX (10)
static struct ofw_dev *ofwdevs[OFWDEV_MAX];
static char *niclist[OFWDEV_MAX];
static int nic_count;
static int debug;
static int dev_count;

static void cp_param(char *dest, const char *name, struct ofw_dev *dev,
		     enum obp_param item, int len)
{
	if (dev->param[item])
		strlcpy(dest, dev->param[item]->val, len);
}

static void cp_int_param(int *dest, const char *name, struct ofw_dev *dev,
			 enum obp_param item)
{
	if (dev->param[item])
		*dest = strtol(dev->param[item]->val, NULL, 10);
}

static char *find_devtree(const char *filename)
{
	char *devtree = strdup(filename);
	char *chop_at;
	struct stat dt_stat;
	int error;

	/*
	 * What is the path to the device-tree?	 The only valid
	 * directories to locate the property are under /aliases or
	 * /chosen.
	 */

	chop_at = strstr(devtree, "/chosen");
	if (!chop_at)
		chop_at = strstr(devtree, "/aliases");

	if (!chop_at) {
		char *vdev = malloc(strlen(filename) + strlen("/vdevice") + 1);

		/*
		 * test to see if there is /vdevice dir
		 */
		if (vdev) {
			sprintf(vdev, "%s%s", filename, "/vdevice");
			error = stat(vdev, &dt_stat);
			free(vdev);
			if (error) {
				free(devtree);
				return NULL;
			}
		}
	} else
		devtree[chop_at - devtree] = 0;

	if (devtree)
		devtree_offset = strlen(devtree);

	return devtree;
}

/*
 * Take the path to the property under chosen, and swizzle to make that
 * the base for the device path discovered.
 */
static int locate_mac(const char *devtree, struct ofw_dev *ofwdev)
{
	int error = 0;
	int mac_path_len = strlen(ofwdev->dev_path) + strlen(LOCAL_MAC_FILE) +
		2;
	char *mac_file;
	int mac_fd;

	mac_path_len += strlen(devtree);
	mac_file = malloc(mac_path_len);
	if (!mac_file) {
		error = ENOMEM;
		fprintf(stderr, "%s: malloc , %s\n", __func__,
			strerror(errno));
		goto lpm_bail;
	}

	snprintf(mac_file, mac_path_len, "%s%s%s", devtree, ofwdev->dev_path,
		 LOCAL_MAC_FILE);
	mac_fd = open(mac_file, O_RDONLY);
	if (mac_fd < 0) {
		error = errno;
		fprintf(stderr, "%s: open %s, %s\n", __func__, mac_file,
			strerror(errno));
		goto lpm_bail;
	}

	bytes_read = read(mac_fd, ofwdev->mac, 6);
	if (bytes_read != 6) {
		error = EIO;
		fprintf(stderr, "%s: read %s, %s\n", __func__, mac_file,
			strerror(errno));
		goto lpm_bail;
	}
	free(mac_file);
	close(mac_fd);


lpm_bail:
	return error;
}

const char *obp_qual_set(struct ofw_dev *ofwdev, const char *qual)
{
	if (!strcmp("bootp", qual))
		ofwdev->quals[ofwdev->qual_count++] = OBP_QUAL_BOOTP;
	else if (!strcmp("dhcpv6", qual))
		ofwdev->quals[ofwdev->qual_count++] = OBP_QUAL_DHCPV6;
	else if (!strcmp("ipv6", qual))
		ofwdev->quals[ofwdev->qual_count++] = OBP_QUAL_IPV6;
	else if (!strcmp("iscsi", qual)) {
		ofwdev->type = OFW_DT_ISCSI;
		ofwdev->quals[ofwdev->qual_count++] = OBP_QUAL_ISCSI;
	} else if (!strcmp("ping", qual))
		ofwdev->quals[ofwdev->qual_count++] = OBP_QUAL_PING;
	else
		printf("%s: %s UNKNOWN\n", __func__, qual);
	return qual;
}

void add_obp_parm(struct ofw_dev *ofwdev, enum obp_param parm, const char *str)
{
	int psz = sizeof(struct ofw_obp_param) + strlen(str);

	ofwdev->param[parm] = malloc(psz);
	if (ofwdev->param[parm] == NULL) {
		printf("%s: ENOMEM!\n", __func__);
		return;
	}
	memset(ofwdev->param[parm], 0, psz);
	ofwdev->param[parm]->len = psz;
	strcpy(ofwdev->param[parm]->val, str);
}

void obp_parm_addr(struct ofw_dev *ofwdev, const char *parm, const char *addr)
{
	if (!strcmp("ciaddr", parm))
		add_obp_parm(ofwdev, OBP_PARAM_CIADDR, addr);
	else if (!strcmp("dhcp", parm))
		add_obp_parm(ofwdev, OBP_PARAM_DHCP, addr);
	else if (!strcmp("giaddr", parm))
		add_obp_parm(ofwdev, OBP_PARAM_GIADDR, addr);
	else if (!strcmp("isns", parm))
		add_obp_parm(ofwdev, OBP_PARAM_ISNS, addr);
	else if (!strcmp("siaddr", parm))
		add_obp_parm(ofwdev, OBP_PARAM_SIADDR, addr);
	else if (!strcmp("slp", parm))
		add_obp_parm(ofwdev, OBP_PARAM_SLP, addr);
	else if (!strcmp("subnet-mask", parm))
		add_obp_parm(ofwdev, OBP_PARAM_SUBNET_MASK, addr);
	else
		printf("%s: %s UNKNOWN\n", __func__, parm);
}

void obp_parm_iqn(struct ofw_dev *ofwdev, const char *parm, const char *iqn)
{
	if (!strcmp("itname", parm))
		add_obp_parm(ofwdev, OBP_PARAM_ITNAME, iqn);
	else if (!strcmp("iname", parm))
		add_obp_parm(ofwdev, OBP_PARAM_INAME, iqn);
	else
		printf("%s: %s UNKNOWN\n", __func__, parm);
}

void obp_parm_hexnum(struct ofw_dev *ofwdev, const char *parm,
		     const char *numstr)
{
	if (!strcmp("bootp-retries", parm))
		add_obp_parm(ofwdev, OBP_PARAM_BOOTP_RETRIES, numstr);
	else if (!strcmp("tftp-retries", parm))
		add_obp_parm(ofwdev, OBP_PARAM_TFTP_RETRIES, numstr);
	else if (!strcmp("iport", parm))
		add_obp_parm(ofwdev, OBP_PARAM_IPORT, numstr);
	else if (!strcmp("ilun", parm))
		add_obp_parm(ofwdev, OBP_PARAM_ILUN, numstr);
	else if (!strcmp("isid", parm))
		add_obp_parm(ofwdev, OBP_PARAM_ISID, numstr);
	else
		printf("%s: %s UNKNOWN <%s>\n", __func__, parm, numstr);
}

void obp_parm_str(struct ofw_dev *ofwdev, const char *parm, const char *str)
{
	if (!strcmp("filename", parm))
		add_obp_parm(ofwdev, OBP_PARAM_FILENAME, str);
	else if (!strcmp("ichapid", parm))
		add_obp_parm(ofwdev, OBP_PARAM_ICHAPID, str);
	else if (!strcmp("ichappw", parm))
		add_obp_parm(ofwdev, OBP_PARAM_ICHAPPW, str);
	else if (!strcmp("chapid", parm))
		add_obp_parm(ofwdev, OBP_PARAM_CHAPID, str);
	else if (!strcmp("chappw", parm))
		add_obp_parm(ofwdev, OBP_PARAM_CHAPPW, str);
	else
		printf("%s: %s UNKNOWN <%s>\n", __func__, parm, str);
}

void yyerror(struct ofw_dev *ofwdev, const char *msg)
{
	fprintf(stderr, "%s: error in <%s> at l%d.c%d\n", "fwparam_ppc",
		ofwdev->prop_path, yylloc.last_line, yylloc.last_column);
}

static int parse_params(const char *buf, struct ofw_dev *ofwdev)
{
	int error = 0;
#if YYDEBUG
	yydebug = 1;
#endif


	if (yy_scan_string(buf))
		error = yyparse(ofwdev);

	return error;
}

static int find_file(const char *filename)
{
	int error, fd;
	struct stat bootpath_stat;

	error = stat(filename, &bootpath_stat);
	if (error < 0) {
		fprintf(stderr, "%s: stat %s, %s\n", __func__, filename,
			strerror(errno));
		return error;
	}

	bootpath_val = malloc(bootpath_stat.st_size);
	if (!bootpath_val) {
		error = ENOMEM;
		fprintf(stderr, "%s: Could not open %s: %s (%d)\n",
			__func__, filename, strerror(error), error);
		return -1;
	}

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "%s: Could not open %s: %s (%d)\n",
			__func__, filename, strerror(errno), errno);
		free(bootpath_val);
		return -1;
	}

	bytes_read = read(fd, bootpath_val, bootpath_stat.st_size);
	close(fd);
	free(bootpath_val);
	if (bytes_read != bootpath_stat.st_size) {
		fprintf(stderr, "%s: Could not open %s: %s (%d)\n",
			__func__, filename, strerror(EIO), EIO);
		return -1;
	}

	return 1;
}

static int find_nics(const char *fpath, const struct stat *sb, int tflag,
		     struct FTW *ftw)
{
	if (tflag == FTW_D &&
	    (strstr(fpath + ftw->base, "iscsi-toe") ||
	     strstr(fpath + ftw->base, "ethernet"))) {

		if (nic_count < OFWDEV_MAX)
			niclist[nic_count++] = strdup(fpath + devtree_offset);

	}
	return 0;
}

int nic_cmp(const char **a, const char **b)
{
	return strcmp(*a, *b);
}

static int find_initiator(const char *fpath, const struct stat *sb, int tflag,
			  struct FTW *ftw)
{
	struct ofw_dev *dev;

	if (tflag == FTW_F && (strstr(fpath + ftw->base,
				      "/aliases/iscsi-disk"))) {

		if (dev_count < OFWDEV_MAX) {
			ofwdevs[dev_count++] = dev =
				calloc(sizeof(struct ofw_dev), 1);
			dev->prop_path = strdup(fpath + devtree_offset);
		}
	}
	return 0;
}

static int loop_devs(const char *devtree)
{
	int error;
	int i;
	char prefix[256];

	nic_count = 0;
	error = nftw(devtree, find_nics, 20, 0);
	if (error)
		return error;

	/*
	 * Sort the nics into "natural" order.	The proc fs
	 * device-tree has them in somewhat random, or reversed order.
	 */
	qsort(niclist, nic_count, sizeof(char *), nic_cmp);

	snprintf(prefix, sizeof(prefix), "%s/%s", devtree, "aliases");
	dev_count = 0;
	error = nftw(prefix, find_initiator, 20, 0);
	if (error)
		return error;

	for (i = 0; i < dev_count; i++) {
		snprintf(prefix, sizeof(prefix), "%s%s", devtree,
			 ofwdevs[i]->prop_path);
		if (find_file(prefix) > 0) {
			error = parse_params(bootpath_val, ofwdevs[i]);
			if (!error)
				error = locate_mac(devtree, ofwdevs[i]);

		}
	}
	return error;
}

#define set_context(fld,abrv,item)					\
	cp_param(context->fld, (abrv), ofwdev, (item), sizeof(context->fld))
#define set_int_context(fld,abrv,item)					    \
	cp_int_param(&context->fld, (abrv), ofwdev, (item))

static void fill_context(struct boot_context *context, struct ofw_dev *ofwdev)
{
	int ndx;

	memset(context, 0, sizeof(*context));

	set_context(initiatorname, "NAME", OBP_PARAM_ITNAME);

	snprintf(context->mac, sizeof(context->mac),
		 "%02x:%02x:%02x:%02x:%02x:%02x",
		 ofwdev->mac[0], ofwdev->mac[1], ofwdev->mac[2],
		 ofwdev->mac[3], ofwdev->mac[4], ofwdev->mac[5]);

	/*
	 * nic parameters
	 */
	for (ndx = 0; ndx < nic_count; ndx++) {
		if (!strcmp(niclist[ndx], ofwdev->dev_path)) {
			snprintf(context->iface, sizeof(context->iface),
				 "eth%d", ndx);
			break;
		}
	}

	set_context(ipaddr, "IPADDR", OBP_PARAM_CIADDR);
	set_context(mask, "MASK", OBP_PARAM_SUBNET_MASK);

	/*
	 * target parameters
	 */
	set_context(target_ipaddr, "IPADDR", OBP_PARAM_SIADDR);
	set_int_context(target_port, "PORT", OBP_PARAM_IPORT);
	set_context(lun, "LUN", OBP_PARAM_ILUN);
	set_context(targetname, "NAME", OBP_PARAM_INAME);
	set_context(isid, "ISID", OBP_PARAM_ISID);

	/*
	 * chap stuff is always associated with the target
	 */
	set_context(chap_name, "CHAP_NAME", OBP_PARAM_ICHAPID);
	set_context(chap_password, "CHAP_PASSWORD", OBP_PARAM_ICHAPPW);
	set_context(chap_name_in, "CHAP_NAME_IN", OBP_PARAM_CHAPID);
	set_context(chap_password_in, "CHAP_PASSWORD_IN", OBP_PARAM_CHAPPW);

}

int fwparam_ppc_boot_info(struct boot_context *context)
{
	char filename[FILENAMESZ];
	int error;
	char *devtree;

	/*
	 * For powerpc, our operations are fundamentally to locate
	 * either the one boot target (the singleton disk), or to find
	 * the nics that support iscsi boot.  The only nics in IBM
	 * systems that can support iscsi are the ones that provide
	 * the appropriate FCODE with a load method.
	 */
	memset(filename, 0, FILENAMESZ);
	snprintf(filename, FILENAMESZ, "%s%s", DT_TOP, BOOTPATH);

	if (debug)
		fprintf(stderr, "%s: file:%s; debug:%d\n", __func__, filename,
			debug);

	devtree = find_devtree(filename);
	if (!devtree)
		return EINVAL;

	/*
	 * Always search the device-tree to find the capable nic devices.
	 */
	error = loop_devs(devtree);
	if (error)
		goto free_devtree;

	if (find_file(filename) < 1)
		error = ENODEV;
	else {
		if (debug)
			printf("%s:\n%s\n\n", filename, bootpath_val);
		/*
		 * We find *almost* everything we need in the
		 * bootpath, save the mac-address.
		 */

		if (!strstr(bootpath_val, "iscsi")) {
			error = EINVAL;
			goto free_devtree;
		}
		ofwdevs[0] = calloc(1, sizeof(struct ofw_dev));
		if (!ofwdevs[0]) {
			error = ENOMEM;
			goto free_devtree;
		}

		error = parse_params(bootpath_val, ofwdevs[0]);
		if (!error)
			error = locate_mac(devtree, ofwdevs[0]);
		if (!error) {
			context = calloc(1, sizeof(*context));
			if (!context)
				error = ENOMEM;
			else
				fill_context(context, ofwdevs[0]);
		}
		free(ofwdevs[0]);
	}

free_devtree:
	free(devtree);
	return error;
}

/*
 * Due to lack of time this is just fwparam_ppc_boot_info which
 * adds the target used for boot to the list. It does not add
 * all possible targets (IBM please add).
 */
int fwparam_ppc_get_targets(struct list_head *list)
{
	char filename[FILENAMESZ];
	struct boot_context *context;
	int error;
	char *devtree;

	/*
	 * For powerpc, our operations are fundamentally to locate
	 * either the one boot target (the singleton disk), or to find
	 * the nics that support iscsi boot.  The only nics in IBM
	 * systems that can support iscsi are the ones that provide
	 * the appropriate FCODE with a load method.
	 */
	memset(filename, 0, FILENAMESZ);
	snprintf(filename, FILENAMESZ, "%s%s", DT_TOP, BOOTPATH);

	if (debug)
		fprintf(stderr, "%s: file:%s; debug:%d\n", __func__, filename,
			debug);

	devtree = find_devtree(filename);
	if (!devtree)
		return EINVAL;

	/*
	 * Always search the device-tree to find the capable nic devices.
	 */
	error = loop_devs(devtree);
	if (error)
		goto free_devtree;

	if (find_file(filename) < 1)
		error = ENODEV;
	else {
		if (debug)
			printf("%s:\n%s\n\n", filename, bootpath_val);
		/*
		 * We find *almost* everything we need in the
		 * bootpath, save the mac-address.
		 */

		if (!strstr(bootpath_val, "iscsi")) {
			error = EINVAL;
			goto free_devtree;
		}
		ofwdevs[0] = calloc(1, sizeof(struct ofw_dev));
		if (!ofwdevs[0]) {
			error = ENOMEM;
			goto free_devtree;
		}

		error = parse_params(bootpath_val, ofwdevs[0]);
		if (!error)
			error = locate_mac(devtree, ofwdevs[0]);
		if (!error) {
			context = calloc(1, sizeof(*context));
			if (!context)
				error = ENOMEM;
			else {
				fill_context(context, ofwdevs[0]);
				list_add_tail(&context->list, list);
			}
		}
		free(ofwdevs[0]);
	}

free_devtree:
	free(devtree);
	return error;
}
