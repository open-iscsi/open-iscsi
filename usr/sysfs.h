/*
 * This is from udev-121 udev.h
 *
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2003-2006 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 *
 *	This program is distributed in the hope that it will be useful, but
 *	WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *	General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, write to the Free Software Foundation, Inc.,
 *	51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#ifndef _SYSFS_
#define _SYSFS_

#include <stdint.h>
#include "list.h"
#include "string.h"

#define PATH_SIZE				512
#define NAME_SIZE				256

struct sysfs_device {
	struct list_head node;			/* for device cache */
	struct sysfs_device *parent;		/* already cached parent*/
	char devpath[PATH_SIZE];
	char subsystem[NAME_SIZE];		/* $class, $bus, drivers, module */
	char kernel[NAME_SIZE];			/* device instance name */
	char kernel_number[NAME_SIZE];
	char driver[NAME_SIZE];			/* device driver name */
};

extern char sysfs_path[PATH_SIZE];
extern int sysfs_init(void);
extern void sysfs_cleanup(void);
extern void sysfs_device_set_values(struct sysfs_device *dev, const char *devpath,
				    const char *subsystem, const char *driver);
extern struct sysfs_device *sysfs_device_get(const char *devpath);
extern struct sysfs_device *sysfs_device_get_parent(struct sysfs_device *dev);
extern struct sysfs_device *sysfs_device_get_parent_with_subsystem(struct sysfs_device *dev, const char *subsystem);
extern char *sysfs_attr_get_value(const char *devpath, const char *attr_name);
extern int sysfs_resolve_link(char *path, size_t size);
extern int sysfs_lookup_devpath_by_subsys_id(char *devpath, size_t len, const char *subsystem, const char *id);

extern char *sysfs_get_value(const char *id, char *subsys, char *param);
extern int sysfs_get_uint(char *id, char *subsys, char *param,
			  unsigned int *value);
extern int sysfs_get_int(const char *id, char *subsys, char *param, int *value);
extern int sysfs_get_str(char *id, char *subsys, char *param, char *value,
			 int value_size);
extern int sysfs_get_uint64(char *id, char *subsys, char *param,
			    uint64_t *value);
extern int sysfs_get_uint8(char *id, char *subsys, char *param,
			   uint8_t *value);
extern int sysfs_get_uint16(char *id, char *subsys, char *param,
			    uint16_t *value);
extern int sysfs_set_param(char *id, char *subsys, char *attr_name,
			   char *write_buf, ssize_t buf_size);

#endif
