/*
 * This is from udev-121's udev_sysfs.c
 *
 * Copyright (C) 2005-2006 Kay Sievers <kay.sievers@vrfy.org>
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


#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <inttypes.h>
#include <sys/stat.h>

#include "log.h"
#include "sysdeps.h"
#include "sysfs.h"

/*
 * We take this file from udev so we want to make as few changes are possible,
 * so we can maintain patches.
 *
 * This is from udev_utils_string.c
 */
static void remove_trailing_chars(char *path, char c)
{
	size_t len;

	len = strlen(path);
	while (len > 0 && path[len-1] == c)
		path[--len] = '\0';
}

/* this converts udevs logging to ours. */
#define dbg(format, arg...)						\
	do {								\
		log_debug(3, "%s: " format, __FUNCTION__,## arg);	\
	} while (0)

/*
 * Begin udev_sysfs.c code
 */
char sysfs_path[PATH_SIZE];

/* device cache */
static LIST_HEAD(dev_list);

int sysfs_init(void)
{
	const char *env;

	env = getenv("SYSFS_PATH");
	if (env) {
		strlcpy(sysfs_path, env, sizeof(sysfs_path));
		remove_trailing_chars(sysfs_path, '/');
	} else
		strlcpy(sysfs_path, "/sys", sizeof(sysfs_path));
	dbg("sysfs_path='%s'", sysfs_path);

	INIT_LIST_HEAD(&dev_list);
	return 0;
}

void sysfs_cleanup(void)
{
	struct sysfs_device *dev_loop;
	struct sysfs_device *dev_temp;

	list_for_each_entry_safe(dev_loop, dev_temp, &dev_list, node) {
		list_del_init(&dev_loop->node);
		free(dev_loop);
	}
}

void sysfs_device_set_values(struct sysfs_device *dev, const char *devpath,
			     const char *subsystem, const char *driver)
{
	char *pos;

	strlcpy(dev->devpath, devpath, sizeof(dev->devpath));
	if (subsystem != NULL)
		strlcpy(dev->subsystem, subsystem, sizeof(dev->subsystem));
	if (driver != NULL)
		strlcpy(dev->driver, driver, sizeof(dev->driver));

	/* set kernel name */
	pos = strrchr(dev->devpath, '/');
	if (pos == NULL)
		return;
	strlcpy(dev->kernel, &pos[1], sizeof(dev->kernel));
	dbg("kernel='%s'", dev->kernel);

	/* some devices have '!' in their name, change that to '/' */
	pos = dev->kernel;
	while (pos[0] != '\0') {
		if (pos[0] == '!')
			pos[0] = '/';
		pos++;
	}

	/* get kernel number */
	pos = &dev->kernel[strlen(dev->kernel)];
	while (isdigit(pos[-1]))
		pos--;
	strlcpy(dev->kernel_number, pos, sizeof(dev->kernel_number));
	dbg("kernel_number='%s'", dev->kernel_number);
}

int sysfs_resolve_link(char *devpath, size_t size)
{
	char link_path[PATH_SIZE];
	char link_target[PATH_SIZE];
	int len;
	int i;
	int back;

	strlcpy(link_path, sysfs_path, sizeof(link_path));
	strlcat(link_path, devpath, sizeof(link_path));
	len = readlink(link_path, link_target, sizeof(link_target) - 1);
	if (len <= 0)
		return -1;
	link_target[len] = '\0';
	dbg("path link '%s' points to '%s'", devpath, link_target);

	for (back = 0; strncmp(&link_target[back * 3], "../", 3) == 0; back++)
		;
	dbg("base '%s', tail '%s', back %i", devpath, &link_target[back * 3], back);
	for (i = 0; i <= back; i++) {
		char *pos = strrchr(devpath, '/');

		if (pos == NULL)
			return -1;
		pos[0] = '\0';
	}
	dbg("after moving back '%s'", devpath);
	strlcat(devpath, "/", size);
	strlcat(devpath, &link_target[back * 3], size);
	return 0;
}

struct sysfs_device *sysfs_device_get(const char *devpath)
{
	char path[PATH_SIZE];
	char devpath_real[PATH_SIZE];
	struct sysfs_device *dev;
	struct sysfs_device *dev_loop;
	struct stat statbuf;
	char link_path[PATH_SIZE];
	char link_target[PATH_SIZE];
	int len;
	char *pos;

	if (!devpath)
		return NULL;

	/* we handle only these devpathes */
	if (strncmp(devpath, "/devices/", 9) != 0 &&
	    strncmp(devpath, "/subsystem/", 11) != 0 &&
	    strncmp(devpath, "/module/", 8) != 0 &&
	    strncmp(devpath, "/bus/", 5) != 0 &&
	    strncmp(devpath, "/class/", 7) != 0 &&
	    strncmp(devpath, "/block/", 7) != 0)
		return NULL;

	dbg("open '%s'", devpath);
	strlcpy(devpath_real, devpath, sizeof(devpath_real));
	remove_trailing_chars(devpath_real, '/');
	if (devpath[0] == '\0' )
		return NULL;

	/* look for device already in cache (we never put an untranslated path in the cache) */
	list_for_each_entry(dev_loop, &dev_list, node) {
		if (strcmp(dev_loop->devpath, devpath_real) == 0) {
			dbg("found in cache '%s'", dev_loop->devpath);
			return dev_loop;
		}
	}

	/* if we got a link, resolve it to the real device */
	strlcpy(path, sysfs_path, sizeof(path));
	strlcat(path, devpath_real, sizeof(path));
	if (lstat(path, &statbuf) != 0) {
		dbg("stat '%s' failed: %s", path, strerror(errno));
		return NULL;
	}
	if (S_ISLNK(statbuf.st_mode)) {
		if (sysfs_resolve_link(devpath_real, sizeof(devpath_real)) != 0)
			return NULL;

		/* now look for device in cache after path translation */
		list_for_each_entry(dev_loop, &dev_list, node) {
			if (strcmp(dev_loop->devpath, devpath_real) == 0) {
				dbg("found in cache '%s'", dev_loop->devpath);
				return dev_loop;
			}
		}
	}

	/* it is a new device */
	dbg("new uncached device '%s'", devpath_real);
	dev = malloc(sizeof(struct sysfs_device));
	if (dev == NULL)
		return NULL;
	memset(dev, 0x00, sizeof(struct sysfs_device));

	sysfs_device_set_values(dev, devpath_real, NULL, NULL);

	/* get subsystem name */
	strlcpy(link_path, sysfs_path, sizeof(link_path));
	strlcat(link_path, dev->devpath, sizeof(link_path));
	strlcat(link_path, "/subsystem", sizeof(link_path));
	len = readlink(link_path, link_target, sizeof(link_target) - 1);
	if (len > 0) {
		/* get subsystem from "subsystem" link */
		link_target[len] = '\0';
		dbg("subsystem link '%s' points to '%s'", link_path, link_target);
		pos = strrchr(link_target, '/');
		if (pos != NULL)
			strlcpy(dev->subsystem, &pos[1], sizeof(dev->subsystem));
	} else if (strstr(dev->devpath, "/drivers/") != NULL) {
		strlcpy(dev->subsystem, "drivers", sizeof(dev->subsystem));
	} else if (strncmp(dev->devpath, "/module/", 8) == 0) {
		strlcpy(dev->subsystem, "module", sizeof(dev->subsystem));
	} else if (strncmp(dev->devpath, "/subsystem/", 11) == 0) {
		pos = strrchr(dev->devpath, '/');
		if (pos == &dev->devpath[10])
			strlcpy(dev->subsystem, "subsystem", sizeof(dev->subsystem));
	} else if (strncmp(dev->devpath, "/class/", 7) == 0) {
		pos = strrchr(dev->devpath, '/');
		if (pos == &dev->devpath[6])
			strlcpy(dev->subsystem, "subsystem", sizeof(dev->subsystem));
	} else if (strncmp(dev->devpath, "/bus/", 5) == 0) {
		pos = strrchr(dev->devpath, '/');
		if (pos == &dev->devpath[4])
			strlcpy(dev->subsystem, "subsystem", sizeof(dev->subsystem));
	}

	/* get driver name */
	strlcpy(link_path, sysfs_path, sizeof(link_path));
	strlcat(link_path, dev->devpath, sizeof(link_path));
	strlcat(link_path, "/driver", sizeof(link_path));
	len = readlink(link_path, link_target, sizeof(link_target) - 1);
	if (len > 0) {
		link_target[len] = '\0';
		dbg("driver link '%s' points to '%s'", link_path, link_target);
		pos = strrchr(link_target, '/');
		if (pos != NULL)
			strlcpy(dev->driver, &pos[1], sizeof(dev->driver));
	}

	dbg("add to cache 'devpath=%s', subsystem='%s', driver='%s'", dev->devpath, dev->subsystem, dev->driver);
	list_add(&dev->node, &dev_list);

	return dev;
}

struct sysfs_device *sysfs_device_get_parent(struct sysfs_device *dev)
{
	char parent_devpath[PATH_SIZE];
	char *pos;

	dbg("open '%s'", dev->devpath);

	/* look if we already know the parent */
	if (dev->parent != NULL)
		return dev->parent;

	strlcpy(parent_devpath, dev->devpath, sizeof(parent_devpath));
	dbg("'%s'", parent_devpath);

	/* strip last element */
	pos = strrchr(parent_devpath, '/');
	if (pos == NULL || pos == parent_devpath)
		return NULL;
	pos[0] = '\0';

	if (strncmp(parent_devpath, "/class", 6) == 0) {
		pos = strrchr(parent_devpath, '/');
		if (pos == &parent_devpath[6] || pos == parent_devpath) {
			dbg("/class top level, look for device link");
			goto device_link;
		}
	}
	if (strcmp(parent_devpath, "/block") == 0) {
		dbg("/block top level, look for device link");
		goto device_link;
	}

	/* are we at the top level? */
	pos = strrchr(parent_devpath, '/');
	if (pos == NULL || pos == parent_devpath)
		return NULL;

	/* get parent and remember it */
	dev->parent = sysfs_device_get(parent_devpath);
	return dev->parent;

device_link:
	strlcpy(parent_devpath, dev->devpath, sizeof(parent_devpath));
	strlcat(parent_devpath, "/device", sizeof(parent_devpath));
	if (sysfs_resolve_link(parent_devpath, sizeof(parent_devpath)) != 0)
		return NULL;

	/* get parent and remember it */
	dev->parent = sysfs_device_get(parent_devpath);
	return dev->parent;
}

struct sysfs_device *sysfs_device_get_parent_with_subsystem(struct sysfs_device *dev, const char *subsystem)
{
	struct sysfs_device *dev_parent;

	dev_parent = sysfs_device_get_parent(dev);
	while (dev_parent != NULL) {
		if (strcmp(dev_parent->subsystem, subsystem) == 0)
			return dev_parent;
		dev_parent = sysfs_device_get_parent(dev_parent);
	}
	return NULL;
}

char *sysfs_attr_get_value(const char *devpath, const char *attr_name)
{
	char path_full[PATH_SIZE];
	char value[NAME_SIZE] = { '\0', };
	struct stat statbuf;
	int fd;
	ssize_t size;
	size_t sysfs_len;

	dbg("open '%s'/'%s'", devpath, attr_name);
	sysfs_len = strlcpy(path_full, sysfs_path, sizeof(path_full));
	if(sysfs_len >= sizeof(path_full))
		sysfs_len = sizeof(path_full) - 1;
	strlcat(path_full, devpath, sizeof(path_full));
	strlcat(path_full, "/", sizeof(path_full));
	strlcat(path_full, attr_name, sizeof(path_full));

	if (lstat(path_full, &statbuf) != 0) {
		dbg("stat '%s' failed: %s", path_full, strerror(errno));
		goto out;
	}

	if (S_ISLNK(statbuf.st_mode)) {
		/* links return the last element of the target path */
		char link_target[PATH_SIZE];
		int len;
		const char *pos;

		len = readlink(path_full, link_target, sizeof(link_target) - 1);
		if (len > 0) {
			link_target[len] = '\0';
			pos = strrchr(link_target, '/');
			if (pos != NULL) {
				dbg("cache '%s' with link value '%s'", path_full, value);
				strlcpy(value, &pos[1], NAME_SIZE);
			}
		}
		goto out;
	}

	/* skip directories */
	if (S_ISDIR(statbuf.st_mode))
		goto out;

	/* skip non-readable files */
	if ((statbuf.st_mode & S_IRUSR) == 0)
		goto out;

	/* read attribute value */
	fd = open(path_full, O_RDONLY);
	if (fd < 0) {
		dbg("attribute '%s' can not be opened", path_full);
		goto out;
	}
	size = read(fd, value, sizeof(value));
	close(fd);
	if (size < 0)
		goto out;
	if (size == sizeof(value))
		goto out;

	/* got a valid value, store and return it */
	value[size] = '\0';
	remove_trailing_chars(value, '\n');

out:
	if (value[0] == '\0')
		return NULL;
	return strdup(value);
}

int sysfs_lookup_devpath_by_subsys_id(char *devpath_full, size_t len, const char *subsystem, const char *id)
{
	size_t sysfs_len;
	char path_full[PATH_SIZE];
	char *path;
	struct stat statbuf;

	sysfs_len = strlcpy(path_full, sysfs_path, sizeof(path_full));
	path = &path_full[sysfs_len];

	if (strcmp(subsystem, "subsystem") == 0) {
		strlcpy(path, "/subsystem/", sizeof(path_full) - sysfs_len);
		strlcat(path, id, sizeof(path_full) - sysfs_len);
		if (stat(path_full, &statbuf) == 0)
			goto found;

		strlcpy(path, "/bus/", sizeof(path_full) - sysfs_len);
		strlcat(path, id, sizeof(path_full) - sysfs_len);
		if (stat(path_full, &statbuf) == 0)
			goto found;
		goto out;

		strlcpy(path, "/class/", sizeof(path_full) - sysfs_len);
		strlcat(path, id, sizeof(path_full) - sysfs_len);
		if (stat(path_full, &statbuf) == 0)
			goto found;
	}

	if (strcmp(subsystem, "module") == 0) {
		strlcpy(path, "/module/", sizeof(path_full) - sysfs_len);
		strlcat(path, id, sizeof(path_full) - sysfs_len);
		if (stat(path_full, &statbuf) == 0)
			goto found;
		goto out;
	}

	if (strcmp(subsystem, "drivers") == 0) {
		char subsys[NAME_SIZE];
		char *driver;

		strlcpy(subsys, id, sizeof(subsys));
		driver = strchr(subsys, ':');
		if (driver != NULL) {
			driver[0] = '\0';
			driver = &driver[1];
			strlcpy(path, "/subsystem/", sizeof(path_full) - sysfs_len);
			strlcat(path, subsys, sizeof(path_full) - sysfs_len);
			strlcat(path, "/drivers/", sizeof(path_full) - sysfs_len);
			strlcat(path, driver, sizeof(path_full) - sysfs_len);
			if (stat(path_full, &statbuf) == 0)
				goto found;

			strlcpy(path, "/bus/", sizeof(path_full) - sysfs_len);
			strlcat(path, subsys, sizeof(path_full) - sysfs_len);
			strlcat(path, "/drivers/", sizeof(path_full) - sysfs_len);
			strlcat(path, driver, sizeof(path_full) - sysfs_len);
			if (stat(path_full, &statbuf) == 0)
				goto found;
		}
		goto out;
	}

	strlcpy(path, "/subsystem/", sizeof(path_full) - sysfs_len);
	strlcat(path, subsystem, sizeof(path_full) - sysfs_len);
	strlcat(path, "/devices/", sizeof(path_full) - sysfs_len);
	strlcat(path, id, sizeof(path_full) - sysfs_len);
	if (stat(path_full, &statbuf) == 0)
		goto found;

	strlcpy(path, "/bus/", sizeof(path_full) - sysfs_len);
	strlcat(path, subsystem, sizeof(path_full) - sysfs_len);
	strlcat(path, "/devices/", sizeof(path_full) - sysfs_len);
	strlcat(path, id, sizeof(path_full) - sysfs_len);
	if (stat(path_full, &statbuf) == 0)
		goto found;

	strlcpy(path, "/class/", sizeof(path_full) - sysfs_len);
	strlcat(path, subsystem, sizeof(path_full) - sysfs_len);
	strlcat(path, "/", sizeof(path_full) - sysfs_len);
	strlcat(path, id, sizeof(path_full) - sysfs_len);
	if (stat(path_full, &statbuf) == 0)
		goto found;

	strlcpy(path, "/firmware/", sizeof(path_full) - sysfs_len);
	strlcat(path, subsystem, sizeof(path_full) - sysfs_len);
	strlcat(path, "/", sizeof(path_full) - sysfs_len);
	strlcat(path, id, sizeof(path_full) - sysfs_len);
	if (stat(path_full, &statbuf) == 0)
		goto found;

out:
	return 0;
found:
	if (S_ISLNK(statbuf.st_mode))
		sysfs_resolve_link(path, sizeof(path_full) - sysfs_len);
	strlcpy(devpath_full, path, len);
	return 1;
}


char *sysfs_get_value(const char *id, char *subsys, char *param)
{
	char devpath[PATH_SIZE];
	char *sysfs_value;

	if (!sysfs_lookup_devpath_by_subsys_id(devpath, sizeof(devpath),
					       subsys, id)) {
		log_debug(3, "Could not lookup devpath for %s %s",
			  subsys, id);
		return NULL;
	}

	sysfs_value = sysfs_attr_get_value(devpath, param);
	if (!sysfs_value) {
		log_debug(3, "Could not read attr %s on path %s",
			  param, devpath);
		return NULL;
	}

	if (!strncmp(sysfs_value, "<NULL>", 6) ||
	    !strncmp(sysfs_value, "(null)", 6)) {
		free(sysfs_value);
		return NULL;
	}

	return sysfs_value;
}

int sysfs_get_uint(char *id, char *subsys, char *param,
		   unsigned int *value)
{
	char *sysfs_value;

	*value = -1;
	sysfs_value = sysfs_get_value(id, subsys, param);
	if (!sysfs_value)
		return EIO;

	errno = 0;
	*value = strtoul(sysfs_value, NULL, 0);
	free(sysfs_value);
	if (errno)
		return errno;
	return 0;
}

int sysfs_get_int(const char *id, char *subsys, char *param, int *value)
{
	char *sysfs_value;

	*value = -1;
	sysfs_value = sysfs_get_value(id, subsys, param);
	if (!sysfs_value)
		return EIO;

	*value = atoi(sysfs_value);
	free(sysfs_value);
	return 0;
}

int sysfs_get_str(char *id, char *subsys, char *param, char *value,
		  int value_size)
{
	char *sysfs_value;
	int len;

	value[0] = '\0';
	sysfs_value = sysfs_get_value(id, subsys, param);
	if (!sysfs_value)
		return EIO;
	if (!strlen(sysfs_value)) {
		free(sysfs_value);
		return EIO;
	}

	len = strlen(sysfs_value);
	if (len && (sysfs_value[len - 1] == '\n'))
		sysfs_value[len - 1] = '\0';
	strncpy(value, sysfs_value, value_size);
	value[value_size - 1] = '\0';
	free(sysfs_value);
	return 0;
}

int sysfs_get_uint64(char *id, char *subsys, char *param, uint64_t *value)
{
	char *sysfs_value;

	*value = -1;
	sysfs_value = sysfs_get_value(id, subsys, param);
	if (!sysfs_value)
		return EIO;

	if (sscanf(sysfs_value, "%" PRIu64 "\n", value) != 1) {
		free(sysfs_value);
		return EINVAL;
	}
	free(sysfs_value);
	return 0;
}

int sysfs_get_uint8(char *id, char *subsys, char *param,
		    uint8_t *value)
{
	char *sysfs_value;

	*value = -1;
	sysfs_value = sysfs_get_value(id, subsys, param);
	if (!sysfs_value)
		return EIO;

	*value = (uint8_t)atoi(sysfs_value);
	free(sysfs_value);
	return 0;
}

int sysfs_get_uint16(char *id, char *subsys, char *param,
		     uint16_t *value)
{
	char *sysfs_value;

	*value = -1;
	sysfs_value = sysfs_get_value(id, subsys, param);
	if (!sysfs_value)
		return EIO;

	*value = (uint16_t)atoi(sysfs_value);
	free(sysfs_value);
	return 0;
}

int sysfs_set_param(char *id, char *subsys, char *attr_name,
		    char *write_buf, ssize_t buf_size)
{
	struct stat statbuf;
	char devpath[PATH_SIZE];
	size_t sysfs_len;
	char path_full[PATH_SIZE];
	int rc = 0, fd;

	if (!sysfs_lookup_devpath_by_subsys_id(devpath, sizeof(devpath),
					       subsys, id)) {
		log_debug(3, "Could not lookup devpath for %s %s",
			  subsys, id);
		return EIO;
	}

	sysfs_len = strlcpy(path_full, sysfs_path, sizeof(path_full));
	if(sysfs_len >= sizeof(path_full))
		sysfs_len = sizeof(path_full) - 1;
	strlcat(path_full, devpath, sizeof(path_full));
	strlcat(path_full, "/", sizeof(path_full));
	strlcat(path_full, attr_name, sizeof(path_full));

	if (lstat(path_full, &statbuf)) {
		log_debug(3, "Could not stat %s", path_full);
		return errno;
	}

	if ((statbuf.st_mode & S_IWUSR) == 0) {
		log_error("Could not write to %s. Invalid permissions.",
			  path_full);
		return EACCES;
	}

	fd = open(path_full, O_WRONLY);
	if (fd < 0) {
		log_error("Could not open %s err %d", path_full, errno);
		return errno;
	}

	if (write(fd, write_buf, buf_size) == -1)
		rc = errno;
	close(fd);
	return rc;
}

char *sysfs_get_uevent_field(const char *path, const char *field)
{
	char *uevent_path = NULL;
	FILE *f = NULL;
	char *line, buffer[1024];
	char *ff, *d;
	char *out = NULL;

	uevent_path = calloc(1, PATH_MAX);
	if (!uevent_path)
		return NULL;
	snprintf(uevent_path, PATH_MAX, "%s/uevent", path);

	f = fopen(uevent_path, "r");
	if (!f)
		goto out;
	while ((line = fgets(buffer, sizeof (buffer), f))) {
		ff = strtok(line, "=");
		d = strtok(NULL, "\n");
		if (strcmp(ff, field))
			continue;
		out = strdup(d);
		break;
	}
	fclose(f);
out:
	free(uevent_path);
	return out;
}

char *sysfs_get_uevent_devtype(const char *path)
{
	return sysfs_get_uevent_field(path, "DEVTYPE");
}

char *sysfs_get_uevent_devname(const char *path)
{
	return sysfs_get_uevent_field(path, "DEVNAME");
}
