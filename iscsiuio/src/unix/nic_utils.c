/*
 * Copyright (c) 2009-2011, Broadcom Corporation
 * Copyright (c) 2014, QLogic Corporation
 *
 * Written by:  Benjamin Li  (benli@broadcom.com)
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Adam Dunkels.
 * 4. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * nic_util.c - shared NIC utility functions
 *
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "logger.h"
#include "nic.h"
#include "nic_id.h"
#include "nic_vlan.h"
#include "nic_utils.h"
#include "options.h"

#define PFX "nic_utils "

/******************************************************************************
 *  String constants
 *****************************************************************************/
static const char nic_uio_sysfs_name_tempate[] = "/sys/class/uio/uio%i/name";
static const char cnic_sysfs_uio_event_template[] =
	"/sys/class/uio/uio%d/event";
static const char base_uio_sysfs_name[] = "/sys/class/uio/";
static const char uio_name[] = "uio";

static const char uio_base_dir[] = "/dev/uio";
static const char uio_udev_path_template[] = "/dev/uio%hd";
static const char uio_uevent_path_template[] = "/sys/class/uio/uio%d/uevent";

static const char base_iscsi_host_name[] = "/sys/class/iscsi_host/";
static const char host_template[] = "host%d";
static const char iscsi_host_path_template[] = "/sys/class/iscsi_host/host%d";
static const char iscsi_host_path_netdev_template[] =
	"/sys/class/iscsi_host/host%d/netdev";
static const char cnic_uio_sysfs_resc_template[] =
	"/sys/class/uio/uio%i/device/resource%i";

/**
 *  manually_trigger_uio_event() - If the uio file node doesn't exist then
 *                                 try to retrigger udev to create the file
 *                                 node by touch the uevent file in sysfs
 *  @param nic - the nic to trigger on
 *  @param uio_minor - UIO the minor number to use
 *  @return 0 on success
 */
int manually_trigger_uio_event(nic_t *nic, int uio_minor)
{
	int fd;
	char uio_uevent_path[sizeof(uio_uevent_path_template) + 10];
	char enable_str[] = "online";
	int rc;
	size_t bytes_wrote;

	rc = sprintf(uio_uevent_path, uio_uevent_path_template, uio_minor);
	if (rc < 0) {
		LOG_ERR(PFX "%s: Could not build uio uevent path",
			nic->log_name);
		return -EIO;
	}

	LOG_DEBUG(PFX "%s: triggering UIO uevent path: %s",
		  nic->log_name, uio_uevent_path);

	fd = open(uio_uevent_path, O_WRONLY);
	if (fd == -1) {
		LOG_ERR(PFX "%s: Could not open uio uevent path: %s [%s]",
			nic->log_name, uio_uevent_path, strerror(errno));
		return -EIO;
	}

	bytes_wrote = write(fd, enable_str, sizeof(enable_str));
	if (bytes_wrote != sizeof(enable_str)) {
		LOG_ERR(PFX "%s: Could write to uio uevent path: %s [%s]",
			nic->log_name, uio_uevent_path, strerror(errno));
		rc = -EIO;
	} else
		rc = 0;

	close(fd);
	return rc;
}

static int wait_for_file_node_timed(nic_t *nic, char *filepath, int seconds)
{
	struct timeval start_time;
	struct timeval wait_time;
	struct timeval total_time;
	struct timespec sleep_req, sleep_rem;

	sleep_req.tv_sec = 0;
	sleep_req.tv_nsec = 250000000;

	wait_time.tv_sec = seconds;
	wait_time.tv_usec = 0;

	if (gettimeofday(&start_time, NULL)) {
		LOG_ERR(PFX "%s: Couldn't gettimeofday() during watch file: %s"
			"[%s]", nic->log_name, filepath, strerror(errno));
		return -EIO;
	}

	timeradd(&start_time, &wait_time, &total_time);

	while (1) {
		struct timeval current_time;
		struct stat file_stat;

		/*  Check if the file node exists */
		if (stat(filepath, &file_stat) == 0)
			return 0;

		if (gettimeofday(&current_time, NULL)) {
			LOG_ERR(PFX "%s: Couldn't get current time for "
				"watching file: %s [%s]",
				nic->log_name, filepath, strerror(errno));
			return -EIO;
		}

		/*  Timeout has excceded return -ETIME */
		if (timercmp(&total_time, &current_time, <)) {
			LOG_ERR(PFX "%s: timeout waiting %d secs for file: %s",
				nic->log_name, seconds, filepath);
			return -ETIME;
		}

		nanosleep(&sleep_req, &sleep_rem);
	}
}

/******************************************************************************
 *  Autodiscovery of iscsi_hosts
 *****************************************************************************/
static int filter_host_name(const struct dirent *entry)
{
	if ((memcmp(entry->d_name, "host", 4) == 0))
		return 1;
	else
		return 0;
}

int nic_discover_iscsi_hosts()
{
	struct dirent **files;
	int count;
	int i;
	int rc;

	count = scandir(base_iscsi_host_name, &files, filter_host_name,
			alphasort);

	switch (count) {
	case 0:
		/*  Currently there are no iSCSI hosts */
		rc = 0;
		break;

	case -1:
		LOG_WARN(PFX "Error when scanning path: %s[%s]",
			 base_iscsi_host_name, strerror(errno));
		rc = -EINVAL;
		break;

	default:
		/*  There are iSCSI hosts */
		pthread_mutex_lock(&nic_list_mutex);
		for (i = 0; i < count; i++) {
			int host_no;
			char *raw = NULL;
			uint32_t raw_size = 0;
			char temp_path[sizeof(iscsi_host_path_netdev_template) +
				       8];
			rc = sscanf(files[i]->d_name, host_template, &host_no);
			nic_t *nic;

			LOG_INFO(PFX "Found host[%d]: %s",
				 host_no, files[i]->d_name);

			/*  Build the path to determine netdev name */
			snprintf(temp_path, sizeof(temp_path),
				 iscsi_host_path_netdev_template, host_no);

			rc = capture_file(&raw, &raw_size, temp_path);
			if (rc != 0)
				continue;

			rc = from_host_no_find_associated_eth_device(host_no,
								     &nic);
			if (rc != 0) {
				/*  Normalize the string */
				if (raw[raw_size - 1] == '\n')
					raw[raw_size - 1] = '\0';

				nic = nic_init();
				if (nic == NULL) {
					LOG_ERR(PFX "Couldn't allocate "
						"space for NIC %s "
						"during scan", raw);

					rc = -ENOMEM;
					break;
				}

				strncpy(nic->eth_device_name, raw, raw_size);
				nic->config_device_name = nic->eth_device_name;
				nic->log_name = nic->eth_device_name;

				if (nic_fill_name(nic) != 0) {
					free(nic);
					free(raw);
					rc = -EIO;
					continue;
				}

				nic_add(nic);

				LOG_INFO(PFX "NIC not found creating an "
					 "instance for host_no: %d %s",
					 host_no, nic->eth_device_name);
			} else
				LOG_INFO(PFX "%s: NIC found host_no: %d",
					 nic->log_name, host_no);

			free(raw);
		}
		pthread_mutex_unlock(&nic_list_mutex);

		/*  Cleanup the scandir() call */
		for (i = 0; i < count; i++)
			free(files[i]);
		free(files);

		rc = 0;
		break;
	}

	return rc;
}

/******************************************************************************
 *  Enable/Disable Multicast on physical interface
 *****************************************************************************/
static int nic_util_enable_disable_multicast(nic_t *nic, uint32_t cmd)
{
	int rc = 0;
	struct uip_eth_addr multicast_addr;
	int fd;
	struct ifreq ifr;

	/* adding ethernet multicast address for IPv6 */
	memcpy(&multicast_addr, nic->mac_addr, ETH_ALEN);
	multicast_addr.addr[0] = 0x33;
	multicast_addr.addr[1] = 0x33;
	multicast_addr.addr[2] = 0xff;

	/* Prepare the request */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, nic->eth_device_name,
		sizeof(nic->eth_device_name));
	memcpy(ifr.ifr_hwaddr.sa_data, multicast_addr.addr, ETH_ALEN);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		LOG_ERR(PFX "%s: Couldn't create socket to %s "
			"multicast address: %s",
			nic->log_name,
			cmd == SIOCADDMULTI ? "added" : "delete",
			strerror(errno));
		return errno;
	}

	rc = fcntl(fd, F_SETFL, O_NONBLOCK);
	if (rc != 0) {
		LOG_WARN("%s: Couldn't set to ethtool IOCTL to "
			 "non-blocking [%s]", nic->log_name, strerror(errno));
	}

	if (ioctl(fd, cmd, (char *)&ifr) != 0) {
		LOG_ERR("%s: Couldn't issue ioctl socket to %s "
			"multicast address: %s",
			nic->log_name,
			cmd == SIOCADDMULTI ? "add" : "delete",
			strerror(errno));
		rc = errno;
		goto error;
	}

	LOG_INFO(PFX "%s: %s address %02x:%02x:%02x:%02x:%02x:%02x "
		 "to multicast list",
		 nic->log_name,
		 cmd == SIOCADDMULTI ? "Added" : "Deleted",
		 multicast_addr.addr[0], multicast_addr.addr[1],
		 multicast_addr.addr[2], multicast_addr.addr[3],
		 multicast_addr.addr[4], multicast_addr.addr[5]);

	if (cmd == SIOCADDMULTI)
		nic->flags |= NIC_ADDED_MULICAST;
	else
		nic->flags &= ~NIC_ADDED_MULICAST;

error:
	close(fd);

	return rc;
}

/**
 *  enable_multicast() - This fuction is used to enable
 *	the listening of multicast addresses for a given network interface
 *  @param nic - NIC device to enable multicast on
 *  @return 0 for success or <0 for failure
 */
int enable_multicast(nic_t *nic)
{
	return nic_util_enable_disable_multicast(nic, SIOCADDMULTI);
}

/**
 *  disable_multicast() - This fuction is used to disable
 *	the listening of multicast addresses for a given network interface
 *  @param dev - NIC  device to disable multicast on
 *  @return 0 for success or <0 for failure
 */
int disable_multicast(nic_t *nic)
{
	return nic_util_enable_disable_multicast(nic, SIOCDELMULTI);
}

/*******************************************************************************
 * Finding associated UIO/physical network interfaces
 ******************************************************************************/
static int filter_net_name(const struct dirent *entry)
{
	if ((memcmp(entry->d_name, "net:", 4) == 0))
		return 1;
	else
		return 0;
}

static char *extract_net_name(struct dirent **files)
{
	return strstr(files[0]->d_name, ":");
}

static int filter_dot_out(const struct dirent *entry)
{
	if ((memcmp(entry->d_name, ".", 1) == 0))
		return 0;
	else
		return 1;
}

static char *extract_none(struct dirent **files)
{
	return files[0]->d_name;
}

/**
 *  from_host_no_find_nic() - Given the host number
 *      this function will try to find the assoicated nic interface
 *  Must be called with nic_list_mutex lock
 *  @param host_no - minor number of the UIO device
 *  @param nic - pointer to the NIC will set if successful
 *  @return 0 on success, <0 on error
 */
int from_host_no_find_associated_eth_device(int host_no, nic_t **nic)
{
	nic_t *current_nic = nic_list;
	char *raw = NULL, *raw_tmp;
	uint32_t raw_size = 0;

	char temp_path[sizeof(iscsi_host_path_netdev_template) + 8];
	int rc = -EIO;

	/*  Build the path to determine uio name */
	snprintf(temp_path, sizeof(temp_path),
		 iscsi_host_path_netdev_template, host_no);

	rc = capture_file(&raw, &raw_size, temp_path);
	if (rc != 0)
		goto error;

	/* sanitize name string by replacing newline with null termination */
	raw_tmp = raw;
	while (*raw_tmp != '\n' && raw_size--)
		raw_tmp++;
	*raw_tmp = '\0';

	rc = -EIO;

	current_nic = nic_list;
	while (current_nic != NULL) {
		if (strcmp(raw, current_nic->eth_device_name) == 0) {
			*nic = current_nic;
			rc = 0;
			break;
		}

		current_nic = current_nic->next;
	}

	free(raw);

error:
	return rc;
}

/*******************************************************************************
 *  NIC packet handling functions
 ******************************************************************************/
/**
 *  from_uio_find_associated_eth_device() - Given the uio minor number
 *      this function will try to find the assoicated phyisical network
 *      interface
 *  @param uio_minor - minor number of the UIO device
 *  @param name - char buffer which will be filled if successful
 *  @param name_size - size of the name buffer
 *  @return >0 minor number <0 an error
 */
static int from_uio_find_associated_eth_device(nic_t *nic,
					       int uio_minor,
					       char *name, size_t name_size)
{
	char *path;
	int rc;
	int count;
	struct dirent **files;
	char *parsed_name;
	int i;
	int path_iterator;
	char *search_paths[] = { "/sys/class/uio/uio%i/device/",
		"/sys/class/uio/uio%i/device/net"
	};
	int path_to[] = { 5, 1 };
	int (*search_filters[]) (const struct dirent *) = {
	filter_net_name, filter_dot_out,};
	char *(*extract_name[]) (struct dirent **files) = {
	extract_net_name, extract_none,};
	int extract_name_offset[] = { 1, 0 };

	path = malloc(PATH_MAX);
	if (path == NULL) {
		LOG_ERR(PFX "Could not allocate memory for path");
		rc = -ENOMEM;
		goto error;
	}

	for (path_iterator = 0;
	     path_iterator < sizeof(search_paths) / sizeof(search_paths[0]);
	     path_iterator++) {
		/*  Build the path to determine uio name */
		rc = sprintf(path, search_paths[path_iterator], uio_minor);

		wait_for_file_node_timed(nic, path, path_to[path_iterator]);

		count = scandir(path, &files,
				search_filters[path_iterator], alphasort);

		switch (count) {
		case 1:
			parsed_name = (*extract_name[path_iterator]) (files);
			if (parsed_name == NULL) {
				LOG_WARN(PFX "Couldn't find delimiter in: %s",
					 files[0]->d_name);

				break;
			}

			strncpy(name,
				parsed_name +
				extract_name_offset[path_iterator], name_size);

			free(files[0]);
			free(files);

			rc = 0;
			break;

		case 0:
			rc = -EINVAL;
			break;

		case -1:
			LOG_WARN(PFX "Error when scanning path: %s[%s]",
				 path, strerror(errno));
			rc = -EINVAL;
			break;

		default:
			LOG_WARN(PFX
				 "Too many entries when looking for device: %s",
				 path);

			/*  Cleanup the scandir() call */
			for (i = 0; i < count; i++)
				free(files[i]);
			free(files);

			rc = -EINVAL;
			break;
		}

		if (rc == 0)
			break;
	}

error:
	free(path);

	return rc;
}

/**
 *  filter_uio_name() - This is the callback used by scandir when looking for
 *                      the number of uio entries
 */
static int filter_uio_name(const struct dirent *entry)
{
	/*  Only return if the name of the file begins with 'uio' */
	if ((memcmp(entry->d_name, uio_name, sizeof(uio_name) - 1) == 0))
		return 1;
	else
		return 0;
}

/**
 * from_netdev_name_find_nic() - This is used to find the NIC device given
 *                               the netdev name
 * @param interface_name - name of the interface to search on
 * @param nic - pointer of the pointer to the NIC
 * @return 0 on success, <0 on failure
 */
int from_netdev_name_find_nic(char *interface_name, nic_t **nic)
{
	nic_t *current_nic;

	current_nic = nic_list;
	while (current_nic != NULL) {
		if (strcmp(interface_name, current_nic->eth_device_name) == 0)
			break;

		current_nic = current_nic->next;
	}

	if (current_nic == NULL)
		return -EINVAL;

	*nic = current_nic;
	return 0;
}

/**
 *  from_phys_name_find_assoicated_uio_device() - This is used to find the
 *						  uio minor
 *      when given a network interface name
 *  @param interface_name - network interface name to search for
 *  @return >0 minor number <0 an error
 */
int from_phys_name_find_assoicated_uio_device(nic_t *nic)
{
	char *path = NULL;
	int count;
	struct dirent **files;
	int i;
	int rc;
	char *interface_name = nic->config_device_name;

	if (interface_name == NULL)
		interface_name = nic->eth_device_name;

	/*  Wait at least 10 seconds for uio sysfs entries to appear */
	rc = wait_for_file_node_timed(nic, (char *)base_uio_sysfs_name, 10);
	if (rc != 0)
		return rc;

	count = scandir(base_uio_sysfs_name,
			&files, filter_uio_name, alphasort);

	switch (count) {
	case 0:
		LOG_WARN(PFX "Couldn't find %s to determine uio minor",
			 interface_name);
		return -EINVAL;

	case -1:
		LOG_WARN(PFX "Error when scanning for %s in path: %s [%s]",
			 interface_name, base_uio_sysfs_name, strerror(errno));
		return -EINVAL;
	}

	path = malloc(PATH_MAX);
	if (path == NULL) {
		LOG_ERR(PFX "Could not allocate memory for path");
		return -ENOMEM;
	}

	/*  Run through the contents of the filtered files to see if the
	 *  network interface name matches that of the uio device */
	for (i = 0; i < count; i++) {
		int uio_minor;
		char eth_name[IFNAMSIZ];

		rc = sscanf(files[i]->d_name, "uio%d", &uio_minor);
		if (rc != 1) {
			LOG_WARN("Could not parse: %s", files[i]->d_name);
			continue;
		}

		rc = from_uio_find_associated_eth_device(nic,
							 uio_minor,
							 eth_name,
							 sizeof(eth_name));
		if (rc != 0) {
			LOG_WARN("uio minor: %d not valid [%D]", uio_minor, rc);
			continue;
		}

		if (strncmp(eth_name, interface_name, sizeof(eth_name)) == 0) {
			memcpy(nic->eth_device_name,
			       eth_name, sizeof(nic->eth_device_name));

			LOG_INFO(PFX "%s associated with uio%d",
				 nic->eth_device_name, uio_minor);

			rc = uio_minor;
			goto done;
		}
	}

	LOG_WARN("Could not find assoicate uio device with %s", interface_name);

	rc = -EINVAL;
done:
	if (path != NULL)
		free(path);

	for (i = 0; i < count; i++)
		free(files[i]);
	free(files);

	return rc;

}

/**
 *  nic_verify_uio_sysfs_name() - Using the name entry in sysfs it will try to
 *      match the NIC library name
 *  @param nic - The NIC hardware to check
 *
 */
int nic_verify_uio_sysfs_name(nic_t *nic)
{
	char *raw = NULL, *raw_tmp;
	uint32_t raw_size = 0;
	char temp_path[sizeof(nic_uio_sysfs_name_tempate) + 8];
	int rc = 0;
	nic_lib_handle_t *handle = NULL;
	size_t name_size;


	/*  Build the path to determine uio name */
	snprintf(temp_path, sizeof(temp_path),
		 nic_uio_sysfs_name_tempate, nic->uio_minor);

	rc = capture_file(&raw, &raw_size, temp_path);
	if (rc != 0)
		goto error;

	/* sanitize name string by replacing newline with null termination */
	raw_tmp = raw;
	while (*raw_tmp != '\n' && raw_size--)
		raw_tmp++;
	*raw_tmp = '\0';

	/*  If the nic library is not set then check if there is a library
	 *  which matches the uio sysfs name */
	if (nic->nic_library == NULL) {
		NIC_LIBRARY_EXIST_T exist;

		exist = does_nic_uio_name_exist(raw, &handle);
		if (exist == NIC_LIBRARY_DOESNT_EXIST) {
			LOG_ERR(PFX "%s: could not find library for uio name: %s",
				nic->log_name, raw);
			rc = -EINVAL;
			goto error;
		}

		/* fill the lib info */
		nic->nic_library = handle;
		nic->ops = handle->ops;
		(*nic->ops->lib_ops.get_library_name) (&nic->library_name,
						       &name_size);
	} else {
		/*  Get the uio sysfs name from the NIC library */
		(*nic->ops->lib_ops.get_uio_name) (&raw_tmp, &name_size);

		if (strncmp(raw, raw_tmp, name_size) != 0) {
			LOG_ERR(PFX "%s: uio names not equal: "
				"expecting %s got %s from %s",
				nic->log_name, raw, raw_tmp, temp_path);
			rc = -EINVAL;
			goto error;
		}
	}

	LOG_INFO(PFX "%s: Verified uio name %s with library %s",
		 nic->log_name, raw, nic->library_name);

error:
	if (raw)
		free(raw);

	return rc;
}

/**
 * nic_fill_name() - This will initialize all the hardware resources underneath
 *                   a struct cnic_uio device
 * @param nic - The nic device to attach the hardware with
 * @return 0 on success, on failure a errno will be returned
 */
int nic_fill_name(nic_t *nic)
{
	int rc;

	if ((nic->config_device_name != NULL) &&
	    (memcmp(uio_base_dir, nic->config_device_name,
		    sizeof(uio_base_dir) - 1) == 0)) {
		uint16_t uio_minor;
		char eth_name[sizeof(nic->eth_device_name)];

		wait_for_file_node_timed(nic, nic->config_device_name, 5);

		/*  Determine the minor number for the UIO device */
		rc = sscanf(nic->config_device_name, uio_udev_path_template,
			    &uio_minor);
		if (rc != 1) {
			LOG_WARN(PFX "%s: Could not parse for minor number",
				 nic->uio_device_name);
			return -EINVAL;
		} else
			nic->uio_minor = uio_minor;

		nic->uio_device_name = nic->config_device_name;

		/*  Determine the assoicated physical network interface */
		rc = from_uio_find_associated_eth_device(nic,
							 nic->uio_minor,
							 eth_name,
							 sizeof(eth_name));
		if (rc != 0) {
			LOG_WARN(PFX "%s: Couldn't find associated eth device",
				 nic->uio_device_name);
		} else {
			memcpy(nic->eth_device_name,
			       eth_name, sizeof(eth_name));
		}

		LOG_INFO(PFX "%s: configured for uio device for %s",
			 nic->log_name, nic->uio_device_name);

	} else {
		LOG_INFO(PFX "looking for uio device for %s",
			 nic->config_device_name);

		rc = from_phys_name_find_assoicated_uio_device(nic);
		if (rc < 0) {
			LOG_ERR(PFX "Could not determine UIO name for %s",
				nic->config_device_name);

			return -rc;
		}

		nic->uio_minor = rc;

		if (nic->flags & NIC_UIO_NAME_MALLOC)
			free(nic->uio_device_name);

		nic->uio_device_name =
		    malloc(sizeof(uio_udev_path_template) + 8);
		if (nic->uio_device_name == NULL) {
			LOG_INFO(PFX "%s: Couldn't malloc space for uio name",
				 nic->log_name);
			return -ENOMEM;
		}

		snprintf(nic->uio_device_name,
			 sizeof(uio_udev_path_template) + 8,
			 uio_udev_path_template, nic->uio_minor);

		nic->flags |= NIC_UIO_NAME_MALLOC;
	}

	return 0;
}

void cnic_get_sysfs_pci_resource_path(nic_t *nic, int resc_no,
				      char *sys_path, size_t size)
{
	/*  Build the path to sysfs pci resource */
	snprintf(sys_path, size,
		 cnic_uio_sysfs_resc_template, nic->uio_minor, resc_no);

}

void prepare_library(nic_t *nic)
{
	int rc;
	NIC_LIBRARY_EXIST_T exist;
	nic_lib_handle_t *handle = NULL;

	nic_fill_name(nic);

	/* No assoicated library, we can skip it */
	if (nic->library_name != NULL) {
		/*  Check that we have the proper NIC library loaded */
		exist = does_nic_library_exist(nic->library_name, &handle);
		if (exist == NIC_LIBRARY_DOESNT_EXIST) {
			LOG_ERR(PFX "NIC library doesn't exists: %s",
				nic->library_name);
			goto error;
		} else if (handle && (nic->nic_library == handle) &&
			  (nic->ops == handle->ops)) {
			LOG_INFO("%s: Have NIC library '%s'",
				 nic->log_name, nic->library_name);
		}
	}

	/*  Verify the NIC library to use */
	rc = nic_verify_uio_sysfs_name(nic);
	if (rc != 0) {
		/*  Determine the NIC library to use based on the PCI Id */
		rc = find_set_nic_lib(nic);
		if (rc != 0) {
			LOG_ERR(PFX "%s: Couldn't find NIC library",
				nic->log_name);
			goto error;
		}

	}

	LOG_INFO("%s: found NIC with library '%s'",
		 nic->log_name, nic->library_name);
error:
	return;
}

void prepare_nic_thread(nic_t *nic)
{
	pthread_attr_t attr;
	int rc;

	pthread_mutex_lock(&nic->nic_mutex);
	if (nic->thread == INVALID_THREAD) {
		struct timespec ts;
		struct timeval tp;

		LOG_INFO(PFX "%s: spinning up thread for nic", nic->log_name);

		/*  Try to spin up the nic thread */
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		rc = pthread_create(&nic->thread, &attr, nic_loop, nic);
		if (rc != 0) {
			LOG_ERR(PFX "%s: Couldn't create thread for nic",
				nic->log_name);
			goto error;
		}

		/* Convert from timeval to timespec */
		rc = gettimeofday(&tp, NULL);
		ts.tv_sec = tp.tv_sec;
		ts.tv_nsec = tp.tv_usec * 1000;
		ts.tv_sec += 5;	/*  TODO: hardcoded wait for 5 seconds */

		/*  Wait for the nic loop thread to to running */
		rc = pthread_cond_timedwait(&nic->nic_loop_started_cond,
					    &nic->nic_mutex, &ts);

		LOG_INFO("Created nic thread: %s", nic->log_name);
	}

	pthread_mutex_unlock(&nic->nic_mutex);

error:
	return;
}

/*******************************************************************************
 * Functions used to enable/disable the NIC
 ******************************************************************************/
/**
 *  nic_enable() - Function used to enable the NIC
 *  @param nic - NIC to enable
 *  @return 0 on success, <0 on failure
 */
int nic_enable(nic_t *nic)
{
	if (nic->flags & NIC_GOING_DOWN) {
		LOG_INFO(PFX "%s: NIC device is going down, "
			 "flag: 0x%x state: 0x%x",
			 nic->log_name, nic->flags, nic->state);
		return -EINVAL;
	}
	if (nic->state == NIC_STOPPED) {
		struct timespec ts;
		struct timeval tp;
		int rc;

		pthread_mutex_lock(&nic->nic_mutex);
		/*  Signal the device to enable itself */
		pthread_cond_broadcast(&nic->enable_wait_cond);

		nic->flags &= ~NIC_DISABLED;
		nic->flags |= NIC_ENABLED;
		nic->flags |= NIC_ENABLED_PENDING;

		/* Convert from timeval to timespec */
		rc = gettimeofday(&tp, NULL);
		ts.tv_sec = tp.tv_sec;
		ts.tv_nsec = tp.tv_usec * 1000;
		ts.tv_sec += 100;

		/*  Wait for the device to be enabled */
		rc = pthread_cond_timedwait(&nic->enable_done_cond,
					    &nic->nic_mutex, &ts);
		if (rc == 0 && nic->flags & NIC_ENABLED) {
			LOG_DEBUG(PFX "%s: device enabled", nic->log_name);
		} else {
			nic->flags &= ~NIC_ENABLED;
			nic->flags |= NIC_DISABLED;
			nic->flags &= ~NIC_ENABLED_PENDING;

			LOG_ERR(PFX "%s: waiting to finish nic_enable err: %s",
				nic->log_name, strerror(rc));
		}
		pthread_mutex_unlock(&nic->nic_mutex);

		return rc;
	} else {
		LOG_INFO(PFX "%s: device already enabled: "
			 "flag: 0x%x state: 0x%x",
			 nic->log_name, nic->flags, nic->state);
		return -EALREADY;
	}
}

/**
 *  nic_disable() - Function used to disable the NIC
 *  @param nic - NIC to disble
 *  @return void
 */
void nic_disable(nic_t *nic, int going_down)
{
	if (nic->state == NIC_STARTED_RUNNING ||
	    nic->state == NIC_RUNNING) {
		struct timespec ts;
		struct timeval tp;
		int rc;

		/*  Wait for the device to be disabled */
		pthread_mutex_lock(&nic->nic_mutex);

		nic->flags &= ~NIC_ENABLED;
		nic->flags |= NIC_DISABLED;
		nic->flags &= ~NIC_STARTED_RUNNING;
		nic->state = NIC_STOPPED;

		if (going_down)
			nic->flags |= NIC_GOING_DOWN;

		/* Convert from timeval to timespec */
		rc = gettimeofday(&tp, NULL);
		if (rc) {
			LOG_ERR("gettimeofday failed, should never happen: %d\n", errno);
			pthread_mutex_unlock(&nic->nic_mutex);
			return;
		}

		ts.tv_sec = tp.tv_sec;
		ts.tv_nsec = tp.tv_usec * 1000;
		ts.tv_sec += 5;	/*  TODO: hardcoded wait for 5 seconds */

		/*  Wait for the device to be disabled */
		rc = pthread_cond_timedwait(&nic->disable_wait_cond,
					    &nic->nic_mutex, &ts);
		if (rc) {
			LOG_ERR("cond_timedwait failed, should never happen: %d\n", errno);
		}

		pthread_mutex_unlock(&nic->nic_mutex);

		LOG_DEBUG(PFX "%s: device disabled", nic->log_name);

	} else {
		LOG_WARN(PFX "%s: device already disabled: "
			 "flag: 0x%x state: 0x%x",
			 nic->log_name, nic->flags, nic->state);
	}
}

void nic_close_all()
{
	nic_t *nic;

	pthread_mutex_lock(&nic_list_mutex);

	/*  Start the shutdown process */
	nic = nic_list;
	while (nic != NULL) {
		pthread_mutex_lock(&nic->nic_mutex);
		nic_close(nic, 1, FREE_ALL_STRINGS);
		pthread_mutex_unlock(&nic->nic_mutex);

		nic = nic->next;
	}
	pthread_mutex_unlock(&nic_list_mutex);

	LOG_INFO(PFX "All NICs closed");
}

void nic_remove_all()
{
	nic_t *nic, *nic_next;

	pthread_mutex_lock(&nic_list_mutex);

	/*  Start the shutdown process */
	nic = nic_list;
	while (nic != NULL) {
		nic_next = nic->next;
		pthread_mutex_lock(&nic->nic_mutex);
		nic_close(nic, 1, FREE_ALL_STRINGS);
		pthread_mutex_unlock(&nic->nic_mutex);
		nic_remove(nic);
		nic = nic_next;
	}
	pthread_mutex_unlock(&nic_list_mutex);

	LOG_INFO(PFX "All NICs removed");
}


/******************************************************************************
 *  Routines to read initialized UIO values from sysfs
 *****************************************************************************/
/**
 * determine_initial_uio_events() - This utility function will
 *    determine the number of uio events that have occured on the
 *    given device.  This value is read from the UIO sysfs entry
 * @param dev - device to read from
 * @param num_of_event - number of UIO events
 * @return 0 is success, <0 failure
 */
int detemine_initial_uio_events(nic_t *nic, uint32_t *num_of_events)
{
	char *raw = NULL;
	uint32_t raw_size = 0;
	ssize_t elements_read;
	char temp_path[sizeof(cnic_sysfs_uio_event_template) + 8];
	int rc;

	/*  Capture RX buffer size */
	snprintf(temp_path, sizeof(temp_path),
		 cnic_sysfs_uio_event_template, nic->uio_minor);

	rc = capture_file(&raw, &raw_size, temp_path);
	if (rc != 0)
		goto error;

	elements_read = sscanf(raw, "%d", num_of_events);
	if (elements_read != 1) {
		LOG_ERR(PFX "%s: Couldn't parse UIO events size from %s",
			nic->log_name, temp_path);
		rc = -EIO;
		goto error;
	}

	rc = 0;
error:
	if (raw != NULL)
		free(raw);

	return rc;
}

/**
 *  nic_set_all_nic_iface_mac_to_parent() - This is a utility function used to
 *      intialize all the MAC addresses of the network interfaces for a given
 *      CNIC UIO device
 *  Call with nic mutex held
 *  @param dev - CNIC UIO device to initialize
 */
void nic_set_all_nic_iface_mac_to_parent(nic_t *nic)
{
	nic_interface_t *current, *vlan_current;

	current = nic->nic_iface;
	while (current != NULL) {
		/*  Set the initial MAC address of this interface to the parent
		 *  adapter */
		memcpy(current->mac_addr, nic->mac_addr, 6);

		vlan_current = current->vlan_next;
		while (vlan_current != NULL) {
			memcpy(vlan_current->mac_addr, nic->mac_addr, 6);
			vlan_current = vlan_current->vlan_next;
		}
		current = current->next;
	}
}

/*******************************************************************************
 *  NIC packet handling functions
 ******************************************************************************/
/**
 *  nic_alloc_packet_buffer() - Used to allocate a packet buffer used to
 *      send a TX packet later
 *  @param nic - nic device to send the packet on
 *  @param nic_iface - nic interface to send out on
 *  @param buf - pointer to the buffer to send
 *  @param buf_size - size in bytes of the buffer to send
 *  @return pointer to the allocated packet buffer
 *          NULL if memory could not be allocated
 */
static packet_t *nic_alloc_packet_buffer(nic_t *nic,
					 nic_interface_t *nic_iface,
					 uint8_t *buf, size_t buf_size)
{
	packet_t *pkt;

	pkt = malloc(sizeof(*pkt) + buf_size);
	if (pkt == NULL) {
		LOG_ERR(PFX "%s: Couldn't allocate space for packet buffer",
			nic->log_name);
		return NULL;
	}

	pkt->next = NULL;
	pkt->nic = nic;
	pkt->nic_iface = nic_iface;
	pkt->buf_size = buf_size;
	memcpy(pkt->buf, buf, buf_size);

	return pkt;
}

/**
 *  nic_queue_tx_packet() - Used to queue a TX packet buffer to send later
 *  @param nic - NIC device to send the packet on
 *  @param nic_iface - NIC interface to send on the packet on
 *  @param pkt - packet to queue
 *  @return 0 if successful or <0 if unsuccessful
 */
int nic_queue_tx_packet(nic_t *nic,
			nic_interface_t *nic_iface, packet_t *pkt)
{
	packet_t *queued_pkt;

	queued_pkt = nic_alloc_packet_buffer(nic, nic_iface,
					     pkt->buf, pkt->buf_size);
	if (queued_pkt == NULL) {
		LOG_ERR(PFX "%s: Couldn't allocate tx packet to queue",
			nic->log_name);
		return -ENOMEM;
	}

	if (nic->tx_packet_queue == NULL) {
		nic->tx_packet_queue = queued_pkt;
	} else {
		packet_t *current_pkt;

		current_pkt = nic->tx_packet_queue;
		while (current_pkt->next != NULL)
			current_pkt = current_pkt->next;

		current_pkt->next = queued_pkt;
	}

	LOG_DEBUG(PFX "%s: tx packet queued", nic->log_name);

	return 0;
}

/**
 *  nic_dequeue_tx_packet() - Used pop a TX packet buffer of the TX
 *  @param dev - cnic_uio device to send the packet on
 *  @param buf - pointer to the buffer to send
 *  @param buf_size - size in bytes of the buffer to send
 *  @return NULL if there are no more TX packet buffers to send
 *	    pointer to the packet buffer which is detached from the device
 */
packet_t *nic_dequeue_tx_packet(nic_t *nic)
{
	packet_t *pkt;

	pkt = nic->tx_packet_queue;

	/* There is a packet buffer to send, time to detach it from the
	 * cnic_uio device */
	if (pkt != NULL) {
		nic->tx_packet_queue = pkt->next;
		pkt->next = NULL;
	}

	return pkt;
}

void nic_fill_ethernet_header(nic_interface_t *nic_iface,
			      void *data,
			      void *src_addr, void *dest_addr,
			      int *pkt_size, void **start_addr,
			      uint16_t ether_type)
{
	struct ether_header *eth;
	uint16_t *vlan_hdr;

	eth = data;

	memcpy(eth->ether_shost, src_addr, ETH_ALEN);
	memcpy(eth->ether_dhost, dest_addr, ETH_ALEN);

	vlan_hdr = (uint16_t *) (eth + 1);
	eth->ether_type = htons(ether_type);

	*start_addr = vlan_hdr;
}

/*******************************************************************************
 *  NIC interface management utility functions
 ******************************************************************************/
/**
 *  nic_find_nic_iface() - This function is used to find an interface
 *                         from the NIC
 *  @param nic - NIC to look for network interfaces
 *  @param vlan_id - VLAN id to look for
 *  @param protocol - either AF_INET or AF_INET6
 *  @param iface_num - iface num to use if present
 *  @param request_type - IPV4/6 DHCP/STATIC
 *  @return nic_iface - if found network interface with the given VLAN ID
 *                      if not found a NULL is returned
 */
nic_interface_t *nic_find_nic_iface(nic_t *nic,
				    uint16_t protocol,
				    uint16_t vlan_id,
				    int iface_num,
				    int request_type)
{
	nic_interface_t *current = nic->nic_iface;
	nic_interface_t *current_vlan = NULL;

	while (current != NULL) {
		if (current->protocol != protocol)
			goto next;

		/* Check for iface_num first */
		if (iface_num != IFACE_NUM_INVALID) {
			if (current->iface_num == iface_num) {
				/* Exception is when iface_num == 0, need to
				   check for request_type also if !=
				   IP_CONFIG_OFF */
				if (!iface_num && request_type !=
				    IP_CONFIG_OFF) {
					if (current->request_type ==
					    request_type)
						goto found;
				} else {
					goto found;
				}
			}
		} else if (vlan_id == NO_VLAN) {
			/* Just return the top of the family */
			goto found;
		} else {
			if ((current->vlan_id == vlan_id) &&
			    ((request_type == IP_CONFIG_OFF) ||
			    (current->request_type == request_type)))
				goto found;
		}
		/* vlan_next loop */
		current_vlan = current->vlan_next;
		while (current_vlan != NULL) {
			if (iface_num != IFACE_NUM_INVALID) {
				if (current_vlan->iface_num == iface_num) {
					if (!iface_num && request_type !=
					    IP_CONFIG_OFF) {
						if (current_vlan->request_type
						    == request_type)
							goto vlan_found;
					} else {
						goto vlan_found;
					}
				}
			}
			if ((current_vlan->vlan_id == vlan_id) &&
			    ((request_type == IP_CONFIG_OFF) ||
			    (current_vlan->request_type == request_type)))
				goto vlan_found;

			current_vlan = current_vlan->vlan_next;
		}
next:
		current = current->next;
	}
vlan_found:
	current = current_vlan;
found:
	return current;
}

/* Called with nic mutex held */
void persist_all_nic_iface(nic_t *nic)
{
	nic_interface_t *current_vlan, *current;

	current = nic->nic_iface;
	while (current != NULL) {
		current->flags |= NIC_IFACE_PERSIST;
		current_vlan = current->vlan_next;
		while (current_vlan != NULL) {
			current_vlan->flags |= NIC_IFACE_PERSIST;
			current_vlan = current_vlan->vlan_next;
		}
		current = current->next;
	}
}

/* Sets the nic_iface to the front of the AF */
void set_nic_iface(nic_t *nic, nic_interface_t *nic_iface)
{
	nic_interface_t *current, *prev;
	nic_interface_t *current_vlan, *prev_vlan;

	prev = NULL;
	current = nic->nic_iface;
	while (current != NULL) {
		if (current->protocol != nic_iface->protocol)
			goto next;
		/* If its already on top of the list, exit */
		if (current == nic_iface)
			goto done;

		prev_vlan = current;
		current_vlan = current->vlan_next;

		while (current_vlan != NULL) {
			if (current_vlan == nic_iface) {
				/* Found inside the vlan list */
				/* For vlan == 0, place on top of
				   the AF list */
				prev_vlan->vlan_next =
						current_vlan->vlan_next;
				current_vlan->vlan_next = current;
				if (prev)
					prev->next = current_vlan;
				else
					nic->nic_iface = current_vlan;
				goto done;
			}
			prev_vlan = current_vlan;
			current_vlan = current_vlan->vlan_next;
		}
next:
		prev = current;
		current = current->next;
	}
done:
	return;
}

/*******************************************************************************
 *  Packet management utility functions
 ******************************************************************************/
/**
 *  get_next_packet_in_queue() - This function will return the next packet in
 *    the queue
 *  @param queue - the queue to pull the packet from
 *  @return the packet in the queue
 */
static packet_t *get_next_packet_in_queue(packet_t **queue)
{
	packet_t *pkt;

	if (*queue == NULL)
		return NULL;

	pkt = *queue;
	*queue = pkt->next;

	return pkt;
}

/**
 *  get_next_tx_packet() - This function will return the next packet in
 *    the TX queue
 *  @param nic - NIC to pull the TX packet from
 *  @return the packet in hte queue
 */
packet_t *get_next_tx_packet(nic_t *nic)
{
	return get_next_packet_in_queue(&nic->tx_packet_queue);
}

/**
 *  get_next_free_packet() - This function will return the next packet in
 *    the free queue
 *  @param nic - NIC to pull the RX packet from
 *  @return the packet in hte queue
 */
packet_t *get_next_free_packet(nic_t *nic)
{
	packet_t *pkt;
	pthread_mutex_lock(&nic->free_packet_queue_mutex);
	pkt = get_next_packet_in_queue(&nic->free_packet_queue);
	pthread_mutex_unlock(&nic->free_packet_queue_mutex);

	if (pkt != NULL)
		reset_packet(pkt);

	return pkt;
}

/**
 *  put_packet_in_queue() - This function will place the packet in the given
 *    queue
 *  @param pkt   - the packet to place
 *  @param queue - the queue to place the packet
 *  @return the packet in the queue
 */
static void put_packet_in_queue(packet_t *pkt, packet_t **queue)
{
	if (*queue == NULL)
		*queue = pkt;
	else {
		pkt->next = *queue;
		*queue = pkt;
	}
}

/**
 *  put_packet_in_tx_queue() - This function will place the packet in
 *    the TX queue
 *  @param pkt - packet to place
 *  @param nic - NIC to pull the TX packet from
 *  @return the packet in hte queue
 */
void put_packet_in_tx_queue(packet_t *pkt, nic_t *nic)
{
	return put_packet_in_queue(pkt, &nic->tx_packet_queue);
}

/**
 *  put_packet_in_free_queue() - This function will place the packet in
 *    the RX queue
 *  @param pkt - packet to place
 *  @param nic - NIC to pull the RX packet from
 *  @return the packet in hte queue
 */
void put_packet_in_free_queue(packet_t *pkt, nic_t *nic)
{
	pthread_mutex_lock(&nic->free_packet_queue_mutex);
	put_packet_in_queue(pkt, &nic->free_packet_queue);
	pthread_mutex_unlock(&nic->free_packet_queue_mutex);
}

uint32_t calculate_default_netmask(uint32_t ip_addr)
{
	uint32_t netmask;

	if (IN_CLASSA(ntohl(ip_addr)))
		netmask = htonl(IN_CLASSA_NET);
	else if (IN_CLASSB(ntohl(ip_addr)))
		netmask = htonl(IN_CLASSB_NET);
	else if (IN_CLASSC(ntohl(ip_addr)))
		netmask = htonl(IN_CLASSC_NET);
	else {
		LOG_ERR("Unable to guess netmask for address %x\n", &ip_addr);
		return -1;
	}

	return netmask;
}

void dump_packet_to_log(struct nic_interface *iface,
			uint8_t *buf, uint16_t buf_len)
{

	FILE *file;
	char str[80];
	int i, count;

	file = fmemopen(str, sizeof(str), "w+");
	if (file == NULL) {
		LOG_ERR(PFX "Could not create logging file stream for packet "
			"logging: [%d: %s]", errno, strerror(errno));
		return;
	}

	LOG_PACKET(PFX "%s: Start packet dump len: %d", iface->parent->log_name,
		   buf_len);

	for (i = 0; i < buf_len; i++) {
		rewind(file);
		fprintf(file, "%03x:  ", i);

		for (count = 0; (count < 8) && i < buf_len; count++, i++)
			fprintf(file, " %02x", buf[i]);
		fflush(file);

		LOG_PACKET(PFX "%s: %s", iface->parent->log_name, str);
	}

	LOG_PACKET(PFX "%s: end packet dump", iface->parent->log_name);

	fclose(file);
}

/*******************************************************************************
 *  File Management
 ******************************************************************************/
 /**
  * determine_file_size_read() - when fstat doesn't work on filepath
  *     within the /proc filesytem, we need to read/count the size of the file
  *     until we hit a EOF
  * @parm filepath - path of the file in which to determine the filesize in
  *                  bytes
  * @return file size in bytes, <0 on failure
  */
int determine_file_size_read(const char *filepath)
{
	size_t total_size = 0;
	ssize_t size = 1;
	int fd;
	char buf[1024];

	fd = open(filepath, O_RDONLY);
	if (fd == -1) {
		LOG_ERR("Could not open file: %s [%s]",
			filepath, strerror(errno));
		return -1;
	}

	while (size > 0) {
		size = read(fd, buf, sizeof(buf));

		switch (size) {
		case 0:
			break;
		case -1:
			LOG_ERR("Error reading file: %s [%s]",
				filepath, strerror(errno));
			total_size = -1;
			break;
		default:
			total_size += size;
			break;
		}
	}

	close(fd);

	return total_size;
}

/**
 *  capture_file() - Used to capture a file into a buffer
 *  @param raw - This pointer will be set to the buffer which will hold the
 *         file contents
 *  @param raw_size - This is the size of the buffer returned
 *  @param path - The file path to capture the data from
 *  @return 0 is returned on success, <0 is returned on failure
 */
int capture_file(char **raw, uint32_t *raw_size, const char *path)
{
	FILE *fp;
	size_t read_size;
	int rc = 0;
	int file_size;

	file_size = determine_file_size_read(path);
	if (file_size < 0) {
		LOG_ERR("Could not determine size %s", path);
		return -EIO;
	}

	fp = fopen(path, "r");
	if (fp == NULL) {
		LOG_ERR("Could not open path %s [%s]", path, strerror(errno));
		return -EIO;
	}

	*raw = malloc(file_size);
	if (*raw == NULL) {
		LOG_ERR("Could not malloc space for capture %s", path);
		rc = -ENOMEM;
		goto error;
	}

	read_size = fread(*raw, file_size, 1, fp);
	if (!read_size) {
		LOG_ERR("Could not read capture, path: %s len: %d [%s]",
			path, file_size, strerror(ferror(fp)));
		free(*raw);
		*raw = NULL;
		rc = errno;
	} else
		*raw_size = file_size;

error:
	fclose(fp);

	LOG_INFO("Done capturing %s", path);

	return rc;
}
