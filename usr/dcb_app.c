/*******************************************************************************

  DCB application support
  Copyright(c) 2007-2010 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  e1000-eedc Mailing List <e1000-eedc@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <asm/errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "dcbnl.h"
#include "dcb_app.h"
#include "sysfs.h"

#define NLA_DATA(nla)        ((void *)((char*)(nla) + NLA_HDRLEN))

/* Maximum size of response requested or message sent */
#define MAX_MSG_SIZE    1024

static struct nlmsghdr *start_dcbmsg(__u16 msg_type, __u8 arg)
{
	struct nlmsghdr *nlh;
	struct dcbmsg *d;

	nlh = malloc(MAX_MSG_SIZE);
	if (!nlh)
		return NULL;
	memset(nlh, 0, MAX_MSG_SIZE);
	nlh->nlmsg_type = msg_type;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 0;
	nlh->nlmsg_pid = getpid();
	if (msg_type != RTM_GETDCB) {
		free(nlh);
		return NULL;
	}

	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct dcbmsg));
	d = NLMSG_DATA(nlh);
	d->cmd = arg;
	d->dcb_family = AF_UNSPEC;
	d->dcb_pad = 0;

	return nlh;
}

static struct rtattr *add_rta(struct nlmsghdr *nlh, __u16 rta_type,
                              void *attr, __u16 rta_len)
{
	struct rtattr *rta;

	rta = (struct rtattr *)((char *)nlh + nlh->nlmsg_len);
	rta->rta_type = rta_type;
	rta->rta_len = rta_len + NLA_HDRLEN;
	if (attr)
		memcpy(NLA_DATA(rta), attr, rta_len);
	nlh->nlmsg_len += NLMSG_ALIGN(rta->rta_len);

	return rta;
}

static int dcbnl_send_msg(int nl_sd, struct nlmsghdr *nlh)
{
	struct sockaddr_nl nladdr;
	void *buf = nlh;
	int r, len = nlh->nlmsg_len;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	do {
		r = sendto(nl_sd, buf, len, 0, (struct sockaddr *)&nladdr,
			sizeof(nladdr));
	} while (r < 0 && errno == EINTR);

	if (r < 0)
		return 1;

	return 0;
}

static struct nlmsghdr *dcbnl_get_msg(int nl_sd)
{
	struct nlmsghdr *nlh;
	int len;

	nlh = malloc(MAX_MSG_SIZE);
	if (!nlh)
		return NULL;
	memset(nlh, 0, MAX_MSG_SIZE);

	len = recv(nl_sd, (void *)nlh, MAX_MSG_SIZE, 0);

	if (len < 0 || nlh->nlmsg_type == NLMSG_ERROR ||
	    !NLMSG_OK(nlh, (unsigned int)len)) {
		free(nlh);
		return NULL;
	}

	return nlh;
}

static int get_app_cfg(const char *ifname, __u8 req_idtype, __u16 req_id)
{
	struct nlmsghdr *nlh;
	struct dcbmsg *d;
	struct rtattr *rta_parent, *rta_child;
	int rval = 0;
	int nl_sd;
	unsigned int seq;
	__u8 idtype;
	__u16 id;

	nlh = start_dcbmsg(RTM_GETDCB, DCB_CMD_GAPP);
	if (!nlh)
		return -EIO;

	seq = nlh->nlmsg_seq;
	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);
	rta_parent = add_rta(nlh, DCB_ATTR_APP, NULL, 0);

	rta_child = add_rta(nlh, DCB_APP_ATTR_IDTYPE,
		(void *)&req_idtype, sizeof(__u8));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);

	rta_child = add_rta(nlh, DCB_APP_ATTR_ID,
		(void *)&req_id, sizeof(__u16));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);

	nl_sd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nl_sd < 0)
		return nl_sd;

	rval = dcbnl_send_msg(nl_sd, nlh);
	free(nlh);
	if (rval) {
		close(nl_sd);
		return -EIO;
	}

	nlh = dcbnl_get_msg(nl_sd);
	close(nl_sd);
	if (!nlh)
		return -EIO;

	d = (struct dcbmsg *)NLMSG_DATA(nlh);
	rta_parent = (struct rtattr *)(((char *)d) +
		NLMSG_ALIGN(sizeof(struct dcbmsg)));

	if (d->cmd != DCB_CMD_GAPP) {
		rval = -EIO;
		goto get_error;
	}
	if (rta_parent->rta_type != DCB_ATTR_APP) {
		rval = -EIO;
		goto get_error;
	}

	rta_child = NLA_DATA(rta_parent);
	rta_parent = (struct rtattr *)((char *)rta_parent +
	                               NLMSG_ALIGN(rta_parent->rta_len));

	idtype = *(__u8 *)NLA_DATA(rta_child);
	rta_child = (struct rtattr *)((char *)rta_child +
		             NLMSG_ALIGN(rta_child->rta_len));
	if (idtype != req_idtype) {
		rval = -EIO;
		goto get_error;
	}

	id = *(__u16 *)NLA_DATA(rta_child);
	rta_child = (struct rtattr *)((char *)rta_child +
		             NLMSG_ALIGN(rta_child->rta_len));
	if (id != req_id) {
		rval = -EIO;
		goto get_error;
	}

	rval = *(__u8 *)NLA_DATA(rta_child);
	rta_child = (struct rtattr *)((char *)rta_child +
		             NLMSG_ALIGN(rta_child->rta_len));

get_error:
	free(nlh);
	return rval;
}

static int get_link_ifname(const char *ifname, char *link_ifname)
{
	int ifindex;

	if (sysfs_get_int(ifname, "net", "iflink", &ifindex))
		return -EIO;

	if (!if_indextoname(ifindex, link_ifname))
		return -ENODEV;

	return 0;
}

int get_dcb_app_pri_by_port(const char *ifname, int port)
{
	char link_ifname[IFNAMSIZ];

	if (get_link_ifname(ifname, link_ifname))
		return 0;

	return get_app_cfg(link_ifname, DCB_APP_IDTYPE_PORTNUM, port);
}

int get_dcb_app_pri_by_ethtype(const char *ifname, int ethtype)
{
	char link_ifname[IFNAMSIZ];

	if (get_link_ifname(ifname, link_ifname))
		return 0;

	return get_app_cfg(link_ifname, DCB_APP_IDTYPE_ETHTYPE, ethtype);
}
