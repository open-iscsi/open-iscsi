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

#ifndef ISCSI_OBP_H_
#define ISCSI_OBP_H_

enum  ofw_dev_type {
	OFW_DT_NONE,
	OFW_DT_BLOCK,
	OFW_DT_NETWORK,
	OFW_DT_ISCSI,
};

enum obp_tftp_qual {
	OBP_QUAL_NONE,
	OBP_QUAL_BOOTP,
	OBP_QUAL_DHCPV6,
	OBP_QUAL_IPV6,
	OBP_QUAL_ISCSI,
	OBP_QUAL_PING,
	OBP_QUAL_COUNT,		/* Numnber of defined OBP qualifiers */
};

enum obp_param {
	/*
	 * Defined iscsi boot parameters.
	 */
	OBP_PARAM_NONE,
	OBP_PARAM_BLKSIZE,	/* default is 512 */
	OBP_PARAM_BOOTP_RETRIES, /* default 5 */
	OBP_PARAM_CHAPID,	/* target chap id */
	OBP_PARAM_CHAPPW,	/* target chap password */
	OBP_PARAM_CIADDR,	/* client (my) ip addr */
	OBP_PARAM_DHCP,		/* dhcp server address */
	OBP_PARAM_FILENAME,	/* boot filename */
	OBP_PARAM_GIADDR,	/* gateway addr */
	OBP_PARAM_ICHAPID,	/* initiator chapid */
	OBP_PARAM_ICHAPPW,	/* initiator chap password */
	OBP_PARAM_ILUN,		/* misnomer, really the target lun */
	OBP_PARAM_INAME,	/* NB: target iqn */
	OBP_PARAM_IPORT,	/* initiator port, defaults to 3260 */
	OBP_PARAM_ISID,		/* session id */
	OBP_PARAM_ISNS,		/* sns server address */
	OBP_PARAM_ITNAME,	/* NB: Initiator iqn */
	OBP_PARAM_SIADDR,	/* iscsi server ip address. */
	OBP_PARAM_SLP,		/* slp server address */
	OBP_PARAM_SUBNET_MASK,
	OBP_PARAM_TFTP_RETRIES,	/* default 5 */
	OBP_PARAM_TIMEOUT,	/* ping timeout period. */

	OBP_PARAM_COUNT,	/* number of defined OBP_PARAMs */
};

struct ofw_obp_param {
	unsigned char  len;	/* length of value string. */
	char	       val[1];	/* string value from the property */
};

struct ofw_dev {
	char *prop_path; /* where we found these properties. */
	enum ofw_dev_type type;	/* known type of boot device. */
	int qual_count;		/* count of qualifiers. */
	enum obp_tftp_qual quals[OBP_QUAL_COUNT];
	struct ofw_obp_param *param[OBP_PARAM_COUNT];
	int cfg_part;		/* boot partition number. */
	char *dev_path;		/* path to this ofw device. */
	unsigned char mac[6];	/* The binary mac address. */
};

const char *obp_qual_set(struct ofw_dev *ofwdev, const char *qual);
void add_obp_parm(struct ofw_dev *ofwdev, enum obp_param parm, const char *str);
void obp_parm_addr(struct ofw_dev *ofwdev, const char *parm, const char *addr);
void obp_parm_iqn(struct ofw_dev *ofwdev, const char *parm, const char *iqn);
void obp_parm_hexnum(struct ofw_dev *ofwdev, const char *parm,
		     const char *numstr);
void obp_parm_str(struct ofw_dev *ofwdev, const char *parm, const char *str);

#endif /* ISCSI_OBP_H_ */
