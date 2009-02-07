/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 *
 * Copyright (C) IBM Corporation, 2006
 *
 * Authors:	Patrick Mansfield <patmans@us.ibm.com>
 * 		Mike Anderson	<andmike@us.ibm.com>
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "fwparam_ibft.h"
#include "fw_context.h"

char *progname = "fwparam_ibft";
int debug;
int dev_count;
char filename[FILENAMESZ];

const char nulls[16]; /* defaults to zero */

int
verify_hdr(char *name, struct ibft_hdr *hdr, int id, int version, int length)
{
#define VERIFY_HDR_FIELD(val) \
	if (hdr->val != val) { \
		fprintf(stderr, \
			"%s: error, %s structure expected %s %d but" \
			" got %d\n", \
			progname, name, #val, hdr->val, val); \
		return -1; \
	}

	if (debug > 1)
		fprintf(stderr, "%s: verifying %s header\n", __FUNCTION__,
			name);

	VERIFY_HDR_FIELD(id);
	VERIFY_HDR_FIELD(version);
	VERIFY_HDR_FIELD(length);

#undef VERIFY_HDR_FIELD
	return 0;
}

#define CHECK_HDR(ident, name) \
	verify_hdr(#name, &ident->hdr, id_##name, version_##name, \
		   sizeof(*ident))

/*
 * Format 8 byte scsi LUN. Just format 8 bytes of hex, we could also
 * format in the format as specified in rfc4173 (1-2-3-4, or 1-2), that is
 * a nice format for humans :)
 */
void
format_lun(char *buf, size_t size, uint8_t *lun)
{
	int i;

	for (i = 0; i < 8; i++)
		snprintf(buf++, size--, "%x", lun[i]);
}

void
dump_lun(char *prefix, char *id, uint8_t *lun)
{
	char buf[32];

	format_lun(buf, sizeof(buf), lun);

	if (prefix)
		printf("%s%s=%s\n", prefix, id, buf);
	else
		printf("%s=%s\n", id, buf);

}

void
dump_word(char *prefix, char *id, unsigned short value)
{
	if (prefix)
		printf("%s%s=%d\n", prefix, id, value);
	else
		printf("%s=%d\n", id, value);
}

void
dump_string(char *prefix, char *id, char *value, int len)
{
	if (len == 0)
		return;
	/*
	 * Not checking if the offset is non-zero, it is not even passed
	 * in, else we need to pass a start and offset rather than value.
	 */

	/*
	 * prints the string in "value" that has "len" characters (the
	 * printf "*" * means use the next argument as the length).
	 */
	if (prefix)
		printf("%s%s=%.*s\n", prefix, id, len, value);
	else
		printf("%s=%.*s\n", id, len, value);
}

void
format_ipaddr(char *buf, size_t size, uint8_t *ip)
{
	if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 &&
	    ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
	    ip[8] == 0 && ip[9] == 0 && ip[10] == 0xff && ip[11] == 0xff) {
		/*
		 * IPV4
		 */
		snprintf(buf, size, "%d.%d.%d.%d", ip[12], ip[13], ip[14], ip[15]);
	} else {
		/* XXX ... */
		fprintf(stderr, "%s: warning no IPV6 support.\n", progname);
		buf[0] = '\0';
		return;
	}

}

/*
 * Dump the 16 byte ipaddr, as IPV6 or IPV4.
 */
void
dump_ipaddr(char *prefix, char *id, uint8_t *ip)
{
	char buf[32];

	/*
	 * Assumes all zero means no IP address.
	 */
	if (!memcmp(ip, nulls, sizeof(nulls)))
		return;

	format_ipaddr(buf, sizeof(buf), ip);

	if (prefix)
		printf("%s%s=%s\n", prefix, id, buf);
	else
		printf("%s=%s\n", id, buf);

}

/*
 * Dump the 8 byte mac address
 */
void
dump_mac(char *prefix, char *id, uint8_t *mac)
{
	int i;

	if (prefix)
		printf("%s%s=", prefix, id);
	else
		printf("%s=", id);

	for (i = 0; i < 5; i++)
		printf("%02x:", mac[i]);
	printf("%02x\n", mac[i]);
}


void
dump_initiator_prefix(void *ibft_loc, struct ibft_initiator *initiator, char *prefix)
{
	if (!initiator)
		return;
	/*
	 * Not all fields are (or were) supported by open-iscsi. Plus,
	 * some of these are for discovery.
	 */
	dump_ipaddr(prefix, "ISNS", initiator->isns_server);
	dump_ipaddr(prefix, "SLP", initiator->slp_server);
	dump_ipaddr(prefix, "PRIMARY_RADIUS_SERVER", initiator->pri_radius_server);
	dump_ipaddr(prefix, "SECONDARY_RADIUS_SERVER", initiator->sec_radius_server);
	dump_string(prefix, "NAME", ibft_loc +
		    initiator->initiator_name_off, initiator->initiator_name_len);
}

void
dump_nic_prefix(void *ibft_loc, struct ibft_nic *nic, char *prefix)
{

	if (!nic)
		return;

	dump_mac(prefix, "HWADDR", nic->mac);
	/*
	 * Assume dhcp if any non-zero portions of its address are set
	 * (again, undocumented).
	 */
	if (memcmp(nic->dhcp, nulls, sizeof(nic->dhcp))) {
		dump_ipaddr(prefix, "DHCP", nic->dhcp);
	} else {
		dump_ipaddr(prefix, "IPADDR", nic->ip_addr);
		/*
		 * XXX: Not sure how a mask "prefix" will be used in network
		 * bringup, this sounds less flexible than the normal
		 * masks used.
		 */
		printf("%s%s=%d\n", prefix, "MASK", nic->subnet_mask_prefix);
		dump_ipaddr(prefix, "GATEWAY", nic->gateway);
		dump_ipaddr(prefix, "DNSADDR1", nic->primary_dns);
		dump_ipaddr(prefix, "DNSADDR2", nic->secondary_dns);
	}

	dump_string(prefix, "HOSTNAME", ibft_loc + nic->hostname_off,
		    nic->hostname_len);
	/*
	 * XXX unknown vlan:
	 */
	dump_word(prefix, "VLAN", nic->vlan);
	/*
	 * XXX sort of unknown pci_bdf: 8 bits bus, 5 bits device, 3 bits
	 * function.
	 */
	if (prefix )
		printf("%s%s=%d:%d:%d\n", prefix, "PCI_BDF",
		       /* bus */ (nic->pci_bdf & 0xff00) >> 8,
		       /* device */ (nic->pci_bdf & 0xf8) >> 3,
		       /* function */ (nic->pci_bdf & 0x07));
	else
		printf("%s=%d:%d:%d\n", "PCI_BDF",
		       /* bus */ (nic->pci_bdf & 0xff00) >> 8,
		       /* device */ (nic->pci_bdf & 0xf8) >> 3,
		       /* function */ (nic->pci_bdf & 0x07));
}

void
dump_tgt_prefix(void *ibft_loc, struct ibft_tgt *tgt, char *prefix)
{

	if (!tgt)
		return;

	dump_ipaddr(prefix, "IPADDR", tgt->ip_addr);
	dump_word(prefix, "PORT", tgt->port);
	/*
	 * XXX there should at least be a "no LUN specified field", or
	 * have different location objects, so the setup can search for
	 * the appropriate LU (like mount by label, or use of the
	 * /dev/disk/by-id names, or ....
	 *
	 * Like:
	 * 	uint8_t lu_type; 0: nothing specified, 1: LUN, 2: misc
	 * 	name - OS can use any way it wants, would have embedded a
	 * 	"NAME=string", like "LABEL=myrootvolume", or
	 * 	"DEV_NAME=/dev/disk/by-id/scsi-198279562093043094003030903".
	 * 	union lu_value {
	 * 		uint8_t lun[8];
	 * 		uint8_t misc_name[64];
	 * 	};
	 *
	 * Maybe just add an extension header, and let the admin/user put
	 * strings like: "area:VALUE=string" into it?
	 */
	dump_lun(prefix, "LUN", tgt->lun);
	dump_string(prefix, "NAME", ibft_loc + tgt->tgt_name_off,
		    tgt->tgt_name_len);
	/*
	 * Note: don't dump the nic association, just let the IP address take
	 * care of the routing.
	 */
	/*
	 * Note: don't dump the chap "type", just the chap names and secrets
	 * if any are specified - they imply CHAP and reversed CHAP.
	 */
	dump_string(prefix, "CHAP_NAME", ibft_loc + tgt->chap_name_off,
		    tgt->chap_name_len);
	dump_string(prefix, "CHAP_PASSWORD", ibft_loc + tgt->chap_secret_off,
		    tgt->chap_secret_len);
	dump_string(prefix, "CHAP_NAME_IN", ibft_loc + tgt->rev_chap_name_off,
		    tgt->rev_chap_name_len);
	dump_string(prefix, "CHAP_PASSWORD_IN",
		    ibft_loc + tgt->rev_chap_secret_off,
		    tgt->rev_chap_secret_len);
}

/*
 * Read in and dump ASCII output for ibft starting at ibft_loc.
 */
int
dump_ibft(void *ibft_loc, struct boot_context *context)
{
	struct ibft_table_hdr *ibft_hdr = ibft_loc;
	struct ibft_control *control;
	struct ibft_initiator *initiator = NULL;
	struct ibft_nic *nic0 = NULL, *nic1 = NULL;
	struct ibft_tgt *tgt0 = NULL, *tgt1 = NULL;
	char ipbuf[32];

	control = ibft_loc + sizeof(*ibft_hdr);
	CHECK_HDR(control, control);

	/*
	 * The ibft is setup to return multiple pieces for each
	 * object (like multiple nic's or multiple targets), but it only
	 * maps 1 initiator, two targets, and two nics, follow that layout
	 * here (i.e. don't search for others).
	 *
	 * Also, unknown what to do for extensions piece, it is not
	 * documented.
	 */

	if (control->initiator_off) {
		initiator = ibft_loc + control->initiator_off;
		CHECK_HDR(initiator, initiator);
	}

	if (control->nic0_off) {
		nic0 = ibft_loc + control->nic0_off;
		CHECK_HDR(nic0, nic);
	}

	if (control->nic1_off) {
		nic1 = ibft_loc + control->nic1_off;
		CHECK_HDR(nic1, nic);
	}

	if (control->tgt0_off) {
		tgt0 = ibft_loc + control->tgt0_off;
		CHECK_HDR(tgt0, target);
	}

	if (control->tgt1_off) {
		tgt1 = ibft_loc + control->tgt1_off;
		CHECK_HDR(tgt1, target);
	}

	strlcpy(context->initiatorname,
		(char *)ibft_loc+initiator->initiator_name_off,
		initiator->initiator_name_len + 1);

	if (tgt0 && (tgt0->hdr.flags & INIT_FLAG_FW_SEL_BOOT)) {
		strlcpy((char *)context->targetname,
			(char *)(ibft_loc+tgt0->tgt_name_off),
			tgt0->tgt_name_len);
		format_ipaddr(ipbuf, sizeof(ipbuf),
			      tgt0->ip_addr);
		strlcpy((char *)context->target_ipaddr, ipbuf,
			sizeof(ipbuf));
		context->target_port = tgt0->port;
		strlcpy(context->chap_name,
			(char *)(ibft_loc + tgt0->chap_name_off),
			tgt0->chap_name_len);
		strlcpy(context->chap_password,
			(char*)(ibft_loc + tgt0->chap_secret_off),
			tgt0->chap_secret_len);
		strlcpy(context->chap_name_in,
			(char *)(ibft_loc + tgt0->rev_chap_name_off),
			tgt0->rev_chap_name_len);
		strlcpy(context->chap_password_in,
			(char *)(ibft_loc + tgt0->rev_chap_secret_off),
			tgt0->rev_chap_secret_len);
	} else if (tgt1 &&
		   (tgt1->hdr.flags & INIT_FLAG_FW_SEL_BOOT)) {
		strlcpy((char *)context->targetname,
			(char *)(ibft_loc+tgt1->tgt_name_off),
			tgt1->tgt_name_len);
		format_ipaddr(ipbuf, sizeof(ipbuf),
			      tgt1->ip_addr);
		strlcpy((char *)context->target_ipaddr,ipbuf,
			sizeof(ipbuf));
		context->target_port = tgt1->port;
		strlcpy(context->chap_name,
			(char *)(ibft_loc + tgt1->chap_name_off),
			tgt1->chap_name_len);
		strlcpy(context->chap_password,
			(char*)(ibft_loc + tgt1->chap_secret_off),
			tgt1->chap_secret_len);
		strlcpy(context->chap_name_in,
			(char *)(ibft_loc + tgt1->rev_chap_name_off),
			tgt1->rev_chap_name_len);
		strlcpy(context->chap_password_in,
			(char *)(ibft_loc + tgt1->rev_chap_secret_off),
			tgt1->rev_chap_secret_len);
	}

	return 0;
}

char *search_ibft(unsigned char *start, int length)
{
	unsigned char *cur_ptr;
	struct ibft_table_hdr *ibft_hdr;
	unsigned char check_sum;
	uint32_t i;

	cur_ptr = (unsigned char *)start;
	for (cur_ptr = (unsigned char *)start;
	     cur_ptr < (start + length);
	     cur_ptr++) {
		if (memcmp(cur_ptr, iBFTSTR,strlen(iBFTSTR)))
			continue;

		ibft_hdr = (struct ibft_table_hdr *)cur_ptr;
		/* Make sure it's correct version. */
		if (ibft_hdr->revision != iBFT_REV)
			continue;

		/* Make sure that length is valid. */
		if ((cur_ptr + ibft_hdr->length) <= (start + length)) {
			/* Let verify the checksum */
			for (i = 0, check_sum = 0; i < ibft_hdr->length; i++)
				check_sum += cur_ptr[i];

			if (check_sum == 0)
				return (char *)cur_ptr;
		}
	}
	return NULL;
}

int
fwparam_ibft(struct boot_context *context, const char *filepath)
{
	int fd, ret;
	char *filebuf, *ibft_loc;
	int start = 512 * 1024; /* 512k */
	int end_search = (1024 * 1024) - start; /* 512k */
	struct stat buf;

	if (filepath)
		strlcpy(filename, filepath, FILENAMESZ);
	else
		strlcpy(filename, X86_DEFAULT_FILENAME, FILENAMESZ);

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Could not open %s: %s (%d)\n",
			filename, strerror(errno), errno);
		return -1;
	}

	/* Find the size. */
	if (stat(filename, &buf)!=0) {
		fprintf(stderr, "Could not stat file %s: %s (%d)\n",
			filename, strerror(errno), errno);
		return -1;
	}
	/* And if not zero use that size */
	if (buf.st_size > 0) {
		start = 0;
		end_search=buf.st_size;
	}
	/*
	 * XXX Possibly warn and exit if start > filesize(fd), or if start +
	 * end_search > filesize(fd). Else, we will get a bus error for
	 * small files (with memmap, and for testing at least, it would
	 * be hard to find a system with less than 1024k).
	 */
	filebuf = mmap(NULL, end_search, PROT_READ, MAP_PRIVATE, fd, start);
	if (filebuf == MAP_FAILED) {
		fprintf(stderr, "Could not mmap %s: %s (%d)\n",
			filename, strerror(errno), errno);
		ret = -1;
		goto done;
	}

	ibft_loc = search_ibft((unsigned char *)filebuf, end_search);
	if (ibft_loc)
		ret = dump_ibft(ibft_loc, context);
	else {
		printf("Could not find iBFT.\n");
		ret = -1;
	}
	munmap(filebuf, end_search);
done:
	close(fd);
	return ret;
}
