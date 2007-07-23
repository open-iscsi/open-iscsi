/*
 * this is from the linux kernel scsi_eh.h
 */
#ifndef _SCSI_SCSI_H
#define _SCSI_SCSI_H

#include <stdint.h>

/*
 * This is a slightly modified SCSI sense "descriptor" format header.
 * The addition is to allow the 0x70 and 0x71 response codes. The idea
 * is to place the salient data from either "fixed" or "descriptor" sense
 * format into one structure to ease application processing.
 *
 * The original sense buffer should be kept around for those cases
 * in which more information is required (e.g. the LBA of a MEDIUM ERROR).
 */
struct scsi_sense_hdr {		/* See SPC-3 section 4.5 */
	uint8_t response_code;	/* permit: 0x0, 0x70, 0x71, 0x72, 0x73 */
	uint8_t sense_key;
	uint8_t asc;
	uint8_t ascq;
	uint8_t byte4;
	uint8_t byte5;
	uint8_t byte6;
	uint8_t additional_length;	/* always 0 for fixed sense format */
};

static inline int scsi_sense_valid(struct scsi_sense_hdr *sshdr)
{
	if (!sshdr)
		return 0;

	return (sshdr->response_code & 0x70) == 0x70;
}

extern int scsi_normalize_sense(const uint8_t *sense_buffer, int sb_len,
				struct scsi_sense_hdr *sshdr);

#endif
