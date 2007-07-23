/*
 * The following is from the linux kernel scsi_error.c
 *
 *  scsi_error.c Copyright (C) 1997 Eric Youngdale
 *
 *  SCSI error/timeout handling
 *      Initial versions: Eric Youngdale.  Based upon conversations with
 *                        Leonard Zubkoff and David Miller at Linux Expo,
 *                        ideas originating from all over the place.
 *
 *	Restructured scsi_unjam_host and associated functions.
 *	September 04, 2002 Mike Anderson (andmike@us.ibm.com)
 *
 *	Forward port of Russell King's (rmk@arm.linux.org.uk) changes and
 *	minor  cleanups.
 *	September 30, 2002 Mike Anderson (andmike@us.ibm.com)
 */

#include <string.h>
#include "scsi.h"

/**
 * scsi_normalize_sense - normalize main elements from either fixed or
 *			descriptor sense data format into a common format.
 *
 * @sense_buffer:	byte array containing sense data returned by device
 * @sb_len:		number of valid bytes in sense_buffer
 * @sshdr:		pointer to instance of structure that common
 *			elements are written to.
 *
 * Notes:
 *	The "main elements" from sense data are: response_code, sense_key,
 *	asc, ascq and additional_length (only for descriptor format).
 *
 *	Typically this function can be called after a device has
 *	responded to a SCSI command with the CHECK_CONDITION status.
 *
 * Return value:
 *	1 if valid sense data information found, else 0;
 **/
int scsi_normalize_sense(const uint8_t *sense_buffer, int sb_len,
                         struct scsi_sense_hdr *sshdr)
{
	if (!sense_buffer || !sb_len)
		return 0;

	memset(sshdr, 0, sizeof(struct scsi_sense_hdr));

	sshdr->response_code = (sense_buffer[0] & 0x7f);

	if (!scsi_sense_valid(sshdr))
		return 0;

	if (sshdr->response_code >= 0x72) {
		/*
		 * descriptor format
		 */
		if (sb_len > 1)
			sshdr->sense_key = (sense_buffer[1] & 0xf);
		if (sb_len > 2)
			sshdr->asc = sense_buffer[2];
		if (sb_len > 3)
			sshdr->ascq = sense_buffer[3];
		if (sb_len > 7)
			sshdr->additional_length = sense_buffer[7];
	} else {
		/* 
		 * fixed format
		 */
		if (sb_len > 2)
			sshdr->sense_key = (sense_buffer[2] & 0xf);
		if (sb_len > 7) {
			sb_len = (sb_len < (sense_buffer[7] + 8)) ?
					 sb_len : (sense_buffer[7] + 8);
			if (sb_len > 12)
				sshdr->asc = sense_buffer[12];
			if (sb_len > 13)
				sshdr->ascq = sense_buffer[13];
		}
	}

	return 1;
}
