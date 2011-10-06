/*
 * Copyright (C) 2011 Aastha Mehta
 * Copyright (C) 2011 Mike Christie
 *
 * maintained by open-iscsi@googlegroups.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * See the file COPYING included with this distribution for more details.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "iscsi_if.h"

#include "kern_err_table.h"

const char *kern_err_code_to_string(int err)
{
	switch (err){
	case ISCSI_OK:
		return "ISCSI_OK: operation successful";
	case ISCSI_ERR_DATASN:
		return "ISCSI_ERR_DATASN: Received invalid data sequence "
			"number from target";
	case ISCSI_ERR_DATA_OFFSET:
		return "ISCSI_ERR_DATA_OFFSET: Seeking offset beyond the size "
			"of the iSCSI segment";
	case ISCSI_ERR_MAX_CMDSN:
		return "ISCSI_ERR_MAX_CMDSN: Received invalid command sequence "
			"number from target";
	case ISCSI_ERR_EXP_CMDSN:
		return "ISCSI_ERR_EXP_CMDSN: Received invalid expected command "			"sequence number from target";
	case ISCSI_ERR_BAD_OPCODE:
		return "ISCSI_ERR_BAD_OPCODE: Received an invalid iSCSI opcode";
	case ISCSI_ERR_DATALEN:
		return "ISCSI_ERR_DATALEN: Invalid data length value";
	case ISCSI_ERR_AHSLEN:
		return "ISCSI_ERR_AHSLEN: Received an invalid AHS length";
	case ISCSI_ERR_PROTO:
		return "ISCSI_ERR_PROTO: iSCSI protocol violation";
	case ISCSI_ERR_LUN:
		return "ISCSI_ERR_LUN: LUN mismatch";
	case ISCSI_ERR_BAD_ITT:
		return "ISCSI_ERR_BAD_ITT: Received invalid initiator task tag "			"from target";
	case ISCSI_ERR_CONN_FAILED:
		return "ISCSI_ERR_CONN_FAILED: iSCSI connection failed";
	case ISCSI_ERR_R2TSN:
		return "ISCSI_ERR_R2TSN: Received invalid R2T (Ready to "
			"Transfer) data sequence number from target";
	case ISCSI_ERR_SESSION_FAILED:
		return "ISCSI_ERR_SESSION_FAILED: iSCSI session failed";
	case ISCSI_ERR_HDR_DGST:
		return "ISCSI_ERR_HDR_DGST: Header digest mismatch";
	case ISCSI_ERR_DATA_DGST:
		return "ISCSI_ERR_DATA_DGST: Data digest mismatch";
	case ISCSI_ERR_PARAM_NOT_FOUND:
		return "ISCSI_ERR_PARAM_NOT_FOUND: Parameter not found";
	case ISCSI_ERR_NO_SCSI_CMD:
		return "ISCSI_ERR_NO_SCSI_CMD: Could not look up SCSI command";
	case ISCSI_ERR_INVALID_HOST:
		return "ISCSI_ERR_INVALID_HOST: iSCSI host is in an invalid "
			"state";
	case ISCSI_ERR_XMIT_FAILED:
		return "ISCSI_ERR_XMIT_FAILED: Transmission of iSCSI packet "
			"failed";
	case ISCSI_ERR_TCP_CONN_CLOSE:
		return "ISCSI_ERR_TCP_CONN_CLOSE: TCP connection closed";
	case ISCSI_ERR_SCSI_EH_SESSION_RST:
		return "ISCSI_ERR_SCSI_EH_SESSION_RST: Session was dropped as "
			"a result of SCSI error recovery";
	default:
		return "Invalid or unknown error code";
	}
}
