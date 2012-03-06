/*
 * Return codes used by iSCSI tools.
 */
#ifndef _ISCSI_ERR_
#define _ISCSI_ERR_

enum {
	ISCSI_SUCCESS			= 0,
	/* Generic error */
	ISCSI_ERR			= 1,
	/* session could not be found */
	ISCSI_ERR_SESS_NOT_FOUND	= 2,
	/* Could not allocate resource for operation */
	ISCSI_ERR_NOMEM			= 3,
	/* Transport error caused operation to fail */
	ISCSI_ERR_TRANS			= 4,
	/* Generic login failure */
	ISCSI_ERR_LOGIN			= 5,
	/* Error accessing/managing iSCSI DB */
	ISCSI_ERR_IDBM			= 6,
	/* Invalid argument */
	ISCSI_ERR_INVAL			= 7,
	/* Connection timer exired while trying to connect */
	ISCSI_ERR_TRANS_TIMEOUT		= 8,
	/* Generic internal iscsid failure */
	ISCSI_ERR_INTERNAL		= 9,
	/* Logout failed */
	ISCSI_ERR_LOGOUT		= 10,
	/* iSCSI PDU timedout */
	ISCSI_ERR_PDU_TIMEOUT		= 11,
	/* iSCSI transport module not loaded in kernel or iscsid */
	ISCSI_ERR_TRANS_NOT_FOUND	= 12,
	/* Permission denied */
	ISCSI_ERR_ACCESS		= 13,
	/* Transport module did not support operation */
	ISCSI_ERR_TRANS_CAPS		= 14,
	/* Session is logged in */
	ISCSI_ERR_SESS_EXISTS		= 15,
	/* Invalid IPC MGMT request */
	ISCSI_ERR_INVALID_MGMT_REQ	= 16,
	/* iSNS service is not supported */
	ISCSI_ERR_ISNS_UNAVAILABLE	= 17,
	/* A read/write to iscsid failed */
	ISCSI_ERR_ISCSID_COMM_ERR	= 18,
	/* Fatal login error */
	ISCSI_ERR_FATAL_LOGIN		= 19,
	/* Could ont connect to iscsid */
	ISCSI_ERR_ISCSID_NOTCONN	= 20,
	/* No records/targets/sessions/portals found to execute operation on */
	ISCSI_ERR_NO_OBJS_FOUND		= 21,
	/* Could not lookup object in sysfs */
	ISCSI_ERR_SYSFS_LOOKUP		= 22,
	/* Could not lookup host */
	ISCSI_ERR_HOST_NOT_FOUND	= 23,
	/* Login failed due to authorization failure */
	ISCSI_ERR_LOGIN_AUTH_FAILED	= 24,
	/* iSNS query failure */
	ISCSI_ERR_ISNS_QUERY		= 25,
	/* iSNS registration/deregistration failed */
	ISCSI_ERR_ISNS_REG_FAILED	= 26,
	/* operation not supported */
	ISCSI_ERR_OP_NOT_SUPP		= 27,
	/* device or resource in use */
	ISCSI_ERR_BUSY			= 28,

	/* Always last. Indicates end of error code space */
	ISCSI_MAX_ERR_VAL,
} iscsi_err;

extern void iscsi_err_print_msg(int err);
extern char *iscsi_err_to_str(int err);

#endif
