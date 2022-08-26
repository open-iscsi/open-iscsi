/*
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Gris Ge <fge@redhat.com>
 */

#ifndef _LIB_OPEN_ISCSI_USR_SESSION_H_
#define _LIB_OPEN_ISCSI_USR_SESSION_H_

#include "libopeniscsiusr_common.h"

#include <stdint.h>

/**
 * iscsi_session_sid_get() - Retrieve iSCSI session ID of specified session.
 *
 * Retrieve iSCSI session ID. The session ID here is the integer used
 * in '/sys/class/iscsi_session/session<session_id>/'
 *
 * @se:
 *	Pointer of 'struct iscsi_session'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	uint32_t.
 */
__DLL_EXPORT uint32_t iscsi_session_sid_get(struct iscsi_session *se);

/**
 * iscsi_session_persistent_address_get() - Retrieve iSCSI target persistent
 * address of specified session
 *
 * Retrieve the iSCSI target persistent address of specified iSCSI session.
 * The 'persistent address' is the network address where iSCSI initiator send
 * initial request. When iSCSI redirection in use, this address might not be
 * the network address used for actual iSCSI transaction.
 * Please use `iscsi_session_address_get()` for target network address of
 * iSCSI transaction.
 *
 * @se:
 *	Pointer of 'struct iscsi_session'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	const char *. Empty string if not supported.
 *	No need to free this memory, the resources will get freed by
 *	iscsi_session_free() or iscsi_sessions_free().
 */
__DLL_EXPORT const char *iscsi_session_persistent_address_get
	(struct iscsi_session *se);

/**
 * iscsi_session_persistent_port_get() - Retrieve iSCSI target persistent
 * port of specified session
 *
 * Retrieve the iSCSI target persistent port of specified iSCSI session.
 * The 'persistent port' is the network port where iSCSI initiator send
 * initial request. When iSCSI redirection in use, this port might not be
 * the network port used for actual iSCSI transaction.
 * Please use `iscsi_session_port_get()` for target network address of
 * iSCSI transaction.
 *
 * @se:
 *	Pointer of 'struct iscsi_session'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	int32_t. -1 if not supported.
 */
__DLL_EXPORT int32_t iscsi_session_persistent_port_get
	(struct iscsi_session *se);

/**
 * iscsi_session_target_name_get() - Retrieve iSCSI target name of specified
 * session
 *
 * Retrieve the iSCSI target name of specified iSCSI session.
 * The iSCSI Target Name specifies the worldwide unique name of the target.
 *
 * @se:
 *	Pointer of 'struct iscsi_session'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	const char *.
 *	No need to free this memory, the resources will get freed by
 *	iscsi_session_free() or iscsi_sessions_free().
 */
__DLL_EXPORT const char *iscsi_session_target_name_get
	(struct iscsi_session *se);

/**
 * iscsi_session_username_get() - Retrieve authentication username of specified
 * session.
 *
 * Retrieve the authentication username of specified iSCSI session.
 * Currently open-iscsi only support CHAP authentication method.
 * It's controlled this setting in iscsid.conf:
 * 'node.session.auth.username'
 *
 * @se:
 *	Pointer of 'struct iscsi_session'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	const char *. Empty string if not using CHAP authentication or failed
 *	to read authentication information.
 *	No need to free this memory, the resources will get freed by
 *	iscsi_session_free() or iscsi_sessions_free().
 */
__DLL_EXPORT const char *iscsi_session_username_get(struct iscsi_session *se);

/**
 * iscsi_session_password_get() - Retrieve authentication password of specified
 * session.
 *
 * Retrieve the authentication password of specified iSCSI session.
 * Currently open-iscsi only support CHAP authentication method.
 * It's controlled this setting in iscsid.conf:
 * 'node.session.auth.password'
 *
 * @se:
 *	Pointer of 'struct iscsi_session'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	const char *. Empty string if not using CHAP authentication or failed
 *	to read authentication information.
 *	No need to free this memory, the resources will get freed by
 *	iscsi_session_free() or iscsi_sessions_free().
 */
__DLL_EXPORT const char *iscsi_session_password_get(struct iscsi_session *se);

/**
 * iscsi_session_username_in_get() - Retrieve authentication username of
 * specified session.
 *
 * Retrieve the inbound authentication username of specified iSCSI session.
 * Currently open-iscsi only support CHAP authentication method.
 * The inbound authentication here means the iSCSI initiator authenticates the
 * iSCSI target using CHAP.
 * It's controlled this setting in iscsid.conf:
 * 'node.session.auth.username_in'
 *
 * @se:
 *	Pointer of 'struct iscsi_session'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	const char *. Empty string if not using inbound CHAP authentication or
 *	failed to read authentication information.
 *	No need to free this memory, the resources will get freed by
 *	iscsi_session_free() or iscsi_sessions_free().
 */
__DLL_EXPORT const char *iscsi_session_username_in_get
	(struct iscsi_session *se);

/**
 * iscsi_session_password_in_get() - Retrieve authentication password of
 * specified session.
 *
 * Retrieve the inbound authentication password of specified iSCSI session.
 * Currently open-iscsi only support CHAP authentication method.
 * The inbound authentication here means the iSCSI initiator authenticates the
 * iSCSI target using CHAP.
 * It's controlled this setting in iscsid.conf:
 * 'node.session.auth.password_in'
 *
 * @se:
 *	Pointer of 'struct iscsi_session'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	const char *. Empty string if not using inbound CHAP authentication or
 *	failed to read authentication information.
 *	No need to free this memory, the resources will get freed by
 *	iscsi_session_free() or iscsi_sessions_free().
 */
__DLL_EXPORT const char *iscsi_session_password_in_get
	(struct iscsi_session *se);

/**
 * iscsi_session_recovery_tmo_get() - Retrieve recovery timeout value of
 * specified session
 *
 * Retrieve the recovery timeout value of specified iSCSI session.
 * The recovery timeout here means the seconds of time to wait for session
 * re-establishment before failing SCSI commands back to the application when
 * running the Linux SCSI Layer error handler.
 * It could be controlled via this setting in iscsid.conf:
 * 'node.session.timeo.replacement_timeout'.
 *
 * @se:
 *	Pointer of 'struct iscsi_session'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	int32_t. If the value is 0, IO will be failed immediately. If the value
 *	is less than 0, IO will remain queued until the session is logged back
 *	in, or until the user runs the logout command.
 */
__DLL_EXPORT int32_t iscsi_session_recovery_tmo_get(struct iscsi_session *se);

/**
 * iscsi_session_lu_reset_tmo_get() - Retrieve logical unit timeout value of
 * specified session
 *
 * Retrieve the logical unit timeout value of specified iSCSI session.
 * The logical unit timeout here means the seconds of time to wait for a logical
 * unit response before before failing the operation and trying session
 * re-establishment.
 * It could be controlled via this setting in iscsid.conf:
 * 'node.session.err_timeo.lu_reset_timeout'
 *
 * @se:
 *	Pointer of 'struct iscsi_session'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	int32_t. -1 if not supported.
 */
__DLL_EXPORT int32_t iscsi_session_lu_reset_tmo_get(struct iscsi_session *se);

/**
 * iscsi_session_tgt_reset_tmo_get() - Retrieve target response timeout value of
 * of specified session
 *
 * Retrieve the target response timeout value of specified iSCSI session.
 * The target response timeout here means the seconds of time to wait for a
 * target response before before failing the operation and trying session
 * re-establishment.
 * It could be controlled via this setting in iscsid.conf:
 * 'node.session.err_timeo.tgt_reset_timeout'.
 *
 * @se:
 *	Pointer of 'struct iscsi_session'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	int32_t. -1 if not supported.
 */
__DLL_EXPORT int32_t iscsi_session_tgt_reset_tmo_get(struct iscsi_session *se);

/**
 * iscsi_session_abort_tmo_get() - Retrieve abort response timeout value of
 * specified session
 *
 * Retrieve the abort response timeout value of specified iSCSI session.
 * The abort response timeout here means the seconds of time to wait for a
 * abort response before before failing the operation and trying session
 * re-establishment.
 * It could be controlled via this setting in iscsid.conf:
 * 'node.session.err_timeo.abort_timeout'.
 *
 * @se:
 *	Pointer of 'struct iscsi_session'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	int32_t. -1 if not supported.
 */
__DLL_EXPORT int32_t iscsi_session_abort_tmo_get(struct iscsi_session *se);

/**
 * iscsi_session_tpgt_get() - Retrieve target portal group tag of specified
 * session
 *
 * Retrieve the target portal group tag of specified iSCSI session.
 *
 * The target portal group tag is a value that uniquely identifies a portal
 * group within an iSCSI target node. This key carries the value of the tag of
 * the portal group that is servicing the Login request. The iSCSI target
 * returns this key to the initiator in the Login Response PDU to the first
 * Login Request PDU that has the C bit set to 0 when TargetName is given by the
 * initiator.
 *
 * @se:
 *	Pointer of 'struct iscsi_session'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	int32_t. -1 if not supported.
 */
__DLL_EXPORT int32_t iscsi_session_tpgt_get(struct iscsi_session *se);

/**
 * iscsi_session_address_get() - Retrieve iSCSI target address of specified
 * session
 *
 * Retrieve the iSCSI target network address of specified iSCSI session.
 *
 * @se:
 *	Pointer of 'struct iscsi_session'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	const char *. Empty string if not supported.
 *	No need to free this memory, the resources will get freed by
 *	iscsi_session_free() or iscsi_sessions_free().
 */
__DLL_EXPORT const char *iscsi_session_address_get
	(struct iscsi_session *se);

/**
 * iscsi_session_port_get() - Retrieve iSCSI target port of specified session
 *
 * Retrieve the iSCSI target port of specified iSCSI session.
 *
 * @se:
 *	Pointer of 'struct iscsi_session'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	int32_t. -1 if not supported.
 */
__DLL_EXPORT int32_t iscsi_session_port_get(struct iscsi_session *se);

/**
 * iscsi_session_iface_get() - Retrieve iSCSI interface information of
 * specified session
 *
 * Retrieve the iSCSI interface information of specified iSCSI session.
 * For the properties of 'struct iscsi_iface', please refer to the functions
 * defined in 'libopeniscsiusr_iface.h' file.
 *
 * @se:
 *	Pointer of 'struct iscsi_session'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	Pointer of 'struct iscsi_iface'. NULL if not supported.
 *	No need to free this memory, the resources will get freed by
 *	iscsi_session_free() or iscsi_sessions_free().
 */
__DLL_EXPORT struct iscsi_iface *iscsi_session_iface_get
	(struct iscsi_session *se);

#endif /* End of _LIB_OPEN_ISCSI_USR_SESSION_H_ */
