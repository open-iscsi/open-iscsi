/*
 * Copyright (C) 2017-2018 Red Hat, Inc.
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

#ifndef __ISCSI_USR_DEFAULT_H__
#define __ISCSI_USR_DEFAULT_H__

#include "libopeniscsiusr/libopeniscsiusr_common.h"
#include "rfc.h"
#include "idbm.h"

#define PORTAL_GROUP_TAG_UNKNOWN	-1
/* q depths */
#define CMDS_MAX			128
#define QUEUE_DEPTH			32

/* system */
#define XMIT_THREAD_PRIORITY		-20

/* login retries */
#define DEF_INITIAL_LOGIN_RETRIES_MAX	4

/* autoscan enabled */
#define DEF_INITIAL_SCAN		INIT_SCAN_AUTO

/*
 * Default initiator settings. These may not be the same as
 * in the RFC. See libopeniscsiusr/libopeniscsiusr_rfc.h for those.
 */
/* timeouts in seconds */
#define DEF_LOGIN_TIMEO			30
#define DEF_LOGOUT_TIMEO		15
#define DEF_NOOP_OUT_INTERVAL		5
#define DEF_NOOP_OUT_TIMEO		5
#define DEF_REPLACEMENT_TIMEO		120

#define DEF_ABORT_TIMEO			15
#define DEF_LU_RESET_TIMEO		30
#define DEF_TGT_RESET_TIMEO		30
#define DEF_HOST_RESET_TIMEO		60

/* session reopen max retries */
#define	DEF_SESSION_REOPEN_MAX		0

/* default window size */
#define TCP_WINDOW_SIZE			(512 * 1024)

/* data and segment lengths in bytes */
#define DEF_INI_FIRST_BURST_LEN		262144
#define DEF_INI_MAX_BURST_LEN		16776192
#define DEF_INI_MAX_RECV_SEG_LEN	262144

#define DEFAULT_TRANSPORT	"tcp"
#define DEFAULT_IFACENAME	"default"
#define DEFAULT_NETDEV		"default"
#define DEFAULT_IPADDRESS	"default"
#define DEFAULT_HWADDRESS	"default"

void __DLL_LOCAL _default_node(struct iscsi_node *node);

#endif /* End of __ISCSI_USR_DEFAULT_H__ */
