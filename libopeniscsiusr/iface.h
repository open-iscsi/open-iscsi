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
#ifndef __ISCSI_USR_IFACE_H__
#define __ISCSI_USR_IFACE_H__

#include "libopeniscsiusr/libopeniscsiusr_common.h"
#include <stdint.h>

/*
 * BUG(Gris Ge): Should include 'iface_kern_id' parameter.
 */
__DLL_LOCAL int _iscsi_iface_get(struct iscsi_context *ctx, uint32_t host_id,
				 uint32_t sid, const char *iface_kern_id,
				 struct iscsi_iface **iface);

__DLL_LOCAL void _iscsi_iface_free(struct iscsi_iface *iface);


#endif /* End of __ISCSI_USR_IFACE_H__ */
