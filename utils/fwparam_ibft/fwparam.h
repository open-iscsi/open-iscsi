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
 */
#ifndef FWPARAM_H_
#define FWPARAM_H_

#include <stdint.h>
#include "fw_context.h"

#define FILENAMESZ (256)

struct boot_context;

int fwparam_sysfs_boot_info(struct boot_context *context);
int fwparam_sysfs_get_targets(struct list_head *list);
int fwparam_ppc_boot_info(struct boot_context *context);
int fwparam_ppc_get_targets(struct list_head *list);

#endif /* FWPARAM_IBFT_H_ */
