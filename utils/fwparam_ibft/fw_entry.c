/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright (C) IBM Corporation. 2007
 * Author: Doug Maxey <dwm@austin.ibm.com>
 * based on code written by "Prasanna Mumbai" <mumbai.prasanna@gmail.com>
 *
 */
#include "fw_context.h"
#include "fwparam_ibft.h"

int
fw_entry_init(struct boot_context *context, int option)
{
	int ret = 0 ;
/*
 ppc should uncomment 

	ret = fwparam_ppc(context, option);
	if (ret)
*/
		ret = fwparam_ibft(context, option);
	return ret;
}
