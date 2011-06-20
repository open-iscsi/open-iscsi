/*******************************************************************************

  DCB application support
  Copyright(c) 2010-2011 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  open-lldp Mailing List <lldp-devel@open-lldp.org>

*******************************************************************************/

#ifndef _DCB_APP_H_
#define _DCB_APP_H_

int get_dcb_app_pri_by_ethtype(const char *ifname, int ethtype);

int get_dcb_app_pri_by_stream_port(const char *ifname, int port);
int get_dcb_app_pri_by_datagram_port(const char *ifname, int port);

/*
 * The selector values for the following call are defined in recent versions
 * of the dcbnl.h file.
 */
int get_dcb_app_pri_by_port_sel(const char *ifname, int port, int sel);

#endif  /* _DCB_APP_H_ */
