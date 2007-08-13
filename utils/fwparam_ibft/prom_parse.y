/*
 * Copyright (C) IBM Corporation. 2007
 * Author: Doug Maxey <dwm@austin.ibm.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* - DEFINITION section. */

%{
	/* literal block. include lines, decls, defns. */
//#define YYDEBUG 1
#if YYDEBUG
#define DPRINT(fmt,...) printf(fmt,__VA_ARGS__)
#else
#define DPRINT(fmt,...) do {} while(0)
#endif
#include "prom_parse.h"
#include "iscsi_obp.h"

%}
%union {
		char str[256];
}

/* definitions. */
%token <str> BUSNAME BOOTDEV
%token <str> IPV4 IQN
%token <str> OBPPARM OBPQUAL
%token <str> HEX4 HEX16
%token <str> VDEVICE VDEVINST VDEVDEV VDEVRAW
%token <str> CHOSEN
%token <str> FILENAME

%type <str> devpath busses bus bootdev
%type <str> disklabel diskpart
%type <str> vdevice vdev_parms vdev_parm
%type <str> obp_quals obp_qual obp_params obp_param
%type <str> ipaddr ipv4 ipv6
%type <str> hexpart hexseq

%locations
%parse-param {struct ofw_dev *ofwdev}

%%

devpath: '/'   {
			DPRINT("****rootonly: \"%s\"\n", "/");
		}
	| '/' busses  bootdev  {
			DPRINT("****devpath busses:\n/%s/%s\n", $2, $3);
		}
	| '/' busses  bootdev disklabel {
			ofwdev->dev_path = malloc(strlen($<str>2) +
                                      strlen($<str>3) + 3);
			sprintf(ofwdev->dev_path, "/%s%s", $<str>2, $<str>3);
			DPRINT("****devpath busses bootdev "
                   "disklabel:\n/%s/%s%s\n",
				   $2, $3, $4);
		}
	| '/' busses  bootdev obp_quals obp_params {
			ofwdev->dev_path = malloc(strlen($<str>2) +
                                      strlen($<str>3) + 3);
			sprintf(ofwdev->dev_path, "/%s%s", $<str>2, $<str>3);
			DPRINT("****busses bootdev obp_quals obp_parms:\n"
                   "/%s/%s:%s%s\n",
				   $2, $3, $4, $5);
		}
	| '/' busses  bootdev obp_quals obp_params disklabel {
			ofwdev->dev_path = malloc(strlen($<str>2) +
                                      strlen($<str>3) + 3);
			sprintf(ofwdev->dev_path, "/%s%s", $<str>2, $<str>3);
			DPRINT("****busses bootdev obp_quals obp_parms "
                   "disklabel:\n/%s:%s%s%s\n", $2, $4, $5, $6);
		}
	| '/' vdevice bootdev vdev_parms obp_quals obp_params disklabel {
			DPRINT("****vdevice bootdev obp_parms "
                   "disklabel:\n/%s:%s%s%s%s\n",
				   $2, $4, $5, $6, $7);
		}
	;

busses:	   bus	{
			strcpy($$, $1);
		}
	| busses '/' bus {
			sprintf($$, "%s/%s", $<str>1, $<str>3);
		}
	;

bus:	BUSNAME {
			strcpy($$, $1);
		}
	| BUSNAME '@' HEX4 {
			sprintf($$, "%s@%s", $<str>1, $<str>3);
		}
	| BUSNAME '@' HEX4 ',' HEX4 {
			sprintf($$, "%s@%s,%s", $<str>1, $<str>3, $<str>5);
		}
	| BUSNAME '@' HEX16 {
			sprintf($$, "%s@%s", $<str>1, $<str>3);
		}
	| BUSNAME ',' HEX4 '@' HEX16  {
			sprintf($$, "%s,%s@%s", $<str>1, $<str>3, $<str>5);
		}
	;


bootdev:  '/' BOOTDEV ':' {
			sprintf($$, "/%s", $<str>2);
		}
	| '/' BOOTDEV '@' HEX4 ':' {
			sprintf($$, "/%s@%s", $<str>2, $<str>4);
		}
	| '/' BOOTDEV '@' HEX4 ',' HEX4 ':' {
			sprintf($$, "/%s@%s,%s", $<str>2, $<str>4, $<str>6);
		}
	;

vdevice: VDEVICE '/' VDEVINST {
			sprintf($$, "%s/%s", $<str>1, $<str>3);
		}
	;

vdev_parms: ':' vdev_parm {
			sprintf($$, ":%s", $<str>2);
		}
	| vdev_parms ',' vdev_parm {
			sprintf($$, "%s,%s", $<str>1, $<str>3);
		}
	| vdev_parms ',' VDEVRAW {
			sprintf($$, "%s,%s", $<str>1, $<str>3);
		}
	;

vdev_parm: VDEVDEV '=' CHOSEN {
			sprintf($$, "%s=%s", $<str>1, $<str>3);
		}
	;

obp_params: ',' obp_param	{
			sprintf($$, ",%s", $2);
		}
	| obp_params ',' obp_param {
			sprintf($$, "%s,%s", $<str>1, $<str>3);
		}
	| obp_params ',' disklabel {
			sprintf($$, "%s,%s", $<str>1, $<str>3);
		}
	;

obp_param: HEX4 {
			sprintf($$, "%s", $1);
		}
	| OBPPARM '=' HEX16 {
			/* luns > 0 are the SAM-3+ hex representation. */
			obp_parm_hexnum(ofwdev, $<str>1, $<str>3);
			sprintf($$, "%s=%s", $<str>1, $<str>3);
		}
	| OBPPARM '=' ipaddr {
			obp_parm_addr(ofwdev, $<str>1, $<str>3);
			sprintf($$, "%s=%s", $<str>1, $<str>3);
		}
	| OBPPARM '=' IQN {
			obp_parm_iqn(ofwdev, $<str>1, $<str>3);
			sprintf($$, "%s=%s", $<str>1, $<str>3);
		}
	| OBPPARM '=' HEX4 {
			obp_parm_hexnum(ofwdev, $<str>1, $<str>3);
			sprintf($$, "%s=%s", $<str>1, $<str>3);
		}
	| OBPPARM '=' FILENAME {
			obp_parm_str(ofwdev, $<str>1, $<str>3);
			sprintf($$, "%s=%s", $<str>1, $<str>3);
		}
	;

obp_quals: obp_qual {
			sprintf($$, "%s", $1);
		}
	|  obp_quals ',' obp_qual {
			sprintf($$, "%s,%s", $<str>1, $<str>3);
		}
	;

obp_qual: OBPQUAL {
			sprintf($$, "%s", obp_qual_set(ofwdev, $<str>1));
		}
	| vdev_parm {
			sprintf($$, "%s", $<str>1);
		}
	;

ipaddr: ipv4 {
			sprintf($$, "%s", $<str>1);
		}
	| ipv6 {
			sprintf($$, "%s", $<str>1);
		}
	;

ipv4: IPV4 {
			sprintf($$, "%s", $1);
		}
	;

ipv6: hexpart {
			sprintf($$, "%s", $1);
		}
	| hexpart ':' ipv4 {
			sprintf($$, "%s:%s", $1, $3);
		}
	;

hexpart: hexseq {
			sprintf($$, "%s", $1);
		}
	| hexpart "::"	{
			sprintf($$, "%s::", $<str>1);
		}
	| hexpart "::" hexseq {
			sprintf($$, "%s::%s", $<str>1, $<str>3);
		}
	| "::" hexseq {
			sprintf($$, "::%s", $<str>2);
		}
	;

hexseq:	HEX4 {
            sprintf($$, "%s", $1);
        }
    | hexseq ":" HEX4 {
            sprintf($$, "%s:%s", $<str>1, $<str>3);
        }
    ;

disklabel:   diskpart {
            sprintf($$, "%s", $<str>1);
        }
    | HEX4 diskpart {
            sprintf($$, "%s%s", $<str>1, $<str>2);
        }
    | '@' HEX4 ',' HEX4 diskpart {
            sprintf($$, "@%s,%s%s", $<str>2, $<str>4, $<str>5);
        }
    ;

diskpart: ':' HEX4 {
            sprintf($$, ":%s", $<str>2);
        }
    | ':' HEX4 ',' FILENAME {
            sprintf($$, ":%s,%s", $<str>2, $<str>4);
        }
    ;

%%
