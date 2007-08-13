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

/* definitions */
%option array

%{
#include "prom_parse.h"

#undef LEXDEBUG
#ifdef LEXDEBUG
#define dbg(a) dbgprint((a))
#else
#define dbg(a) do {} while (0)
#endif  /* LEXDEBUG */

#define upval(d)				\
    dbg(#d);					\
    yylval.str[0] = 0;                          \
    strcat(yylval.str, yytext);			\
    yylloc.first_column = yylloc.last_column;	\
    yylloc.last_column += yyleng;		\
    return d

void dbgprint(const char *item) { fprintf(stderr, "%s: \"%s\" len=%d ", item, yytext, yyleng);}

%}

%option noyywrap
%option never-interactive

VDEVICE     vdevice
VDEVINST    gscsi
VDEVDEV     dev
VDEVRAW     rawio
                                /* CHOSEN uses only boot related paths. */
CHOSEN      bootpath|bootargs|iscsi-bootargs|nas-bootdevice
BUSNAME     ata|i2c|ide|pci|sata|scsi|usb|lhea
BOOTDEV     cdrom|disk|ethernet|iscsi-(disk[0-9]|toe)|sd
HEX4        [[:xdigit:]]{1,4}
HEX16       [[:xdigit:]]{5,16}
IPV4        [0-9]{1,3}(\.[0-9]{1,3}){3}
IQN         iqn\.[-[:alnum:]:.]{1,219}
OBPQUAL     bootp|ipv6|iscsi|dhcpv6
OBPPARM     blksize|bootp-retries|chapid|chappw|ciaddr|dhcp|filename|giaddr|ichapid|ichappw|ilun|iname|iport|isid|isns|itname|siaddr|slp|subnet-mask|tftp-retries
FILENAME    \\[-[:alnum:]\\\.]{1,}

%% /* rules */

{CHOSEN}      { upval(CHOSEN); }
{VDEVICE}     { upval(VDEVICE); }
{VDEVINST}    { upval(VDEVINST); }
{VDEVDEV}     { upval(VDEVDEV); }
{VDEVRAW}     { upval(VDEVRAW); }
{OBPQUAL}     { upval(OBPQUAL); }
{BUSNAME}     { upval(BUSNAME); }
{IPV4}        { upval(IPV4); }
{IQN}         { upval(IQN); }
{BOOTDEV}     { upval(BOOTDEV); }
{OBPPARM}     { upval(OBPPARM); }
{HEX4}        { upval(HEX4); }
{HEX16}       { upval(HEX16); }
{FILENAME}    { upval(FILENAME); }
[ \t\n]+      {                  /* eat all whitespace. */
	yylloc.first_column = yylloc.last_column;
	yylloc.last_column += yyleng;
}
.             {			/* any other single char. */
	dbg("??");
	yylloc.first_column = yylloc.last_column;
	yylloc.last_column += yyleng;
	return *yytext;
}

<<EOF>> yyterminate();
%% /* user code */
