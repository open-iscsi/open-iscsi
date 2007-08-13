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

#ifndef PROM_PARSE_H_
#define PROM_PARSE_H_

#include <stdlib.h>
#include <string.h>
#include "iscsi_obp.h"

struct ofw_dev;
void yyerror(struct ofw_dev *ofwdev, const char *msg);
extern int yyleng;
extern int yydebug;
#include <stdio.h>
extern FILE *yyin;
extern char yytext[];
int yylex(void);

#define YY_NO_UNPUT 1 /* match this with %option never-interactive. */
#include "prom_parse.tab.h"


#endif /* PROM_PARSE_H_ */
