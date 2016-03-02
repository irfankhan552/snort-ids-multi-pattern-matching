/* $Id: getopt.h,v 1.1 2006/01/19 17:08:02 ssturges Exp $ */
/*
** Copyright (C) 2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef _SNORT_GETOPT_H_
#define _SNORT_GETOPT_H_

#ifdef SNORT_GETOPT
#define _next_char(string)  (char)(*(string+1))

extern char * optarg; 
extern int    optind; 

int getopt(int, char**, char*);

#else
#include <getopt1.h>
#endif

#endif /* _SNORT_GETOPT_H_ */