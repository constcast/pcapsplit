//  Copyright (C) 2008-2011 Lothar Braun <lothar@lobraun.de>
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

#ifndef _MODULE_LIST_H_
#define _MODULE_LIST_H_

#define MAIN_NAME "main"
#define SIZE_DUMPER_NAME "size_dumper"
#define FILTER_DUMPER_NAME "filter_dumper"
#define FLOWSTART_DUMPER_NAME "flowstart_dumper"
#define IPLIST_DUMPER_NAME "iplist_dumper"
#define STATS_MODULE_NAME "stats_module"

struct dumping_module;

struct dumping_module* get_module(const char* name);

#endif
