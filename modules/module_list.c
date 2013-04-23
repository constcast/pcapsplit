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

#include "module_list.h"
#include "dumping_module.h"
#include <modules/size_dumper.h>
#include <modules/filter_dumper.h>
#include <modules/flowstart_dumper.h>
#include <modules/iplist_dumper.h>
#include <modules/stats_module.h>
#include <modules/connstats_module.h>
#include <modules/ssh_dumper.h>

#include <string.h>

struct dumping_module* get_module(const char* name)
{
	struct dumping_module* ret = NULL;

	if (strcmp(name, SIZE_DUMPER_NAME) == 0) {
		ret = size_dumper_new();
	} else if (strcmp(name, FILTER_DUMPER_NAME) == 0) {
		ret = filter_dumper_new();
	} else if (strcmp(name, MAIN_NAME) == 0) {
		// no module for main
	} else if (strcmp(name, FLOWSTART_DUMPER_NAME) == 0) {
		ret = flowstart_dumper_new();
	} else if (strcmp(name, IPLIST_DUMPER_NAME) == 0) {
		ret = iplist_dumper_new();
	} else if (strcmp(name, STATS_MODULE_NAME) == 0) {
		ret = stats_module_new();
	} else if (strcmp(name, CONNSTATS_MODULE_NAME) == 0) {
		ret = connstats_module_new();
	} else if (strcmp(name, SSH_DUMPER_NAME) == 0) {
		ret = ssh_dumper_new();
	}

	return ret;
}
