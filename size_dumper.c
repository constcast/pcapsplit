//  Copyright (C) 2008 Lothar Braun <lothar@lobraun.de>
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

#include "size_dumper.h"

#include <stdlib.h>
#include <string.h>

#define MAX_FILENAME 65535

struct size_dumper_data {
	char base_filename[MAX_FILENAME];
	char dump_filename[MAX_FILENAME];
	size_t number;
};

int size_dumper_init(struct dumping_module* m, void* data)
{
	struct size_dumper_data* sdata = (struct size_dumper_data*)malloc(
		sizeof(struct size_dumper_data));
	strncpy(sdata->base_filename, (char*)data, MAX_FILENAME);
	sdata->number = 0;
	m->module_data = (void*)sdata;
	return 0;
}

int size_dumper_finish(struct dumping_module* m)
{
	free(m->module_data);
	m->module_data = NULL;
	return 0;
}

int size_dumper_run(struct dumping_module* m, struct packet* p)
{
	return 0;
}
