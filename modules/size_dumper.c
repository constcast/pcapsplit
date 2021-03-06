//  Copyright (C) 2008-2010 Lothar Braun <lothar@lobraun.de>
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

#include <module_list.h>
#include <tools/pcap-tools.h>
#include <tools/msg.h>

#include <stdlib.h>
#include <string.h>

#define MAX_FILENAME 65535

struct dumping_module* size_dumper_new()
{
	struct dumping_module* ret = (struct dumping_module*)malloc(sizeof(struct dumping_module));
	ret->dinit = size_dumper_init;
	ret->dfunc = size_dumper_run;
	ret->dfinish = size_dumper_finish;
	return ret;
}

struct size_dumper_data {
	char base_filename[MAX_FILENAME];
	char dump_filename[MAX_FILENAME];
	size_t number;
	size_t file_data_count;
	size_t max_file_data_count;
	struct dumper_tool* dumper;
};

int createNewFile(struct size_dumper_data* data, int linktype)
{
	snprintf(data->dump_filename, MAX_FILENAME, "%s.%lu",
		data->base_filename, (unsigned long)data->number);
	data->dumper = dumper_tool_open_file(data->dump_filename, linktype);
	if (!data->dumper) {
		return -1;
	}
	data->number++;
	data->file_data_count = 0;
	return 0;
}

int size_dumper_init(struct dumping_module* m, struct config* c)
{
	struct size_dumper_data* sdata = (struct size_dumper_data*)malloc(
		sizeof(struct size_dumper_data));

	const char* tmp = config_get_option(c, SIZE_DUMPER_NAME, "file_prefix");
	if (tmp == NULL) {
		msg(MSG_ERROR, "%s: no filename in config file", SIZE_DUMPER_NAME);
		return -1;
	}
	strncpy(sdata->base_filename, tmp, MAX_FILENAME);

	sdata->number = 0;
	sdata->file_data_count = 0;
	
	tmp = config_get_option(c, SIZE_DUMPER_NAME, "size");
	if (tmp == NULL) {
		msg(MSG_ERROR, "%s: no file size in config file", "size");
		return -1;
	}
	sdata->max_file_data_count = atoi(tmp);

	if (-1 == createNewFile(sdata, m->linktype)) 
		goto out;
	

	m->module_data = (void*)sdata;
	return 0;

out: 
	free(sdata);
	return -1;
}

int size_dumper_finish(struct dumping_module* m)
{
	struct size_dumper_data* d = (struct size_dumper_data*)m->module_data;
	dumper_tool_close_file(&d->dumper);
	free(d);
	m->module_data = NULL;
	return 0;
}

int size_dumper_run(struct dumping_module* m, struct packet* p)
{
	struct size_dumper_data* d = (struct size_dumper_data*)m->module_data;
	
	dumper_tool_dump(d->dumper, &p->header, p->data);
	d->file_data_count += p->header.len;
	if (d->file_data_count >= d->max_file_data_count) {
		dumper_tool_close_file(&d->dumper);
		if (-1 == createNewFile(d, m->linktype)) {
			return -1;
		}
	}
	return 0;
}
