//  Copyright (C) 2010 Lothar Braun <lothar@lobraun.de>
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

#include "iplist_dumper.h"

#include <module_list.h>
#include <tools/pcap-tools.h>
#include <tools/msg.h>

#include <stdlib.h>
#include <string.h>

#define MAX_FILENAME 65535

struct dumping_module* iplist_dumper_new()
{
	struct dumping_module* ret = (struct dumping_module*)malloc(sizeof(struct dumping_module));
	ret->dinit = iplist_dumper_init;
	ret->dfunc = iplist_dumper_run;
	ret->dfinish = iplist_dumper_finish;
	return ret;
}

struct iplist_dumper_data {
	char dump_filename[MAX_FILENAME];
	struct dumper_tool* dumper;
};


int iplist_dumper_init(struct dumping_module* m, struct config* c)
{
	struct iplist_dumper_data* data = (struct iplist_dumper_data*)malloc(
		sizeof(struct iplist_dumper_data));

	const char* tmp = config_get_option(c, IPLIST_DUMPER_NAME, "filename");
	if (tmp == NULL) {
		msg(MSG_ERROR, "%s: no filename in config file", IPLIST_DUMPER_NAME);
		return -1;
	}
	strncpy(data->dump_filename, tmp, MAX_FILENAME);

	data->dumper = dumper_tool_open_file(data->dump_filename, m->linktype);
	if (!data->dumper)
		goto out;
	
	m->module_data = (void*)data;
	return 0;

out: 
	free(data);
	return -1;
}

int iplist_dumper_finish(struct dumping_module* m)
{
	struct iplist_dumper_data* d = (struct iplist_dumper_data*)m->module_data;
	dumper_tool_close_file(&d->dumper);
	free(d);
	m->module_data = NULL;
	return 0;
}

int iplist_dumper_run(struct dumping_module* m, struct packet* p)
{
	struct iplist_dumper_data* d = (struct iplist_dumper_data*)m->module_data;
	
	dumper_tool_dump(d->dumper, &p->header, p->data);
	return 0;
}
