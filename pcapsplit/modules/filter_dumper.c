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

#include "filter_dumper.h"
#include "dump_classes.h"

#include <tools/list.h>
#include <tools/pcap-tools.h>
#include <tools/msg.h>
#include <module_list.h>

#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <errno.h>

#define MAX_FILENAME 65535

struct dumping_module* filter_dumper_new()
{
	struct dumping_module* ret = (struct dumping_module*)malloc(sizeof(struct dumping_module));
	ret->dinit = filter_dumper_init;
	ret->dfunc = filter_dumper_run;
	ret->dfinish = filter_dumper_finish;
	return ret;
}

struct filter_dumper_data {
	list_t* filter_list;
};

int filter_dumper_init(struct dumping_module* m, struct config* c)
{
	struct filter_dumper_data* sdata = (struct filter_dumper_data*)malloc(sizeof(struct filter_dumper_data));
	if (!sdata) {
		msg(MSG_ERROR, "filter_dumper: Could not create filter dumper data: %s", strerror(errno));
		goto out1;
	}

	sdata->filter_list = classes_create(FILTER_DUMPER_NAME, c, m->linktype);
	if (!sdata->filter_list)
		goto out2;

	m->module_data = (void*)sdata;

	return 0;

out2:
	free(sdata);
out1: 
	return -1;
}

int filter_dumper_finish(struct dumping_module* m)
{
	struct filter_dumper_data* d = (struct filter_dumper_data*)m->module_data;
	struct list_element_t* i = d->filter_list->tail;
	while (i) {
		struct class_t* f = (struct class_t*)i->data;
		dumper_tool_close_file(&f->dumper);
		pcap_freecode(&f->filter_program);
		i = i->next;
	}
	list_destroy(d->filter_list);
	free(d);
	m->module_data = NULL;
	return 0;
}

int filter_dumper_run(struct dumping_module* m, struct packet* p)
{
	struct filter_dumper_data* d = (struct filter_dumper_data*)m->module_data;

	struct list_element_t* i = d->filter_list->head;
	while (i)  {
		struct class_t* f = (struct class_t*)i->data;
		if (bpf_filter(f->filter_program.bf_insns, (u_char*)p->data, p->header.len, p->header.caplen)) {
			dumper_tool_dump(f->dumper , &p->header, p->data);
			return 0;
		}
		i = i->next;
	}

	msg(MSG_INFO, "No matching filter for packet: Skipping packet!");

	return 0;
}
