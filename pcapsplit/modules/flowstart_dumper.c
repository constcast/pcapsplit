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

#include "flowstart_dumper.h"
#include "dump_classes.h"

#include <tools/list.h>
#include <tools/pcap-tools.h>
#include <tools/connection.h>
#include <tools/msg.h>
#include <module_list.h>

#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <errno.h>

#define MAX_FILENAME 65535

int fd_handle_packet(struct class_t* t, struct packet* p);

struct dumping_module* flowstart_dumper_new()
{
	struct dumping_module* ret = (struct dumping_module*)malloc(sizeof(struct dumping_module));
	ret->dinit = flowstart_dumper_init;
	ret->dfunc = flowstart_dumper_run;
	ret->dfinish = flowstart_dumper_finish;
	return ret;
}

struct flowstart_dumper_data {
	list_t* filter_list;
};

int flowstart_dumper_init(struct dumping_module* m, struct config* c)
{
	uint32_t conn_no = 0;
	uint32_t conn_max = 0;
	uint32_t flow_timeout = 0;
	char pcap_file[MAX_FILENAME];

	struct flowstart_dumper_data* sdata = (struct flowstart_dumper_data*)malloc(sizeof(struct flowstart_dumper_data));
	if (!sdata) {
		msg(MSG_ERROR, "flowstart_dumper: Could not create flowstart dumper data: %s", strerror(errno));
		goto out1;
	}

	sdata->filter_list = classes_create(FLOWSTART_DUMPER_NAME, c, m->linktype);
	if (!sdata->filter_list)
		goto out2;

	if (!config_get_option(c, FLOWSTART_DUMPER_NAME, "init_connection_pool")) {
		msg(MSG_ERROR, "flowstart_dumper: \"init_connection_pool\" missing in section %s", FLOWSTART_DUMPER_NAME);
		goto out2;
	}
	conn_no = atoi(config_get_option(c, FLOWSTART_DUMPER_NAME, "init_connection_pool"));

	if (!config_get_option(c, FLOWSTART_DUMPER_NAME, "max_connection_pool")) {
		msg(MSG_ERROR, "flowstart_dumper: \"max_connection_pool\" missing in section %s", FLOWSTART_DUMPER_NAME);
		goto out2;
	}
	conn_max = atoi(config_get_option(c, FLOWSTART_DUMPER_NAME, "max_connection_pool"));

	if (!config_get_option(c, FLOWSTART_DUMPER_NAME, "flow_timeout")) {
		msg(MSG_ERROR, "flowstart_dumper: \"flow_timeout\" missing in section %s", FLOWSTART_DUMPER_NAME);
		goto out2;
	}
	flow_timeout = atoi(config_get_option(c, FLOWSTART_DUMPER_NAME, "flow_timeout"));

	connection_init_pool(conn_no, conn_max, flow_timeout);

	struct list_element_t* i = sdata->filter_list->head;
	while (i) {
		struct class_t* t = i->data;
		snprintf(pcap_file, MAX_FILENAME, "%s%s", t->prefix, t->class_name);
		t->dumper = dumper_tool_open_file(pcap_file, m->linktype);
		if (!t->dumper) {
			msg(MSG_ERROR, "filter_dumper: Cannot open pcap file %s", pcap_file);
			goto out2;
		}
		
		i = i->next;
	}


	m->module_data = (void*)sdata;

	return 0;

out2:
	free(sdata);
out1: 
	return -1;
}

int flowstart_dumper_finish(struct dumping_module* m)
{
	struct flowstart_dumper_data* d = (struct flowstart_dumper_data*)m->module_data;
	struct list_element_t* i = d->filter_list->tail;
	while (i) {
		struct class_t* f = (struct class_t*)i->data;
		dumper_tool_close_file(&f->dumper);
		pcap_freecode(&f->filter_program);
		i = i->next;
	}
	list_destroy(d->filter_list);
	free(d);
	connection_deinit_pool();
	m->module_data = NULL;
	return 0;
}

int flowstart_dumper_run(struct dumping_module* m, struct packet* p)
{
	struct flowstart_dumper_data* d = (struct flowstart_dumper_data*)m->module_data;

	struct list_element_t* i = d->filter_list->head;
	while (i)  {
		struct class_t* c = (struct class_t*)i->data;
		if (bpf_filter(c->filter_program.bf_insns, (u_char*)p->data, p->header.len, p->header.caplen)) {
			return fd_handle_packet(c, p);
		}
		i = i->next;
	}

	//msg(MSG_INFO, "No matching filter for packet: Skipping packet!");

	return 0;
}

int fd_handle_packet(struct class_t* class, struct packet* p)
{
	struct connection* c = connection_get(p);
	if (!c) {
		//msg(MSG_FATAL, "Something is fucked up: Did not get a connection object! You should never see this message.");
		return 0;
	}
	c->last_seen = p->header.ts.tv_sec;
	if (c->traffic_seen <= class->cutoff) {
		c->traffic_seen += p->header.len;
		dumper_tool_dump(class->dumper , &p->header, p->data);
	} else {
		//connection_free(c);
	}

	return 0;
}
