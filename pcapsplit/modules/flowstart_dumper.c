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
#include <unistd.h>

#define MAX_FILENAME 65535

int fd_handle_packet(struct class_t* t, struct packet* p, struct connection* c);
int perform_postprocessing(const char* command, const char* filename);

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
	char pcap_file[MAX_FILENAME];

	struct flowstart_dumper_data* sdata = (struct flowstart_dumper_data*)malloc(sizeof(struct flowstart_dumper_data));
	if (!sdata) {
		msg(MSG_ERROR, "flowstart_dumper: Could not create flowstart dumper data: %s", strerror(errno));
		goto out1;
	}

	sdata->filter_list = classes_create(FLOWSTART_DUMPER_NAME, c, m->linktype);
	if (!sdata->filter_list)
		goto out2;

	struct list_element_t* i = sdata->filter_list->head;
	while (i) {
		struct class_t* t = i->data;
		if (t->is_stdout) {
			snprintf(pcap_file, 2, "-");
		} else {
			snprintf(pcap_file, MAX_FILENAME, "%s%s-%08x", t->prefix, t->class_name, t->suffix);
			t->suffix++;
		}
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
	m->module_data = NULL;
	return 0;
}

int flowstart_dumper_run(struct dumping_module* m, struct packet* p)
{
	struct flowstart_dumper_data* d = (struct flowstart_dumper_data*)m->module_data;
	struct connection* c = p->connection;
	uint32_t max_cutoff = 0;
	if (!c) {
		//msg(MSG_FATAL, "Something is fucked up: Did not get a connection object! You should never see this message.");
		return 0;
	}


	struct list_element_t* i = d->filter_list->head;
	while (i)  {
		struct class_t* class = (struct class_t*)i->data;
		if (bpf_filter(class->filter_program.bf_insns, (u_char*)p->data, p->header.len, p->header.caplen)) {
			if (class->cutoff > max_cutoff) {
				max_cutoff = class->cutoff;
			}
			fd_handle_packet(class, p, c);
		}
		i = i->next;
	}

	// mark connection as active if it has not yet received
	// any traffic
	if (c->traffic_seen == 0) {
		connection_get_stats()->active_conns++;
	}

	// mark connetion as inactive, if the current paket would exeed the
	// maximum connection limit of all classes that matches the connection

	// TODO: do we want to use len or caplen?
	if (c->traffic_seen <= max_cutoff && (c->traffic_seen + p->header.len > max_cutoff)) {
		connection_get_stats()->active_conns--;
		if (!c->active) {
			msg(MSG_ERROR, "Active/Inactive connection calculation is fucked up!. Fix This!");
		}
		c->active = 0;
		
	}
	c->traffic_seen += p->header.len;

	//msg(MSG_INFO, "No matching filter for packet: Skipping packet!");

	return 0;
}

int fd_handle_packet(struct class_t* class, struct packet* p, struct connection* c)
{
	if (!class->cutoff || c->traffic_seen <= class->cutoff) {
		// Check whether we need to open a new file
		// we have to open a new file only if class_file_size if defined
		if (class->file_size && (class->file_traffic_seen + p->header.len) > class->file_size) {
			char pcap_file[MAX_FILENAME];
			// finish old file 
			if (class->post_process)
				perform_postprocessing(class->post_process, class->dumper->filename);

			// close old file in case we are not dumping to stdout
			if (!class->is_stdout) {
				dumper_tool_close_file(&class->dumper);

				// open new file, if not dumping to stdout
				snprintf(pcap_file, MAX_FILENAME, "%s%s-%08x", class->prefix, class->class_name, class->suffix);
				class->suffix++;
				class->dumper = dumper_tool_open_file(pcap_file, class->linktype);
				if (!class->dumper) {
					msg(MSG_ERROR, "filter_dumper: Cannot open pcap file %s", pcap_file);
					return -1;
				}
			}
			class->file_traffic_seen = p->header.len;
			// update statistics
			// TODO: what about disk_traffic_seen?

			// TODO: rotate files if necessary
		} else {
			class->file_traffic_seen += p->header.len;
		}

		dumper_tool_dump(class->dumper , &p->header, p->data);
	} 
	return 0;
}

int perform_postprocessing(const char* command, const char* filename)
{
	msg(MSG_INFO, "starting post-processing with command %s on file %s", command, filename);
	pid_t pid = fork();
	if (pid < 0) {
		msg(MSG_FATAL, "Error forking process! Cannot post-process file!");
		return -1;
	} else if (pid > 0) {
		// we are the parent. we don't have to do anything
		return 0;
	}

	// child code: exec the command
	int ret;
	int command_len = strlen(command) + strlen(filename) + 10;
	char* c = malloc(command_len);
	memset(c, 0, command_len);
	snprintf(c, command_len, "%s %s", command, filename);
	ret = execl("/bin/sh", "/bin/sh", "-c", c, NULL);

	free(c);
	
	// if we are here, we ahve a problem:
	msg(MSG_FATAL, "Could not exec command \"%s\": %s", command, strerror(errno));
	exit(-1);
	
	return -1;
}

