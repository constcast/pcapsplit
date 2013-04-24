//  Copyright (C) 2013 Lothar Braun <braun@net.in.tum.de>
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

#include "ssh_dumper.h"
#include "dump_classes.h"

#include <tools/list.h>
#include <tools/pcap-tools.h>
#include <tools/msg.h>
#include <tools/connection.h>
#include <module_list.h>

#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_FILENAME 65535

struct dumping_module* ssh_dumper_new()
{
	struct dumping_module* ret = (struct dumping_module*)malloc(sizeof(struct dumping_module));
	ret->dinit = ssh_dumper_init;
	ret->dfunc = ssh_dumper_run;
	ret->dfinish = ssh_dumper_finish;
	return ret;
}

struct ssh_dumper_data {
	list_t* classes_list;
};

int ssh_dumper_init(struct dumping_module* m, struct config* c)
{
	char pcap_file[MAX_FILENAME];
	struct ssh_dumper_data* sdata = (struct ssh_dumper_data*)malloc(sizeof(struct ssh_dumper_data));
	if (!sdata) {
		msg(MSG_ERROR, "ssh_dumper: Could not create ssh dumper data: %s", strerror(errno));
		goto out1;
	}

	sdata->classes_list = classes_create(SSH_DUMPER_NAME, c, m->linktype);
	if (!sdata->classes_list)
		goto out2;

	struct list_element_t* i = sdata->classes_list->head;
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

int ssh_dumper_finish(struct dumping_module* m)
{
	struct ssh_dumper_data* d = (struct ssh_dumper_data*)m->module_data;
	struct list_element_t* i = d->classes_list->tail;
	while (i) {
		struct class_t* f = (struct class_t*)i->data;
		dumper_tool_close_file(&f->dumper);
		pcap_freecode(&f->filter_program);
		i = i->next;
	}
	list_destroy(d->classes_list);
	free(d);
	m->module_data = NULL;
	return 0;
}

int ssh_dumper_run(struct dumping_module* m, struct packet* p)
{
	struct ssh_dumper_data* d = (struct ssh_dumper_data*)m->module_data;
        struct connection* conn = p->connection;
	if (!conn) {
		msg(MSG_FATAL, "Something is fucked up: Did not get a connection object! You should never see this message.");
		return 0;
	}

	struct list_element_t* i = d->classes_list->head;
	while (i)  {
		struct class_t* c = (struct class_t*)i->data;
		if (conn->ssh_dumper_data) {
			dumper_tool_dump(c->dumper , &p->header, p->data);
		} else {
			// we are only after TCP
			struct ip* ip = p->ip;
			if (p->is_ip && ip->ip_p == IPPROTO_TCP) {
				struct tcphdr* tcp = (struct tcphdr*)((uint8_t*)ip + (uint8_t)IP_HDR_LEN(ip));
				unsigned char tcpDataOffset = (tcp->th_off * 4);
				uint16_t payload_len = ntohs(ip->ip_len) - ((uint8_t)IP_HDR_LEN(ip) + tcpDataOffset);
				//msg(MSG_FATAL, "%u %u %u %u", payload_len, ntohs(ip->ip_len), (uint8_t)IP_HDR_LEN(ip), tcpDataOffset);
				if (payload_len > 0) {
					//msg(MSG_FATAL, "%u",  p->ipheader_offset + (uint8_t)IP_HDR_LEN(ip) + tcpDataOffset);
					unsigned char* payload_offset = p->data + p->ipheader_offset + tcpDataOffset + (uint8_t)IP_HDR_LEN(ip);
					
					//msg(MSG_FATAL, "%s %s %u %u: %c%c%c", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst), ntohs(tcp->th_sport), ntohs(tcp->th_dport), payload_offset[0], payload_offset[1], payload_offset[2]);
					if (strncmp((char*)payload_offset, "SSH-", 4) == 0) {
						msg(MSG_FATAL, "FOUND SSH string ... ");	
						conn->ssh_dumper_data = 1;
						dumper_tool_dump(c->dumper, &p->header, p->data);
						return 0;
					} else {
						conn->active = 0;
					}
				} else {
					//msg(MSG_FATAL, "control");
				} 
	 		} else {
				// skip the rest of this connection
				conn->active = 0;
			}

		}
		return 0;
		i = i->next;
	}

	msg(MSG_INFO, "No matching filter for packet: Skipping packet!");

	return 0;
}


