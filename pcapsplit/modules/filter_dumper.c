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

#include <tools/list.h>
#include <tools/pcap-tools.h>
#include <module_list.h>

#include <stdlib.h>
#include <string.h>
#include <pcap.h>

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
	pcap_t* p;
};

struct filter_element {
	struct bpf_program filter_program;
	struct dumper_tool* dumper;
};
	

int filter_dumper_init(struct dumping_module* m, struct config* c)
{
	struct filter_dumper_data* sdata = (struct filter_dumper_data*)malloc(sizeof(struct filter_dumper_data));
	int class_no = 0;
	char conf_name[MAX_FILENAME];
	const char* class_name;
	const char* filter_string;
	char pcap_file[MAX_FILENAME];
	const char* prefix = config_get_option(c, FILTER_DUMPER_NAME, "file_prefix");
	
	sdata->filter_list = list_create();
	if (!sdata->filter_list) {
		fprintf(stderr, "Could not create filter_list\n");
		// TODO: cleanup
		return -1;
	}
	sdata->p = pcap_open_dead(m->linktype, 65535);

	// TODO: Introdcude a config parameter fro configuring the number of classes because the code below sucks
	// build filters from module confiugration
	// open pcap files for every defined class
	do {
		class_no++;
		snprintf(conf_name, MAX_FILENAME, "class%d", class_no);
		class_name = config_get_option(c, FILTER_DUMPER_NAME, conf_name);
		if (!class_name)
			continue;

		snprintf(conf_name, MAX_FILENAME, "filter%d", class_no);
		filter_string = config_get_option(c, FILTER_DUMPER_NAME, conf_name);
		if (!filter_string) {
			fprintf(stderr, "Could not find filter expression for class %s. Cannot recover from that!\n", class_name);
			// TODO: cleanup allocated memory ...!
			// TODO2: We could recover .... !
			return -1;
		}
		struct list_element_t* le = (struct list_element_t*)malloc(sizeof(struct list_element_t));
		struct filter_element* f = (struct filter_element*)malloc(sizeof(struct filter_element));
		if (-1 == pcap_compile(sdata->p, &f->filter_program, filter_string,  0, 0)) { // TODO: check whether optimize in pcap_compile could be usefull
			fprintf(stderr, "Could not compile pcap filter %s: %s\n", filter_string, pcap_geterr(sdata->p));
			// TODO: cleanup this one, too 
			return -1;
		}

		// open pcap file
		snprintf(pcap_file, MAX_FILENAME, "%s%s", prefix, class_name);
		f->dumper = dumper_tool_open_file(pcap_file, m->linktype);
		if (!f->dumper) {
			fprintf(stderr, "Cannot open pcap file\n");
			//TODO: cleanup
			return -1;
		}
	
		le->data = f;
		list_push_back(sdata->filter_list, le);
	} while (class_name);

	m->module_data = (void*)sdata;

	return 0;
}

int filter_dumper_finish(struct dumping_module* m)
{
	struct filter_dumper_data* d = (struct filter_dumper_data*)m->module_data;
	free(d);
	m->module_data = NULL;
	return 0;
}

int filter_dumper_run(struct dumping_module* m, struct packet* p)
{
	//struct size_dumper_data* d = (struct size_dumper_data*)m->module_data;
	return 0;
}
