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

#include "dump_classes.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <tools/pcap-tools.h>
#include <tools/msg.h>

#define MAX_FILENAME 65535

list_t* classes_create(const char* module_name, struct config* c, int linktype)
{
        list_t* ret;
        uint32_t class_no;
        uint32_t class_count;
	uint32_t cutoff;
        char conf_name[MAX_FILENAME];
        const char* class_name;
        const char* filter_string;
        const char* prefix;
	const char* tmp;
	pcap_t* p;

        ret = list_create();
        if (!ret) {
                msg(MSG_ERROR, "%s: Could not create list: %s", module_name, strerror(errno));
                goto out1;
        }

        if (!config_get_option(c, module_name, "number_of_classes")) {
                msg(MSG_ERROR, "%s: missing \"number_of_classes\". Cannot configure %s", module_name, module_name);
                goto out2;
        } else {
                class_count = atoi(config_get_option(c, module_name, "number_of_classes"));
        }

        prefix = config_get_option(c, module_name, "file_prefix");
        if (!prefix) {
                msg(MSG_ERROR, "%s: missing \"file_prefix\". Cannot configure %s", module_name, module_name);
                goto out2;
        }

        p = pcap_open_dead(linktype, 65535);
        // TODO: Introdcude a config parameter fro configuring the number of classes because the code below sucks
        // build filters from module confiugration
        // open pcap files for every defined class
        for (class_no = 1; class_no <= class_count; ++class_no) {
                snprintf(conf_name, MAX_FILENAME, "class%d", class_no);
                class_name = config_get_option(c, module_name, conf_name);
                if (!class_name) {
                        msg(MSG_ERROR, "%s: could not find %s in config file!", module_name, conf_name);
                        goto out2;
                }

                snprintf(conf_name, MAX_FILENAME, "filter%d", class_no);
                filter_string = config_get_option(c, module_name, conf_name);
                if (!filter_string) {
                        msg(MSG_ERROR, "%s: Could not find filter expression for class %s. Cannot recover from that!", module_name, class_name);
                        goto out2;
                }

		tmp = config_get_option(c, module_name, "cutoff");
		if (!tmp) {
			cutoff = 0;
		} else {
			cutoff = atoi(tmp);
		}
		
                struct list_element_t* le = (struct list_element_t*)malloc(sizeof(struct list_element_t));
                struct class_t* f = (struct class_t*)malloc(sizeof(struct class_t));
                if (-1 == pcap_compile(p, &f->filter_program, filter_string,  0, 0)) { // TODO: check whether optimize in pcap_compile could be usefull
                        msg(MSG_ERROR, "%s: Could not compile pcap filter %s: %s", module_name, filter_string, pcap_geterr(p));
                        // TODO: cleanup this one, too 
                        goto out2;
                }

               	f->prefix = prefix;
		f->class_name = class_name;
		f->cutoff = cutoff;

                le->data = f;
                list_push_back(ret, le);
        };

        return ret;
out2:
        free(ret);
out1: 
        return NULL;

}

