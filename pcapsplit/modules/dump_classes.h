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

#ifndef _DUMP_CLASSES_H_
#define _DUMP_CLASSES_H_

#include <pcap.h>
#include <tools/list.h>
#include <conf.h>
#include <stdint.h>

struct class_t {
        struct bpf_program filter_program;
	const char* prefix;
	const char* class_name;
	uint32_t cutoff;
	struct dumper_tool* dumper;
};

list_t* classes_create(const char* module_name, struct config* c, int linktype);


#endif
