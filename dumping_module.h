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

#ifndef _DUMPING_MODULE_H_
#define _DUMPING_MODULE_H_

#include "packet.h"
#include "conf.h"

#include <sys/types.h>

struct dumping_module;

#define MAX_MODULES 100

typedef int (dumper_init)(struct dumping_module* m, struct config* data);
typedef int (dumper_finish)(struct dumping_module* m);
typedef int (dumper_func)(struct dumping_module* m, struct packet* p);

struct dumping_module {
	dumper_init* dinit;
	dumper_finish* dfinish;
	dumper_func* dfunc;
	void* module_data;
};

struct dumpers {
	struct dumping_module* modules[MAX_MODULES];
	size_t count;
};

int dumpers_init(struct dumpers* d);
int dumpers_finish(struct dumpers* d);
int dumpers_add(struct dumpers* d, struct dumping_module* dm);

void create_all_dumpers(struct dumpers* d, struct config* c);

#endif
