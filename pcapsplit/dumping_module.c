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

#include "dumping_module.h"
#include "module_list.h"

#include <stdlib.h>
#include <string.h>

int dumpers_init(struct dumpers* d)
{
	d->count = 0;
	return 0;
}

int dumpers_finish(struct dumpers* d)
{
	size_t i;
	for (i = 0; i != d->count; ++i) {
		if (d->modules[i]->dfinish) {
			d->modules[i]->dfinish(d->modules[i]);
		}
	}
	return 0;
}

int dumpers_add(struct dumpers* d, struct dumping_module* dm)
{
	d->modules[d->count] = dm;
	++d->count;
	return 0;
}

void create_all_dumpers(struct dumpers* d, struct config* c, int linktype, int snaplen)
{
	const char* module_names[MAX_MODULES];
	size_t mod_count = config_get_module_names(c, module_names);
	size_t i;
	for (i = 0; i != mod_count; ++i) {
		struct dumping_module* m = get_module(module_names[i]);
		if (m == NULL) {
			fprintf(stderr, "No such module %s\n", module_names[i]);
			continue;
		}
		m->linktype = linktype;
		m->snaplen = snaplen;
		m->dinit(m, c);
		dumpers_add(d, m);
	}
}

