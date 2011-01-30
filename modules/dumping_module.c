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
#include <modules/module_list.h>

#include <stdlib.h>
#include <string.h>

#include <tools/msg.h>

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

void dumpers_create_all(struct dumpers* d, struct config* c, int linktype, int snaplen)
{
	const char* module_names[MAX_MODULES];
	size_t mod_count = config_get_module_names(c, module_names);
	size_t i;

	msg(MSG_INFO, "Found %d modules in configuration file.", mod_count);

	if (mod_count > MAX_MODULES) {
		msg(MSG_ERROR, "More modules in config files than allowed!");
		return;
	}
	for (i = 0; i != mod_count; ++i) {
		if (strcmp(module_names[i], MAIN_NAME) == 0) {
			continue;
		}
		msg(MSG_INFO, "Initializing module \"%s\" ...", module_names[i]);
		struct dumping_module* m = get_module(module_names[i]);
		if (m == NULL) {
			msg(MSG_ERROR, "No such module %s", module_names[i]);
			continue;
		}
		m->linktype = linktype;
		m->snaplen = snaplen;
		if (m->dinit(m, c) < 0) {
			msg(MSG_ERROR, "Failed to initialize module %s. Not adding module to dumper tree", module_names[i]);
			continue;
		}
		dumpers_add(d, m);
	}
	msg(MSG_INFO, "Initialized all modules ...");
}

