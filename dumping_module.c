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

#include "dumping_module.h"

#include <stdlib.h>
#include <string.h>

int dumpers_init(struct dumpers* d)
{
	d->modules = NULL;
	d->count = 0;
	return 0;
}

int dumpers_finish(struct dumpers* d)
{
	size_t i;
	for (i = 0; i != d->count; ++i) {
		if (d->modules[i].dfinish) {
			d->modules[i].dfinish(&d->modules[i]);
		}
	}
	free(d->modules);
	return 0;
}

int dumpers_add(struct dumpers* d, struct dumping_module* dm)
{
	size_t n = ++d->count;
	d->modules = (struct dumping_module*)realloc(d->modules,
		n * sizeof(struct dumping_module));
	memcpy(&d->modules[n-1], &dm, sizeof(struct dumping_module));
	return 0;
}
