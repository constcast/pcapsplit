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

#ifndef _SIZE_DUMPER_H_
#define _SIZE_DUMPER_H_

#include <tools/dumping_module.h>
#include <tools/conf.h>

struct dumping_module* size_dumper_new();

int size_dumper_init(struct dumping_module* m, struct config* data);
int size_dumper_finish(struct dumping_module* m);
int size_dumper_run(struct dumping_module* m, struct packet* p);

#endif
