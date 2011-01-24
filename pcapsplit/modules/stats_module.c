//  Copyright (C) 2011 Lothar Braun <lothar@lobraun.de>
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

#include "stats_module.h"

#include <module_list.h>
#include <tools/connection.h>
#include <tools/msg.h>

#include <stdlib.h>

struct dumping_module* stats_module_new()
{
	struct dumping_module* ret = (struct dumping_module*)malloc(sizeof(struct dumping_module));
	ret->dinit = stats_module_init;
	ret->dfunc = stats_module_run;
	ret->dfinish = stats_module_finish;

	return ret;
}

static void stats_connection_finished(struct connection* c)
{
	msg(MSG_DEBUG, "Finished connection");
}

int stats_module_init(struct dumping_module* m, struct config* data)
{
	conn_finished_cb = stats_connection_finished;
	return 0;
}

int stats_module_finish(struct dumping_module* m)
{
	return 0;
}


int stats_module_run(struct dumping_module* m, struct packet* p)
{
	return 0;
}
