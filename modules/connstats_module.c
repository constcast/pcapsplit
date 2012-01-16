//  Copyright (C) 2012 Lothar Braun <lothar@lobraun.de>
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

#include "connstats_module.h"

#include <module_list.h>
#include <tools/connection.h>
#include <tools/msg.h>
#include <tools/conf.h>

#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <errno.h>

struct dumping_module* connstats_module_new()
{
	struct dumping_module* ret = (struct dumping_module*)malloc(sizeof(struct dumping_module));
	ret->dinit = connstats_module_init;
	ret->dfunc = connstats_module_run;
	ret->dfinish = connstats_module_finish;

	return ret;
}

static uint8_t has_init = 0;
struct connstats_module_data {
	const char* filename;
	FILE* fd;
} cs;

static void connstats_connection_finished(struct connection* c)
{
	//msg(MSG_DEBUG, "Conn: %u %u %llu", c->first_seen, c->last_seen, c->traffic_seen);
	/* uint32_t tmp = floorl((long double)c->traffic_seen / sm_data.binwidth); */
	/* if (tmp >= sm_data.bin_count) { */
	/* 	tmp = sm_data.bin_count - 1; */
	/* } */
	/* sm_data.bins[tmp]++; */
}

int connstats_module_init(struct dumping_module* m, struct config* c)
{
	// we can only run one instance of the stats_module. If this has already been allocated,
	// then we have no other choice than exiting ...
	if (has_init) {
		msg(MSG_FATAL, "stats module has already been initiatlized. It may not be instanciated twice ...");
		return -1;
	}

	has_init = 1;

	const char* tmp;

	tmp = config_get_option(c, CONNSTATS_MODULE_NAME, "filename");
	if (tmp) {
		cs.filename = tmp;
	} else {
		msg(MSG_FATAL, "%s: Could not find configuration for \"filename\"", CONNSTATS_MODULE_NAME);
		return -1;
	}

	cs.fd = fopen(cs.filename, "w+");
	if (!cs.fd) {
		msg(MSG_FATAL, "%s: Could not open log file \"%s\" for writing: %s", CONNSTATS_MODULE_NAME, cs.filename, strerror(errno));
		return -1;
	}

	conn_finished_cb = connstats_connection_finished;
	return 0;
}

int connstats_module_finish(struct dumping_module* m)
{
	fclose(cs.fd);
	return 0;
}


int connstats_module_run(struct dumping_module* m, struct packet* p)
{
	struct ether_header* eth = ETHERNET(p);
	int dmac;
	memcpy(&dmac, &eth->ether_dhost, sizeof(dmac));;
	if (dmac == 1) {
		msg(MSG_FATAL, "Last packet of connection");
	} else {
		return 0;

	}
        uint32_t sampled;
	memcpy(&sampled, &eth->ether_shost, sizeof(sampled));
	msg(MSG_FATAL, "sampled %u", sampled);
	return 0;
}
