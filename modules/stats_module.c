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
#include <tools/conf.h>

#include <stdlib.h>
#include <math.h>

struct dumping_module* stats_module_new()
{
	struct dumping_module* ret = (struct dumping_module*)malloc(sizeof(struct dumping_module));
	ret->dinit = stats_module_init;
	ret->dfunc = stats_module_run;
	ret->dfinish = stats_module_finish;

	return ret;
}

struct stats_module_data {
	uint64_t total_data;
	uint32_t min;
	uint32_t max;
	uint32_t binwidth;
	uint32_t* bins;
	uint32_t bin_count;
} sm_data;

static uint8_t has_init = 0;

static void stats_connection_finished(struct connection* c)
{
	//msg(MSG_DEBUG, "Conn: %u %u %llu", c->first_seen, c->last_seen, c->traffic_seen);
	uint32_t tmp = floorl((long double)c->traffic_seen / sm_data.binwidth);
	if (tmp >= sm_data.bin_count) {
		tmp = sm_data.bin_count - 1;
	}
	sm_data.bins[tmp]++;
}

int stats_module_init(struct dumping_module* m, struct config* c)
{
	// we can only run one instance of the stats_module. If this has already been allocated,
	// then we have no other choice than exiting ...
	if (has_init) {
		msg(MSG_FATAL, "stats module has already been initiatlized. It may not be instanciated twice ...");
		return -1;
	}

	has_init = 1;

	uint32_t min, max, binwidth, i;
	const char* tmp;

	tmp = config_get_option(c, STATS_MODULE_NAME, "min");
	if (tmp) {
		min = atoi(tmp);
	} else {
		msg(MSG_FATAL, "%s: Could not find configuration for \"min\"", STATS_MODULE_NAME);
		return -1;
	}

	tmp = config_get_option(c, STATS_MODULE_NAME, "max");
	if (tmp) {
		max = atoi(tmp);
	} else {
		msg(MSG_FATAL, "%s: Could not find configuration for \"max\"", STATS_MODULE_NAME);
		return -1;
	}

	if (max < min) {
		msg(MSG_FATAL, "%s: Max < Min!!!!!", STATS_MODULE_NAME);
		return -1;
	}

	tmp = config_get_option(c, STATS_MODULE_NAME, "binwidth");
	if (tmp) {
		binwidth = atoi(tmp);
	} else {
		msg(MSG_FATAL, "%s: Could not find configuration for \"binwidth\"", STATS_MODULE_NAME);
		return -1;
	}

	if (binwidth == 0) {
		msg(MSG_FATAL, "%s: Binwidth == 0. This is stupid!", STATS_MODULE_NAME);
		return -1;
	}

	sm_data.min = min;
	sm_data.max = max;
	sm_data.binwidth = binwidth;
	sm_data.total_data = 0;
	sm_data.bin_count = (max - min) / binwidth;
	sm_data.bins = malloc(sizeof(uint32_t) * sm_data.bin_count);
	for (i = 0; i != sm_data.bin_count; ++i) {
		sm_data.bins[i] = 0;
	}

	conn_finished_cb = stats_connection_finished;
	return 0;
}

int stats_module_finish(struct dumping_module* m)
{
	uint32_t i;
	for (i = 0; i != sm_data.bin_count; ++i) {
		msg(MSG_DEBUG, "%lu %u", i * sm_data.binwidth, sm_data.bins[i]);
	}

	free(sm_data.bins);
	return 0;
}


int stats_module_run(struct dumping_module* m, struct packet* p)
{
	// do nothing on the packet
	return 0;
}
