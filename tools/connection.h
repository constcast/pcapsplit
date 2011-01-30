//  Copyright (C) 2010-2011 Lothar Braun <lothar@lobraun.de>
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

#ifndef _CONNECTION_H_
#define _CONNECTION_H_

#include <stdint.h>
#include <netinet/in.h>
#include <tools/uthash.h>
#include <tools/packet.h>
#include <tools/list.h>

struct connection_v4 {
	uint32_t ip1;
	uint32_t ip2;
	uint16_t p1;
	uint16_t p2;
	uint8_t proto;
};

struct connection_v6 {
	struct in6_addr ip1;
	struct in6_addr ip2;
	uint16_t p1;
	uint16_t p2;
	uint8_t proto;
};

typedef union {
	struct connection_v4 c_v4;
	struct connection_v4 c_v6;
} record_key_t;


struct connection {
	record_key_t key;
	
	struct list_element_t element;

	time_t first_seen;
	time_t last_seen;
	uint64_t traffic_seen;
	uint8_t active;
	
	UT_hash_handle hh;
};

struct connection_stats {
	uint64_t used_conns;
	uint64_t free_conns;
	uint64_t active_conns;
	uint64_t active_conns_timed_out;

	uint64_t out_of_connections;

};

int connection_init_pool(uint32_t pool_size, uint32_t max_pool_size, uint32_t timeout);
int connection_deinit_pool();
int connection_flush_all_active_conns();

struct connection* connection_get(const struct packet* p);
int connection_free(struct connection*);

uint32_t connection_get_used();
uint32_t connection_get_free();

struct connection_stats* connection_get_stats();

// callbacks that can be used for statistics
void (*conn_finished_cb)(struct connection* c);

#endif
