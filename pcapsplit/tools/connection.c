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

#include "connection.h"

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <string.h>
#include <tools/list.h>
		
struct connection_pool_t {
	struct connection* pool;
	list_t* free_list;
	list_t* used_list;

	uint32_t pool_size;
	uint32_t max_pool_size;
};

struct connection_pool_t connection_pool;

int connection_fill(struct connection* c, struct packet* p)
{
	if (p->is_ip) {
		uint16_t sport, dport;
		sport = dport = 0;
		struct ip* ip = p->ip;

		// TOOD: Handle SCTP. Is this relevant?
		if (ip->ip_p == IPPROTO_TCP) {
			struct tcphdr* tcp = (struct tcphdr*)(ip + IP_HDR_LEN(ip));
			sport = tcp->th_sport;
			dport = tcp->th_dport;
		} else if (ip->ip_p == IPPROTO_UDP) {
			struct udphdr* udp = (struct udphdr*)(ip + IP_HDR_LEN(ip));
			sport = udp->uh_sport;
			dport = udp->uh_dport;
		}
		if (ip->ip_src.s_addr < ip->ip_dst.s_addr) {
			c->key.c_v4.ip1 = ip->ip_src.s_addr;
			c->key.c_v4.ip2 = ip->ip_dst.s_addr;
			c->key.c_v4.p1  = sport;
			c->key.c_v4.p2  = dport; 
		} else {
			c->key.c_v4.ip1 = ip->ip_dst.s_addr;
			c->key.c_v4.ip2 = ip->ip_src.s_addr;
			c->key.c_v4.p1  = dport;
			c->key.c_v4.p2  = sport;
		}
	} else if (p->is_ip6) {
		// TOOD handle IPv6. This is relevant!
	} else {
		fprintf(stderr, "connection_fill: Error, unkonwn packet type\n");
		return -1;
	}	
	return 0;
}

int connection_init_pool(uint32_t pool_size, uint32_t max_pool_size)
{
	uint32_t i;

	connection_pool.pool_size = pool_size;
	connection_pool.max_pool_size = max_pool_size;
	connection_pool.pool = (struct connection*)malloc(sizeof(struct connection) * pool_size);

	connection_pool.free_list = list_create();
	connection_pool.used_list = list_create();

	for (i = 0; i != pool_size; ++i) {
		memset(&connection_pool.pool[i], 0, sizeof(struct connection));
		struct list_element_t* e = (struct list_element_t*)malloc(sizeof(struct list_element_t));
		e->data = &connection_pool.pool[i];
		list_push_back(connection_pool.free_list, e);
	}

	return 0;
}

int connection_deinit_pool()
{
	free(connection_pool.pool);
	list_destroy(connection_pool.free_list);
	list_destroy(connection_pool.used_list);

	return 0;
}

struct connection* connection_new()
{
	
	return NULL;
}

int connection_free(struct connection* c)
{
	return 0;
}

