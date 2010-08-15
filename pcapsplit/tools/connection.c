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
#include <tools/msg.h>

#include <arpa/inet.h>
		
struct connection_pool_t {
	struct connection* pool;
	list_t* free_list;
	list_t* used_list;

	uint32_t pool_size;
	uint32_t max_pool_size;
	uint32_t timeout;

	struct connection_stats stats;
};

struct connection_pool_t connection_pool;
struct connection*  connections = NULL;
struct connection lookup_conn;
struct connection* found_conn;

int check_and_free_last(time_t current_time)
{
	struct connection* c = NULL;
	// check if we can recycle any of the used connecitons ...
	struct list_element_t* last = connection_pool.used_list->tail;
	if (!last) {
		if (!connection_pool.free_list->head) {
			msg(MSG_FATAL, "Whoops. We do not have any free connections and also no used connections. This should not happen! I cannot work like this! Einmal mit Profis arbeiten!");
			exit(-1);
		}
		return 0;
	}

	c = last->data;
	if (c->last_seen > current_time) {
		msg(MSG_FATAL, "Whaaa! Something is fucked up in our timing! Old time: %u New Time: %u", c->last_seen, current_time);
		exit(-1);
	} 

	if ((current_time - c->last_seen) > connection_pool.timeout) {
		// Cool! we can reuse the connection as it timed out!
		connection_free(c);
		return 1;
	}
	// we could not free up a connection
	return 0;
}

int key_fill(record_key_t* key, const struct packet* p)
{
	memset(key, 0, sizeof(*key));
	if (p->is_ip) {
		uint16_t sport, dport;
		sport = dport = 0;
		struct ip* ip = p->ip;

		// TOOD: Handle SCTP. Is this relevant?
		if (ip->ip_p == IPPROTO_TCP) {
			struct tcphdr* tcp = (struct tcphdr*)((uint8_t*)ip + (uint8_t)IP_HDR_LEN(ip));
			sport = tcp->th_sport;
			dport = tcp->th_dport;
		} else if (ip->ip_p == IPPROTO_UDP) {
			struct udphdr* udp = (struct udphdr*)((uint8_t*)ip + (uint8_t)IP_HDR_LEN(ip));
			sport = udp->uh_sport;
			dport = udp->uh_dport;
		}
		if (ip->ip_src.s_addr < ip->ip_dst.s_addr) {
			key->c_v4.ip1 = ip->ip_src.s_addr;
			key->c_v4.ip2 = ip->ip_dst.s_addr;
			key->c_v4.p1  = sport;
			key->c_v4.p2  = dport; 
		} else {
			key->c_v4.ip1 = ip->ip_dst.s_addr;
			key->c_v4.ip2 = ip->ip_src.s_addr;
			key->c_v4.p1  = dport;
			key->c_v4.p2  = sport;
		}
		key->c_v4.proto = ip->ip_p;
		//msg(MSG_ERROR, "%d %d %d %d %d", key->c_v4.ip1, key->c_v4.ip2, key->c_v4.p1, key->c_v4.p2, key->c_v4.proto);
	} else if (p->is_ip6) {
		// TOOD handle IPv6. This is relevant!
		//msg(MSG_FATAL, "This is IPv6 and not yet implemented");
	} else {
		// We do not care at the moment
		//msg(MSG_ERROR, "connection_fill: Error, unkonwn packet type: ");
		return -1;
	}	
	return 0;
}

void connection_reset_counters(struct connection* c)
{
	memset(&c->key, 0, sizeof(c->key));
	c->last_seen = 0;
	c->traffic_seen = 0;
	c->active = 0;
}

int connection_init_pool(uint32_t pool_size, uint32_t max_pool_size, uint32_t timeout)
{
	uint32_t i;
	struct connection* c;

	msg(MSG_INFO, "Creating connection pool with size %u", pool_size);
	connection_pool.pool_size = pool_size;
	msg(MSG_INFO, "Connection timeout is %u seconds", timeout);
	connection_pool.timeout = timeout;
	connection_pool.max_pool_size = max_pool_size;
	connection_pool.pool = (struct connection*)malloc(sizeof(struct connection) * pool_size);

	connection_pool.free_list = list_create();
	connection_pool.used_list = list_create();
	
	connection_pool.stats.out_of_connections = 0;
	connection_pool.stats.used_conns = 0;
	connection_pool.stats.free_conns = 0;
	connection_pool.stats.active_conns = 0;
	connection_pool.stats.active_conns_timed_out = 0;

	for (i = 0; i != pool_size; ++i) {
		c = &connection_pool.pool[i];
		memset(c, 0, sizeof(struct connection));
		c->element.data = c;
		
		list_push_back(connection_pool.free_list, &c->element);
		connection_pool.stats.free_conns++;
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

struct connection* connection_new(const struct packet* p)
{
	struct list_element_t* t = list_pop_front(connection_pool.free_list);
	struct connection* ret = NULL;
	if (t) {
		ret = t->data;
		list_push_front(connection_pool.used_list, t);
		connection_pool.stats.used_conns++;
		connection_pool.stats.free_conns--;
	} else {
		if (check_and_free_last(p->header.ts.tv_sec)) {
			// we have now a connection in free_list -> take it;
			// we coud remove it from free_list ourself and save the function call, but we are lazy
			// TODO: check if saving the function is important and fix the call if it is
			ret = connection_new(p);
		} else {
			// TODO: impelement memory reallocation for the conneciotn pool
			//msg(MSG_FATAL, "Whoops. You hit a missing feature. I have used our available conneciotns (specified by \"init_connection_pool\" in the configuration file. I  should now try to allocate more memory until we reach the value given in \"max_connection_pool\". But this is not implemeneted yet. Please increase \"init_connection_pool\" for the next run!");
			connection_pool.stats.out_of_connections++;
			if (connection_pool.stats.out_of_connections % 100000) {
				msg(MSG_FATAL, "Could not find a connection object for %llu packets", connection_pool.stats.out_of_connections);
			}
			ret = NULL;
		}
	}
	if (ret) {
		ret->active = 1;
	}
	
	return ret;
}

int connection_free(struct connection* c)
{
	HASH_FIND(hh, connections, &c->key, sizeof(record_key_t), found_conn);
	if (found_conn) {
		HASH_DEL(connections, c);
	}
	list_delete_element(connection_pool.used_list, &c->element);
	if (c->active) {
		connection_pool.stats.active_conns--;
		connection_pool.stats.active_conns_timed_out++;
	}
	connection_reset_counters(c);
	list_push_back(connection_pool.free_list, &c->element);
	connection_pool.stats.used_conns--;
	connection_pool.stats.free_conns++;
	return 0;
}

struct connection* connection_get(const struct packet* p)
{
	check_and_free_last(p->header.ts.tv_sec);
	key_fill(&lookup_conn.key, p);
	//msg(MSG_ERROR, "New connection: %d %d %d %d", lookup_conn.key.c_v4.ip1, lookup_conn.key.c_v4.ip2, lookup_conn.key.c_v4.p1, lookup_conn.key.c_v4.p2);
	
	HASH_FIND(hh, connections, &lookup_conn.key, sizeof(record_key_t), found_conn);
	if (found_conn) {
		found_conn->last_seen = p->header.ts.tv_sec;
		list_delete_element(connection_pool.used_list, &found_conn->element);
		list_push_front(connection_pool.used_list, &found_conn->element);
		//msg(MSG_ERROR, "New connection: %d %d %d %d", found_conn->key.c_v4.ip1, found_conn->key.c_v4.ip2, found_conn->key.c_v4.p1, found_conn->key.c_v4.p2);
		//msg(MSG_ERROR, "Found connection");
	} else {
		found_conn = connection_new(p);
		if (found_conn) {
			found_conn->last_seen = p->header.ts.tv_sec;
			key_fill(&found_conn->key, p);
			//msg(MSG_ERROR, "New connection: %d %d %d %d", found_conn->key.c_v4.ip1, found_conn->key.c_v4.ip2, found_conn->key.c_v4.p1, found_conn->key.c_v4.p2);
			HASH_ADD(hh, connections, key, sizeof(record_key_t), found_conn);
		}
	}
	return found_conn;
}

struct connection_stats* connection_get_stats()
{
	return &connection_pool.stats;
}

