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

#include "packet.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

#include <pthread.h>

#include <tools/msg.h>
#include <tools/connection.h>

struct packet_pool {
	struct packet* pool;
	list_t* free_list;
	list_t* used_list;

	uint32_t pool_size;
	uint32_t max_packet_size;

	pthread_mutex_t free_lock;
	pthread_mutex_t used_lock;

	uint64_t packets_lost;

	uint64_t packets_seen;
};

struct packet_pool*  packet_pool_init(uint32_t pool_size, uint32_t max_packet_size)
{
	struct packet_pool* ret = (struct packet_pool*)malloc(sizeof(struct packet_pool));
	uint32_t i;
	if (!ret) {
		msg(MSG_ERROR, "Could not allocate memory for packet_pool!");
		return NULL;
	}
	ret->pool_size = pool_size;
	ret->max_packet_size = max_packet_size;
	ret->free_list = list_create();
	pthread_mutex_init(&ret->free_lock, NULL);
	pthread_mutex_init(&ret->used_lock, NULL);

	if (!ret->free_list) {
		msg(MSG_ERROR, "Could not allocate memory for free_list");
		goto out;
	}

	ret->used_list = list_create();
	if (!ret->used_list) {
		msg(MSG_ERROR, "Could not allocate memory for used_list");
		goto out;
	}
	ret->pool = (struct packet*)malloc(pool_size * (sizeof(struct packet)));
	for (i = 0; i != pool_size; ++i) {
		struct packet* p = &ret->pool[i];
		p->data = malloc(sizeof(unsigned char) * max_packet_size);
		p->elem = (struct list_element_t*)malloc(sizeof(struct list_element_t));
		p->elem->data = p;
		list_push_back(ret->free_list, p->elem);
	}
	ret->packets_lost = 0;
	ret->packets_seen = 0;

	return ret;
out:
	free(ret);
	return NULL;
}

int packet_pool_deinit(struct packet_pool* pool)
{
	struct list_element_t* e = pool->free_list->head; 
	struct packet* p;
	while (e) {
		p = e->data;	
		free(p->data);
		e = e->next;
	}
	e = pool->used_list->head;
	while (e) {
		p = e->data;
		free(p->data);
		e = e->next;
	}
	pthread_mutex_destroy(&pool->free_lock);
	pthread_mutex_destroy(&pool->used_lock);
	free(pool->pool);
	free(pool);
	return 0;
}

int packet_new(struct packet_pool* pool, struct pcap_pkthdr* header, const unsigned char* data)
{
	struct packet* ret = NULL;
	pthread_mutex_lock(&pool->free_lock);
	struct list_element_t* e = list_pop_front(pool->free_list);
	pthread_mutex_unlock(&pool->free_lock);

	pool->packets_seen++;
	if (!(pool->packets_seen % 1000000)) {
		msg(MSG_STATS, "Seen: %llu, Used: %llu, Free: %llu", pool->packets_seen, pool->used_list->size, pool->free_list->size);
	}

	if (!e) {
		pool->packets_lost++;
		return -1;
	}
	ret = e->data;

	memcpy(&ret->header, header, sizeof(*header));
	memcpy(ret->data, data, header->caplen);
	uint16_t et = ntohs(ETHERNET(data)->ether_type);
	if (!(et == ETHERTYPE_IP || et == ETHERTYPE_IPV6 || et == ETHERTYPE_VLAN)) {
		ret->is_ip = ret->is_ip6 = 0;
		ret->ip =  NULL;
		ret->ip6 = NULL;
	}

	uint8_t  offset = et == ETHERTYPE_VLAN?4:0; // ethernetheader is shifted by four bytes if vlan is available
	// we don't know whether we received ip or ipv6. So lets try:
	if ((IP(data + offset))->ip_v == 4 || et == ETHERTYPE_IP) {
		ret->is_ip6 = 0;
		ret->is_ip  = 1;
		ret->ip =  IP(ret->data + offset);
		ret->ip6 = NULL;
		ret->ipheader_offset = ETHER_HDR_LEN + offset;
		//msg(MSG_ERROR, "Found IPv4 packet");
	} else if ((IP(data + offset))->ip_v == 6 || et == ETHERTYPE_IPV6) {
		ret->is_ip6 = 1;
		ret->is_ip  = 0;
		ret->ip = NULL;
		ret->ip6 = IP6(ret->data + offset);
		ret->ipheader_offset = ETHER_HDR_LEN + offset;
	} else {
		//msg(MSG_ERROR, "Well. Something is weird here!: Ethertype: %d, IP vesrsion: %d", et, (IP(data + offset))->ip_v);
	}
	
	// only handle packets if its connection is still active
	ret->connection = connection_get(ret);
	// TODO: we should discard the packet earlier, at best before copying the packet content
	if (ret->connection && ret->connection->active) {
		pthread_mutex_lock(&pool->used_lock);
		list_push_back(pool->used_list, e);
		pthread_mutex_unlock(&pool->used_lock);
	} else {
		packet_free(pool, ret);
	}

	return 0;
}

int packet_free(struct packet_pool* pool, struct packet* packet)
{
	pthread_mutex_lock(&pool->free_lock);
	list_push_back(pool->free_list, packet->elem);
	pthread_mutex_unlock(&pool->free_lock);
	return 0;
}

struct packet* packet_get(struct packet_pool* pool)
{
	pthread_mutex_lock(&pool->used_lock);
	struct list_element_t* e = list_pop_front(pool->used_list);
	pthread_mutex_unlock(&pool->used_lock);
	if (!e) {
		return NULL;
	}
	return e->data;
}

uint64_t packet_lost(struct packet_pool* pool)
{
	return pool->packets_lost;
}

