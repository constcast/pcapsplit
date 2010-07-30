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

#include "packet.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

#include <pthread.h>

#include <tools/msg.h>

struct packet_pool {
	struct packet* pool;
	list_t* free_list;
	list_t* used_list;

	uint32_t pool_size;
	uint32_t max_packet_size;

	pthread_mutex_t free_lock;
	pthread_mutex_t used_lock;

	pthread_mutex_t wait_for_free;
	pthread_mutex_t wait_for_used;
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

	pthread_mutex_init(&ret->wait_for_free, NULL);
	pthread_mutex_init(&ret->wait_for_used, NULL);

	if (!ret->free_list) {
		msg(MSG_ERROR, "Could not allocate memory for free_list");
		goto out;
	}

	ret->used_list = list_create();
	if (!ret->used_list) {
		msg(MSG_ERROR, "Could not allocate memory for used_list");
	}
	ret->pool = (struct packet*)malloc(pool_size * (sizeof(struct packet)));
	for (i = 0; i != pool_size; ++i) {
		struct packet* p = &ret->pool[i];
		p->data = malloc(sizeof(unsigned char) * max_packet_size);
		p->elem = (struct list_element_t*)malloc(sizeof(struct list_element_t));
		p->elem->data = p;
		list_push_back(ret->free_list, p->elem);
	}

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
	pthread_mutex_destroy(&pool->wait_for_free);
	pthread_mutex_destroy(&pool->wait_for_used);
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

	if (!e) {
		pthread_mutex_lock(&pool->wait_for_free);
		return packet_new(pool, header, data);
	}
	ret = e->data;
	if (!ret) {
		msg(MSG_ERROR, "No new free packets. Losing packet!");
		return -1;
	}
	memcpy(&ret->header, header, sizeof(*header));
	memcpy(ret->data, data, header->caplen);
	uint16_t et = ntohs(ETHERNET(data)->ether_type);
	if (!(et == ETHERTYPE_IP || et == ETHERTYPE_IPV6 || et == ETHERTYPE_VLAN)) {
		ret->is_ip = ret->is_ip6 = 0;
		ret->ip =  NULL;
		ret->ip6 = NULL;
		//msg(MSG_ERROR, "Unknown packet type: %d. What is it?", et);
	}

	uint8_t  offset = et == ETHERTYPE_VLAN?4:0; // ethernetheader is shifted by four bytes if vlan is available
	// we don't know whether we received ip or ipv6. So lets try:
	if ((IP(data + offset))->ip_v == 4 || et == ETHERTYPE_IP) {
		ret->is_ip6 = 0;
		ret->is_ip  = 1;
		ret->ip =  IP(data);
		ret->ip6 = NULL;
		//msg(MSG_ERROR, "Found IPv4 packet");
	} else if ((IP(data + offset))->ip_v == 6 || et == ETHERTYPE_IPV6) {
		ret->is_ip6 = 1;
		ret->is_ip  = 0;
		ret->ip = NULL;
		ret->ip6 = IP6(data);
		//msg(MSG_ERROR, "Found IPv6 packet");
	} else {
		//msg(MSG_ERROR, "Well. Something is weird here!: Ethertype: %d, IP vesrsion: %d", et, (IP(data + offset))->ip_v);
	}

	pthread_mutex_lock(&pool->used_lock);
	list_push_back(pool->used_list, e);
	pthread_mutex_unlock(&pool->used_lock);
	pthread_mutex_unlock(&pool->wait_for_used);

	return 0;
}

int packet_free(struct packet_pool* pool, struct packet* packet)
{
	//list_delete_element(pool->used_list, packet->elem);
	pthread_mutex_lock(&pool->free_lock);
	list_push_back(pool->free_list, packet->elem);
	pthread_mutex_unlock(&pool->free_lock);
	pthread_mutex_unlock(&pool->wait_for_free);
	return 0;
}

struct packet* packet_get(struct packet_pool* pool)
{
	pthread_mutex_lock(&pool->used_lock);
	struct list_element_t* e = list_pop_front(pool->used_list);
	pthread_mutex_unlock(&pool->used_lock);
	if (!e) {
		pthread_mutex_lock(&pool->wait_for_used);
		return packet_get(pool);	
	}
	return e->data;
}

