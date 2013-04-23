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

#ifndef _PACKET_H_
#define _PACKET_H_

#include <pcap.h>
#include <tools/list.h>

#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#ifdef linux
#define __FAVOR_BSD
#endif

#include <netinet/udp.h>
#include <netinet/tcp.h>

#define ETHERNET(p) ((struct ether_header*)p)
#define IP(p) (struct ip*)(p + ETHER_HDR_LEN)
#define IP6(p) (struct ip6_hdr*)(p + ETHER_HDR_LEN)
#define IP_HDR_LEN(ip)      (ip->ip_hl*4)

struct connection;

struct packet {
	struct pcap_pkthdr header;
	unsigned char* data;

	uint8_t is_ip;
	uint8_t is_ip6;

	struct ip* ip;
	struct ip6_hdr* ip6;

	uint8_t ipheader_offset;

	struct list_element_t* elem;	
	struct connection* connection;
};

struct packet_pool;

struct packet_pool*  packet_pool_init(uint32_t pool_size, uint32_t max_packet_size);
int packet_pool_deinit(struct packet_pool* pool);

int packet_new(struct packet_pool* pool, struct pcap_pkthdr* header, const unsigned char* data);
int packet_free(struct packet_pool* pool, struct packet* packet);
struct packet* packet_get(struct packet_pool* pool);

uint64_t packet_lost(struct packet_pool* pool);

#endif
