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

