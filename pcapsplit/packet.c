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

#define ETHERNET(p) ((struct ether_header*)p)
#define IP(p) (struct ip*)(p + ETHER_HDR_LEN)
#define IP6(p) (struct ip6_hdr*)(p + ETHER_HDR_LEN)

int packet_init(struct packet* p, struct pcap_pkthdr* header, const unsigned char* data)
{
	uint16_t et = ntohs(ETHERNET(data)->ether_type);
	if (!(et == ETHERTYPE_IP || et == ETHERTYPE_IPV6 || et == ETHERTYPE_VLAN)) {
		p->data = data;
		p->is_ip = p->is_ip6 = 0;
		p->ip =  NULL;
		p->ip6 = NULL;
		return 0;
	}

	p->data = data;
	uint8_t  offset = et == ETHERTYPE_VLAN?4:0; // ethernetheader is shifted by four bytes if vlan is available
	// we don't know whether we received ip or ipv6. So lets try:
	if ((IP(data + offset))->ip_hl == 4 || et == ETHERTYPE_IP) {
		p->is_ip6 = 0;
		p->ip =  IP(p);
		p->ip6 = NULL;
	} else if ((IP(data + offset))->ip_hl == 6 || et == ETHERTYPE_IPV6) {
		p->is_ip6 = 1;
		p->ip = NULL;
		p->ip6 = IP6(p);
	} 

	return 0;
}

