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

#ifndef _CONNECTION_H_
#define _CONNECTION_H_

#include <stdint.h>
#include <netinet/in.h>
#include <tools/uthash.h>
#include <packet.h>

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
	UT_hash_handle hh;
};

struct connection*  connections = NULL;

int connection_fill(struct connection* c, struct packet* p);

#endif
