#ifndef _CONNPACKET_H_
#define _CONNPACKET_H_

#include <stdint.h>

struct ConnPacket {
	uint32_t seq;
	uint32_t ack;
	uint64_t id;
	uint16_t len;

	bool operator==(const ConnPacket& other);
};

#endif
