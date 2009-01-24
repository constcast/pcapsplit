#ifndef _CONNPACKET_H_
#define _CONNPACKET_H_

struct ConnPacket {
	uint32_t seq;
	uint32_t ack;
	uint64_t oldId;
	uint64_t newId;
	uint16_t len;

	bool operator==(const ConnPacket& other);
};

#endif
