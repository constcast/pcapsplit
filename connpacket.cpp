#include "connpacket.h"

bool ConnPacket::operator==(const ConnPacket& other)
{
	if (other.seq == seq && other.ack == ack && other.len == len)
		return true;
	return false;
}
