#ifndef _CONNTRACKER_H_
#define _CONNTRACKER_H_

#include <pcap.h>
#include <sys/types.h>

#include <map>
#include <list>

#include "flowkey.h"

struct ConnPacket {
	uint32_t seq;
	uint32_t ack;
	uint64_t oldId;
	uint64_t newId;
};

class ConnTracker {
public:
	ConnTracker();
	void addPacket(const uint8_t* packetData, struct pcap_pkthdr* packetHeader);

	typedef std::list<ConnPacket> PacketList;
	typedef std::map<TcpFlowKey, PacketList> ConnList;

	void reorder();
	void removeDuplicates();
	void generateOutputList();

	size_t count() { return connList.size(); }
private:
	ConnList connList;
	std::map<uint64_t, uint64_t> outputList;
};

#endif
