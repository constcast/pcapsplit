#ifndef _CONNTRACKER_H_
#define _CONNTRACKER_H_

#include <pcap.h>

#include <map>
#include <vector>

#include "flowkey.h"
#include "connpacket.h"

class ConnTracker {
public:
	ConnTracker();
	void addPacket(const uint8_t* packetData, struct pcap_pkthdr* packetHeader);

	typedef std::vector<ConnPacket> PacketList;
	typedef std::map<TcpFlowKey, PacketList> ConnList;

	void reorder();
	void removeDuplicates();
	void generateOutputList();

	size_t count() { return connList.size(); }
private:
	ConnList connList;
	std::map<uint64_t, uint64_t> outputList;
	
	void reorderConnection(PacketList& pList);
	void removeDuplicatesFromConnection(PacketList& pList);

	static bool compare_seq(const ConnPacket& l, const ConnPacket& r);
	static uint32_t start_seq;
};

#endif
